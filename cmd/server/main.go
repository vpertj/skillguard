// Command server 启动 SkillGuard Web API 服务。
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/vpertj/skillguard/internal/analyzer"
	"github.com/vpertj/skillguard/internal/cryptx"
	"github.com/vpertj/skillguard/internal/httpapi"
	"github.com/vpertj/skillguard/internal/llm"
	"github.com/vpertj/skillguard/internal/rules"
	"github.com/vpertj/skillguard/internal/store"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	_ = godotenv.Load() // 有 .env 则加载，没有静默忽略

	dsn := envOr("DATABASE_URL", "postgres://tianjun@localhost:5432/skillguard_dev?sslmode=disable")
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("必须设置环境变量 JWT_SECRET（用户会话签名密钥）")
	}
	port := envOr("PORT", "8080")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}
	log.Printf("数据库迁移完成: %s", dsn)

	rs, err := rules.LoadRules("rules/rules.yaml", "rules/pro-rules.yaml")
	if err != nil {
		log.Fatalf("加载规则库失败: %v", err)
	}
	log.Printf("规则库加载完成: %s", rs.Summary())

	// IOC 威胁情报：启动预热 + 定时刷新（feed 持续更新）。默认本地内嵌文件；
	// 设 SKILLGUARD_IOC_URL 时启用 HTTP feed。版本元数据写入 settings 表便于追溯。
	if db := analyzer.WarmIOC(ctx); db != nil {
		log.Printf("IOC 威胁情报预热完成: %d 条", db.Len())
		recordIOCMeta(ctx, st, db.Len())
	} else {
		log.Printf("IOC 威胁情报不可用（降级无查表）")
	}
	startIOCRefresher(st)

	// LLM 深度分析（付费档）：优先级 环境变量 DEEPSEEK_API_KEY > 库中 settings（管理员后台配置）
	registry := llm.NewRegistry()
	if apiKey := os.Getenv("DEEPSEEK_API_KEY"); apiKey != "" {
		registry.Enable(apiKey, "", "")
		log.Printf("LLM 深度分析已启用（环境变量 key，模型 %s）", registry.Model())
	} else if enc, err := st.GetSetting(ctx, "deepseek_api_key"); err == nil && enc != "" {
		if plain, err := cryptx.Decrypt(jwtSecret, enc); err == nil {
			registry.Enable(plain, "", "")
			log.Printf("LLM 深度分析已启用（后台配置 key，模型 %s）", registry.Model())
		} else {
			log.Printf("警告: 库中 DeepSeek key 解密失败（JWT_SECRET 可能已变更），深度分析不可用: %v", err)
		}
	} else {
		log.Printf("未配置 DeepSeek API Key，深度分析接口将提示未配置（可在管理后台系统设置中配置）")
	}

	// ADMIN_EMAILS 自举：启动时将指定邮箱提升为管理员
	if emails := os.Getenv("ADMIN_EMAILS"); emails != "" {
		list := []string{}
		for _, e := range strings.Split(emails, ",") {
			if e = strings.TrimSpace(e); e != "" {
				list = append(list, e)
			}
		}
		if n, err := st.PromoteAdmins(ctx, list); err != nil {
			log.Printf("警告: 管理员自举失败: %v", err)
		} else if n > 0 {
			log.Printf("已提升 %d 个管理员账号", n)
		}
	}

	router := httpapi.NewRouter(httpapi.Deps{Store: st, JWTSecret: jwtSecret, Rules: rs, LLM: registry})
	srv := &http.Server{Addr: ":" + port, Handler: router}
	log.Printf("SkillGuard API 启动于 http://localhost:%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务异常退出: %v", err)
	}
}

// iocRefreshInterval IOC 定时刷新周期（默认 10 分钟；与 Provider TTL 一致）。
const iocRefreshInterval = 10 * time.Minute

// iocMeta 记录在 settings 表（key="ioc_meta"）的 IOC 版本元数据，用于追溯。
type iocMeta struct {
	Entries   int       `json:"entries"`
	Refreshed time.Time `json:"refreshed"`
}

// recordIOCMeta 把 IOC 元数据写入 settings 表（尽力而为，失败仅记日志不阻塞）。
func recordIOCMeta(ctx context.Context, st *store.Store, entries int) {
	meta := iocMeta{Entries: entries, Refreshed: time.Now().UTC()}
	b, err := json.Marshal(meta)
	if err != nil {
		log.Printf("[skillguard/server] IOC 元数据序列化失败: %v", err)
		return
	}
	if err := st.SetSetting(ctx, "ioc_meta", string(b)); err != nil {
		log.Printf("[skillguard/server] 记录 IOC 元数据失败: %v", err)
	}
}

// startIOCRefresher 启动后台 goroutine 定时刷新 IOC feed（feed 持续更新）。
// 使用 context.Background()（跟随进程生命周期），不依赖 main 的短超时 ctx，
// 避免 30 秒启动超时 ctx 到期后定时刷新停止。
func startIOCRefresher(st *store.Store) {
	go func() {
		ctx := context.Background()
		ticker := time.NewTicker(iocRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				db, err := analyzer.RefreshIOC(ctx)
				if err != nil {
					log.Printf("[skillguard/server] IOC 定时刷新失败（保留旧缓存）: %v", err)
					continue
				}
				log.Printf("[skillguard/server] IOC 定时刷新完成: %d 条", db.Len())
				recordIOCMeta(ctx, st, db.Len())
			}
		}
	}()
}
