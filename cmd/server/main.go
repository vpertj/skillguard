// Command server 启动 SkillGuard Web API 服务。
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
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
