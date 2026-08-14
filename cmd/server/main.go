// Command server 启动 SkillGuard Web API 服务。
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/tianjun/skillguard/internal/httpapi"
	"github.com/tianjun/skillguard/internal/store"
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

	router := httpapi.NewRouter(httpapi.Deps{Store: st, JWTSecret: jwtSecret})
	srv := &http.Server{Addr: ":" + port, Handler: router}
	log.Printf("SkillGuard API 启动于 http://localhost:%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务异常退出: %v", err)
	}
}
