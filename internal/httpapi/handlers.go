// Package httpapi HTTP API 层：路由、认证中间件、用户/API Key/审计处理器。
package httpapi

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vpertj/skillguard/internal/auth"
	"github.com/vpertj/skillguard/internal/llm"
	"github.com/vpertj/skillguard/internal/rules"
	"github.com/vpertj/skillguard/internal/store"
)

// Deps 依赖注入。
type Deps struct {
	Store     *store.Store
	JWTSecret string
	Rules     *rules.RuleSet
	LLM       *llm.Registry // nil 或未启用时深度分析接口返回 503
}

const (
	ctxUserID = "uid"
	ctxEmail  = "email"
	ctxRole   = "role"
	// jwtTTL 用户会话有效期。
	jwtTTL = 7 * 24 * time.Hour
)

// NewRouter 组装全部路由。
func NewRouter(d Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	v1 := r.Group("/v1")
	{
		v1.POST("/auth/register", d.handleRegister)
		v1.POST("/auth/login", d.handleLogin)

		authed := v1.Group("", d.authenticate)
		{
			authed.POST("/keys", d.handleCreateKey)
			authed.GET("/keys", d.handleListKeys)
			authed.DELETE("/keys/:id", d.handleRevokeKey)
			authed.POST("/audit", d.handleAudit)
			authed.POST("/audit/deep", d.handleAuditDeep)
			authed.GET("/audits", d.handleListAudits)
			authed.GET("/audits/:id", d.handleGetAudit)
			authed.GET("/usage", d.handleUsage)

			admin := authed.Group("", d.requireAdmin)
			{
				admin.GET("/admin/users", d.handleAdminListUsers)
				admin.PUT("/admin/users/:id", d.handleAdminUpdateUser)
				admin.GET("/admin/settings/deepseek", d.handleGetDeepSeekSettings)
				admin.PUT("/admin/settings/deepseek", d.handlePutDeepSeekSettings)
			}
		}
	}
	return r
}

// authenticate 认证中间件：优先 API Key（Bearer sk_xxx），其次 JWT。
// 成功后注入 uid/email/role 到上下文。
func (d Deps) authenticate(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if header == "" {
		abort(c, http.StatusUnauthorized, "缺少 Authorization 头")
		return
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		abort(c, http.StatusUnauthorized, "Authorization 格式应为 Bearer <token>")
		return
	}
	cred := parts[1]

	// API Key：sk_live_ 前缀
	if strings.HasPrefix(cred, auth.APIKeyPrefix) {
		key, err := d.Store.GetAPIKeyByHash(c.Request.Context(), auth.HashAPIKey(cred))
		if err != nil {
			abort(c, http.StatusUnauthorized, "API Key 无效或已吊销")
			return
		}
		c.Set(ctxUserID, key.UserID)
		c.Set(ctxRole, "user")
		c.Set("api_key_id", key.ID)
		c.Next()
		return
	}

	// JWT
	claims, err := auth.ParseJWT(d.JWTSecret, cred)
	if err != nil {
		abort(c, http.StatusUnauthorized, "Token 无效或已过期")
		return
	}
	c.Set(ctxUserID, claims.UserID)
	c.Set(ctxEmail, claims.Email)
	c.Set(ctxRole, claims.Role)
	c.Next()
}

// currentUser 从上下文取用户 ID。
func currentUser(c *gin.Context) int64 {
	if v, ok := c.Get(ctxUserID); ok {
		if id, ok := v.(int64); ok {
			return id
		}
	}
	return 0
}

func abort(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg})
}

// --- auth handlers ---

type credReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (d Deps) handleRegister(c *gin.Context) {
	var req credReq
	if err := c.ShouldBindJSON(&req); err != nil {
		abort(c, http.StatusBadRequest, "请求体必须是 JSON")
		return
	}
	if !strings.Contains(req.Email, "@") || len(req.Email) < 5 {
		abort(c, http.StatusBadRequest, "邮箱格式非法")
		return
	}
	if len(req.Password) < 8 {
		abort(c, http.StatusBadRequest, "密码至少 8 位")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		abort(c, http.StatusInternalServerError, "密码处理失败")
		return
	}
	u, err := d.Store.CreateUser(c.Request.Context(), req.Email, hash, "user")
	if err != nil {
		log.Printf("[httpapi] 注册失败: %v", err)
		abort(c, http.StatusConflict, "邮箱已注册")
		return
	}
	token, err := auth.IssueJWT(d.JWTSecret, u.ID, u.Email, u.Role, jwtTTL)
	if err != nil {
		abort(c, http.StatusInternalServerError, "签发 token 失败")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"token": token, "user": u})
}

func (d Deps) handleLogin(c *gin.Context) {
	var req credReq
	if err := c.ShouldBindJSON(&req); err != nil {
		abort(c, http.StatusBadRequest, "请求体必须是 JSON")
		return
	}
	u, err := d.Store.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil || !auth.CheckPassword(u.PasswordHash, req.Password) {
		abort(c, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	token, err := auth.IssueJWT(d.JWTSecret, u.ID, u.Email, u.Role, jwtTTL)
	if err != nil {
		abort(c, http.StatusInternalServerError, "签发 token 失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "user": u})
}

// --- api key handlers ---

func (d Deps) handleCreateKey(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
	}
	_ = c.ShouldBindJSON(&req)
	uid := currentUser(c)
	plain, prefix, hash, err := auth.GenerateAPIKey()
	if err != nil {
		abort(c, http.StatusInternalServerError, "生成 API Key 失败")
		return
	}
	k, err := d.Store.CreateAPIKey(c.Request.Context(), uid, prefix, hash, req.Name)
	if err != nil {
		abort(c, http.StatusInternalServerError, "保存 API Key 失败")
		return
	}
	// 明文仅此一次返回
	c.JSON(http.StatusCreated, gin.H{
		"key":        plain,
		"key_prefix": k.KeyPrefix,
		"name":       k.Name,
		"id":         k.ID,
		"created_at": k.CreatedAt,
	})
}

func (d Deps) handleListKeys(c *gin.Context) {
	uid := currentUser(c)
	keys, err := d.Store.ListAPIKeys(c.Request.Context(), uid)
	if err != nil {
		abort(c, http.StatusInternalServerError, "查询 API Key 失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

func (d Deps) handleRevokeKey(c *gin.Context) {
	uid := currentUser(c)
	var id int64
	if _, err := fmt.Sscanf(c.Param("id"), "%d", &id); err != nil {
		abort(c, http.StatusBadRequest, "id 非法")
		return
	}
	if err := d.Store.RevokeAPIKey(c.Request.Context(), uid, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			abort(c, http.StatusNotFound, "Key 不存在")
			return
		}
		abort(c, http.StatusInternalServerError, "吊销失败")
		return
	}
	c.Status(http.StatusNoContent)
}
