package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vpertj/skillguard/internal/cryptx"
	"github.com/vpertj/skillguard/internal/store"
)

// requireAdmin 权限中间件：必须在 authenticate 之后使用。
func (d Deps) requireAdmin(c *gin.Context) {
	role, _ := c.Get(ctxRole)
	if role != "admin" {
		abort(c, http.StatusForbidden, "需要管理员权限")
		return
	}
	c.Next()
}

// handleAdminListUsers 用户列表（含配额）。
func (d Deps) handleAdminListUsers(c *gin.Context) {
	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	users, err := d.Store.ListUsers(c.Request.Context(), limit)
	if err != nil {
		abort(c, http.StatusInternalServerError, "查询用户列表失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

type adminUpdateUserReq struct {
	QuotaAudits     *int    `json:"quota_audits"`
	QuotaLLMReviews *int    `json:"quota_llm_reviews"`
	Role            *string `json:"role"`
}

// handleAdminUpdateUser 调整用户配额/角色。
func (d Deps) handleAdminUpdateUser(c *gin.Context) {
	var req adminUpdateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		abort(c, http.StatusBadRequest, "请求体非法")
		return
	}
	if req.QuotaAudits == nil && req.QuotaLLMReviews == nil && req.Role == nil {
		abort(c, http.StatusBadRequest, "至少提供一个更新字段")
		return
	}
	if req.QuotaAudits != nil && (*req.QuotaAudits < 0 || *req.QuotaAudits > 100000) {
		abort(c, http.StatusBadRequest, "quota_audits 越界")
		return
	}
	if req.QuotaLLMReviews != nil && (*req.QuotaLLMReviews < 0 || *req.QuotaLLMReviews > 100000) {
		abort(c, http.StatusBadRequest, "quota_llm_reviews 越界")
		return
	}
	if req.Role != nil && *req.Role != "user" && *req.Role != "admin" {
		abort(c, http.StatusBadRequest, "角色仅支持 user/admin")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		abort(c, http.StatusBadRequest, "id 非法")
		return
	}
	if err := d.Store.UpdateUserAdmin(c.Request.Context(), id, req.QuotaAudits, req.QuotaLLMReviews, req.Role); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			abort(c, http.StatusNotFound, "用户不存在")
			return
		}
		abort(c, http.StatusBadRequest, fmt.Sprintf("更新失败: %v", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleGetDeepSeekSettings 查询 DeepSeek 配置状态（不回传 key 明文）。
func (d Deps) handleGetDeepSeekSettings(c *gin.Context) {
	configured := d.LLM != nil && d.LLM.Enabled()
	model := ""
	baseURL := ""
	if d.LLM != nil {
		model = d.LLM.Model()
	}
	if configured {
		baseURL = "https://api.deepseek.com"
	}
	c.JSON(http.StatusOK, gin.H{
		"configured": configured,
		"model":      model,
		"base_url":   baseURL,
	})
}

// handlePutDeepSeekSettings 配置/更新 DeepSeek API Key（加密存库 + 热更新）。
// 传空 api_key 表示停用深度分析。
func (d Deps) handlePutDeepSeekSettings(c *gin.Context) {
	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		abort(c, http.StatusBadRequest, "请求体非法")
		return
	}
	req.APIKey = strings.TrimSpace(req.APIKey)

	if req.APIKey == "" {
		// 停用：清空库中配置 + 停用注册表
		if err := d.Store.SetSetting(c.Request.Context(), "deepseek_api_key", ""); err != nil {
			abort(c, http.StatusInternalServerError, "保存设置失败")
			return
		}
		if d.LLM != nil {
			d.LLM.Disable()
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "configured": false})
		return
	}
	if !strings.HasPrefix(req.APIKey, "sk-") {
		abort(c, http.StatusBadRequest, "API Key 格式非法（应以 sk- 开头）")
		return
	}
	enc, err := cryptx.Encrypt(d.JWTSecret, req.APIKey)
	if err != nil {
		abort(c, http.StatusInternalServerError, "加密失败")
		return
	}
	if err := d.Store.SetSetting(c.Request.Context(), "deepseek_api_key", enc); err != nil {
		abort(c, http.StatusInternalServerError, "保存设置失败")
		return
	}
	if d.LLM == nil {
		abort(c, http.StatusInternalServerError, "LLM 注册表未初始化")
		return
	}
	if err := d.LLM.UpdateKey(req.APIKey); err != nil {
		abort(c, http.StatusBadRequest, fmt.Sprintf("更新失败: %v", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "configured": true, "model": d.LLM.Model()})
}
