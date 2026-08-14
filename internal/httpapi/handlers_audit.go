package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/tianjun/skillguard/internal/analyzer"
	"github.com/tianjun/skillguard/internal/parser"
	"github.com/tianjun/skillguard/internal/report"
)

// handleAudit 上传技能包（zip）→ 静态审计 → 报告入库 + 用量记录。
// 同日同 hash 重复提交返回缓存报告且不计费。
func (d Deps) handleAudit(c *gin.Context) {
	uid := currentUser(c)
	if uid == 0 {
		abort(c, http.StatusUnauthorized, "未认证")
		return
	}
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		abort(c, http.StatusBadRequest, "缺少 file 字段（multipart zip）")
		return
	}
	defer file.Close()

	// 落盘临时文件（zip 需随机访问）
	tmp, err := os.CreateTemp("", "skillguard-upload-*.zip")
	if err != nil {
		abort(c, http.StatusInternalServerError, "临时文件创建失败")
		return
	}
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		abort(c, http.StatusBadRequest, "读取上传内容失败")
		return
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	// 采集技能包文件（zip 解压到临时目录）
	files, root, err := parser.CollectFiles(tmp.Name())
	if err != nil {
		abort(c, http.StatusBadRequest, "技能包格式无法解析（需为 zip）")
		return
	}
	defer os.RemoveAll(root)

	// 内容哈希（去重缓存键）
	hash, err := skillHash(files, root)
	if err != nil {
		abort(c, http.StatusInternalServerError, "计算技能包哈希失败")
		return
	}

	// 去重缓存：同日同 hash 直接返回历史报告，不计费
	if cached, err := d.Store.FindCachedAudit(c.Request.Context(), uid, hash); err != nil {
		abort(c, http.StatusInternalServerError, "查询缓存失败")
		return
	} else if cached != nil {
		c.JSON(http.StatusOK, gin.H{"cached": true, "report": json.RawMessage(cached.ReportJSON)})
		return
	}

	// 配额检查（缓存命中不计费，故在缓存 miss 之后）
	if exceeded, err := d.Store.QuotaExceeded(c.Request.Context(), uid, "static_audit"); err != nil {
		abort(c, http.StatusInternalServerError, "配额查询失败")
		return
	} else if exceeded {
		abort(c, http.StatusPaymentRequired, "免费配额已用尽，请升级套餐")
		return
	}

	// 内核审计
	res, err := analyzer.Analyze(files, root, d.Rules)
	if err != nil {
		abort(c, http.StatusInternalServerError, "审计执行失败")
		return
	}
	score := analyzer.Score(res.Findings)
	data := report.BuildReportData(res, score, "upload.zip", d.Rules.Meta())
	reportJSON, err := report.RenderJSON(data)
	if err != nil {
		abort(c, http.StatusInternalServerError, "报告生成失败")
		return
	}
	findingsJSON, _ := json.Marshal(res.Findings)
	scoreVal := score.Score

	var apiKeyID *int64
	if v, ok := c.Get("api_key_id"); ok {
		if id, ok := v.(int64); ok {
			apiKeyID = &id
		}
	}
	a, err := d.Store.CreateAudit(c.Request.Context(), uid, apiKeyID, hash, &scoreVal, score.LevelKey, findingsJSON, reportJSON)
	if err != nil {
		log.Printf("[httpapi] 审计入库失败: %v", err)
		abort(c, http.StatusInternalServerError, "审计入库失败")
		return
	}
	if err := d.Store.CreateUsage(c.Request.Context(), uid, &a.ID, "static_audit", 1); err != nil {
		log.Printf("[httpapi] 用量记录失败: %v", err)
	}
	c.JSON(http.StatusCreated, gin.H{"cached": false, "report": json.RawMessage(reportJSON)})
}

// handleListAudits 审计历史（最新在前，不含完整报告）。
func (d Deps) handleListAudits(c *gin.Context) {
	uid := currentUser(c)
	list, err := d.Store.ListAudits(c.Request.Context(), uid, 50)
	if err != nil {
		abort(c, http.StatusInternalServerError, "查询审计历史失败")
		return
	}
	// 列表轻量化：只保留摘要字段
	type brief struct {
		ID        int64    `json:"id"`
		SkillHash string   `json:"skill_hash"`
		Score     *float64 `json:"score,omitempty"`
		LevelKey  string   `json:"level_key"`
		CreatedAt string   `json:"created_at"`
	}
	out := make([]brief, 0, len(list))
	for _, a := range list {
		out = append(out, brief{ID: a.ID, SkillHash: a.SkillHash[:12], Score: a.Score, LevelKey: a.LevelKey, CreatedAt: a.CreatedAt.Format("2006-01-02 15:04:05")})
	}
	c.JSON(http.StatusOK, gin.H{"audits": out})
}

// skillHash 计算技能包内容哈希（文件名 + 内容，排序后拼接）。
func skillHash(files []string, root string) (string, error) {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, f := range sorted {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			continue
		}
		h.Write([]byte(f))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// handleUsage 返回用户用量与配额。
func (d Deps) handleUsage(c *gin.Context) {
	uid := currentUser(c)
	used, err := d.Store.CountUsage(c.Request.Context(), uid, "static_audit")
	if err != nil {
		abort(c, http.StatusInternalServerError, "用量查询失败")
		return
	}
	u, err := d.Store.GetUserByID(c.Request.Context(), uid)
	if err != nil {
		abort(c, http.StatusInternalServerError, "用户查询失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"kind":  "static_audit",
		"used":  used,
		"quota": u.QuotaAudits,
	})
}
