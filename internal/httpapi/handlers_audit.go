package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vpertj/skillguard/internal/analyzer"
	"github.com/vpertj/skillguard/internal/llm"
	"github.com/vpertj/skillguard/internal/parser"
	"github.com/vpertj/skillguard/internal/report"
	"github.com/vpertj/skillguard/internal/store"
)

// parseUpload 解析上传的技能包（multipart file 字段，zip）。
// 成功时返回文件列表、解压根目录（zip 时需清理）、内容哈希；失败时已写响应，ok=false。
func (d Deps) parseUpload(c *gin.Context) (files []string, root, hash string, ok bool) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		abort(c, http.StatusBadRequest, "缺少 file 字段（multipart zip）")
		return nil, "", "", false
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "skillguard-upload-*.zip")
	if err != nil {
		abort(c, http.StatusInternalServerError, "临时文件创建失败")
		return nil, "", "", false
	}
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		abort(c, http.StatusBadRequest, "读取上传内容失败")
		return nil, "", "", false
	}
	tmp.Close()

	files, root, err = parser.CollectFiles(tmp.Name())
	os.Remove(tmp.Name())
	if err != nil {
		abort(c, http.StatusBadRequest, "技能包格式无法解析（需为 zip）")
		return nil, "", "", false
	}
	// 仅 zip 输入才解压到独立临时目录需要清理；非 zip 内容走单文件分支时 root 指向系统临时目录，绝不能删
	if strings.EqualFold(filepath.Ext(tmp.Name()), ".zip") {
		c.Set("sg_cleanup_root", root)
	}
	hash, err = skillHash(files, root)
	if err != nil {
		abort(c, http.StatusInternalServerError, "计算技能包哈希失败")
		return nil, "", "", false
	}
	return files, root, hash, true
}

// cleanupUpload 在 handler 结束时清理 zip 解压的临时目录。
func cleanupUpload(c *gin.Context) {
	if v, ok := c.Get("sg_cleanup_root"); ok {
		if root, ok := v.(string); ok {
			os.RemoveAll(root)
		}
	}
}

// handleAudit 上传技能包（zip）→ 静态审计 → 报告入库 + 用量记录（免费档）。
// 同日同 hash 重复提交返回缓存报告且不计费。
func (d Deps) handleAudit(c *gin.Context) {
	defer cleanupUpload(c)
	uid := currentUser(c)
	if uid == 0 {
		abort(c, http.StatusUnauthorized, "未认证")
		return
	}
	files, root, hash, ok := d.parseUpload(c)
	if !ok {
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

	a, err := d.Store.CreateAudit(c.Request.Context(), uid, currentAPIKeyID(c), hash, &scoreVal, score.LevelKey, findingsJSON, reportJSON, nil)
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

// handleAuditDeep 付费档：静态审计 + LLM 语义分析（RS-018/RS-019），按 llm_review 计费。
func (d Deps) handleAuditDeep(c *gin.Context) {
	defer cleanupUpload(c)
	if d.LLM == nil || !d.LLM.Enabled() {
		abort(c, http.StatusServiceUnavailable, "LLM 深度分析未配置（请联系管理员在系统设置中配置）")
		return
	}
	uid := currentUser(c)
	if uid == 0 {
		abort(c, http.StatusUnauthorized, "未认证")
		return
	}
	files, root, hash, ok := d.parseUpload(c)
	if !ok {
		return
	}

	// 缓存：需 llm_results 非空（纯静态缓存不算深度分析缓存）
	if cached, err := d.Store.FindCachedAudit(c.Request.Context(), uid, hash); err != nil {
		abort(c, http.StatusInternalServerError, "查询缓存失败")
		return
	} else if cached != nil && len(cached.LLMResults) > 2 {
		c.JSON(http.StatusOK, gin.H{"cached": true, "report": json.RawMessage(cached.ReportJSON), "llm_results": json.RawMessage(cached.LLMResults)})
		return
	}

	// 深度分析配额（缓存命中不计费）
	if exceeded, err := d.Store.QuotaExceeded(c.Request.Context(), uid, "llm_review"); err != nil {
		abort(c, http.StatusInternalServerError, "配额查询失败")
		return
	} else if exceeded {
		abort(c, http.StatusPaymentRequired, "深度分析配额已用尽，请升级套餐")
		return
	}

	// 静态审计
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

	// LLM 语义分析（失败不扣配额，返回静态报告）
	llmReq := collectLLMContext(files, root)
	llmRes, err := d.LLM.Analyze(c.Request.Context(), llmReq)
	if err != nil {
		log.Printf("[httpapi] LLM 分析失败: %v", err)
		abort(c, http.StatusBadGateway, "LLM 分析失败："+err.Error())
		return
	}
	llmResults := buildLLMResults(llmRes)
	llmResultsJSON, _ := json.Marshal(llmResults)

	// 二次裁决：LLM 复核静态命中（误报移除后重评分）。失败降级：保留原静态报告。
	reviewedScore := score
	if d.LLM.Enabled() && len(res.Findings) > 0 {
		revRes, revErr := d.LLM.ReviewFindings(c.Request.Context(), llm.ReviewRequest{
			SkillName:        llmReq.SkillName,
			SkillDescription: llmReq.SkillDescription,
			SkillBody:        llmReq.SkillBody,
			Findings:         toReviewInputs(res.Findings),
		})
		if revErr != nil {
			log.Printf("[httpapi] LLM 二次裁决失败（降级为静态报告）: %v", revErr)
		} else if len(revRes.Reviews) > 0 {
			kept, rejected := analyzer.ApplyReview(res.Findings, revRes.Reviews)
			reviewedScore = analyzer.Score(kept)
			// 报告用裁决后命中重渲染
			res.Findings = kept
			reportJSON, _ = report.RenderJSON(report.BuildReportData(res, reviewedScore, "upload.zip", d.Rules.Meta()))
			// llm_results 追加裁决明细
			for _, rv := range revRes.Reviews {
				llmResults = append(llmResults, map[string]any{
					"rule_id":    "REVIEW:" + rv.RuleID,
					"file":       rv.File,
					"verdict":    rv.EffectiveVerdict(), // malicious | suspicious | benign
					"confidence": rv.Confidence,
					"reason":     rv.Reason,
				})
			}
			llmResultsJSON, _ = json.Marshal(llmResults)
			log.Printf("[httpapi] 二次裁决: 移除误报命中 %d 条，评分 %.1f → %.1f", len(rejected), score.Score, reviewedScore.Score)
		}
	}

	findingsJSON, _ := json.Marshal(res.Findings)
	scoreVal := reviewedScore.Score
	a, err := d.Store.CreateAudit(c.Request.Context(), uid, currentAPIKeyID(c), hash, &scoreVal, reviewedScore.LevelKey, findingsJSON, reportJSON, llmResultsJSON)
	if err != nil {
		log.Printf("[httpapi] 审计入库失败: %v", err)
		abort(c, http.StatusInternalServerError, "审计入库失败")
		return
	}
	if err := d.Store.CreateUsage(c.Request.Context(), uid, &a.ID, "llm_review", 1); err != nil {
		log.Printf("[httpapi] 用量记录失败: %v", err)
	}
	c.JSON(http.StatusCreated, gin.H{"cached": false, "report": json.RawMessage(reportJSON), "llm_results": json.RawMessage(llmResultsJSON)})
}

// toReviewInputs 静态命中 → LLM 裁决输入。
func toReviewInputs(findings []analyzer.Finding) []llm.ReviewFindingInput {
	out := make([]llm.ReviewFindingInput, 0, len(findings))
	for _, f := range findings {
		out = append(out, llm.ReviewFindingInput{RuleID: f.RuleID, File: f.File, Snippet: f.Snippet})
	}
	return out
}

// collectLLMContext 收集 SKILL.md 声明与脚本内容摘要，供 LLM 比对。
func collectLLMContext(files []string, root string) llm.AnalyzeRequest {
	var req llm.AnalyzeRequest
	for _, f := range files {
		path := filepath.Join(root, filepath.FromSlash(f))
		info, err := os.Stat(path)
		if err != nil || !parser.IsScannable(path, info.Size()) {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(parser.FindSkillMD([]string{f})) > 0 {
			if fm, body, err := parser.ParseSkillMD(string(content)); err == nil {
				req.SkillName = fm.Name
				req.SkillDescription = fm.Description
				req.SkillBody = body
			}
		} else {
			req.Scripts = append(req.Scripts, llm.ScriptSnippet{File: f, Snippet: truncateBytes(content, 8000)})
		}
	}
	return req
}

func truncateBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// buildLLMResults 将 LLM 判定转为 API 响应结构。
func buildLLMResults(r *llm.AnalyzeResult) []map[string]any {
	out := make([]map[string]any, 0, 2)
	if r.RoleImpersonation != nil {
		out = append(out, map[string]any{
			"rule_id":    "RS-018",
			"verdict":    r.RoleImpersonation.Verdict(),
			"confidence": r.RoleImpersonation.Confidence,
			"reason":     r.RoleImpersonation.Reason,
		})
	}
	if r.ClaimMismatch != nil {
		out = append(out, map[string]any{
			"rule_id":    "RS-019",
			"verdict":    r.ClaimMismatch.Verdict(),
			"confidence": r.ClaimMismatch.Confidence,
			"reason":     r.ClaimMismatch.Reason,
		})
	}
	return out
}

func currentAPIKeyID(c *gin.Context) *int64 {
	if v, ok := c.Get("api_key_id"); ok {
		if id, ok := v.(int64); ok {
			return &id
		}
	}
	return nil
}

// handleGetAudit 查询单条审计的完整报告（仅本人）。
func (d Deps) handleGetAudit(c *gin.Context) {
	uid := currentUser(c)
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		abort(c, http.StatusBadRequest, "id 非法")
		return
	}
	a, err := d.Store.GetAuditByID(c.Request.Context(), uid, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			abort(c, http.StatusNotFound, "审计记录不存在")
			return
		}
		abort(c, http.StatusInternalServerError, "查询审计失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"report":      json.RawMessage(a.ReportJSON),
		"llm_results": json.RawMessage(a.LLMResults),
	})
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
	llmUsed, err := d.Store.CountUsage(c.Request.Context(), uid, "llm_review")
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
		"static_audit": gin.H{"used": used, "quota": u.QuotaAudits},
		"llm_review":   gin.H{"used": llmUsed, "quota": u.QuotaLLMReviews},
	})
}
