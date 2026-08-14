// Package llm LLM 语义分析：对技能包做角色伪装（RS-018）与声明-行为不一致（RS-019）判定。
// Provider 可插拔：DeepSeek 为 OpenAI 兼容实现，后续可加通义/Claude。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Verdict 判定结果枚举。
type Verdict string

const (
	VerdictSuspicious Verdict = "suspicious" // 可疑
	VerdictClean      Verdict = "clean"      // 正常
	VerdictUnknown    Verdict = "unknown"    // 无法判定（解析失败等，不影响主流程）
)

// ScriptSnippet 脚本摘要（供 LLM 比对声明与行为）。
type ScriptSnippet struct {
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// AnalyzeRequest 分析输入。
type AnalyzeRequest struct {
	SkillName        string          `json:"skill_name"`
	SkillDescription string          `json:"skill_description"`
	SkillBody        string          `json:"skill_body"`
	Scripts          []ScriptSnippet `json:"scripts"`
	StaticFindings   []FindingBrief  `json:"static_findings,omitempty"`
}

// FindingBrief 静态命中摘要（辅助 LLM 判断，可选）。
type FindingBrief struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name"`
	File   string `json:"file"`
}

// VerdictDetail 单条规则的判定。
type VerdictDetail struct {
	Suspicious bool   `json:"suspicious"`
	Confidence string `json:"confidence"` // high | medium | low
	Reason     string `json:"reason"`
}

// Verdict 语义判定值（nil / 解析失败时为 unknown）。
func (v *VerdictDetail) Verdict() Verdict {
	if v == nil {
		return VerdictUnknown
	}
	if v.Suspicious {
		return VerdictSuspicious
	}
	return VerdictClean
}

// AnalyzeResult LLM 判定结果（RS-018 / RS-019）。
type AnalyzeResult struct {
	RoleImpersonation *VerdictDetail `json:"role_impersonation"`
	ClaimMismatch     *VerdictDetail `json:"claim_mismatch"`
	Raw               string         `json:"-"`
}

// Provider LLM 服务抽象（可插拔）。
type Provider interface {
	Analyze(ctx context.Context, req AnalyzeRequest) (*AnalyzeResult, error)
}

// DeepSeek OpenAI 兼容客户端。
type DeepSeek struct {
	apiKey  string
	baseURL string
	model   string
	http    *http.Client
}

// NewDeepSeek 从环境变量构造：DEEPSEEK_API_KEY（必填）、DEEPSEEK_MODEL（默认 deepseek-v4-flash）。
func NewDeepSeek(apiKey string) (*DeepSeek, error) {
	if apiKey == "" {
		return nil, errors.New("DEEPSEEK_API_KEY 未设置")
	}
	model := os.Getenv("DEEPSEEK_MODEL")
	if model == "" {
		model = "deepseek-v4-flash"
	}
	return NewDeepSeekWithBase(apiKey, "https://api.deepseek.com", model), nil
}

// NewDeepSeekWithBase 测试用：自定义 base URL。
func NewDeepSeekWithBase(apiKey, baseURL, model string) *DeepSeek {
	return &DeepSeek{
		apiKey:  apiKey,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		model:   model,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// Analyze 调用模型判定 RS-018/RS-019，返回结构化结果。
// 模型返回非 JSON / 字段缺失时降级为 unknown，不返回错误（审计主流程不受影响）。
func (d *DeepSeek) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalyzeResult, error) {
	prompt := buildPrompt(req)
	payload := map[string]any{
		"model": d.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
		"max_tokens":  800,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+d.apiKey)

	resp, err := d.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("调用 DeepSeek 失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DeepSeek 返回 %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &completion); err != nil || len(completion.Choices) == 0 {
		return nil, errors.New("DeepSeek 响应格式异常")
	}
	content := completion.Choices[0].Message.Content

	result := &AnalyzeResult{Raw: content}
	if err := json.Unmarshal(extractJSON(content), result); err != nil {
		// 解析失败：判定置 nil（对外表现为 unknown），不阻断审计
		return result, nil
	}
	return result, nil
}

// extractJSON 剥掉 markdown 代码块围栏，取首个 JSON 对象。
func extractJSON(s string) []byte {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i != -1 {
		rest := s[i+3:]
		// 去掉 "json" 语言标注行
		if j := strings.IndexByte(rest, '\n'); j != -1 {
			rest = rest[j+1:]
		}
		if k := strings.LastIndex(rest, "```"); k != -1 {
			rest = rest[:k]
		}
		s = strings.TrimSpace(rest)
	}
	return []byte(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// systemPrompt 模型行为约束（强制 JSON schema 输出）。
const systemPrompt = `你是技能安全审计专家。用户会给你一个 AI Agent 技能包的信息（SKILL.md 声明 + 脚本内容 + 静态检测命中）。
请判断两条规则：
1. role_impersonation（RS-018 角色伪装）：技能是否冒充官方/系统级/可信厂商身份，且与实际行为不符。
2. claim_mismatch（RS-019 声明-行为不一致）：SKILL.md 声明的无害行为（如"只读"、"不联网"、"仅清理"）是否与脚本实际行为矛盾。

只输出 JSON，不要任何其他文字，格式严格如下：
{"role_impersonation":{"suspicious":true,"confidence":"high","reason":"简短中文理由"},"claim_mismatch":{"suspicious":false,"confidence":"medium","reason":"简短中文理由"}}
confidence 取值 high/medium/low。拿不准时 suspicious 取 false 并降低 confidence。`

// buildPrompt 组装分析输入（裁剪防 token 爆炸）。
func buildPrompt(req AnalyzeRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "技能名称: %s\n", orDash(req.SkillName))
	fmt.Fprintf(&b, "技能描述: %s\n", orDash(req.SkillDescription))
	fmt.Fprintf(&b, "SKILL.md 正文(前800字):\n%s\n\n", truncateRunes(req.SkillBody, 800))
	if len(req.Scripts) > 0 {
		b.WriteString("脚本内容:\n")
		for _, s := range req.Scripts {
			fmt.Fprintf(&b, "--- %s ---\n%s\n", s.File, truncate(s.Snippet, 8000))
		}
	}
	if len(req.StaticFindings) > 0 {
		b.WriteString("静态检测命中:\n")
		for _, f := range req.StaticFindings {
			fmt.Fprintf(&b, "- %s %s (%s)\n", f.RuleID, f.Name, f.File)
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
