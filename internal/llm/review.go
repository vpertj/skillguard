package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ReviewFindingInput 待复核的静态命中（LLM 需要规则 ID + 片段 + 文件）。
type ReviewFindingInput struct {
	RuleID  string `json:"rule_id"`
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// FindingReview 单条命中的 LLM 裁决。
type FindingReview struct {
	RuleID     string `json:"rule_id"`
	File       string `json:"file"`
	Snippet    string `json:"snippet"`
	Confirmed  bool   `json:"confirmed"`  // true=真实恶意，false=误报
	Confidence string `json:"confidence"` // high | medium | low
	Reason     string `json:"reason"`
}

// ReviewRequest 二次裁决输入：技能上下文 + 全部静态命中。
type ReviewRequest struct {
	SkillName        string               `json:"skill_name"`
	SkillDescription string               `json:"skill_description"`
	SkillBody        string               `json:"skill_body"`
	Findings         []ReviewFindingInput `json:"findings"`
}

// ReviewResult 二次裁决结果。
type ReviewResult struct {
	Reviews []FindingReview `json:"reviews"`
	Raw     string          `json:"-"`
}

// ReviewProvider 二次裁决能力（静态命中 → 意图复核）。
type ReviewProvider interface {
	ReviewFindings(ctx context.Context, req ReviewRequest) (*ReviewResult, error)
}

// reviewSystemPrompt 二次裁决的 system 提示词。
const reviewSystemPrompt = `你是 Agent 技能安全审计员。用户会给你一个 AI Agent 技能（SKILL.md 及附属脚本）的内容，以及静态扫描器的命中列表。
对每一条命中，判断它是否为真实的恶意行为，还是正常开发用法/文档提及造成的误报。

判断标准：
- confirmed=true：该命中确实构成恶意行为（窃取数据、执行任意命令、外联传输、隐藏指令等）
- confirmed=false：该命中是误报（如 subprocess 调用 LibreOffice 是合法文档转换、re.compile 是正常正则编译、文档里提到 URL 是正常引用）
- 无法确定时 confirmed=false 且 confidence=low（宁可不罚，不可误杀）

必须逐条输出，rule_id 与输入一一对应，不得遗漏。输出 JSON：{"reviews":[{"rule_id":"...","file":"...","snippet":"...","confirmed":bool,"confidence":"high|medium|low","reason":"简短中文理由"}]}`

// ReviewFindings 调用模型对静态命中做意图复核。
// 模型失败/非 JSON 时返回空 Reviews（不报错，主流程不受影响）。
func (d *DeepSeek) ReviewFindings(ctx context.Context, req ReviewRequest) (*ReviewResult, error) {
	if len(req.Findings) == 0 {
		return &ReviewResult{}, nil
	}
	prompt := buildReviewPrompt(req)
	payload := map[string]any{
		"model": d.model,
		"messages": []map[string]string{
			{"role": "system", "content": reviewSystemPrompt},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
		"max_tokens":  1200,
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

	var chat struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &chat); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if len(chat.Choices) == 0 {
		return &ReviewResult{Raw: string(respBody)}, nil
	}
	content := chat.Choices[0].Message.Content
	raw := extractJSON(content)

	var out ReviewResult
	out.Raw = content
	if len(raw) == 0 {
		return &out, nil // 模型未返回 JSON，降级为空（不影响主流程）
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return &out, nil // 解析失败同样降级
	}
	return &out, nil
}

// buildReviewPrompt 组装二次裁决用户提示词。
func buildReviewPrompt(req ReviewRequest) string {
	var b strings.Builder
	b.WriteString("## 技能信息\n")
	b.WriteString(fmt.Sprintf("- 名称: %s\n", orDash(req.SkillName)))
	b.WriteString(fmt.Sprintf("- 描述: %s\n", orDash(req.SkillDescription)))
	if len(req.SkillBody) > 0 {
		b.WriteString(fmt.Sprintf("- 正文预览: %s\n", truncateRunes(req.SkillBody, 1500)))
	}
	b.WriteString("\n## 静态命中列表\n")
	for i, f := range req.Findings {
		b.WriteString(fmt.Sprintf("%d. [%s] %s @%s\n   片段: %s\n",
			i+1, f.RuleID, f.File, f.RuleID, truncateRunes(f.Snippet, 200)))
	}
	b.WriteString("\n逐条判断并输出 JSON（规则见 system 提示）。")
	return b.String()
}

var _ ReviewProvider = (*DeepSeek)(nil)
