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
	Verdict    string `json:"verdict"`    // malicious | suspicious | benign（缺省回退 Confirmed）
	Confirmed  bool   `json:"confirmed"`  // 兼容旧字段：true=malicious，false=benign
	Confidence string `json:"confidence"` // high | medium | low
	Reason     string `json:"reason"`
}

// EffectiveVerdict 归一化裁决：优先 verdict 字段，缺省按 Confirmed 回退。
func (r FindingReview) EffectiveVerdict() string {
	switch r.Verdict {
	case "malicious", "suspicious", "benign":
		return r.Verdict
	}
	if r.Confirmed {
		return "malicious"
	}
	return "benign"
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
对每一条命中，给出三级裁决：

- verdict=malicious：命中构成明确的恶意行为（窃取数据、执行任意命令、外联传输、隐藏指令、可疑下载执行等）
- verdict=suspicious：命中是高风险功能但可能是合法用途（如技能的核心功能就是调用 subprocess/网络/环境变量），或你无法确定——不确定时一律用 suspicious
- verdict=benign：明确合法的业务场景（文档处理技能调用 subprocess 执行 LibreOffice/soffice 转换、re.compile 正则编译、os.environ.copy() 给子进程传环境）

重要背景：攻击者会刻意把恶意技能伪装成专业、无害的正常工具（ClawHavoc 活动就是这样——文档专业、外观正常，恶意藏在脚本调用里）。因此：
- 静态命中是强信号；只有能明确识别出合法业务场景才判 benign
- 无法确定时 verdict=suspicious（安全审计宁可降权不可漏检）

必须逐条输出，rule_id 与输入一一对应，不得遗漏。输出 JSON：{"reviews":[{"rule_id":"...","file":"...","snippet":"...","verdict":"malicious|suspicious|benign","confidence":"high|medium|low","reason":"简短中文理由"}]}`

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
