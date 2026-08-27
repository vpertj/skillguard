// Package report 审计报告生成（Markdown / JSON）。
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vpertj/skillguard/internal/analyzer"
	"github.com/vpertj/skillguard/internal/rules"
)

// ToolName 报告工具名。
const ToolName = "SkillGuard"

// ToolVersion 报告工具版本。
const ToolVersion = "0.1.0"

// ReportData 审计报告数据（JSON Schema 对齐 ARCHITECTURE §3.4）。
type ReportData struct {
	Tool         string                `json:"tool"`
	Version      string                `json:"version"`
	RulesVersion string                `json:"rules_version"`
	Target       string                `json:"target"`
	ScannedFiles int                   `json:"scanned_files"`
	SkippedFiles int                   `json:"skipped_files"`
	SkillMD      *analyzer.SkillMDInfo `json:"skill_md"`
	Score        analyzer.ScoreResult  `json:"score"`
	Findings     []analyzer.Finding    `json:"findings"`
	LLMReview    []*rules.Rule         `json:"llm_review_rules"`
}

// BuildReportData 组装报告数据。空切片统一为 []（保证 JSON 输出为数组而非 null）。
func BuildReportData(scan *analyzer.Result, score analyzer.ScoreResult, target string, meta rules.Meta) ReportData {
	d := ReportData{
		Tool:         ToolName,
		Version:      ToolVersion,
		RulesVersion: meta.Version,
		Target:       target,
		Findings:     []analyzer.Finding{},
		LLMReview:    []*rules.Rule{},
		SkillMD:      nil,
		Score:        score,
	}
	if scan != nil {
		d.ScannedFiles = scan.ScannedFiles
		d.SkippedFiles = scan.SkippedFiles
		if scan.Findings != nil {
			d.Findings = scan.Findings
		}
		if scan.LLMReview != nil {
			d.LLMReview = scan.LLMReview
		}
		d.SkillMD = scan.SkillMD
	}
	return d
}

// RenderJSON 输出 JSON 报告（缩进 2 空格）。
func RenderJSON(d ReportData) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// RenderMarkdown 输出人读 Markdown 报告。
func RenderMarkdown(d ReportData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SkillGuard 审计报告\n\n")
	fmt.Fprintf(&b, "- 目标: `%s`\n", d.Target)
	fmt.Fprintf(&b, "- 规则库版本: %s | 工具版本: %s\n", d.RulesVersion, d.Version)
	fmt.Fprintf(&b, "- 扫描文件: %d（跳过 %d）\n", d.ScannedFiles, d.SkippedFiles)
	fmt.Fprintf(&b, "- 风险评分: **%.1f / 100 — %s %s**\n", d.Score.Score, d.Score.Icon, d.Score.Level)
	fmt.Fprintf(&b, "- 评分说明: 分数越高风险越高（0-20 安全 / 21-50 低风险 / 51-80 高风险 / 81-100 恶意）\n")
	if len(d.Score.Notes) > 0 {
		fmt.Fprintf(&b, "- 行为链加成: %s\n", strings.Join(d.Score.Notes, "；"))
	}
	if len(d.Score.Breakdown) > 0 {
		b.WriteString("\n## 评分分解\n\n| 维度 | 权重 | 最高命中权重 | 贡献 |\n| --- | --- | --- | --- |\n")
		for _, bd := range d.Score.Breakdown {
			fmt.Fprintf(&b, "| %s | %.2f | %d | %.1f |\n", bd.Dimension, bd.Weight, bd.GroupMaxWeight, bd.Contrib)
		}
	}
	b.WriteString("\n## 命中明细\n")
	if len(d.Findings) == 0 {
		b.WriteString("\n未命中任何规则。\n")
	} else {
		fmt.Fprintf(&b, "\n共 %d 条命中：\n", len(d.Findings))
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "\n### [%s] %s %s — %s:%d\n\n```\n%s\n```\n", f.Severity, f.RuleID, f.RuleName, f.File, f.Line, f.Snippet)
		}
	}
	if len(d.LLMReview) > 0 {
		b.WriteString("\n## 待 LLM 复核规则\n\n")
		for _, r := range d.LLMReview {
			fmt.Fprintf(&b, "- %s %s：%s\n", r.ID, r.Name, r.Rationale)
		}
	}
	return b.String()
}
