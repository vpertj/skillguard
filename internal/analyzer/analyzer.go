// Package analyzer 静态分析器：规则匹配 + 行为链检测 + 风险评分。
package analyzer

import (
	"github.com/tianjun/skillguard/internal/rules"
)

// Finding 单次规则命中（ARCHITECTURE §3.3）。
type Finding struct {
	RuleID    string `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Weight    int    `json:"weight"`
	Detection string `json:"detection"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Snippet   string `json:"snippet"`
}

// ScanContent 对单文件内容扫描给定规则，返回全部命中（每条规则至多 1 条）。
// llm 规则与无 patterns 的规则不参与扫描。
func ScanContent(content string, ruleList []*rules.Rule, fileLabel string) []Finding {
	var findings []Finding
	for _, r := range ruleList {
		if r.Detection == "llm" || len(r.Patterns) == 0 {
			continue
		}
		compiled, err := rules.CompilePatterns(r.Patterns)
		if err != nil {
			continue
		}
		line, snippet, ok := rules.FindFirstMatch(compiled, content)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			RuleID:    r.ID,
			RuleName:  r.Name,
			Category:  r.Category,
			Severity:  r.Severity,
			Weight:    r.Weight,
			Detection: r.Detection,
			File:      fileLabel,
			Line:      line,
			Snippet:   snippet,
		})
	}
	return findings
}
