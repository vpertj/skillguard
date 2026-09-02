// Package report 审计报告生成（Markdown / JSON / SARIF）。
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// sarifSchema SARIF 2.1.0 JSON Schema 地址。
const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// sarifModel SARIF 2.1.0 顶层结构（手写映射，避免第三方依赖，契合单二进制交付）。
type sarifModel struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription *sarifDescription `json:"shortDescription,omitempty"`
	Properties       *sarifProperties  `json:"properties,omitempty"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifProperties struct {
	Category string   `json:"category,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Weight   int      `json:"weight,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex,omitempty"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int           `json:"startLine"`
	Snippet   *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

// severityLevel 把规则 severity 映射为 SARIF level：critical/high→error，medium→warning，low→note。
// 未知 severity 保守降级为 warning（宁可提醒不可漏报）。
func severityLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// sarifURI 把文件路径转为 SARIF URI（反斜杠转正斜杠，跨平台一致）。
func sarifURI(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

// RenderSARIF 输出 SARIF 2.1.0 报告（供 GitHub code-scanning / CI 门禁集成）。
// 每条 finding 映射为一条 result；driver.rules 声明去重后的规则元数据，保证可追溯。
// 空 findings 输出合法 SARIF（results 为空数组），良性技能可被 CI 放行。
func RenderSARIF(d ReportData) ([]byte, error) {
	// 收集报告涉及的全部规则（按 RuleID 字典序去重），建立 ruleIndex 映射。
	ruleIDs := make(map[string]bool)
	for _, f := range d.Findings {
		ruleIDs[f.RuleID] = true
	}
	ruleIndex := make(map[string]int)
	var rules []sarifRule
	for _, id := range sortRuleIDs(ruleIDs) {
		ruleIndex[id] = len(rules)
		rules = append(rules, sarifRule{
			ID:               id,
			ShortDescription: &sarifDescription{Text: id},
		})
	}
	// 用 finding 的元数据补全 rule 信息。
	for _, f := range d.Findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			continue
		}
		rules[idx] = sarifRule{
			ID:               f.RuleID,
			Name:             f.RuleName,
			ShortDescription: &sarifDescription{Text: f.RuleName},
			Properties: &sarifProperties{
				Category: f.Category,
				Severity: f.Severity,
				Weight:   f.Weight,
			},
		}
	}

	results := make([]sarifResult, 0, len(d.Findings))
	for _, f := range d.Findings {
		// SARIF 规范要求 startLine >= 1；Line 异常时保守置 1，保证输出合法。
		startLine := f.Line
		if startLine < 1 {
			startLine = 1
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     severityLevel(f.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("[%s] %s: %s", f.RuleID, f.RuleName, f.Snippet),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifURI(f.File)},
						Region:           &sarifRegion{StartLine: startLine, Snippet: &sarifSnippet{Text: f.Snippet}},
					},
				},
			},
		})
	}

	model := sarifModel{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    ToolName,
						Version: ToolVersion,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}
	return json.MarshalIndent(model, "", "  ")
}

// sortRuleIDs 返回按字典序排列的规则 ID 切片。
func sortRuleIDs(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
