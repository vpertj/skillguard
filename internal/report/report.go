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

// SandboxReport 沙箱行为观察结果（report 包独立定义，避免对 internal/sandbox 的依赖，
// 保持 parser ← analyzer ← report 的单向依赖；CLI 层负责把 sandbox.Report 适配到此结构）。
type SandboxReport struct {
	Backend            string   `json:"backend"`               // 沙箱后端名（static / gvisor）
	FileReads          []string `json:"file_reads,omitempty"`  // 读取的文件路径
	FileWrites         []string `json:"file_writes,omitempty"` // 写入的文件路径
	NetworkConnections []string `json:"network_connections,omitempty"`
	ProcessTree        []string `json:"process_tree,omitempty"`
	EnvReads           []string `json:"env_reads,omitempty"`
	PVBehavior         string   `json:"pv_behavior,omitempty"`
}

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
	Sandbox      *SandboxReport        `json:"sandbox,omitempty"` // 沙箱启用时填充，默认 off 时不存在
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
	if d.Sandbox != nil {
		b.WriteString("\n## 沙箱行为观察\n\n")
		fmt.Fprintf(&b, "- 后端: `%s`（默认静态模拟，未真正执行代码）\n", d.Sandbox.Backend)
		writeSliceSection(&b, "读取文件", d.Sandbox.FileReads)
		writeSliceSection(&b, "写入文件", d.Sandbox.FileWrites)
		writeSliceSection(&b, "网络外联", d.Sandbox.NetworkConnections)
		writeSliceSection(&b, "进程调用", d.Sandbox.ProcessTree)
		writeSliceSection(&b, "环境变量读取", d.Sandbox.EnvReads)
		if d.Sandbox.PVBehavior != "" {
			fmt.Fprintf(&b, "- 说明: %s\n", d.Sandbox.PVBehavior)
		}
	}
	return b.String()
}

// writeSliceSection 输出一个行为分组（为空时标注"无"）。
func writeSliceSection(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, "- %s: ", title)
	if len(items) == 0 {
		b.WriteString("无\n")
		return
	}
	b.WriteString(strings.Join(items, "、") + "\n")
}
