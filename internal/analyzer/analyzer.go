// Package analyzer 静态分析器：规则匹配 + 行为链检测 + 风险评分。
package analyzer

import (
	"log"
	"math"
	"sort"

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

// Breakdown 单维度评分分解（ARCHITECTURE §6.1）。
type Breakdown struct {
	Dimension      string  `json:"dimension"`
	Weight         float64 `json:"weight"`
	GroupMaxWeight int     `json:"group_max_weight"`
	Contrib        float64 `json:"contrib"`
}

// ScoreResult 风险评分结果（ARCHITECTURE §3.4 score 字段）。
type ScoreResult struct {
	Score         float64     `json:"score"`
	Level         string      `json:"level"`
	LevelKey      string      `json:"level_key"`
	Icon          string      `json:"icon"`
	Breakdown     []Breakdown `json:"breakdown"`
	Bonus         int         `json:"bonus"`
	Notes         []string    `json:"notes"`
	HitCategories []string    `json:"hit_categories"`
}

// dimension 评分维度。
type dimension struct {
	name   string
	weight float64
}

// categoryDims 类别 → 维度映射（含 V2 预留类别；未知类别落入代码危害性）。
var categoryDims = map[string]dimension{
	"CODE_EXECUTION":   {"代码危害性", 0.40},
	"PERSISTENCE":      {"代码危害性", 0.40},
	"OBFSUSCATION":     {"代码危害性", 0.40},
	"PRIVILEGE_ABUSE":  {"代码危害性", 0.40}, // V2
	"DESTRUCTIVE":      {"代码危害性", 0.40}, // V2
	"DATA_THEFT":       {"数据访问", 0.25},
	"CREDENTIAL_HUNT":  {"数据访问", 0.25}, // V2
	"NETWORK_EXFIL":    {"网络行为", 0.20},
	"NETWORK_EXFIL_V2": {"网络行为", 0.20}, // V2
	"PROMPT_INJECTION": {"提示注入", 0.10},
	"LLM_SPECIFIC":     {"提示注入", 0.10}, // V2
	"SUPPLY_CHAIN":     {"供应链", 0.05},
	"SUPPLY_CHAIN_V2":  {"供应链", 0.05}, // V2
}

var orderedDims = []dimension{
	{"代码危害性", 0.40},
	{"数据访问", 0.25},
	{"网络行为", 0.20},
	{"提示注入", 0.10},
	{"供应链", 0.05},
}

// Score 按五维加权算法计算 0-100 风险分（ARCHITECTURE §6）。
func Score(findings []Finding) ScoreResult {
	if len(findings) == 0 {
		level, key, icon := Grade(0)
		return ScoreResult{
			Score: 0, Level: level, LevelKey: key, Icon: icon,
			Breakdown: []Breakdown{}, Notes: []string{}, HitCategories: []string{},
		}
	}
	groupMax := map[string]int{}
	catSet := map[string]bool{}
	destructiveMax := 0
	for _, f := range findings {
		dim, ok := categoryDims[f.Category]
		if !ok {
			log.Printf("[skillguard/analyzer] 未知类别 %q，落入代码危害性", f.Category)
			dim = dimension{"代码危害性", 0.40}
		}
		if f.Weight > groupMax[dim.name] {
			groupMax[dim.name] = f.Weight
		}
		catSet[f.Category] = true
		if f.Category == "DESTRUCTIVE" && f.Weight > destructiveMax {
			destructiveMax = f.Weight
		}
	}
	var (
		total     float64
		breakdown []Breakdown
	)
	for _, dim := range orderedDims {
		mw, ok := groupMax[dim.name]
		if !ok {
			continue
		}
		contrib := float64(mw) * dim.weight
		total += contrib
		breakdown = append(breakdown, Breakdown{
			Dimension: dim.name, Weight: dim.weight,
			GroupMaxWeight: mw, Contrib: round1(contrib),
		})
	}
	bonus := 0
	notes := []string{}
	dataTheft := catSet["DATA_THEFT"] || catSet["CREDENTIAL_HUNT"]
	exfil := catSet["NETWORK_EXFIL"] || catSet["NETWORK_EXFIL_V2"]
	if dataTheft && exfil {
		bonus += 10
		notes = append(notes, "检测到「数据收集 → 外联」完整链路，+10 分")
	}
	total = round1(total) + float64(bonus)
	if destructiveMax >= 90 {
		if total < 85 {
			total = 85
			notes = append(notes, "破坏性行为最高权重 ≥90，评分下限 85")
		}
	} else if destructiveMax >= 80 {
		if total < 75 {
			total = 75
			notes = append(notes, "破坏性行为最高权重 ≥80，评分下限 75")
		}
	}
	if total > 100 {
		total = 100
	}
	total = round1(total)
	level, key, icon := Grade(total)
	hit := make([]string, 0, len(catSet))
	for c := range catSet {
		hit = append(hit, c)
	}
	sort.Strings(hit)
	return ScoreResult{
		Score: total, Level: level, LevelKey: key, Icon: icon,
		Breakdown: breakdown, Bonus: bonus, Notes: notes, HitCategories: hit,
	}
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// Grade 按分数分级（ARCHITECTURE §6.3）。
func Grade(score float64) (level, key, icon string) {
	switch {
	case score <= 20:
		return "安全", "safe", "✅"
	case score <= 50:
		return "低风险", "low", "⚠️"
	case score <= 80:
		return "高风险", "high", "🔴"
	default:
		return "恶意", "malicious", "☠️"
	}
}
