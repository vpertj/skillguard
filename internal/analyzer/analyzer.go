// Package analyzer 静态分析器：规则匹配 + 行为链检测 + 风险评分。
package analyzer

import (
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vpertj/skillguard/internal/astscan"
	"github.com/vpertj/skillguard/internal/ioc"
	"github.com/vpertj/skillguard/internal/parser"
	"github.com/vpertj/skillguard/internal/rules"
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
// 文件类型加权（2026-08-28，基准驱动）：文档（.md 等）里的代码行为类命中是示例/说明，
// 降权 50%；提示注入类（攻击载体就是文档）与脚本类命中保持全权重。
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
		w := effectiveWeight(f)
		if w > groupMax[dim.name] {
			groupMax[dim.name] = w
		}
		catSet[f.Category] = true
		if f.Category == "DESTRUCTIVE" && w > destructiveMax {
			destructiveMax = w
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
	// IOC 命中保底：已知 C2/恶意基础设施是确凿证据，即使单维 100×0.20=20 恰卡线，
	// 也保证检出（+5 分）。
	if hasIOCHit(findings) {
		bonus += 5
		notes = append(notes, "命中已知 C2/恶意基础设施（IOC），+5 分")
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

// effectiveWeight 应用文件类型加权：
// - 文档（.md/.markdown/.txt）里的代码行为类命中 → 权重减半（示例/说明，非执行）
// - 提示注入/混淆类（攻击载体就是文档内容）→ 不降权
// - IOC 查表命中 → 不降权（内容出现已知 C2/恶意域名即确凿证据）
// - 脚本/其他文件 → 全权重
func effectiveWeight(f Finding) int {
	if !isDocFile(f.File) {
		return f.Weight
	}
	if f.Detection == "ioc" {
		return f.Weight
	}
	switch f.Category {
	case "PROMPT_INJECTION", "LLM_SPECIFIC", "OBFSUSCATION":
		return f.Weight
	}
	w := f.Weight / 2
	if w < 1 {
		w = 1
	}
	return w
}

// hasIOCHit 判断命中列表是否含 IOC 查表命中。
func hasIOCHit(findings []Finding) bool {
	for _, f := range findings {
		if f.Detection == "ioc" {
			return true
		}
	}
	return false
}

// isDocFile 判断是否为文档文件（命中可能是示例/说明而非执行代码）。
func isDocFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".markdown") ||
		strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".mdx")
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

// SkillMDInfo SKILL.md 解析信息（报告 skill_md 字段）。
type SkillMDInfo struct {
	File        string             `json:"file"`
	Frontmatter parser.Frontmatter `json:"frontmatter"`
	BodyPreview string             `json:"body_preview"`
}

// Result 一次全包扫描的结果。
type Result struct {
	Findings     []Finding
	LLMReview    []*rules.Rule
	SkillMD      *SkillMDInfo
	ScannedFiles int
	SkippedFiles int
}

// Analyze 对技能包文件集做全量静态扫描（ARCHITECTURE §4.1 阶段 1-3）。
// files 为相对 root 的路径列表（parser.CollectFiles 的产物）。
func Analyze(files []string, root string, rs *rules.RuleSet) (*Result, error) {
	res := &Result{LLMReview: rs.LLMOnly()}
	extRules := rs.FileExtOnly()
	astEnabled := len(rs.ByDetection("ast")) > 0
	iocEnabled := len(rs.ByDetection("ioc")) > 0
	var iocDB *ioc.DB
	if iocEnabled {
		iocDB = loadIOCDB()
	}
	for _, f := range files {
		path := filepath.Join(root, filepath.FromSlash(f))
		info, err := os.Stat(path)
		if err != nil {
			res.SkippedFiles++
			continue
		}
		// 文件级检测：扩展名黑名单（zip/可执行等恶意分发特征）
		if len(extRules) > 0 && !info.IsDir() {
			lower := strings.ToLower(f)
			for _, r := range extRules {
				for _, ext := range r.Patterns {
					if strings.HasSuffix(lower, strings.ToLower(ext)) {
						res.Findings = append(res.Findings, Finding{
							RuleID: r.ID, RuleName: r.Name, Category: r.Category,
							Severity: r.Severity, Weight: r.Weight, Detection: r.Detection,
							File: f, Line: 1, Snippet: "内嵌分发包: " + filepath.Base(f),
						})
						break
					}
				}
			}
		}
		if !parser.IsScannable(path, info.Size()) {
			res.SkippedFiles++
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			res.SkippedFiles++
			continue
		}
		res.ScannedFiles++
		// IOC 查表：已知 C2 IP/恶意域名（快且确凿）
		if iocDB != nil {
			for _, hit := range iocDB.MatchAll(string(content)) {
				res.Findings = append(res.Findings, Finding{
					RuleID: "RS-038", RuleName: "已知 C2/恶意基础设施（IOC）",
					Category: "NETWORK_EXFIL", Severity: "critical",
					Weight: 100, Detection: "ioc",
					File: f, Line: 1,
					Snippet: "已知恶意基础设施: " + hit.Value + "（" + hit.Category + "）",
				})
			}
		}
		// AST 级检测：Python 脚本危险调用链（tree-sitter）
		if astEnabled && strings.HasSuffix(strings.ToLower(f), ".py") {
			for _, d := range astscan.ScanPython(content, f) {
				res.Findings = append(res.Findings, Finding{
					RuleID: d.RuleID, RuleName: "危险子进程调用链（AST）",
					Category: d.Category, Severity: d.Severity,
					Weight: d.Weight, Detection: "ast",
					File: d.File, Line: d.Line, Snippet: d.Snippet,
				})
			}
		}
		if len(parser.FindSkillMD([]string{f})) > 0 {
			fm, body, err := parser.ParseSkillMD(string(content))
			if err != nil {
				log.Printf("[skillguard/analyzer] SKILL.md 解析失败: %v", err)
			}
			res.SkillMD = &SkillMDInfo{File: f, Frontmatter: fm, BodyPreview: preview(body)}
		}
		for _, r := range rs.AutoDetectable() {
			line, snippet, ok := rs.MatchRule(r.ID, string(content))
			if !ok {
				continue
			}
			res.Findings = append(res.Findings, Finding{
				RuleID: r.ID, RuleName: r.Name, Category: r.Category,
				Severity: r.Severity, Weight: r.Weight, Detection: r.Detection,
				File: f, Line: line, Snippet: snippet,
			})
		}
	}
	sort.Slice(res.Findings, func(i, j int) bool {
		if res.Findings[i].File != res.Findings[j].File {
			return res.Findings[i].File < res.Findings[j].File
		}
		if res.Findings[i].Line != res.Findings[j].Line {
			return res.Findings[i].Line < res.Findings[j].Line
		}
		return res.Findings[i].RuleID < res.Findings[j].RuleID
	})
	return res, nil
}

// loadIOCDB 加载内嵌威胁情报（C2/域名/发布者）；文件缺失返回 nil（开源版降级）。
func loadIOCDB() *ioc.DB {
	db, err := ioc.Load(
		"internal/bench/ioc/c2-ips.txt",
		"internal/bench/ioc/malicious-domains.txt",
		"internal/bench/ioc/malicious-publishers.txt",
	)
	if err != nil {
		log.Printf("[skillguard/analyzer] IOC 加载失败（降级无查表）: %v", err)
		return nil
	}
	if db.Len() == 0 {
		return nil
	}
	return db
}

// preview 截取正文前 500 字符作为报告预览。
func preview(body string) string {
	r := []rune(strings.TrimSpace(body))
	if len(r) > 500 {
		return string(r[:500]) + "…"
	}
	return string(r)
}
