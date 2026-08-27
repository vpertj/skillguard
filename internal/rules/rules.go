// Package rules 加载 rules/rules.yaml 规则库，提供 regexp2 正则匹配能力。
package rules

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v3"
)

// Rule 单条检测规则（与 rules/rules.yaml 条目一一对应）。
type Rule struct {
	ID                string   `yaml:"id" json:"id"`
	Name              string   `yaml:"name" json:"name"`
	Category          string   `yaml:"category" json:"category"`
	Severity          string   `yaml:"severity" json:"severity"`
	Weight            int      `yaml:"weight" json:"weight"`
	Detection         string   `yaml:"detection" json:"detection"`
	Patterns          []string `yaml:"patterns" json:"patterns"`
	Rationale         string   `yaml:"rationale" json:"rationale"`
	FalsePositiveNote string   `yaml:"false_positive_note" json:"false_positive_note"`
}

// Meta 规则库元信息（随报告输出，保证可追溯）。
type Meta struct {
	Version string `json:"version"`
}

// ruleFile rules.yaml 顶层结构。
type ruleFile struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// RuleSet 已加载的规则集，含预编译正则缓存。
type RuleSet struct {
	meta     Meta
	rules    []*Rule
	compiled map[string][]*regexp2.Regexp // 规则 ID → 已编译 patterns
	failed   map[string]error             // 规则 ID → 编译失败原因
}

var (
	idRe           = regexp.MustCompile(`^RS-\d{3}$`)
	validSeverity  = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	validDetection = map[string]bool{"regex": true, "heuristic": true, "llm": true, "file_ext": true, "ast": true}
)

// LoadRules 从路径加载规则文件：解析、校验、预编译。
// 支持多文件合并（变参）：第一个文件缺失报错，后续文件缺失跳过（开源版无闭源规则时降级）。
// 单条规则正则编译失败不致命：跳过该规则并记日志（降级策略，ARCHITECTURE §4.3）。
func LoadRules(paths ...string) (*RuleSet, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("至少需要一个规则文件路径")
	}
	rs := &RuleSet{
		compiled: make(map[string][]*regexp2.Regexp),
		failed:   make(map[string]error),
	}
	seen := make(map[string]bool)
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("读取规则文件失败: %w", err)
			}
			log.Printf("[skillguard/rules] 附加规则文件缺失（跳过）: %s", path)
			continue
		}
		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("解析规则文件 %s 失败: %w", path, err)
		}
		if strings.TrimSpace(rf.Version) == "" {
			return nil, fmt.Errorf("规则文件 %s 缺少 version 字段", path)
		}
		if len(rf.Rules) == 0 {
			return nil, fmt.Errorf("规则文件 %s rules 为空", path)
		}
		if i == 0 {
			rs.meta = Meta{Version: rf.Version}
		}
		for j := range rf.Rules {
			r := &rf.Rules[j]
			if err := validateRule(r, seen); err != nil {
				return nil, fmt.Errorf("规则校验失败: %w", err)
			}
			seen[r.ID] = true
			rs.rules = append(rs.rules, r)
			if r.Detection == "llm" || r.Detection == "file_ext" || r.Detection == "ast" {
				continue // llm 无 patterns；file_ext/ast 不预编译正则
			}
			compiled, err := CompilePatterns(r.Patterns)
			if err != nil {
				rs.failed[r.ID] = err
				log.Printf("[skillguard/rules] 规则 %s 正则编译失败，已跳过: %v", r.ID, err)
				continue
			}
			rs.compiled[r.ID] = compiled
		}
	}
	return rs, nil
}

func validateRule(r *Rule, seen map[string]bool) error {
	if !idRe.MatchString(r.ID) {
		return fmt.Errorf("规则 %q: ID 必须匹配 RS-\\d{3}", r.ID)
	}
	if seen[r.ID] {
		return fmt.Errorf("规则 ID 重复: %s", r.ID)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("规则 %s: name 为空", r.ID)
	}
	if strings.TrimSpace(r.Category) == "" {
		return fmt.Errorf("规则 %s: category 为空", r.ID)
	}
	if !validSeverity[r.Severity] {
		return fmt.Errorf("规则 %s: severity 非法: %q", r.ID, r.Severity)
	}
	if r.Weight < 0 || r.Weight > 100 {
		return fmt.Errorf("规则 %s: weight 越界: %d", r.ID, r.Weight)
	}
	if !validDetection[r.Detection] {
		return fmt.Errorf("规则 %s: detection 非法: %q", r.ID, r.Detection)
	}
	if r.Detection != "llm" && r.Detection != "ast" && len(r.Patterns) == 0 {
		return fmt.Errorf("规则 %s: detection=%s 但 patterns 为空", r.ID, r.Detection)
	}
	if r.Detection == "file_ext" {
		// file_ext 规则 patterns 是扩展名黑名单，不参与正则编译
		return nil
	}
	return nil
}

// CompilePatterns 编译一组 regexp2 模式：优先 RE2 语法（兼容 RE2 子集），
// 失败退化为 .NET 语法（支持 lookahead/lookbehind）。
func CompilePatterns(patterns []string) ([]*regexp2.Regexp, error) {
	compiled := make([]*regexp2.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp2.Compile(p, regexp2.RE2)
		if err != nil {
			re, err = regexp2.Compile(p, regexp2.None)
			if err != nil {
				return nil, fmt.Errorf("模式 %q 编译失败: %w", p, err)
			}
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// FindFirstMatch 返回已编译模式组在 content 中的首个命中（行号 + 片段）。
func FindFirstMatch(compiled []*regexp2.Regexp, content string) (line int, snippet string, ok bool) {
	bestIndex := -1
	for _, re := range compiled {
		m, err := re.FindStringMatch(content)
		if err != nil || m == nil {
			continue
		}
		if bestIndex == -1 || m.Index < bestIndex {
			bestIndex = m.Index
			line = lineOf(content, m.Index)
			snippet = matchLine(content, m.Index, m.Length)
		}
	}
	return line, snippet, bestIndex != -1
}

// MatchRule 返回规则在 content 中的首个命中（行号 + 片段），无命中时 ok=false。
// llm 规则与编译失败的规则恒无命中。
func (rs *RuleSet) MatchRule(ruleID, content string) (line int, snippet string, ok bool) {
	compiled, found := rs.compiled[ruleID]
	if !found {
		return 0, "", false
	}
	return FindFirstMatch(compiled, content)
}

// lineOf 返回 content 中 rune 偏移 runeIndex 处的 1-based 行号。
func lineOf(content string, runeIndex int) int {
	line, idx := 1, 0
	for _, r := range content {
		if idx >= runeIndex {
			break
		}
		if r == '\n' {
			line++
		}
		idx++
	}
	return line
}

// matchLine 返回命中所在行内容（按 rune 截断到 200 字符）。
func matchLine(content string, runeIndex, runeLength int) string {
	runes := []rune(content)
	start := runeIndex
	for start > 0 && runes[start-1] != '\n' {
		start--
	}
	end := runeIndex + runeLength
	if end > len(runes) {
		end = len(runes)
	}
	for end < len(runes) && runes[end] != '\n' {
		end++
	}
	line := strings.TrimSpace(string(runes[start:end]))
	if utf8.RuneCountInString(line) > 200 {
		r := []rune(line)
		line = string(r[:200]) + "…"
	}
	return line
}

func (rs *RuleSet) Version() string { return rs.meta.Version }
func (rs *RuleSet) Meta() Meta      { return rs.meta }
func (rs *RuleSet) Rules() []*Rule  { return rs.rules }

// AutoDetectable 引擎自动扫描的规则（regex/heuristic）。
func (rs *RuleSet) AutoDetectable() []*Rule {
	var out []*Rule
	for _, r := range rs.rules {
		if r.Detection == "regex" || r.Detection == "heuristic" {
			out = append(out, r)
		}
	}
	return out
}

// LLMOnly 需 LLM 判定的规则（detection == llm）。
func (rs *RuleSet) LLMOnly() []*Rule {
	var out []*Rule
	for _, r := range rs.rules {
		if r.Detection == "llm" {
			out = append(out, r)
		}
	}
	return out
}

// ByDetection 按检测类型返回规则。
func (rs *RuleSet) ByDetection(detection string) []*Rule {
	var out []*Rule
	for _, r := range rs.rules {
		if r.Detection == detection {
			out = append(out, r)
		}
	}
	return out
}

// FileExtOnly 文件级检测规则（detection == file_ext，扩展名黑名单）。
func (rs *RuleSet) FileExtOnly() []*Rule {
	var out []*Rule
	for _, r := range rs.rules {
		if r.Detection == "file_ext" {
			out = append(out, r)
		}
	}
	return out
}

func (rs *RuleSet) ByCategory(cat string) []*Rule {
	var out []*Rule
	for _, r := range rs.rules {
		if r.Category == cat {
			out = append(out, r)
		}
	}
	return out
}

func (rs *RuleSet) Get(id string) *Rule {
	for _, r := range rs.rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// FailedRuleIDs 返回编译失败被跳过的规则 ID（升序）。
func (rs *RuleSet) FailedRuleIDs() []string {
	out := make([]string, 0, len(rs.failed))
	for id := range rs.failed {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (rs *RuleSet) Summary() string {
	return fmt.Sprintf("规则库 v%s：%d 条规则，预编译成功 %d 条，失败 %d 条",
		rs.meta.Version, len(rs.rules), len(rs.compiled), len(rs.failed))
}
