package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimalRules = `
version: "1.0"
rules:
  - id: RS-001
    name: 测试规则
    category: CODE_EXECUTION
    severity: critical
    weight: 90
    detection: regex
    patterns: ['\beval\s*\(']
    rationale: 测试
    false_positive_note: 测试
  - id: RS-002
    name: LLM 规则
    category: PROMPT_INJECTION
    severity: medium
    weight: 50
    detection: llm
    patterns: []
    rationale: 测试
    false_positive_note: 测试
`

func TestLoadRulesOK(t *testing.T) {
	rs, err := LoadRules(writeFixture(t, minimalRules))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if rs.Version() != "1.0" {
		t.Errorf("Version = %q, want 1.0", rs.Version())
	}
	if len(rs.Rules()) != 2 {
		t.Errorf("Rules = %d, want 2", len(rs.Rules()))
	}
	if got := rs.AutoDetectable(); len(got) != 1 || got[0].ID != "RS-001" {
		t.Errorf("AutoDetectable = %v, want [RS-001]", got)
	}
	if got := rs.LLMOnly(); len(got) != 1 || got[0].ID != "RS-002" {
		t.Errorf("LLMOnly = %v, want [RS-002]", got)
	}
	if r := rs.Get("RS-001"); r == nil || r.Weight != 90 {
		t.Errorf("Get(RS-001) = %v, want weight 90", r)
	}
	if rs.Get("RS-999") != nil {
		t.Error("Get(RS-999) should be nil")
	}
	if got := rs.ByCategory("CODE_EXECUTION"); len(got) != 1 || got[0].ID != "RS-001" {
		t.Errorf("ByCategory = %v, want [RS-001]", got)
	}
	if len(rs.FailedRuleIDs()) != 0 {
		t.Errorf("FailedRuleIDs = %v, want empty", rs.FailedRuleIDs())
	}
	if !strings.Contains(rs.Summary(), "1.0") {
		t.Errorf("Summary = %q", rs.Summary())
	}
}

func TestLoadRulesMissingFile(t *testing.T) {
	if _, err := LoadRules("/nonexistent/rules.yaml"); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestLoadRulesBadYAML(t *testing.T) {
	if _, err := LoadRules(writeFixture(t, "not: [valid")); err == nil {
		t.Fatal("want error for bad yaml")
	}
}

func TestLoadRulesMissingVersion(t *testing.T) {
	if _, err := LoadRules(writeFixture(t, "rules: []\n")); err == nil {
		t.Fatal("want error for missing version")
	}
}

func TestLoadRulesEmptyRules(t *testing.T) {
	if _, err := LoadRules(writeFixture(t, "version: \"1.0\"\nrules: []\n")); err == nil {
		t.Fatal("want error for empty rules")
	}
}

func TestLoadRulesDuplicateID(t *testing.T) {
	content := `
version: "1.0"
rules:
  - {id: RS-001, name: a, category: X, severity: low, weight: 1, detection: regex, patterns: ["a"]}
  - {id: RS-001, name: b, category: Y, severity: low, weight: 1, detection: regex, patterns: ["b"]}
`
	if _, err := LoadRules(writeFixture(t, content)); err == nil {
		t.Fatal("want error for duplicate ID")
	}
}

func TestLoadRulesBadSeverity(t *testing.T) {
	content := `
version: "1.0"
rules:
  - {id: RS-001, name: a, category: X, severity: fatal, weight: 1, detection: regex, patterns: ["a"]}
`
	if _, err := LoadRules(writeFixture(t, content)); err == nil {
		t.Fatal("want error for bad severity")
	}
}

func TestLoadRulesBadWeight(t *testing.T) {
	content := `
version: "1.0"
rules:
  - {id: RS-001, name: a, category: X, severity: low, weight: 101, detection: regex, patterns: ["a"]}
`
	if _, err := LoadRules(writeFixture(t, content)); err == nil {
		t.Fatal("want error for bad weight")
	}
}

func TestLoadRulesEmptyPatternsOnRegex(t *testing.T) {
	content := `
version: "1.0"
rules:
  - {id: RS-001, name: a, category: X, severity: low, weight: 1, detection: regex, patterns: []}
`
	if _, err := LoadRules(writeFixture(t, content)); err == nil {
		t.Fatal("want error for regex rule with empty patterns")
	}
}

func TestLoadRulesBadIDFormat(t *testing.T) {
	content := `
version: "1.0"
rules:
  - {id: XX-001, name: a, category: X, severity: low, weight: 1, detection: regex, patterns: ["a"]}
`
	if _, err := LoadRules(writeFixture(t, content)); err == nil {
		t.Fatal("want error for bad ID format")
	}
}

func TestMatchRule(t *testing.T) {
	rs, err := LoadRules(writeFixture(t, minimalRules))
	if err != nil {
		t.Fatal(err)
	}
	line, snippet, ok := rs.MatchRule("RS-001", "第一行\nresult = eval(code)\n第三行\n")
	if !ok || line != 2 || !strings.Contains(snippet, "eval") {
		t.Errorf("MatchRule = (%d, %q, %v), want (2, contains eval, true)", line, snippet, ok)
	}
	if _, _, ok := rs.MatchRule("RS-001", "nothing here\n"); ok {
		t.Error("want no match")
	}
	// llm 规则不参与匹配
	if _, _, ok := rs.MatchRule("RS-002", "anything"); ok {
		t.Error("llm rule should never match")
	}
}

func TestRegexLookaheadFallback(t *testing.T) {
	// RE2 不支持 lookahead，应自动降级到 .NET 语法
	content := `
version: "1.0"
rules:
  - {id: RS-001, name: a, category: X, severity: low, weight: 1, detection: regex, patterns: ["foo(?=bar)"]}
`
	rs, err := LoadRules(writeFixture(t, content))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := rs.MatchRule("RS-001", "foobar"); !ok {
		t.Error("lookahead pattern should match after fallback")
	}
	if len(rs.FailedRuleIDs()) != 0 {
		t.Errorf("FailedRuleIDs = %v, want empty", rs.FailedRuleIDs())
	}
}

func TestBrokenPatternSkipped(t *testing.T) {
	content := `
version: "1.0"
rules:
  - {id: RS-001, name: a, category: X, severity: low, weight: 1, detection: regex, patterns: ["["]}
`
	rs, err := LoadRules(writeFixture(t, content))
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(rs.FailedRuleIDs(), "RS-001") {
		t.Errorf("FailedRuleIDs = %v, want [RS-001]", rs.FailedRuleIDs())
	}
	if _, _, ok := rs.MatchRule("RS-001", "[hello"); ok {
		t.Error("broken rule should never match")
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestRealRulesFileLoads(t *testing.T) {
	// 规则自检：真实规则库（公开 + 闭源）必须可加载、可编译、ID 唯一
	base := filepath.Join("..", "..", "rules")
	rs, err := LoadRules(filepath.Join(base, "rules.yaml"), filepath.Join(base, "pro-rules.yaml"))
	if err != nil {
		t.Fatalf("真实规则库加载失败: %v", err)
	}
	if rs.Version() != "1.0" {
		t.Errorf("Version = %q, want 1.0", rs.Version())
	}
	if len(rs.Rules()) != 37 {
		t.Errorf("Rules = %d, want 37（30 公开 + 7 闭源）", len(rs.Rules()))
	}
	if len(rs.FailedRuleIDs()) != 0 {
		t.Errorf("FailedRuleIDs = %v, want empty（所有正则必须可编译）", rs.FailedRuleIDs())
	}
	if got := rs.LLMOnly(); len(got) != 2 || got[0].ID != "RS-018" || got[1].ID != "RS-019" {
		t.Errorf("LLMOnly = %v, want [RS-018 RS-019]", got)
	}
	if got := rs.AutoDetectable(); len(got) != 33 {
		t.Errorf("AutoDetectable = %d, want 33", len(got))
	}
	if got := rs.FileExtOnly(); len(got) != 1 || got[0].ID != "RS-025" {
		t.Errorf("FileExtOnly = %v, want [RS-025]", got)
	}
}

// 开源降级：pro-rules.yaml 缺失时只加载公开规则，不报错
func TestLoadRulesMissingProRulesDegrades(t *testing.T) {
	base := filepath.Join("..", "..", "rules")
	rs, err := LoadRules(filepath.Join(base, "rules.yaml"), "/nonexistent/pro-rules.yaml")
	if err != nil {
		t.Fatalf("缺失闭源规则应降级而非报错: %v", err)
	}
	if len(rs.Rules()) != 30 {
		t.Errorf("Rules = %d, want 30（仅公开）", len(rs.Rules()))
	}
	if got := rs.FileExtOnly(); len(got) != 1 || got[0].ID != "RS-025" {
		t.Errorf("FileExtOnly = %v, want [RS-025]（RS-025 在公开层）", got)
	}
}
