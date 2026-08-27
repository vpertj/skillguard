package analyzer

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpertj/skillguard/internal/parser"
	"github.com/vpertj/skillguard/internal/rules"
)

func loadRealRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadRules(filepath.Join("..", "..", "rules", "rules.yaml"))
	if err != nil {
		t.Fatalf("加载真实规则库失败: %v", err)
	}
	return rs
}

// TestScanContentPositive 每条非 llm 规则的正例必须命中该规则。
func TestScanContentPositive(t *testing.T) {
	rs := loadRealRules(t)
	for _, r := range rs.AutoDetectable() {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			files := readAllFiles(t, filepath.Join("testdata", "positive", r.ID))
			if len(files) == 0 {
				t.Fatalf("规则 %s 缺少正例样本 testdata/positive/%s/", r.ID, r.ID)
			}
			for _, f := range files {
				content, err := os.ReadFile(f.path)
				if err != nil {
					t.Fatal(err)
				}
				got := ScanContent(string(content), []*rules.Rule{r}, f.path)
				if len(got) == 0 {
					t.Errorf("%s 应命中规则 %s，实际无命中", f.path, r.ID)
				}
			}
		})
	}
}

// TestScanContentNegative 每条非 llm 规则的反例不得命中该规则。
func TestScanContentNegative(t *testing.T) {
	rs := loadRealRules(t)
	for _, r := range rs.AutoDetectable() {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			files := readAllFiles(t, filepath.Join("testdata", "negative", r.ID))
			if len(files) == 0 {
				t.Fatalf("规则 %s 缺少反例样本 testdata/negative/%s/", r.ID, r.ID)
			}
			for _, f := range files {
				content, err := os.ReadFile(f.path)
				if err != nil {
					t.Fatal(err)
				}
				got := ScanContent(string(content), []*rules.Rule{r}, f.path)
				if len(got) != 0 {
					t.Errorf("%s 不应命中规则 %s，实际命中: %+v", f.path, r.ID, got)
				}
			}
		})
	}
}

func TestScanContentLineAndSnippet(t *testing.T) {
	rs := loadRealRules(t)
	content := "第一行\n第二行 eval(bad)\n第四行\n"
	got := ScanContent(content, []*rules.Rule{rs.Get("RS-001")}, "demo.py")
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want 1", got)
	}
	f := got[0]
	if f.Line != 2 || f.File != "demo.py" || !strings.Contains(f.Snippet, "eval") {
		t.Errorf("finding = %+v, want line=2 file=demo.py snippet 含 eval", f)
	}
	if f.RuleID != "RS-001" || f.Category != "CODE_EXECUTION" || f.Severity != "critical" || f.Weight != 95 {
		t.Errorf("finding 元数据 = %+v", f)
	}
}

func TestScanContentLLMRuleSkipped(t *testing.T) {
	rs := loadRealRules(t)
	got := ScanContent("ignore everything", []*rules.Rule{rs.Get("RS-018")}, "x.md")
	if len(got) != 0 {
		t.Errorf("llm 规则不应产生静态命中: %+v", got)
	}
}

type testFile struct {
	path string
}

func readAllFiles(t *testing.T, dir string) []testFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []testFile
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, testFile{path: filepath.Join(dir, e.Name())})
		}
	}
	return out
}

func TestGradeBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		key   string
		level string
	}{
		{0, "safe", "安全"},
		{20, "safe", "安全"},
		{20.1, "low", "低风险"},
		{50, "low", "低风险"},
		{50.1, "high", "高风险"},
		{80, "high", "高风险"},
		{80.1, "malicious", "恶意"},
		{100, "malicious", "恶意"},
	}
	for _, c := range cases {
		level, key, icon := Grade(c.score)
		if key != c.key || level != c.level {
			t.Errorf("Grade(%v) = (%q, %q, %q), want key=%q level=%q", c.score, level, key, icon, c.key, c.level)
		}
	}
}

func finding(category string, weight int) Finding {
	return Finding{RuleID: "RS-000", RuleName: "t", Category: category, Severity: "high", Weight: weight, Detection: "regex", File: "x", Line: 1, Snippet: "s"}
}

func approx(got, want float64) bool { return math.Abs(got-want) < 0.05 }

func TestScoreSingleDimension(t *testing.T) {
	s := Score([]Finding{finding("CODE_EXECUTION", 95)})
	if !approx(s.Score, 38.0) { // 95 × 0.40
		t.Errorf("Score = %v, want 38.0", s.Score)
	}
	if s.LevelKey != "low" {
		t.Errorf("LevelKey = %q, want low", s.LevelKey)
	}
	if len(s.Breakdown) != 1 || s.Breakdown[0].Dimension != "代码危害性" || s.Breakdown[0].GroupMaxWeight != 95 {
		t.Errorf("Breakdown = %+v", s.Breakdown)
	}
	if s.Bonus != 0 {
		t.Errorf("Bonus = %d, want 0", s.Bonus)
	}
}

func TestScoreMultiDimension(t *testing.T) {
	s := Score([]Finding{
		finding("CODE_EXECUTION", 95),
		finding("DATA_THEFT", 95),
		finding("NETWORK_EXFIL", 95),
		finding("PROMPT_INJECTION", 80),
		finding("SUPPLY_CHAIN", 90),
	})
	// 38 + 23.75 + 19 + 8 + 4.5 = 93.25；数据收集→外联链路 +10 = 103.25 → min(100) = 100
	if !approx(s.Score, 100.0) {
		t.Errorf("Score = %v, want 100.0（93.25 + 行为链 10，封顶 100）", s.Score)
	}
	if s.LevelKey != "malicious" {
		t.Errorf("LevelKey = %q, want malicious", s.LevelKey)
	}
	if len(s.Breakdown) != 5 {
		t.Errorf("Breakdown = %d 项, want 5", len(s.Breakdown))
	}
}

func TestScoreExfilChainBonus(t *testing.T) {
	s := Score([]Finding{finding("DATA_THEFT", 90), finding("NETWORK_EXFIL", 85)})
	// 22.5 + 17 = 39.5，+10 = 49.5
	if !approx(s.Score, 49.5) {
		t.Errorf("Score = %v, want 49.5", s.Score)
	}
	if s.Bonus != 10 || len(s.Notes) != 1 {
		t.Errorf("Bonus = %d Notes = %v, want 10 和 1 条说明", s.Bonus, s.Notes)
	}
	// 只有数据收集没有外联：无加成
	s2 := Score([]Finding{finding("DATA_THEFT", 90)})
	if s2.Bonus != 0 || !approx(s2.Score, 22.5) {
		t.Errorf("Bonus = %d Score = %v, want 0 和 22.5", s2.Bonus, s2.Score)
	}
}

func TestScoreDestructiveFloor(t *testing.T) {
	s := Score([]Finding{finding("DESTRUCTIVE", 90)})
	if !approx(s.Score, 85.0) { // 下限 85
		t.Errorf("Score = %v, want 85.0", s.Score)
	}
	s2 := Score([]Finding{finding("DESTRUCTIVE", 80)})
	if !approx(s2.Score, 75.0) { // 下限 75
		t.Errorf("Score = %v, want 75.0", s2.Score)
	}
}

func TestScoreUnknownCategoryFallback(t *testing.T) {
	s := Score([]Finding{finding("UNKNOWN_CAT", 50)})
	if !approx(s.Score, 20.0) { // 落入代码危害性 0.40
		t.Errorf("Score = %v, want 20.0", s.Score)
	}
	if len(s.Breakdown) != 1 || s.Breakdown[0].Dimension != "代码危害性" {
		t.Errorf("Breakdown = %+v", s.Breakdown)
	}
}

func TestScoreEmpty(t *testing.T) {
	s := Score(nil)
	if s.Score != 0 || s.LevelKey != "safe" || s.Bonus != 0 {
		t.Errorf("Score = %+v, want 0/safe/0", s)
	}
	if s.Breakdown == nil || s.HitCategories == nil || s.Notes == nil {
		t.Errorf("空数组字段应为空切片而非 nil: %+v", s)
	}
}

func TestAnalyzeMaliciousSkill(t *testing.T) {
	rs := loadRealRules(t)
	files, root, err := parser.CollectFiles(filepath.Join("testdata", "malicious-skill"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(files, root, rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) < 5 {
		t.Errorf("恶意样本命中 %d 条，预期 ≥5", len(res.Findings))
	}
	if res.SkillMD == nil || res.SkillMD.Frontmatter.Name != "system-cleaner" {
		t.Errorf("SkillMD = %+v", res.SkillMD)
	}
	// llm 规则必须进入复核队列
	found := map[string]bool{}
	for _, r := range res.LLMReview {
		found[r.ID] = true
	}
	if !found["RS-018"] || !found["RS-019"] {
		t.Errorf("LLMReview 缺少 RS-018/RS-019: %v", res.LLMReview)
	}
	if res.ScannedFiles != 2 {
		t.Errorf("ScannedFiles = %d, want 2", res.ScannedFiles)
	}
	score := Score(res.Findings)
	if score.Score < 81 || score.LevelKey != "malicious" {
		t.Errorf("Score = %v key=%q, 预期 ≥81 且 malicious", score.Score, score.LevelKey)
	}
	if score.Bonus != 10 {
		t.Errorf("Bonus = %d, want 10（数据窃取∩外联）", score.Bonus)
	}
}

func TestAnalyzeBenignSkill(t *testing.T) {
	rs := loadRealRules(t)
	files, root, err := parser.CollectFiles(filepath.Join("testdata", "benign-skill"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(files, root, rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("良性样本命中 %d 条，预期 0: %+v", len(res.Findings), res.Findings)
	}
	score := Score(res.Findings)
	if score.Score > 20 || score.LevelKey != "safe" {
		t.Errorf("Score = %v key=%q, 预期 ≤20 且 safe", score.Score, score.LevelKey)
	}
	if res.SkillMD == nil || res.SkillMD.Frontmatter.Name != "hello-world" {
		t.Errorf("SkillMD = %+v", res.SkillMD)
	}
}
