package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tianjun/skillguard/internal/rules"
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
