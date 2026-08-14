package report

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tianjun/skillguard/internal/analyzer"
	"github.com/tianjun/skillguard/internal/parser"
	"github.com/tianjun/skillguard/internal/rules"
)

func auditFixture(t *testing.T, dir string) (ReportData, *rules.RuleSet) {
	t.Helper()
	rs, err := rules.LoadRules(filepath.Join("..", "..", "rules", "rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files, root, err := parser.CollectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := analyzer.Analyze(files, root, rs)
	if err != nil {
		t.Fatal(err)
	}
	score := analyzer.Score(res.Findings)
	return BuildReportData(res, score, dir, rs.Meta()), rs
}

func TestRenderJSONMaliciousSchema(t *testing.T) {
	d, _ := auditFixture(t, filepath.Join("..", "analyzer", "testdata", "malicious-skill"))
	data, err := RenderJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("报告 JSON 不可解析: %v", err)
	}
	// 顶层字段（ARCHITECTURE §3.4）
	for _, key := range []string{"tool", "version", "rules_version", "target", "scanned_files", "skipped_files", "skill_md", "score", "findings", "llm_review_rules"} {
		if _, ok := m[key]; !ok {
			t.Errorf("缺少顶层字段 %q", key)
		}
	}
	if m["tool"] != "SkillGuard" || m["version"] != "0.1.0" || m["rules_version"] != "1.0" {
		t.Errorf("tool/version/rules_version = %v/%v/%v", m["tool"], m["version"], m["rules_version"])
	}
	score := m["score"].(map[string]any)
	for _, key := range []string{"score", "level", "level_key", "icon", "breakdown", "bonus", "notes", "hit_categories"} {
		if _, ok := score[key]; !ok {
			t.Errorf("score 缺少字段 %q", key)
		}
	}
	if score["level_key"] != "malicious" {
		t.Errorf("level_key = %v, want malicious", score["level_key"])
	}
	if len(m["findings"].([]any)) == 0 {
		t.Error("恶意样本 findings 不应为空")
	}
	f0 := m["findings"].([]any)[0].(map[string]any)
	for _, key := range []string{"rule_id", "rule_name", "category", "severity", "weight", "detection", "file", "line", "snippet"} {
		if _, ok := f0[key]; !ok {
			t.Errorf("finding 缺少字段 %q", key)
		}
	}
}

func TestRenderJSONBenignEmptyArrays(t *testing.T) {
	d, _ := auditFixture(t, filepath.Join("..", "analyzer", "testdata", "benign-skill"))
	data, err := RenderJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"findings": null`) {
		t.Error("findings 为空时必须是 [] 而非 null")
	}
	if !strings.Contains(string(data), `"findings": []`) {
		t.Error("findings 应为空数组")
	}
	var m map[string]any
	json.Unmarshal(data, &m)
	if m["score"].(map[string]any)["level_key"] != "safe" {
		t.Error("良性样本应为 safe")
	}
}

func TestRenderMarkdown(t *testing.T) {
	d, _ := auditFixture(t, filepath.Join("..", "analyzer", "testdata", "malicious-skill"))
	md := RenderMarkdown(d)
	for _, want := range []string{"# SkillGuard 审计报告", "评分分解", "命中明细", "待 LLM 复核规则", "恶意", "RS-018", "RS-019"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown 缺少 %q", want)
		}
	}
}
