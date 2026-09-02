package report

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderSARIFMaliciousSchema(t *testing.T) {
	d, _ := auditFixture(t, filepath.Join("..", "analyzer", "testdata", "malicious-skill"))
	data, err := RenderSARIF(d)
	if err != nil {
		t.Fatal(err)
	}
	var m sarifModel
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("SARIF 不可解析: %v", err)
	}
	if m.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", m.Version)
	}
	if m.Schema == "" {
		t.Error("$schema 为空")
	}
	if len(m.Runs) != 1 {
		t.Fatalf("runs 数量 = %d, want 1", len(m.Runs))
	}
	run := m.Runs[0]
	if run.Tool.Driver.Name != "SkillGuard" || run.Tool.Driver.Version != "0.1.0" {
		t.Errorf("driver = %s/%s, want SkillGuard/0.1.0", run.Tool.Driver.Name, run.Tool.Driver.Version)
	}
	if len(run.Results) == 0 {
		t.Fatal("恶意样本 results 不应为空")
	}
	if len(run.Tool.Driver.Rules) == 0 {
		t.Fatal("driver.rules 不应为空")
	}
	// 每条 result 的 ruleIndex 必须指向合法 rule，且 level 映射有效。
	for i, r := range run.Results {
		if r.RuleID == "" {
			t.Errorf("results[%d].ruleId 为空", i)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("results[%d].ruleIndex = %d 越界", i, r.RuleIndex)
		}
		if r.Level != "error" && r.Level != "warning" && r.Level != "note" {
			t.Errorf("results[%d].level = %q 非法", i, r.Level)
		}
		if len(r.Locations) == 0 {
			t.Errorf("results[%d] 缺少 locations", i)
		} else if r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("results[%d] 缺少 artifact URI", i)
		}
		if r.Message.Text == "" {
			t.Errorf("results[%d] 缺少 message", i)
		}
	}
	// 校验 rule 元数据：所有被引用的 ruleIndex 对应 rule 存在 ID。
	for _, sr := range run.Tool.Driver.Rules {
		if sr.ID == "" {
			t.Error("driver.rules 中存在无 ID 的 rule")
		}
	}
}

func TestRenderSARIFBenignEmptyResults(t *testing.T) {
	d, _ := auditFixture(t, filepath.Join("..", "analyzer", "testdata", "benign-skill"))
	data, err := RenderSARIF(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"results": null`) {
		t.Error("results 为空时必须是 [] 而非 null")
	}
	if !strings.Contains(string(data), `"results": []`) {
		t.Error("results 应为空数组")
	}
	// 良性样本即使无 finding，也要输出合法 SARIF（保证 CI 放行）。
	var m sarifModel
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("良性样本 SARIF 不可解析: %v", err)
	}
	if m.Version != "2.1.0" || len(m.Runs) != 1 {
		t.Errorf("良性样本版本/run 结构异常: %+v", m)
	}
}

func TestSeverityLevel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "warning"},
		{"", "warning"},
	}
	for _, c := range cases {
		if got := severityLevel(c.in); got != c.want {
			t.Errorf("severityLevel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
