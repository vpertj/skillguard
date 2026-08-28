package analyzer

import "testing"

// 文档里的代码行为命中降权（示例/说明非执行）
func TestScoreDocHitHalved(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", Category: "CODE_EXECUTION", Weight: 90, File: "SKILL.md"},
	}
	s := Score(findings)
	// 90/2=45 → 45×0.40 = 18
	if s.Score != 18 {
		t.Fatalf("score = %f, want 18（文档命中降权）", s.Score)
	}
}

// 脚本里的命中保持全权重
func TestScoreScriptHitFullWeight(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", Category: "CODE_EXECUTION", Weight: 90, File: "scripts/install.sh"},
	}
	s := Score(findings)
	// 90×0.40 = 36
	if s.Score != 36 {
		t.Fatalf("score = %f, want 36（脚本全权重）", s.Score)
	}
}

// 文档里的提示注入命中不降权（攻击载体就是文档）
func TestScoreDocPromptInjectionFullWeight(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-017", Category: "PROMPT_INJECTION", Weight: 80, File: "SKILL.md"},
	}
	s := Score(findings)
	// 80×0.10 = 8
	if s.Score != 8 {
		t.Fatalf("score = %f, want 8（提示注入不降权）", s.Score)
	}
}

// 文档降权 < 脚本同命中（降权生效的直接对比）
func TestScoreDocLessThanScript(t *testing.T) {
	doc := Score([]Finding{
		{RuleID: "RS-002", Category: "CODE_EXECUTION", Weight: 90, File: "README.md"},
		{RuleID: "RS-010", Category: "DATA_THEFT", Weight: 70, File: "README.md"},
	})
	script := Score([]Finding{
		{RuleID: "RS-002", Category: "CODE_EXECUTION", Weight: 90, File: "scripts/x.py"},
		{RuleID: "RS-010", Category: "DATA_THEFT", Weight: 70, File: "scripts/x.py"},
	})
	if doc.Score >= script.Score {
		t.Fatalf("doc score %f should be < script score %f", doc.Score, script.Score)
	}
	// 脚本：90×0.4 + 70×0.25 = 53.5
	if script.Score != 53.5 {
		t.Fatalf("script score = %f, want 53.5", script.Score)
	}
	// 文档：45×0.4 + 35×0.25 = 26.75 → round1 → 26.8
	if doc.Score != 26.8 {
		t.Fatalf("doc score = %f, want 26.8", doc.Score)
	}
}
