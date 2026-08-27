package analyzer

import (
	"testing"

	"github.com/tianjun/skillguard/internal/llm"
)

// confirmed 保留、rejected 移除
func TestApplyReviewKeepsConfirmedRemovesRejected(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", RuleName: "Shell 命令执行", Category: "CODE_EXECUTION", Weight: 90, File: "scripts/x.py"},
		{RuleID: "RS-010", RuleName: "环境变量转储", Category: "DATA_THEFT", Weight: 70, File: "SKILL.md"},
		{RuleID: "RS-004", RuleName: "命令替换执行", Category: "CODE_EXECUTION", Weight: 80, File: "README.md"},
	}
	reviews := []llm.FindingReview{
		{RuleID: "RS-002", File: "scripts/x.py", Confirmed: false, Confidence: "high", Reason: "soffice 合法"},
		{RuleID: "RS-010", File: "SKILL.md", Confirmed: true, Confidence: "high", Reason: "真实窃取"},
		// RS-004 无裁决 → 保留（LLM 未覆盖不惩罚）
	}

	kept, rejected := ApplyReview(findings, reviews)
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2 (RS-010 + RS-004)", len(kept))
	}
	if len(rejected) != 1 || rejected[0].RuleID != "RS-002" {
		t.Fatalf("rejected = %+v, want [RS-002]", rejected)
	}
	// 移除后评分应显著下降（RS-002 的 90 分权重没了）
	score := Score(kept)
	scoreAll := Score(findings)
	if score.Score >= scoreAll.Score {
		t.Fatalf("reviewed score %f should be < full score %f", score.Score, scoreAll.Score)
	}
}

// 裁决按 (rule_id + file) 匹配，同规则多文件各自裁决
func TestApplyReviewMatchesFile(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", File: "a.py"},
		{RuleID: "RS-002", File: "b.py"},
	}
	reviews := []llm.FindingReview{
		{RuleID: "RS-002", File: "a.py", Confirmed: false},
	}
	kept, rejected := ApplyReview(findings, reviews)
	if len(kept) != 1 || kept[0].File != "b.py" {
		t.Fatalf("kept = %+v, want only b.py", kept)
	}
	if len(rejected) != 1 || rejected[0].File != "a.py" {
		t.Fatalf("rejected = %+v, want only a.py", rejected)
	}
}

// 空裁决列表 → 全部保留（LLM 未启用时不改变任何行为）
func TestApplyReviewNoReviews(t *testing.T) {
	findings := []Finding{{RuleID: "RS-001", Weight: 95}}
	kept, rejected := ApplyReview(findings, nil)
	if len(kept) != 1 || len(rejected) != 0 {
		t.Fatalf("kept=%d rejected=%d, want 1/0", len(kept), len(rejected))
	}
}
