package analyzer

import (
	"testing"

	"github.com/tianjun/skillguard/internal/llm"
)

// 三分裁决：malicious 保留、suspicious 降权、benign 移除、未覆盖保留
func TestApplyReviewKeepsConfirmedRemovesRejected(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", RuleName: "Shell 命令执行", Category: "CODE_EXECUTION", Weight: 90, File: "scripts/x.py"},
		{RuleID: "RS-010", RuleName: "环境变量转储", Category: "DATA_THEFT", Weight: 70, File: "SKILL.md"},
		{RuleID: "RS-004", RuleName: "命令替换执行", Category: "CODE_EXECUTION", Weight: 80, File: "README.md"},
		{RuleID: "RS-001", RuleName: "动态代码执行", Category: "CODE_EXECUTION", Weight: 95, File: "a.py"},
	}
	reviews := []llm.FindingReview{
		{RuleID: "RS-002", File: "scripts/x.py", Verdict: "benign", Confidence: "high", Reason: "soffice 合法"},
		{RuleID: "RS-010", File: "SKILL.md", Verdict: "malicious", Confidence: "high", Reason: "真实窃取"},
		// RS-004 无裁决 → 保留原权重
		// RS-001 suspicious → 降权 50%（95 → 47）
		{RuleID: "RS-001", File: "a.py", Verdict: "suspicious", Confidence: "medium", Reason: "无法确定"},
	}

	kept, rejected := ApplyReview(findings, reviews)
	if len(kept) != 3 {
		t.Fatalf("kept = %d, want 3 (RS-010 + RS-004 + RS-001-suspicious)", len(kept))
	}
	if len(rejected) != 1 || rejected[0].RuleID != "RS-002" {
		t.Fatalf("rejected = %+v, want [RS-002]", rejected)
	}
	// suspicious 降权：RS-001 权重 95 → 47
	for _, f := range kept {
		if f.RuleID == "RS-001" && f.Weight != 47 {
			t.Fatalf("RS-001 weight = %d, want 47 (halved)", f.Weight)
		}
	}
	// 降权后评分应低于全量（RS-002 移除 + RS-001 降权）
	score := Score(kept)
	scoreAll := Score(findings)
	if score.Score >= scoreAll.Score {
		t.Fatalf("reviewed score %f should be < full score %f", score.Score, scoreAll.Score)
	}
}

// 兼容旧字段：confirmed=true → malicious（保留），confirmed=false → benign（移除）
func TestApplyReviewLegacyConfirmed(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-001", Weight: 95},
		{RuleID: "RS-002", Weight: 90},
	}
	reviews := []llm.FindingReview{
		{RuleID: "RS-001", File: "", Confirmed: true},
		{RuleID: "RS-002", File: "", Confirmed: false},
	}
	kept, rejected := ApplyReview(findings, reviews)
	if len(kept) != 1 || kept[0].RuleID != "RS-001" {
		t.Fatalf("kept = %+v, want [RS-001]", kept)
	}
	if len(rejected) != 1 || rejected[0].RuleID != "RS-002" {
		t.Fatalf("rejected = %+v, want [RS-002]", rejected)
	}
}

// 裁决按 (rule_id + file) 匹配，同规则多文件各自裁决
func TestApplyReviewMatchesFile(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", File: "a.py"},
		{RuleID: "RS-002", File: "b.py"},
	}
	reviews := []llm.FindingReview{
		{RuleID: "RS-002", File: "a.py", Confirmed: false, Confidence: "high"},
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
