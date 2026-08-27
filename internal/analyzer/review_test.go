package analyzer

import (
	"testing"

	"github.com/tianjun/skillguard/internal/llm"
)

// 二值裁决（R2 最优）：malicious/suspicious 保留、benign 移除、未覆盖保留
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
		// RS-001 benign → 移除（CODE_EXECUTION 维最高权重消失，评分必须下降）
		{RuleID: "RS-001", File: "a.py", Verdict: "benign", Confidence: "high", Reason: "元编程误报"},
	}

	kept, rejected := ApplyReview(findings, reviews)
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2 (RS-010 + RS-004)", len(kept))
	}
	if len(rejected) != 2 || rejected[0].RuleID != "RS-002" || rejected[1].RuleID != "RS-001" {
		t.Fatalf("rejected = %+v, want [RS-002 RS-001]", rejected)
	}
	// 移除维度最高权重后评分应低于全量
	score := Score(kept)
	scoreAll := Score(findings)
	if score.Score >= scoreAll.Score {
		t.Fatalf("reviewed score %f should be < full score %f", score.Score, scoreAll.Score)
	}
}

// suspicious 保留原权重（LLM 不确定不惩罚）
func TestApplyReviewSuspiciousKept(t *testing.T) {
	findings := []Finding{
		{RuleID: "RS-002", Category: "CODE_EXECUTION", Weight: 90, File: "x.py"},
	}
	reviews := []llm.FindingReview{
		{RuleID: "RS-002", File: "x.py", Verdict: "suspicious", Confidence: "medium"},
	}
	kept, rejected := ApplyReview(findings, reviews)
	if len(kept) != 1 || kept[0].Weight != 90 {
		t.Fatalf("suspicious should keep full weight, got %+v", kept)
	}
	if len(rejected) != 0 {
		t.Fatalf("rejected = %+v, want none", rejected)
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
