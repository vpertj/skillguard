package analyzer

import (
	"github.com/vpertj/skillguard/internal/llm"
)

// ApplyReview 把 LLM 二次裁决应用到静态命中（二值 R2 最优配置，2026-08-27 实验确定；
// 三分降权版实测检出率崩至 58.3% 已回退——降权对恶意单命中太狠、对良性多命中太温和）：
// - verdict=malicious（或 confirmed=true）→ 保留
// - verdict=benign（或 confirmed=false）→ 移除（明确误报，不进评分）
// - verdict=suspicious → 按 malicious 保留（LLM 不确定时不惩罚，宁可不罚不可漏检）
// - 无对应裁决 → 保留（LLM 未覆盖/不可用时不惩罚，主流程不受影响）
// 返回 (处理后列表, 被移除的误报列表)。
func ApplyReview(findings []Finding, reviews []llm.FindingReview) (kept, rejected []Finding) {
	// 裁决索引：(rule_id, file) → review
	idx := make(map[string]llm.FindingReview, len(reviews))
	for _, rv := range reviews {
		idx[rv.RuleID+"\x00"+rv.File] = rv
	}
	for _, f := range findings {
		rv, ok := idx[f.RuleID+"\x00"+f.File]
		if !ok {
			kept = append(kept, f)
			continue
		}
		if rv.EffectiveVerdict() == "benign" {
			rejected = append(rejected, f)
			continue
		}
		kept = append(kept, f) // malicious / suspicious / 兼容 confirmed=true 全部保留
	}
	return kept, rejected
}
