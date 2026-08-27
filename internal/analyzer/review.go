package analyzer

import (
	"github.com/tianjun/skillguard/internal/llm"
)

// ApplyReview 把 LLM 二次裁决应用到静态命中（三分裁决，2026-08-27）：
// - verdict=malicious → 保留原权重
// - verdict=suspicious → 降权 50%（高风险功能但可能合法，报告可见但降权计分）
// - verdict=benign → 移除（明确误报，不进评分）
// - 无对应裁决 → 保留（LLM 未覆盖/不可用时不惩罚，主流程不受影响）
// 返回 (处理后列表, 被移除的误报列表)。suspicious 命中在原列表就地降权。
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
		switch rv.EffectiveVerdict() {
		case "benign":
			rejected = append(rejected, f)
		case "suspicious":
			f.Weight = f.Weight / 2 // 降权一半（向下取整，权重最低可为 0——保持 >0 语义用 max(1)）
			if f.Weight < 1 {
				f.Weight = 1
			}
			kept = append(kept, f)
		default: // malicious / 兼容 confirmed=true
			kept = append(kept, f)
		}
	}
	return kept, rejected
}
