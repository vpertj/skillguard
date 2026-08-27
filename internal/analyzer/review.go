package analyzer

import (
	"github.com/tianjun/skillguard/internal/llm"
)

// ApplyReview 把 LLM 二次裁决应用到静态命中（R2 最优配置，2026-08-27 四轮实验确定）：
// - confirmed=true → 保留
// - confirmed=false → 移除（误报，不进评分）
// - 无对应裁决 → 保留（LLM 未覆盖/不可用时不惩罚，主流程不受影响）
// 返回 (保留列表, 被裁决移除的误报列表)。
func ApplyReview(findings []Finding, reviews []llm.FindingReview) (kept, rejected []Finding) {
	// 裁决索引：(rule_id, file) → review
	idx := make(map[string]llm.FindingReview, len(reviews))
	for _, rv := range reviews {
		idx[rv.RuleID+"\x00"+rv.File] = rv
	}
	for _, f := range findings {
		rv, ok := idx[f.RuleID+"\x00"+f.File]
		if ok && !rv.Confirmed {
			rejected = append(rejected, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, rejected
}
