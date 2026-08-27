package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockDeepSeek 返回固定 JSON 的测试服务器 + DeepSeek 客户端。
func mockReviewDeepSeek(t *testing.T, respBody string) *DeepSeek {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return NewDeepSeekWithBase("test-key", srv.URL, "test-model")
}

// reviewResponse 构造模型返回体（含 markdown 围栏，模拟真实输出）。
func reviewResponse(t *testing.T, reviews []FindingReview) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"reviews": reviews})
	if err != nil {
		t.Fatal(err)
	}
	content := "```json\n" + string(payload) + "\n```"
	msg, err := json.Marshal(map[string]any{"choices": []any{
		map[string]any{"message": map[string]any{"content": content}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(msg)
}

func TestReviewFindingsParsesReviews(t *testing.T) {
	d := mockReviewDeepSeek(t, reviewResponse(t, []FindingReview{
		{RuleID: "RS-002", File: "scripts/x.py", Snippet: "subprocess.run", Confirmed: false, Confidence: "high", Reason: "soffice 是合法文档转换"},
		{RuleID: "RS-010", File: "SKILL.md", Snippet: "os.environ", Confirmed: true, Confidence: "high", Reason: "转储环境变量到外联"},
	}))

	res, err := d.ReviewFindings(context.Background(), ReviewRequest{
		SkillName: "docx",
		SkillBody: "create documents",
		Findings: []ReviewFindingInput{
			{RuleID: "RS-002", File: "scripts/x.py", Snippet: `subprocess.run(["soffice"])`},
			{RuleID: "RS-010", File: "SKILL.md", Snippet: "print(os.environ)"},
		},
	})
	if err != nil {
		t.Fatalf("ReviewFindings: %v", err)
	}
	if len(res.Reviews) != 2 {
		t.Fatalf("reviews = %d, want 2", len(res.Reviews))
	}
	byRule := map[string]FindingReview{}
	for _, rv := range res.Reviews {
		byRule[rv.RuleID] = rv
	}
	if rv := byRule["RS-002"]; rv.Confirmed {
		t.Fatalf("RS-002 should be rejected (soffice is legit), got %+v", rv)
	}
	if rv := byRule["RS-010"]; !rv.Confirmed {
		t.Fatalf("RS-010 should be confirmed, got %+v", rv)
	}
	if res.Raw == "" {
		t.Fatal("Raw should contain the model response")
	}
}

// 模型返回非 JSON / 空 → 不报错，Reviews 为空（不影响主流程）
func TestReviewFindingsBadJSON(t *testing.T) {
	d := mockReviewDeepSeek(t, `{"choices":[{"message":{"content":"抱歉，我无法回答"}}]}`)
	res, err := d.ReviewFindings(context.Background(), ReviewRequest{
		SkillName: "x", Findings: []ReviewFindingInput{{RuleID: "RS-001", File: "a.py", Snippet: "eval"}},
	})
	if err != nil {
		t.Fatalf("ReviewFindings should not error on bad JSON: %v", err)
	}
	if len(res.Reviews) != 0 {
		t.Fatalf("reviews = %d, want 0 (degrade gracefully)", len(res.Reviews))
	}
}

// 无命中时不调用（空 Findings）
func TestReviewFindingsEmpty(t *testing.T) {
	d := mockReviewDeepSeek(t, `{}`)
	res, err := d.ReviewFindings(context.Background(), ReviewRequest{SkillName: "x"})
	if err != nil {
		t.Fatalf("ReviewFindings(empty): %v", err)
	}
	if res == nil || len(res.Reviews) != 0 {
		t.Fatalf("want empty reviews, got %+v", res)
	}
}

// prompt 必须包含命中规则 ID 与片段（LLM 需要上下文）
func TestBuildReviewPromptContainsFindings(t *testing.T) {
	p := buildReviewPrompt(ReviewRequest{
		SkillName: "docx",
		Findings: []ReviewFindingInput{
			{RuleID: "RS-002", File: "scripts/x.py", Snippet: `subprocess.run(["soffice"])`},
		},
	})
	if !strings.Contains(p, "RS-002") || !strings.Contains(p, "soffice") {
		t.Fatalf("prompt should include rule id and snippet:\n%s", p)
	}
	if !strings.Contains(p, "docx") {
		t.Fatalf("prompt should include skill name:\n%s", p)
	}
}

// JSON 提取：剥 markdown 围栏
func TestExtractJSONFromFenced(t *testing.T) {
	raw := "```json\n{\"reviews\":[]}\n```"
	got := extractJSON(raw)
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("extractJSON failed: %v, got %s", err, got)
	}
}

func TestBuildReviewSystemPromptNotEmpty(t *testing.T) {
	if strings.TrimSpace(reviewSystemPrompt) == "" {
		t.Fatal("reviewSystemPrompt should not be empty")
	}
	for _, kw := range []string{"malicious", "suspicious", "benign"} {
		if !strings.Contains(reviewSystemPrompt, kw) {
			t.Fatalf("review prompt should instruct %s verdict: %s", kw, fmt.Sprintf("%.80s", reviewSystemPrompt))
		}
	}
}
