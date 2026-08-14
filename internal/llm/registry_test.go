package llm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockAuthServer 检查 Authorization 头的 mock 服务器，记录收到的 key。
func mockAuthServer(t *testing.T, received *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*received = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"role_impersonation\":{\"suspicious\":false,\"confidence\":\"low\",\"reason\":\"x\"},\"claim_mismatch\":{\"suspicious\":false,\"confidence\":\"low\",\"reason\":\"x\"}}"}}]}`))
	}))
}

func TestRegistryNotConfigured(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Analyze(context.Background(), AnalyzeRequest{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("未启用应返回 ErrNotConfigured, got %v", err)
	}
	if r.Enabled() {
		t.Error("未启用时 Enabled 应为 false")
	}
}

func TestRegistryEnableAndHotUpdate(t *testing.T) {
	var received string
	srv := mockAuthServer(t, &received)
	defer srv.Close()

	r := NewRegistry()
	r.Enable("key-1", srv.URL, "m1")
	if !r.Enabled() {
		t.Fatal("Enable 后应启用")
	}
	if _, err := r.Analyze(context.Background(), AnalyzeRequest{SkillName: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(received, "key-1") {
		t.Errorf("第一次调用应带 key-1, got %q", received)
	}

	// 热更新
	if err := r.UpdateKey("key-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Analyze(context.Background(), AnalyzeRequest{SkillName: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(received, "key-2") {
		t.Errorf("热更新后应带 key-2, got %q", received)
	}

	// 空 key 拒绝
	if err := r.UpdateKey(""); err == nil {
		t.Error("空 key 应拒绝")
	}
	// 停用
	r.Disable()
	if _, err := r.Analyze(context.Background(), AnalyzeRequest{}); !errors.Is(err, ErrNotConfigured) {
		t.Error("Disable 后应 ErrNotConfigured")
	}
}
