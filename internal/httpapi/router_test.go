package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tianjun/skillguard/internal/store"
)

func testDSN() string {
	if dsn := os.Getenv("SKILLGUARD_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://tianjun@localhost:5432/skillguard_test?sslmode=disable"
}

func newTestRouter(t *testing.T) (*gin.Engine, *store.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	st, err := store.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("跳过：无法连接测试库: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	return NewRouter(Deps{Store: st, JWTSecret: "test-jwt-secret"}), st
}

func doJSON(t *testing.T, r *gin.Engine, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != "" {
		buf.WriteString(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func parseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("响应不可解析: %v, body=%s", err, w.Body.String())
	}
	return m
}

func TestHealthz(t *testing.T) {
	r, _ := newTestRouter(t)
	w := doJSON(t, r, "GET", "/healthz", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("healthz = %d %s", w.Code, w.Body.String())
	}
}

func TestRegisterAndLogin(t *testing.T) {
	r, _ := newTestRouter(t)

	// 注册成功
	w := doJSON(t, r, "POST", "/v1/auth/register", `{"email":"alice@example.com","password":"password123"}`, "")
	if w.Code != 201 {
		t.Fatalf("register = %d %s", w.Code, w.Body.String())
	}
	m := parseBody(t, w)
	if m["token"] == nil || m["token"] == "" {
		t.Error("注册应返回 token")
	}
	if m["user"] == nil {
		t.Error("注册应返回 user")
	}

	// 重复注册 409
	w = doJSON(t, r, "POST", "/v1/auth/register", `{"email":"alice@example.com","password":"password123"}`, "")
	if w.Code != 409 {
		t.Errorf("重复注册 = %d, want 409", w.Code)
	}

	// 登录成功
	w = doJSON(t, r, "POST", "/v1/auth/login", `{"email":"alice@example.com","password":"password123"}`, "")
	if w.Code != 200 || parseBody(t, w)["token"] == nil {
		t.Errorf("login = %d %s", w.Code, w.Body.String())
	}

	// 密码错误 401
	w = doJSON(t, r, "POST", "/v1/auth/login", `{"email":"alice@example.com","password":"wrong"}`, "")
	if w.Code != 401 {
		t.Errorf("错误密码 = %d, want 401", w.Code)
	}

	// 非法输入 400
	w = doJSON(t, r, "POST", "/v1/auth/register", `{"email":"bad","password":"short"}`, "")
	if w.Code != 400 {
		t.Errorf("非法输入 = %d, want 400", w.Code)
	}
}

func TestAPIKeyFlow(t *testing.T) {
	r, st := newTestRouter(t)

	// 注册拿 JWT
	w := doJSON(t, r, "POST", "/v1/auth/register", `{"email":"bob@example.com","password":"password123"}`, "")
	token := parseBody(t, w)["token"].(string)

	// 建 Key
	w = doJSON(t, r, "POST", "/v1/keys", `{"name":"dev"}`, token)
	if w.Code != 201 {
		t.Fatalf("create key = %d %s", w.Code, w.Body.String())
	}
	m := parseBody(t, w)
	plain, _ := m["key"].(string)
	if !strings.HasPrefix(plain, "sk_live_") || len(plain) != len("sk_live_")+32 {
		t.Fatalf("key = %q 格式错误", plain)
	}

	// 用 API Key 访问受保护接口（列表）
	w = doJSON(t, r, "GET", "/v1/keys", "", plain)
	if w.Code != 200 {
		t.Fatalf("list with api key = %d %s", w.Code, w.Body.String())
	}
	list := parseBody(t, w)["keys"].([]any)
	if len(list) != 1 {
		t.Errorf("keys = %d 条, want 1", len(list))
	}
	first := list[0].(map[string]any)
	if first["key_prefix"] == nil || first["name"] != "dev" {
		t.Errorf("key 字段 = %+v", first)
	}
	if first["key_hash"] != nil {
		t.Error("列表不应返回 key_hash")
	}

	// 无认证 401
	w = doJSON(t, r, "GET", "/v1/keys", "", "")
	if w.Code != 401 {
		t.Errorf("无认证 = %d, want 401", w.Code)
	}
	// 坏 Key 401
	w = doJSON(t, r, "GET", "/v1/keys", "", "sk_live_00000000000000000000000000000000")
	if w.Code != 401 {
		t.Errorf("坏 Key = %d, want 401", w.Code)
	}

	// 吊销
	id := int64(first["id"].(float64))
	w = doJSON(t, r, "DELETE", "/v1/keys/"+fmt.Sprintf("%d", id), "", token)
	if w.Code != 204 {
		t.Errorf("revoke = %d, want 204", w.Code)
	}
	// 吊销后 Key 失效
	w = doJSON(t, r, "GET", "/v1/keys", "", plain)
	if w.Code != 401 {
		t.Errorf("吊销后调用 = %d, want 401", w.Code)
	}
	// 列表只剩已吊销的（仍可见但标记 revoked）
	w = doJSON(t, r, "GET", "/v1/keys", "", token)
	if w.Code != 200 {
		t.Fatalf("list after revoke = %d", w.Code)
	}
	list = parseBody(t, w)["keys"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["revoked"] != true {
		t.Errorf("吊销后列表 = %+v", list)
	}
	_ = st
}
