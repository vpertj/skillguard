package httpapi

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vpertj/skillguard/internal/llm"
	"github.com/vpertj/skillguard/internal/rules"
	"github.com/vpertj/skillguard/internal/store"
)

func sprint64(n int64) string { return fmt.Sprintf("%d", n) }

func newAdminRouter(t *testing.T) (*gin.Engine, *store.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	st, err := store.Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("跳过：无法连接测试库: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.LoadRules(filepath.Join("..", "..", "rules", "rules.yaml"), filepath.Join("..", "..", "rules", "pro-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(Deps{Store: st, JWTSecret: "test-secret", Rules: rs, LLM: llm.NewRegistry()}), st
}

func registerAs(t *testing.T, r *gin.Engine, email string) string {
	t.Helper()
	w := doJSON(t, r, "POST", "/v1/auth/register", `{"email":"`+email+`","password":"password123"}`, "")
	if w.Code != 201 {
		t.Fatalf("注册 %s = %d %s", email, w.Code, w.Body.String())
	}
	return parseBody(t, w)["token"].(string)
}

func TestAdminUsersFlow(t *testing.T) {
	r, st := newAdminRouter(t)

	// 两个普通用户
	registerAs(t, r, "admin@example.com")
	registerAs(t, r, "user1@example.com")
	// 提升 admin 后重新登录（JWT 携带角色声明，需重新签发）
	if _, err := st.PromoteAdmins(context.Background(), []string{"admin@example.com"}); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, r, "POST", "/v1/auth/login", `{"email":"admin@example.com","password":"password123"}`, "")
	adminToken := parseBody(t, w)["token"].(string)

	// 普通用户访问 admin 接口 → 403
	user1Token := registerAs(t, r, "user1b@example.com")
	if w := doJSON(t, r, "GET", "/v1/admin/users", "", user1Token); w.Code != 403 {
		t.Errorf("普通用户 = %d, want 403", w.Code)
	}
	// 未登录 → 401
	if w := doJSON(t, r, "GET", "/v1/admin/users", "", ""); w.Code != 401 {
		t.Errorf("未登录 = %d, want 401", w.Code)
	}

	// admin 列表
	w = doJSON(t, r, "GET", "/v1/admin/users?limit=50", "", adminToken)
	if w.Code != 200 {
		t.Fatalf("admin 列表 = %d %s", w.Code, w.Body.String())
	}
	users := parseBody(t, w)["users"].([]any)
	if len(users) < 3 {
		t.Errorf("users = %d 条, want ≥3", len(users))
	}

	// 调整 user1 配额 + 提升角色
	targetID := int64(users[0].(map[string]any)["id"].(float64))
	// 找 user1b 的 id
	var user1bID int64
	for _, u := range users {
		m := u.(map[string]any)
		if m["email"] == "user1b@example.com" {
			user1bID = int64(m["id"].(float64))
		}
	}
	if user1bID == 0 {
		t.Fatal("未找到 user1b")
	}
	w = doJSON(t, r, "PUT", "/v1/admin/users/"+sprint64(user1bID), `{"quota_audits":500,"quota_llm_reviews":20,"role":"admin"}`, adminToken)
	if w.Code != 200 {
		t.Fatalf("更新用户 = %d %s", w.Code, w.Body.String())
	}
	got, _ := st.GetUserByID(context.Background(), user1bID)
	if got.QuotaAudits != 500 || got.QuotaLLMReviews != 20 || got.Role != "admin" {
		t.Errorf("更新后 = %+v", got)
	}
	// 新 admin 重新登录后可访问（JWT 需重新签发含 admin 角色）
	loginW := doJSON(t, r, "POST", "/v1/auth/login", `{"email":"user1b@example.com","password":"password123"}`, "")
	adminToken2 := parseBody(t, loginW)["token"].(string)
	if w := doJSON(t, r, "GET", "/v1/admin/users", "", adminToken2); w.Code != 200 {
		t.Errorf("新 admin = %d, want 200", w.Code)
	}
	// 非法角色 → 400
	w = doJSON(t, r, "PUT", "/v1/admin/users/"+sprint64(targetID), `{"role":"superuser"}`, adminToken)
	if w.Code != 400 {
		t.Errorf("非法角色 = %d, want 400", w.Code)
	}
	// 不存在用户 → 404
	w = doJSON(t, r, "PUT", "/v1/admin/users/99999", `{"quota_audits":1}`, adminToken)
	if w.Code != 404 {
		t.Errorf("不存在用户 = %d, want 404", w.Code)
	}
}

func TestAdminDeepSeekSettings(t *testing.T) {
	r, st := newAdminRouter(t)

	// 注册 + 提升 admin（重新登录）
	registerAs(t, r, "boss@example.com")
	if _, err := st.PromoteAdmins(context.Background(), []string{"boss@example.com"}); err != nil {
		t.Fatal(err)
	}
	lw := doJSON(t, r, "POST", "/v1/auth/login", `{"email":"boss@example.com","password":"password123"}`, "")
	adminToken := parseBody(t, lw)["token"].(string)

	// 初始未配置
	w := doJSON(t, r, "GET", "/v1/admin/settings/deepseek", "", adminToken)
	if w.Code != 200 {
		t.Fatalf("get settings = %d", w.Code)
	}
	m := parseBody(t, w)
	if m["configured"] != false {
		t.Errorf("初始 configured = %v, want false", m["configured"])
	}

	// 配置 key（加密存库 + 热更新）
	w = doJSON(t, r, "PUT", "/v1/admin/settings/deepseek", `{"api_key":"sk-test-1234567890"}`, adminToken)
	if w.Code != 200 || parseBody(t, w)["configured"] != true {
		t.Fatalf("put settings = %d %s", w.Code, w.Body.String())
	}
	// 库中应为密文（非明文）
	enc, err := st.GetSetting(context.Background(), "deepseek_api_key")
	if err != nil || enc == "" || enc == "sk-test-1234567890" {
		t.Errorf("库中应存密文, enc=%q err=%v", enc, err)
	}
	// GET 显示 configured=true 且不回传明文
	w = doJSON(t, r, "GET", "/v1/admin/settings/deepseek", "", adminToken)
	m = parseBody(t, w)
	if m["configured"] != true || m["model"] == "" {
		t.Errorf("配置后 = %+v", m)
	}
	if strings.Contains(w.Body.String(), "sk-test-1234567890") {
		t.Error("响应不应包含 key 明文")
	}
	// 非法 key 格式 → 400
	if w := doJSON(t, r, "PUT", "/v1/admin/settings/deepseek", `{"api_key":"not-a-key"}`, adminToken); w.Code != 400 {
		t.Errorf("非法 key = %d, want 400", w.Code)
	}
	// 清空 → 停用
	w = doJSON(t, r, "PUT", "/v1/admin/settings/deepseek", `{"api_key":""}`, adminToken)
	if w.Code != 200 || parseBody(t, w)["configured"] != false {
		t.Fatalf("清空 = %d %s", w.Code, w.Body.String())
	}
	// 普通用户访问 → 403
	userToken := registerAs(t, r, "normal@example.com")
	if w := doJSON(t, r, "GET", "/v1/admin/settings/deepseek", "", userToken); w.Code != 403 {
		t.Errorf("普通用户 = %d, want 403", w.Code)
	}
}
