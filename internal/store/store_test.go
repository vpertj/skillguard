package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// testDSN 默认连本地 skillguard_test 库；无 DB 时测试跳过（CI 友好）。
func testDSN() string {
	if dsn := os.Getenv("SKILLGUARD_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://tianjun@localhost:5432/skillguard_test?sslmode=disable"
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), testDSN())
	if err != nil {
		t.Skipf("跳过：无法连接测试库 %s: %v", testDSN(), err)
	}
	t.Cleanup(s.Close)
	// 每次测试重建 schema，保证隔离
	if err := s.Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	return s
}

func TestOpenAndMigrate(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestUserLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice@example.com", "hash-1", "user")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 || u.Email != "alice@example.com" || u.QuotaAudits != 100 || u.Role != "user" {
		t.Errorf("User = %+v", u)
	}

	got, err := s.GetUserByEmail(ctx, "alice@example.com")
	if err != nil || got.ID != u.ID {
		t.Errorf("GetUserByEmail = %+v, err=%v", got, err)
	}
	got, err = s.GetUserByID(ctx, u.ID)
	if err != nil || got.Email != "alice@example.com" {
		t.Errorf("GetUserByID = %+v, err=%v", got, err)
	}

	// 重复邮箱必须报错
	if _, err := s.CreateUser(ctx, "alice@example.com", "hash-2", "user"); err == nil {
		t.Fatal("重复邮箱应报错")
	}
	if _, err := s.GetUserByEmail(ctx, "nobody@example.com"); err == nil {
		t.Error("不存在用户应报错")
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "bob@example.com", "hash", "user")

	k, err := s.CreateAPIKey(ctx, u.ID, "sk_live_ab12", "deadbeef", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID == 0 || k.UserID != u.ID || k.KeyPrefix != "sk_live_ab12" {
		t.Errorf("APIKey = %+v", k)
	}

	got, err := s.GetAPIKeyByHash(ctx, "deadbeef")
	if err != nil || got.ID != k.ID || got.Revoked {
		t.Errorf("GetAPIKeyByHash = %+v, err=%v", got, err)
	}
	if _, err := s.GetAPIKeyByHash(ctx, "nope"); err == nil {
		t.Error("未知 key hash 应报错")
	}

	keys, err := s.ListAPIKeys(ctx, u.ID)
	if err != nil || len(keys) != 1 {
		t.Errorf("ListAPIKeys = %v, err=%v", keys, err)
	}

	if err := s.RevokeAPIKey(ctx, u.ID, k.ID); err != nil {
		t.Fatal(err)
	}
	// 吊销后不可再用
	if _, err := s.GetAPIKeyByHash(ctx, "deadbeef"); err == nil {
		t.Error("吊销后的 key 应不可用")
	}
}

func TestAuditCacheDedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "carol@example.com", "hash", "user")
	k, _ := s.CreateAPIKey(ctx, u.ID, "sk_live_cd34", "cafe01", "")

	score := 91.8
	a1, err := s.CreateAudit(ctx, u.ID, &k.ID, "abc123", &score, "malicious", []byte(`[{"rule_id":"RS-001"}]`), []byte(`{"tool":"SkillGuard"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a1.ID == 0 || a1.SkillHash != "abc123" || a1.LevelKey != "malicious" {
		t.Errorf("Audit = %+v", a1)
	}

	// 同日同 hash 命中缓存
	cached, err := s.FindCachedAudit(ctx, u.ID, "abc123")
	if err != nil || cached == nil || cached.ID != a1.ID {
		t.Errorf("FindCachedAudit = %+v, err=%v", cached, err)
	}
	// 不同 hash 无缓存
	if c, _ := s.FindCachedAudit(ctx, u.ID, "zzz"); c != nil {
		t.Error("不同 hash 不应命中缓存")
	}
	// 其他用户无缓存（隔离）
	u2, _ := s.CreateUser(ctx, "dave@example.com", "hash", "user")
	if c, _ := s.FindCachedAudit(ctx, u2.ID, "abc123"); c != nil {
		t.Error("缓存不应跨用户")
	}

	list, err := s.ListAudits(ctx, u.ID, 10)
	if err != nil || len(list) != 1 || list[0].ID != a1.ID {
		t.Errorf("ListAudits = %+v, err=%v", list, err)
	}
}

func TestUsageQuota(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "erin@example.com", "hash", "user")

	for i := 0; i < 3; i++ {
		if err := s.CreateUsage(ctx, u.ID, nil, "static_audit", 1); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountUsage(ctx, u.ID, "static_audit")
	if err != nil || n != 3 {
		t.Errorf("CountUsage = %d, err=%v, want 3", n, err)
	}
	// 带审计关联
	score := 10.0
	a, _ := s.CreateAudit(ctx, u.ID, nil, "h1", &score, "safe", []byte("[]"), []byte("{}"), nil)
	if err := s.CreateUsage(ctx, u.ID, &a.ID, "static_audit", 1); err != nil {
		t.Fatal(err)
	}
	n, _ = s.CountUsage(ctx, u.ID, "static_audit")
	if n != 4 {
		t.Errorf("CountUsage = %d, want 4", n)
	}
	// 其他用户隔离
	u2, _ := s.CreateUser(ctx, "frank@example.com", "hash", "user")
	if n, _ := s.CountUsage(ctx, u2.ID, "static_audit"); n != 0 {
		t.Errorf("其他用户 CountUsage = %d, want 0", n)
	}
}

func TestQuotaExceededReturnsError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "grace@example.com", "hash", "user")
	if err := s.UpdateQuota(ctx, u.ID, 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.CreateUsage(ctx, u.ID, nil, "static_audit", 1); err != nil {
			t.Fatal(err)
		}
	}
	exceeded, err := s.QuotaExceeded(ctx, u.ID, "static_audit")
	if err != nil {
		t.Fatal(err)
	}
	if !exceeded {
		t.Error("用量 2/2 应判定超限")
	}
	// 2 次以内不超限
	u2, _ := s.CreateUser(ctx, "heidi@example.com", "hash", "user")
	exceeded, err = s.QuotaExceeded(ctx, u2.ID, "static_audit")
	if err != nil || exceeded {
		t.Errorf("0 用量不应超限: exceeded=%v err=%v", exceeded, err)
	}
}

var _ = time.Now // 保留 time 引用（后续迁移测试可能用到）

func TestListUsersAndAdminUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u1, _ := s.CreateUser(ctx, "admin1@example.com", "h", "user")
	u2, _ := s.CreateUser(ctx, "user1@example.com", "h", "user")

	users, err := s.ListUsers(ctx, 10)
	if err != nil || len(users) != 2 {
		t.Fatalf("ListUsers = %d 条, err=%v, want 2", len(users), err)
	}

	// 提升 + 改配额
	qAudits, qLLM := 500, 50
	role := "admin"
	if err := s.UpdateUserAdmin(ctx, u1.ID, &qAudits, &qLLM, &role); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUserByID(ctx, u1.ID)
	if got.Role != "admin" || got.QuotaAudits != 500 || got.QuotaLLMReviews != 50 {
		t.Errorf("更新后 = %+v", got)
	}
	// 不动 u2
	got2, _ := s.GetUserByID(ctx, u2.ID)
	if got2.Role != "user" || got2.QuotaAudits != 100 {
		t.Errorf("u2 不应被改: %+v", got2)
	}
	// 部分更新：只改配额不改角色（nil 字段跳过）
	qAudits2 := 999
	if err := s.UpdateUserAdmin(ctx, u2.ID, &qAudits2, nil, nil); err != nil {
		t.Fatal(err)
	}
	got2, _ = s.GetUserByID(ctx, u2.ID)
	if got2.QuotaAudits != 999 || got2.Role != "user" {
		t.Errorf("部分更新 = %+v", got2)
	}
	// 不存在用户报错
	if err := s.UpdateUserAdmin(ctx, 99999, &qAudits, nil, nil); err == nil {
		t.Error("不存在用户应报错")
	}
}

func TestPromoteAdmins(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.CreateUser(ctx, "boss@example.com", "h", "user")
	s.CreateUser(ctx, "other@example.com", "h", "user")

	n, err := s.PromoteAdmins(ctx, []string{"boss@example.com"})
	if err != nil || n != 1 {
		t.Fatalf("PromoteAdmins = %d, err=%v, want 1", n, err)
	}
	boss, _ := s.GetUserByEmail(ctx, "boss@example.com")
	if boss.Role != "admin" {
		t.Errorf("boss.role = %q, want admin", boss.Role)
	}
	other, _ := s.GetUserByEmail(ctx, "other@example.com")
	if other.Role != "user" {
		t.Errorf("other.role = %q, want user", other.Role)
	}
	// 幂等：再跑一次仍 1 条（不重复计数？返回受影响行，重复提升影响 0 行——预期行为：仍返回 1？）
	// 实现用 UPDATE ... WHERE role <> 'admin'，第二次影响 0 行，返回 0
	n2, _ := s.PromoteAdmins(ctx, []string{"boss@example.com"})
	if n2 != 0 {
		t.Errorf("二次提升 = %d, want 0（已是 admin 不再更新）", n2)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.GetSetting(ctx, "deepseek_api_key"); err != ErrNotFound {
		t.Fatalf("初始应 ErrNotFound, got %v", err)
	}
	if err := s.SetSetting(ctx, "deepseek_api_key", "cipher-text-1"); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetSetting(ctx, "deepseek_api_key")
	if err != nil || v != "cipher-text-1" {
		t.Errorf("GetSetting = %q, err=%v", v, err)
	}
	// 覆盖更新
	if err := s.SetSetting(ctx, "deepseek_api_key", "cipher-text-2"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetSetting(ctx, "deepseek_api_key")
	if v != "cipher-text-2" {
		t.Errorf("覆盖后 = %q", v)
	}
}
