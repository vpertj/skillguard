package auth

import (
	"strings"
	"testing"
	"time"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "s3cret-pass" || !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("hash = %q, want bcrypt 前缀", hash)
	}
	if !CheckPassword(hash, "s3cret-pass") {
		t.Error("正确密码应通过校验")
	}
	if CheckPassword(hash, "wrong-pass") {
		t.Error("错误密码不应通过")
	}
	if CheckPassword(hash, "") {
		t.Error("空密码不应通过")
	}
}

func TestGenerateAPIKeyFormat(t *testing.T) {
	plain, prefix, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	// sk_live_ + 32 hex
	if !strings.HasPrefix(plain, "sk_live_") || len(plain) != len("sk_live_")+32 {
		t.Errorf("plain = %q, want sk_live_ 前缀 + 32 hex", plain)
	}
	if prefix != plain[:len("sk_live_")+8] {
		t.Errorf("prefix = %q, want %q", prefix, plain[:len("sk_live_")+8])
	}
	if HashAPIKey(plain) != hash {
		t.Error("HashAPIKey 应等于生成的 hash")
	}
	// 哈希不可逆：hash 中不应出现明文
	if strings.Contains(hash, plain) {
		t.Error("hash 不应包含明文")
	}
	// 两次生成不同
	plain2, _, _, _ := GenerateAPIKey()
	if plain == plain2 {
		t.Error("两次生成的 key 不应相同")
	}
}

func TestHashAPIKeyDeterministic(t *testing.T) {
	if HashAPIKey("sk_live_abc") != HashAPIKey("sk_live_abc") {
		t.Error("同明文哈希应一致")
	}
	if HashAPIKey("sk_live_abc") == HashAPIKey("sk_live_abd") {
		t.Error("不同明文哈希不应一致")
	}
	if len(HashAPIKey("x")) != 64 { // sha256 hex
		t.Errorf("hash 长度 = %d, want 64", len(HashAPIKey("x")))
	}
}

func TestJWTIssueParse(t *testing.T) {
	secret := "test-secret-0123456789"
	token, err := IssueJWT(secret, 42, "alice@example.com", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJWT(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 42 || claims.Email != "alice@example.com" || claims.Role != "user" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestJWTWrongSecret(t *testing.T) {
	token, _ := IssueJWT("secret-a", 1, "a@b.c", "user", time.Hour)
	if _, err := ParseJWT("secret-b", token); err == nil {
		t.Error("错误 secret 应解析失败")
	}
}

func TestJWTExpired(t *testing.T) {
	token, _ := IssueJWT("secret-a", 1, "a@b.c", "user", -time.Minute)
	if _, err := ParseJWT("secret-a", token); err == nil {
		t.Error("过期 token 应解析失败")
	}
}

func TestJWTTampered(t *testing.T) {
	token, _ := IssueJWT("secret-a", 1, "a@b.c", "user", time.Hour)
	tampered := token[:len(token)-4] + "XXXX"
	if _, err := ParseJWT("secret-a", tampered); err == nil {
		t.Error("篡改 token 应解析失败")
	}
}
