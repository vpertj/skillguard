package cryptx

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cipher, err := Encrypt("secret-123", "sk_live_hello-world")
	if err != nil {
		t.Fatal(err)
	}
	if cipher == "sk_live_hello-world" {
		t.Error("密文不应等于明文")
	}
	plain, err := Decrypt("secret-123", cipher)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "sk_live_hello-world" {
		t.Errorf("plain = %q", plain)
	}
}

func TestDecryptWrongSecret(t *testing.T) {
	cipher, _ := Encrypt("secret-a", "value")
	if _, err := Decrypt("secret-b", cipher); err == nil {
		t.Error("错误密钥应解密失败")
	}
}

func TestDecryptTampered(t *testing.T) {
	cipher, _ := Encrypt("secret-a", "value")
	tampered := cipher[:len(cipher)-4] + "AAAA"
	if _, err := Decrypt("secret-a", tampered); err == nil {
		t.Error("篡改密文应解密失败")
	}
}

func TestEncryptEmptySecret(t *testing.T) {
	if _, err := Encrypt("", "x"); err == nil {
		t.Error("空密钥应报错")
	}
	if _, err := Decrypt("", "x"); err == nil {
		t.Error("空密钥应报错")
	}
}

func TestDifferentNonce(t *testing.T) {
	// 同明文两次加密应不同（随机 nonce）
	a, _ := Encrypt("secret", "same")
	b, _ := Encrypt("secret", "same")
	if a == b {
		t.Error("随机 nonce 应产生不同密文")
	}
}
