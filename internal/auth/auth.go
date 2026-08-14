// Package auth 认证与凭据：bcrypt 密码、JWT 用户会话、API Key 生成与校验。
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword bcrypt 哈希密码（cost 10）。
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("密码不能为空")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", fmt.Errorf("密码哈希失败: %w", err)
	}
	return string(h), nil
}

// CheckPassword 校验明文密码与 bcrypt 哈希。
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// Claims JWT 载荷。
type Claims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// IssueJWT 签发 HS256 JWT。
func IssueJWT(secret string, userID int64, email, role string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// ParseJWT 校验并解析 JWT。
func ParseJWT(secret, token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("签名算法不符")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("JWT 解析失败: %w", err)
	}
	return claims, nil
}

const (
	keyPrefix   = "sk_live_"
	keyRandHex  = 32 // 随机部分 32 hex 字符 = 128 bit
	keyFullLen  = len(keyPrefix) + keyRandHex
	keyShowPref = len(keyPrefix) + 8 // 展示前缀：sk_live_ + 前 8 hex
)

// GenerateAPIKey 生成 API Key：返回明文、展示前缀、sha256 哈希。
// 明文仅创建时返回一次，库中只存 hash。
func GenerateAPIKey() (plain, prefix, hash string, err error) {
	buf := make([]byte, keyRandHex/2)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("生成随机数失败: %w", err)
	}
	plain = keyPrefix + hex.EncodeToString(buf)
	return plain, plain[:keyShowPref], HashAPIKey(plain), nil
}

// HashAPIKey 计算 API Key 的 sha256 十六进制摘要。
func HashAPIKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
