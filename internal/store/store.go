// Package store 数据层：PostgreSQL 连接、迁移、用户/API Key/审计/用量存取。
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // 注册 "pgx" 驱动供 golang-migrate 使用
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store 封装 pgx 连接池。
type Store struct {
	pool *pgxpool.Pool
}

// User 用户记录。
type User struct {
	ID              int64     `json:"id"`
	Email           string    `json:"email"`
	PasswordHash    string    `json:"-"`
	Role            string    `json:"role"`
	QuotaAudits     int       `json:"quota_audits"`
	QuotaLLMReviews int       `json:"quota_llm_reviews"`
	CreatedAt       time.Time `json:"created_at"`
}

// APIKey API Key 记录（key_hash 为 sha256 摘要，不回传明文）。
type APIKey struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	KeyPrefix string    `json:"key_prefix"`
	KeyHash   string    `json:"-"`
	Name      string    `json:"name"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// Audit 一次审计记录。
type Audit struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	APIKeyID   *int64    `json:"api_key_id,omitempty"`
	SkillHash  string    `json:"skill_hash"`
	Score      *float64  `json:"score,omitempty"`
	LevelKey   string    `json:"level_key"`
	Findings   []byte    `json:"findings"`
	ReportJSON []byte    `json:"report_json"`
	LLMResults []byte    `json:"llm_results"`
	CreatedAt  time.Time `json:"created_at"`
}

// ErrNotFound 记录不存在。
var ErrNotFound = errors.New("记录不存在")

// Open 建立连接池并 Ping。
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("创建连接池失败: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("连接数据库失败: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close 释放连接池。
func (s *Store) Close() { s.pool.Close() }

// Ping 健康检查。
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate 执行 pending 迁移（embed 的 migrations/*.sql）。
func (s *Store) Migrate(ctx context.Context) error {
	db, err := sql.Open("pgx", s.pool.Config().ConnConfig.ConnString())
	if err != nil {
		return fmt.Errorf("打开迁移连接失败: %w", err)
	}
	defer db.Close()
	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		return fmt.Errorf("初始化迁移驱动失败: %w", err)
	}
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("加载迁移文件失败: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		return fmt.Errorf("初始化迁移器失败: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("执行迁移失败: %w", err)
	}
	return nil
}

// Reset 回滚全部再重放（仅测试使用）。
func (s *Store) Reset(ctx context.Context) error {
	db, err := sql.Open("pgx", s.pool.Config().ConnConfig.ConnString())
	if err != nil {
		return err
	}
	defer db.Close()
	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		return err
	}
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("回滚迁移失败: %w", err)
	}
	if err := m.Up(); err != nil {
		return fmt.Errorf("重放迁移失败: %w", err)
	}
	return nil
}

// --- users ---

// CreateUser 创建用户（email 唯一，冲突返回错误）。
func (s *Store) CreateUser(ctx context.Context, email, passwordHash, role string) (*User, error) {
	if role == "" {
		role = "user"
	}
	var u User
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)
		 RETURNING id, email, password_hash, role, quota_audits, quota_llm_reviews, created_at`,
		email, passwordHash, role,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.QuotaAudits, &u.QuotaLLMReviews, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("创建用户失败: %w", err)
	}
	return &u, nil
}

// GetUserByEmail 按邮箱查用户。
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, role, quota_audits, quota_llm_reviews, created_at FROM users WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.QuotaAudits, &u.QuotaLLMReviews, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return &u, nil
}

// GetUserByID 按 ID 查用户。
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, role, quota_audits, quota_llm_reviews, created_at FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.QuotaAudits, &u.QuotaLLMReviews, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return &u, nil
}

// UpdateQuota 调整用户静态审计配额（admin/测试用）。
func (s *Store) UpdateQuota(ctx context.Context, userID int64, quota int) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET quota_audits = $1 WHERE id = $2`, quota, userID)
	if err != nil {
		return fmt.Errorf("更新配额失败: %w", err)
	}
	return nil
}

// UpdateQuotaLLM 调整用户 LLM 深度分析配额（admin/测试用）。
func (s *Store) UpdateQuotaLLM(ctx context.Context, userID int64, quota int) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET quota_llm_reviews = $1 WHERE id = $2`, quota, userID)
	if err != nil {
		return fmt.Errorf("更新 LLM 配额失败: %w", err)
	}
	return nil
}

// --- api keys ---

// CreateAPIKey 创建 API Key。
func (s *Store) CreateAPIKey(ctx context.Context, userID int64, keyPrefix, keyHash, name string) (*APIKey, error) {
	var k APIKey
	err := s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (user_id, key_prefix, key_hash, name) VALUES ($1, $2, $3, $4)
		 RETURNING id, user_id, key_prefix, key_hash, name, revoked, created_at`,
		userID, keyPrefix, keyHash, name,
	).Scan(&k.ID, &k.UserID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.Revoked, &k.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("创建 API Key 失败: %w", err)
	}
	return &k, nil
}

// GetAPIKeyByHash 按哈希查未吊销 Key。
func (s *Store) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	var k APIKey
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, key_prefix, key_hash, name, revoked, created_at FROM api_keys
		 WHERE key_hash = $1 AND revoked = false`,
		keyHash,
	).Scan(&k.ID, &k.UserID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.Revoked, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询 API Key 失败: %w", err)
	}
	return &k, nil
}

// ListAPIKeys 列出用户全部 Key（含已吊销）。
func (s *Store) ListAPIKeys(ctx context.Context, userID int64) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, key_prefix, key_hash, name, revoked, created_at FROM api_keys
		 WHERE user_id = $1 ORDER BY id DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("查询 API Key 列表失败: %w", err)
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.Revoked, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey 吊销 Key（幂等）。
func (s *Store) RevokeAPIKey(ctx context.Context, userID, keyID int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked = true WHERE id = $1 AND user_id = $2`, keyID, userID)
	if err != nil {
		return fmt.Errorf("吊销 API Key 失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- audits ---

// CreateAudit 写入审计记录。
func (s *Store) CreateAudit(ctx context.Context, userID int64, apiKeyID *int64, skillHash string, score *float64, levelKey string, findings, reportJSON, llmResults []byte) (*Audit, error) {
	if llmResults == nil {
		llmResults = []byte("[]")
	}
	var a Audit
	err := s.pool.QueryRow(ctx,
		`INSERT INTO audits (user_id, api_key_id, skill_hash, score, level_key, findings, report_json, llm_results)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, user_id, api_key_id, skill_hash, score, level_key, findings, report_json, llm_results, created_at`,
		userID, apiKeyID, skillHash, score, levelKey, findings, reportJSON, llmResults,
	).Scan(&a.ID, &a.UserID, &a.APIKeyID, &a.SkillHash, &a.Score, &a.LevelKey, &a.Findings, &a.ReportJSON, &a.LLMResults, &a.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("写入审计记录失败: %w", err)
	}
	return &a, nil
}

// FindCachedAudit 查找同用户当日同 hash 的审计记录（去重缓存）。
func (s *Store) FindCachedAudit(ctx context.Context, userID int64, skillHash string) (*Audit, error) {
	var a Audit
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, api_key_id, skill_hash, score, level_key, findings, report_json, llm_results, created_at
		 FROM audits
		 WHERE user_id = $1 AND skill_hash = $2
		   AND created_at >= date_trunc('day', now())
		 ORDER BY id DESC LIMIT 1`,
		userID, skillHash,
	).Scan(&a.ID, &a.UserID, &a.APIKeyID, &a.SkillHash, &a.Score, &a.LevelKey, &a.Findings, &a.ReportJSON, &a.LLMResults, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // 无缓存，非错误
	}
	if err != nil {
		return nil, fmt.Errorf("查询缓存审计失败: %w", err)
	}
	return &a, nil
}

// ListAudits 列出用户审计历史（最新在前）。
func (s *Store) ListAudits(ctx context.Context, userID int64, limit int) ([]Audit, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, api_key_id, skill_hash, score, level_key, findings, report_json, llm_results, created_at
		 FROM audits WHERE user_id = $1 ORDER BY id DESC LIMIT $2`,
		userID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("查询审计列表失败: %w", err)
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var a Audit
		if err := rows.Scan(&a.ID, &a.UserID, &a.APIKeyID, &a.SkillHash, &a.Score, &a.LevelKey, &a.Findings, &a.ReportJSON, &a.LLMResults, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- usage ---

// CreateUsage 写入一条用量记录。
func (s *Store) CreateUsage(ctx context.Context, userID int64, auditID *int64, kind string, units int) error {
	if units <= 0 {
		units = 1
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO usage_logs (user_id, audit_id, kind, units) VALUES ($1, $2, $3, $4)`,
		userID, auditID, kind, units,
	)
	if err != nil {
		return fmt.Errorf("写入用量记录失败: %w", err)
	}
	return nil
}

// CountUsage 统计用户某类用量总和。
func (s *Store) CountUsage(ctx context.Context, userID int64, kind string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(units), 0) FROM usage_logs WHERE user_id = $1 AND kind = $2`,
		userID, kind,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("统计用量失败: %w", err)
	}
	return n, nil
}

// QuotaExceeded 判定用户某类用量是否已达配额（kind 决定对应配额列）。
func (s *Store) QuotaExceeded(ctx context.Context, userID int64, kind string) (bool, error) {
	quotaCol := "quota_audits"
	if kind == "llm_review" {
		quotaCol = "quota_llm_reviews"
	}
	// 列名来自白名单（上面已限定），可安全拼接
	query := fmt.Sprintf(
		`SELECT u.%s,
		        (SELECT COALESCE(SUM(units), 0) FROM usage_logs WHERE user_id = u.id AND kind = $2)
		 FROM users u WHERE u.id = $1`, quotaCol)
	var quota, used int
	err := s.pool.QueryRow(ctx, query, userID, kind).Scan(&quota, &used)
	if err != nil {
		return false, fmt.Errorf("查询配额失败: %w", err)
	}
	return used >= quota, nil
}
