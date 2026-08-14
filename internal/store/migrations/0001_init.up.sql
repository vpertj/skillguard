CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    quota_audits  INT  NOT NULL DEFAULT 100,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    key_hash   TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL DEFAULT '',
    revoked    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);

CREATE TABLE audits (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id  BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    skill_hash  TEXT NOT NULL,
    score       NUMERIC(5,1),
    level_key   TEXT NOT NULL,
    findings    JSONB NOT NULL DEFAULT '[]',
    report_json JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audits_user ON audits(user_id, created_at DESC);
-- 去重：应用层 FindCachedAudit 先查当日同 hash；此索引加速查询（唯一约束需 IMMUTABLE 表达式，
-- date_trunc 不满足，故用普通索引 + 应用层去重）
CREATE INDEX idx_audits_dedup ON audits(user_id, skill_hash, created_at DESC);

CREATE TABLE usage_logs (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    audit_id   BIGINT REFERENCES audits(id) ON DELETE SET NULL,
    kind       TEXT NOT NULL,
    units      INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_usage_user ON usage_logs(user_id, created_at DESC);
