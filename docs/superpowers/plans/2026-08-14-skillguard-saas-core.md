# SkillGuard SaaS 内核实施计划（M7-M13）

> **For agentic workers:** 沿用 M0-M6 引擎内核计划风格：TDD（先失败测试→最小实现→验证→commit）。
> 每 task 结束前：`gofmt -l .` 为空 + `go vet ./...` 无告警 + 相关包测试全绿 + git commit。

**Goal:** 在引擎内核之上落地 SaaS 骨架：用户系统（注册/登录 JWT）+ API Key 管理 + Web API（上传技能包 → 风险报告）+ 用量记录与免费配额（按次计费的数据基础）。

**依赖决策（2026-08-14 锁定）：**
- **同步审计接口先行**：`POST /v1/audit` 同步返回报告。asynq 异步化需 Redis（本机未装），留待并发量真实出现时切换；接口契约不变，切换只动内部实现。
- **PG 直连 pgxpool**（本地 PG17，库 `skillguard_dev` / `skillguard_test`），迁移用 golang-migrate（公司标准，AGENTS.md 已定）。
- **API Key**：`sk_live_<32hex>`，明文仅创建时返回一次，库中存 sha256 哈希 + 前缀；请求头 `Authorization: Bearer <key>`。
- **JWT**（用户会话）：HS256，`JWT_SECRET` 环境变量，7 天过期。
- **密码**：bcrypt cost 10。
- **审计去重防刷**：sha256(技能包全部文件内容) 为 skill_hash，24h 内重复提交直接返回缓存报告且不计费。
- **配额**：users.quota_audits 默认 100（MVP 总量制，月重置后置）；超限返回 402。
- **计费分层**（本次只做计量层，出账后置）：usage_logs 记录每次审计（kind=static_audit），LLM 深度分析后续接入时 kind=llm_review 计 token。
- **配置**：环境变量 + godotenv（DATABASE_URL / JWT_SECRET / PORT）。

## 数据模型（M7 迁移 0001）

```sql
users (
  id            BIGSERIAL PK
  email         TEXT UNIQUE NOT NULL
  password_hash TEXT NOT NULL              -- bcrypt
  role          TEXT NOT NULL DEFAULT 'user'  -- user | admin
  quota_audits  INT  NOT NULL DEFAULT 100
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
)
api_keys (
  id         BIGSERIAL PK
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE
  key_prefix TEXT NOT NULL                 -- sk_live_ 前 8 位，UI 识别
  key_hash   TEXT NOT NULL UNIQUE          -- sha256 十六进制
  name       TEXT NOT NULL DEFAULT ''
  revoked    BOOL NOT NULL DEFAULT false
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
audits (
  id          BIGSERIAL PK
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE
  api_key_id  BIGINT REFERENCES api_keys(id) ON DELETE SET NULL
  skill_hash  TEXT NOT NULL
  score       NUMERIC(5,1)
  level_key   TEXT NOT NULL
  findings    JSONB NOT NULL DEFAULT '[]'
  report_json JSONB NOT NULL
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
-- 去重：同用户 24h 内同 hash 只计一次
CREATE UNIQUE INDEX idx_audits_dedup ON audits(user_id, skill_hash, date_trunc('day', created_at))
usage_logs (
  id         BIGSERIAL PK
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE
  audit_id   BIGINT REFERENCES audits(id) ON DELETE SET NULL
  kind       TEXT NOT NULL                 -- static_audit | llm_review
  units      INT NOT NULL DEFAULT 1
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
```

## 包结构与任务分解

```
cmd/server/main.go        ← M9  Gin 入口（路由注册 + 配置加载 + 迁移）
internal/store/           ← M7  pgxpool 封装 + 迁移执行 + users/api_keys/audits/usage 存取
internal/auth/            ← M8  bcrypt、JWT 签发校验、API Key 生成/校验
internal/httpapi/         ← M9  Gin 路由 + 中间件（Bearer 校验 / 配额检查 / 限流基础）
internal/auditapi/        ← M10 上传解析 → 内核审计 → 去重缓存 → 报告入库
internal/usage/           ← M11 用量写入 + 配额判定
cmd/audit/main.go         ← M12  Cobra CLI（本地审计目录/zip，企业自托管形态）
migrations/0001_init.up.sql / .down.sql  ← M7
```

| 任务 | 内容 | 验收 |
| :--- | :--- | :--- |
| M7 | 迁移 + store 层（用户/Key/审计/用量 CRUD，含去重查询、配额查询） | store 测试全绿（真库 skillguard_test） |
| M8 | auth 包：注册（bcrypt）、登录（JWT）、API Key 创建/校验/吊销 | auth 测试全绿（纯单元） |
| M9 | cmd/server：Gin 骨架 + /healthz + Bearer 中间件 + 注册/登录/Key 管理接口 | curl 冒烟：注册→登录→建 Key→用 Key 调受保护接口 |
| M10 | POST /v1/audit（zip 上传或目录路径）→ 内核审计 → 缓存去重 → audits 入库；GET /v1/audits 历史 | 冒烟：zip 上传得报告；重复提交返回缓存且 audits 不新增 |
| M11 | usage_logs 写入 + 配额中间件（超限 402）+ GET /v1/usage | 冒烟：配额 100 上限生效 |
| M12 | cmd/audit CLI（Cobra）：audit 子命令输出报告文件 | CLI 审计 testdata/malicious-skill 输出报告 |
| M13 | 收尾：全量回归、ARCHITECTURE 状态标注、README 快速开始更新、commit | gofmt/vet/build/test 全绿 |

## 执行顺序与依赖

```
M7（store）→ M8（auth）→ M9（server 骨架）→ M10（审计 API）→ M11（用量/配额）→ M12（CLI）→ M13（收尾）
```

M8 依赖 M7（users 表）；M9 依赖 M7/M8；M10 依赖 M9 + 引擎内核（已完成）；M11 依赖 M10；M12 独立（仅依赖引擎内核）。
