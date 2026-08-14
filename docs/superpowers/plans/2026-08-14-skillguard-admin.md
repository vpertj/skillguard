# SkillGuard 管理后台里程碑（A1-A4）

> **For agentic workers:** 沿用 TDD 风格。每 task 结束前：`gofmt -l .` 空 + `go vet ./...` 无告警 + 相关包测试全绿 + commit。

**Goal:** 管理员权限体系 + 系统配置管理（DeepSeek Key 后台维护）+ 用户配额管理（管理员按用户分配/升级配额）。

## 设计决策（2026-08-14 锁定）

1. **角色**：users.role ∈ {user, admin}（已有字段）。注册默认 user。
   - 提升 admin 方式：服务启动环境变量 `ADMIN_EMAILS="a@x.com"`（逗号分隔）——启动时将这些邮箱提升为 admin；之后管理员可在后台把用户提升为 admin（自举闭环）。
2. **权限中间件**：JWT role=admin 才可访问 `/v1/admin/*`（401 普通用户，403 无权限）。
3. **DeepSeek Key 存储**：新表 `settings`（k/v）。value 用 AES-GCM 加密存储，密钥由 `JWT_SECRET` 派生（SHA-256）。加载优先级：环境变量 `DEEPSEEK_API_KEY` > 库中 settings。
4. **热更新**：新增 `internal/llm.Registry`（持当前 Provider，支持 Update(apiKey) 立即生效），Deps 由 `llm.Provider` 改为 `*llm.Registry`——管理员更新 key 后无需重启。
5. **配额管理**：管理员按用户 ID/邮箱查看与调整 `quota_audits` / `quota_llm_reviews` / `role`。
6. **前端**：管理员侧边菜单多「用户管理」「系统设置」两项；RequireAdmin 路由守卫；普通用户不可见。

## 数据模型（迁移 0003）

```sql
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 键：deepseek_api_key（AES-GCM 密文，带 nonce 前缀）
```

## API 契约

```
GET  /v1/admin/users?limit=50        → {users:[{id,email,role,quota_audits,quota_llm_reviews,created_at}]}
PUT  /v1/admin/users/:id             → {quota_audits?, quota_llm_reviews?, role?}  → 200 {ok:true}
GET  /v1/admin/settings/deepseek     → {configured:bool, model, base_url, updated_at?}（不回传 key）
PUT  /v1/admin/settings/deepseek     → {api_key} → 200 {ok:true, configured:true}（加密存库 + 热更新）
```

## 任务分解

| 任务 | 内容 | 验收 |
| :--- | :--- | :--- |
| A1 | 权限体系：RequireAdmin 中间件 + GET/PUT /v1/admin/users（配额/角色）+ ADMIN_EMAILS 启动提升 | httpapi 测试：admin 可管理、user 403、未登录 401 |
| A2 | settings 表（0003）+ AES-GCM 加密 + GET/PUT deepseek 设置 + llm.Registry 热更新 + 启动优先级 | store/llm/httpapi 测试全绿；key 更新后新请求即用新 key |
| A3 | 前端：用户管理页（列表/配额编辑/角色切换）+ 系统设置页（key 配置/回显状态）+ RequireAdmin + 菜单 | build 通过 + 浏览器实测 admin 流程 |
| A4 | 收尾：ADMIN_EMAILS 自举冒烟 + 文档（AGENTS/README）+ 全量回归 | 全链路可操作 |

## 执行顺序

```
A1（权限+用户管理）→ A2（key 管理+热更新）→ A3（前端）→ A4（收尾）
```
