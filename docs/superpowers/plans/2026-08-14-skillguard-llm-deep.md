# SkillGuard LLM 深度分析（付费档）实施计划（L1-L3）

> **For agentic workers:** 沿用 TDD 风格分里程碑实施。每 task 结束前：`gofmt -l .` 空 + `go vet ./...` 无告警 + 相关包测试全绿 + commit。

**Goal:** 接入 DeepSeek 语义分析（RS-018 角色伪装 / RS-019 声明-行为不一致），作为**付费档**：静态审计保持免费，LLM 深度分析按次计费（usage kind=llm_review，独立配额）。

**API 核实（2026-08-14）：** Base URL `https://api.deepseek.com`，endpoint `/chat/completions`（OpenAI 兼容），模型 `deepseek-v4-flash`（文档页确认；模型名可配置防变动）。

## 技术决策（2026-08-14 锁定）

- **Provider 抽象**：`internal/llm` 定义 Provider 接口，DeepSeek 为 OpenAI 兼容实现（可插拔，AGENTS.md 既定方向）
- **API Key**：环境变量 `DEEPSEEK_API_KEY`（严禁硬编码）；模型 `DEEPSEEK_MODEL` 默认 `deepseek-v4-flash`
- **结构化输出**：system prompt 强制 JSON schema；解析容错（剥 markdown 围栏 + 失败降级 verdict=unknown，不影响审计主流程）
- **输入裁剪**：SKILL.md（frontmatter + 正文前 800 字）+ 可扫描脚本文件内容（每文件前 200 行 / 上限 8KB），防 token 爆炸
- **计费**：`POST /v1/audit/deep` 独立入口；LLM 结果缓存（audits.llm_results 列，同 hash 当日重复提交返回缓存不计费）
- **失败降级**：LLM 超时/报错 → 返回静态报告 + llm_results 空数组 + 不扣配额（提示稍后重试）

## 数据模型变更（迁移 0002）

```sql
ALTER TABLE users ADD COLUMN quota_llm_reviews INT NOT NULL DEFAULT 10;
ALTER TABLE audits ADD COLUMN llm_results JSONB NOT NULL DEFAULT '[]';
```

## 包结构与任务分解

| 任务 | 内容 | 验收 |
| :--- | :--- | :--- |
| L1 | `internal/llm`：Provider 接口 + DeepSeek 客户端（OpenAI 兼容）+ Analyze 分析 + 结构化解析 + 降级 | 单测全绿（httptest mock，不发真实请求） |
| L2 | 后端：迁移 0002 + store 支持（quota_llm_reviews / llm_results）+ `POST /v1/audit/deep` handler（静态+LLM+配额+缓存+计费） | httpapi 测试全绿（mock LLM）；curl 冒烟 |
| L3 | 前端：审计页深度分析开关 + LLM 判定结果卡片 + 用量页 llm 配额展示 | build 通过 + 浏览器实测 |

## 接口契约

```
POST /v1/audit/deep   (multipart file=xx.zip, Bearer key)
→ 201 { cached: false, report: Report, llm_results: [
     { rule_id: "RS-018", verdict: "suspicious|clean|unknown", confidence: "high|medium|low", reason: "..." },
     { rule_id: "RS-019", ... } ] }
→ 200 缓存命中（不计费） | 402 深度分析配额用尽 | 400 非 zip
```

## 执行顺序

```
L1（llm 包）→ L2（后端 deep 接口）→ L3（前端展示）
```
