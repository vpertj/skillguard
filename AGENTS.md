# AGENTS.md — AI 协作指南

> 本文件是 AI 编码助手（Claude Code / Cursor / Codex 等）在本仓库工作的首要参考。
> 任何 AI 在开始修改代码前，必须通读本文件并遵守其中约定。

## 项目是什么

**skillguard** —— AI Agent 技能（Skills/SKILL.md）安全审计服务。

给每一个 AI Agent 技能做"安全体检"：上传/提交一个技能（SKILL.md + 附属脚本），
输出风险评分报告，检测恶意代码、提示注入、数据窃取、供应链攻击等风险。

定位：技能生态（LobeHub / ClawHub / GitHub 等）的**中立第三方安全审计层**。

## 核心目录结构

```
skillguard/
├── agents.md              # 本文件（AI 协作指南）
├── README.md              # 项目简介与快速开始
├── go.mod                 # Go 模块（module github.com/tianjun/skillguard）
├── docs/                  # 产品与设计文档
│   ├── 产品方案.md          # 完整产品方案（背景/客户/定价/路线图）
│   └── 规则库V1.md          # 检测规则库 V1 详细文档（24 条规则）
├── rules/
│   └── rules.yaml          # 机器可读规则定义（Go 引擎直接加载）
├── cmd/
│   ├── server/             # Web API 服务入口（Gin）
│   └── audit/              # CLI 审计工具入口（Cobra）
└── internal/
    ├── parser/             # SKILL.md 解析器（目录结构、脚本提取）
    ├── rules/              # 规则引擎（加载 YAML 规则 + 匹配执行）
    ├── analyzer/           # 静态分析器（规则匹配 + 行为链检测）
    ├── llm/                # LLM 语义分析（提示注入、意图识别）
    └── report/             # 报告生成（风险评分、报告输出）
```

## 技术栈（已确定，勿擅自更改）

- **语言**：Go 1.22+（唯一后端语言，Web API + CLI 全用 Go）
- **Web 框架**：Gin（server 入口）
- **CLI 框架**：Cobra（audit 入口）
- **规则引擎**：YAML 规则文件（`rules/rules.yaml`）+ regexp2（支持 lookahead，标准库 regexp 不支持）
- **AST 深度分析**（可选）：tree-sitter Go 绑定，解析 Python/JS 脚本
- **LLM 调用**：DeepSeek / 通义 / Claude 官方 Go SDK（可插拔）
- **任务队列**：asynq（审计任务异步处理）
- **存储**：PostgreSQL + S3（技能样本、审计报告）
- **沙箱**（阶段二）：gVisor（Go 生态，衔接最顺）
- **部署**：Docker + 单二进制（企业私有化交付友好）
- **管理后台前端**（阶段二/三）：React 19 + Ant Design 6 + TypeScript（公司 B 端标准，Vite 独立 SPA，Zustand + TanStack Query）

> **技术栈决策记录（2026-08-13 锁定，一次到位不重构）**
> - **Gin vs Fiber → 维持 Gin**：net/http 生态中间件（swagger/prometheus/otel/JWT/限流）现成；`POST /v1/audit` 异步交接 asynq 无 fasthttp Ctx 回收陷阱；本产品低并发长任务，Fiber 的性能优势无意义
> - **Go vs Rust → 维持 Go**：gVisor/asynq 为 Go 生态（阶段二硬需求）、regexp2 规则引擎、LLM 官方 Go SDK、CLI+Web 单二进制共用内核是产品卖点；审计负载 IO+LLM 主导，性能无差异
> - 阶段二 `cmd/server` 吸收公司 Go 工程标准：slog 日志 / Viper+godotenv 配置 / golang-jwt v5 鉴权 / golang-migrate 迁移 / testify 测试 / 统一响应格式
> - 依据：公司知识库《Go 技术栈选型》（对内服务标准）、《前端技术栈选型》；skillguard 是 AGENTS.md 明确拍板的 Go 特例

## 开发约定

### 包组织
- 所有业务代码放 `internal/`，对外只暴露 `cmd/` 入口
- 每个 `internal/` 子包保持职责单一：
  - `parser` 只负责解析，不输出报告
  - `analyzer` 只负责检测逻辑，不关心 HTTP
  - `report` 只负责输出格式，不执行检测
- 禁止循环依赖（parser ← analyzer ← report 的单向依赖方向）

### 规则引擎约定
- 规则定义**优先放 `rules/rules.yaml`**，代码中不硬编码检测模式
- 新增规则必须同时更新：`rules/rules.yaml` + `docs/规则库V1.md`（保持同步）
- 规则字段：`id` / `name` / `category` / `severity` / `weight` / `detection` / `patterns` / `rationale` / `false_positive_note`（与 ARCHITECTURE.md §3.1 一致，patterns 为列表）
- severity 取值：critical / high / medium / low
- **检出优先于精确**：宁可误报不可漏报（恶意技能漏检代价 >> 误报），后续用真实样本校准

### 命名与风格
- Go 代码遵循官方风格：`gofmt` + `go vet` 必须通过
- 目录/文件命名：小写蛇形（snake_case）
- 提交信息：`feat:` / `fix:` / `docs:` / `refactor:` 前缀（Conventional Commits）

### 测试要求
- 规则引擎必须配套单元测试（`internal/rules` + `internal/analyzer`）
- 新增规则必须附带 1 个正例（应命中）和 1 个反例（不应命中）测试样本
- 测试数据放 `internal/analyzer/testdata/`

## 当前阶段状态

**阶段一（进行中）：静态审计 MVP**

> 当前里程碑（2026-08-13 起）：**引擎内核四件套**——`rules/rules.yaml`(V1 24 条) + `internal/rules` + `internal/parser` + `internal/analyzer` + `internal/report` + 单测/正反样本。CLI/LLM/Web 为下一里程碑。设计文档：`docs/superpowers/specs/2026-08-13-skillguard-engine-core-design.md`

- [ ] 规则库 V1（24 条规则，7 类攻击面）—— 本次里程碑 M1 起草 `rules/rules.yaml` + `docs/规则库V1.md`
- [ ] SKILL.md 解析器（`internal/parser`）
- [ ] 规则引擎（`internal/rules`，加载 rules.yaml）
- [ ] 静态分析器（`internal/analyzer`）
- [ ] 报告生成（`internal/report`）
- [ ] LLM 语义分析接入（`internal/llm`）—— 下一里程碑（引擎预留 detection: llm 队列）
- [ ] Web 页面（上传 → 报告）+ 基础风险评分（`cmd/server`）—— 阶段二（ARCHITECTURE.md P1-2）
- [ ] CLI 工具（`cmd/audit`）—— 下一里程碑

**阶段二（未开始）**：沙箱动态执行（gVisor）+ Pro/Team 订阅 + 安全认证徽章
**阶段三（未开始）**：企业版（私有化部署）+ 威胁情报月报

## 关键验证指标

- 用 ClawHavoc 公开样本（341 个恶意技能）回归测试：恶意检出率 ≥ 85%，误报率 ≤ 15%
- MVP 上线标准：100 个真实技能审计通过，无阻塞性 bug

## 给 AI 助手的特别提醒

1. 本仓库是**安全工具**，写检测逻辑时不要引入"绕过检测"的示例代码进主逻辑（测试样本除外）
2. 涉及 LLM 调用时，API Key 必须从环境变量读取，**严禁硬编码**
3. 修改 `rules.yaml` 结构时，必须先确认 `internal/rules` 的加载器能兼容（或同步修改）
4. 文档同步原则：改代码 → 改对应 docs；改规则 → 改规则文档；不要只改一边
