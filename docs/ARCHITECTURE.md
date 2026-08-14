# SkillGuard 架构规格说明书（Architecture Specification）

**版本**：V1.1
**日期**：2026年8月13日
**用途**：技能安全审计服务的整体架构与开发规格——定义分层架构、核心数据结构、审计流水线、模块接口、评分算法、扩展点与验收标准。开发者按此规格实现。
**技术栈**：Go 1.22+（Gin / Cobra / regexp2 / yaml.v3 / asynq / PostgreSQL+S3 / gVisor）——详见 `AGENTS.md`。
**状态标注**：`[已实现]` = 已有代码；`[待开发]` = 后续阶段。

> 本文件与 LobeHub Agent 文档《SkillGuard 架构规格说明书》同步，以 Agent 文档为权威版本。

---

## 1. 系统概述

### 1.1 定位

AI Agent 技能（SKILL.md）生态的"安全质检 + 可信分发"中间层：对技能包做静态分析（+ 后续 LLM 语义分析、沙箱动态执行），输出 0-100 风险评分与审计报告。

### 1.2 目标

- 单二进制交付（Go），CLI / Web API 共用同一审计内核
- 规则可版本化、可插拔（YAML 规则文件，新增规则不改引擎代码）
- 多形态接入：CLI（Cobra）→ Web SaaS（Gin）→ REST API → 平台集成
- 审计结果可追溯（时间戳、规则版本、样本留档）

### 1.3 非目标（V1 明确不做）

- 不做沙箱逃逸对抗（沙箱为阶段二，且"默认断网"）
- 不做代码执行（审计器自身不运行被审计脚本）
- 不做实时监控（只做提交时审计，不做运行时防护）

---

## 2. 总体架构（分层）

```plain
┌──────────────────────────────────────────────────────────┐
│ L1 接入层  [已实现: CLI + Web API]                            │
│   cmd/audit (Cobra CLI) │ cmd/server (Gin；asynq 异步化待接入) │
├──────────────────────────────────────────────────────────┤
│ L2 编排层  [待开发]                                        │
│   asynq 任务队列 → 审计流水线编排 → 结果持久化              │
├──────────────────────────────────────────────────────────┤
│ L3 审计引擎                                               │
│   ├─ internal/analyzer 静态分析器          [已实现]        │
│   ├─ internal/llm      LLM 分析器          [待开发]        │
│   └─ internal/sandbox  沙箱执行器          [阶段二]        │
├──────────────────────────────────────────────────────────┤
│ L4 数据层                                                 │
│   ├─ rules/rules.yaml  规则库              [已实现: V1 24 条]│
│   ├─ 白名单机制                           [待开发]          │
│   ├─ PostgreSQL + S3 样本/报告/徽章         [已实现: PG 用户/Key/审计/用量]│
└──────────────────────────────────────────────────────────┘
```

**依赖方向**：L1 → L2 → L3 → L4。L3 内部三个分析器**可独立启停**（feature flag），静态分析是底座，LLM/沙箱为增强。

**包组织约定**（AGENTS.md）：所有业务代码放 `internal/`，对外只暴露 `cmd/` 入口；禁止循环依赖（parser ← analyzer ← report 单向依赖）。

---

## 3. 核心数据模型（Schema 规格）

> 数据结构以 YAML/JSON 序列化为准。Go 侧定义于 `internal/rules` 与 `internal/analyzer`。

### 3.1 规则 Rule（rules/rules.yaml 条目）

```yaml
- id: RS-001
  name: 动态代码执行
  category: CODE_EXECUTION
  severity: critical        # critical | high | medium | low
  weight: 90                # 0-100，评分权重
  detection: regex          # regex | heuristic | llm
  patterns:
    - '\b(eval|exec|compile)\s*\('
  rationale: 攻击原理说明
  false_positive_note: 误报提示
```

**约定**：
- `detection == regex|heuristic`：引擎自动扫描（任一 pattern 命中即触发该规则）
- `detection == llm`：不自动执行，进入"人工复核/LLM 分析"队列
- `patterns` 使用 **regexp2** 语法（支持 lookahead/lookbehind，标准库 regexp 不支持）
- 每条规则每文件最多报告 1 次命中（首个匹配），避免刷屏

### 3.2 类别枚举（13 类）与维度映射

| Category | 说明 | 评分维度 |
| :--- | :--- | :--- |
| CODE_EXECUTION | 代码执行与命令注入 | 代码危害性 |
| PERSISTENCE | 持久化与后门 | 代码危害性 |
| OBFSUSCATION | 混淆与反检测 | 代码危害性 |
| PRIVILEGE_ABUSE | 权限与提权滥用 | 代码危害性 |
| DESTRUCTIVE | 破坏性行为 | 代码危害性 |
| DATA_THEFT | 数据窃取 | 数据访问 |
| CREDENTIAL_HUNT | 凭据猎取 | 数据访问 |
| NETWORK_EXFIL | 网络外联与 C2 | 网络行为 |
| NETWORK_EXFIL_V2 | 外联隐蔽通道 | 网络行为 |
| PROMPT_INJECTION | 提示注入 | 提示注入 |
| LLM_SPECIFIC | LLM/AI 特定攻击 | 提示注入 |
| SUPPLY_CHAIN | 供应链攻击 | 供应链 |
| SUPPLY_CHAIN_V2 | 供应链补充 | 供应链 |

### 3.3 发现 Finding（internal/analyzer）

```go
type Finding struct {
    RuleID    string `json:"rule_id"`
    RuleName  string `json:"rule_name"`
    Category  string `json:"category"`
    Severity  string `json:"severity"`
    Weight    int    `json:"weight"`
    Detection string `json:"detection"`
    File      string `json:"file"`
    Line      int    `json:"line"`
    Snippet   string `json:"snippet"`
}
```

### 3.4 审计结果 AuditResult（报告 JSON Schema）

```json
{
  "tool": "SkillGuard",
  "version": "0.1.0",
  "rules_version": "2.0",
  "target": "提交路径",
  "scanned_files": 2,
  "skipped_files": 0,
  "skill_md": {
    "file": "SKILL.md",
    "frontmatter": {"name": "...", "description": "..."},
    "body_preview": "..."
  },
  "score": {
    "score": 100.0,
    "level": "恶意",           // 安全|低风险|高风险|恶意
    "level_key": "malicious",  // safe|low|high|malicious
    "icon": "☠️",
    "breakdown": [{"dimension": "代码危害性", "weight": 0.4, "group_max_weight": 100, "contrib": 40.0}],
    "bonus": 10,
    "notes": ["检测到「数据收集 → 外联」完整链路，+10 分"],
    "hit_categories": ["CODE_EXECUTION"]
  },
  "findings": [ /* Finding[] */ ],
  "llm_review_rules": [ /* Rule[] 待 LLM 判定 */ ]
}
```

---

## 4. 审计流水线（Pipeline 规格）

### 4.1 主流程

```plain
提交技能（路径/zip/URL）
   │ 1. 采集 internal/parser.CollectFiles
   ▼
技能包文件集 (files, root)
   │ 2. 解析 internal/parser.ParseSkillMD
   ▼
SKILL.md frontmatter + 可扫描文件清单
   │ 3. 静态扫描 internal/analyzer.Analyze (P0 必选)
   ▼
findings[] + llm_review_rules[]
   │ 4. LLM 语义分析 internal/llm.Analyze (P1，无模型时跳过) [待开发]
   ▼
补充软性发现（声明-行为比对、角色伪装判定）
   │ 5. 沙箱动态执行 internal/sandbox.Run (P2，feature flag) [阶段二]
   ▼
补充动态发现（网络行为、真实文件访问）
   │ 6. 评分 internal/analyzer.Score
   ▼
score 0-100 + 分级
   │ 7. 报告 internal/report.Render (md / json)
   ▼
输出 + 退出码 (0 安全 / 1 高危 / 2 恶意)
```

### 4.2 阶段化特性开关

| 特性 | 默认 | 说明 |
| :--- | :--- | :--- |
| STATIC_SCAN | on | 静态分析，不可关闭 |
| LLM_ANALYZE | off | 需配置模型 API；off 时 llm 规则进人工复核队列 |
| SANDBOX | off | 阶段二；off 时静态盲区在报告"已知限制"标注 |
| WHITELIST | off | 白名单文件加载；off 时纯规则匹配 |

### 4.3 降级策略

- LLM 不可用 → `llm_review_rules` 原样输出，评分不受影响
- 规则库缺失 → 报错退出（提示检查 `rules/rules.yaml`）
- 单条规则正则编译失败 → 跳过该规则（错误记录到日志），不影响其余规则

---

## 5. 模块规格（接口签名）

> 以下为 Go 接口契约，与 AGENTS.md 的 internal 包结构一一对应。实现以 Go 为准。

### 5.1 internal/parser — 技能包解析 [骨架]

```go
type Frontmatter struct {
    Name         string   `yaml:"name"`
    Description  string   `yaml:"description"`
    AllowedTools []string `yaml:"allowed-tools"`
}

func CollectFiles(path string) (files []string, root string, err error) // 支持目录/单文件/zip
func ParseSkillMD(content string) (fm Frontmatter, body string, err error)
func IsScannable(path string, size int64) bool   // ≤2MB 且非二进制扩展名
func FindSkillMD(files []string) []string        // 定位 SKILL.md
```

**约定**：zip 解压到临时目录（`os.MkdirTemp`），审计结束后清理。

### 5.2 internal/rules — 规则引擎 [待开发]

```go
type Rule struct {
    ID                string   `yaml:"id"`
    Name              string   `yaml:"name"`
    Category          string   `yaml:"category"`
    Severity          string   `yaml:"severity"`
    Weight            int      `yaml:"weight"`
    Detection         string   `yaml:"detection"` // regex | heuristic | llm
    Patterns          []string `yaml:"patterns"`
    Rationale         string   `yaml:"rationale"`
    FalsePositiveNote string   `yaml:"false_positive_note"`
}

type RuleSet struct { rules []*Rule; compiled map[string][]*regexp2.Regexp } // regexp2 预编译缓存

func LoadRules(path string) (*RuleSet, error)
func (rs *RuleSet) AutoDetectable() []*Rule  // detection ∈ {regex, heuristic}
func (rs *RuleSet) LLMOnly() []*Rule         // detection == llm
func (rs *RuleSet) ByCategory(cat string) []*Rule
func (rs *RuleSet) Get(id string) *Rule
func (rs *RuleSet) Summary() string
```

**约定**：YAML 规则文件路径 `rules/rules.yaml`（相对项目根）；正则用 `regexp2.Compile(pattern, regexp2.RE2)` 兼容 RE2 子集，必要时放宽以支持 lookahead。

### 5.3 internal/analyzer — 静态分析器 [待开发]

```go
type Result struct {
    Findings      []Finding
    LLMReview     []*rules.Rule
    SkillMD       *SkillMDInfo
    ScannedFiles  int
    SkippedFiles  int
}

func Analyze(files []string, root string, rs *rules.RuleSet) (*Result, error)  // 全包扫描
func ScanContent(content string, rules []*rules.Rule, fileLabel string) []Finding // 单文件扫描
func Score(findings []Finding) ScoreResult   // 见 §6 算法
func Grade(score float64) (level, key, icon string) // 分级
```

### 5.4 internal/report — 报告生成 [待开发]

```go
type ReportData struct { /* 见 §3.4 AuditResult */ }
func BuildReportData(scan *analyzer.Result, score analyzer.ScoreResult, target string, meta rules.Meta) ReportData
func RenderMarkdown(d ReportData) string
func RenderJSON(d ReportData) ([]byte, error)
```

### 5.5 cmd/audit — CLI [待开发]

```text
skillguard audit <path> [--format md|json] [-o FILE] [--rules PATH]
skillguard rules [--category CODE_EXECUTION]
退出码: 0 = 安全/低风险, 1 = 高风险, 2 = 恶意
```

### 5.6 cmd/server — Web API [待开发]

```text
POST /v1/audit             multipart 上传技能包 → 异步审计（asynq）→ 返回 report_id
GET  /v1/reports/{id}      查询审计结果（JSON/Markdown）
GET  /v1/rules             规则库列表
GET  /v1/health            健康检查
```

### 5.7 internal/llm — LLM 语义分析 [待开发]

```go
type LLMClient interface {
    Complete(ctx context.Context, prompt string) (string, error) // OpenAI 兼容 /v1/chat/completions
}
func Analyze(ctx context.Context, in *analyzer.Result, rs *rules.RuleSet, client LLMClient) ([]analyzer.Finding, error)
func BuildPrompt(skillMD *analyzer.SkillMDInfo, scriptSummaries []string) string
```

**接入约定**：
- 模型可插拔（DeepSeek / 通义 / Claude 官方 Go SDK，实现 `LLMClient` 即可）
- 输出强制 JSON：`{"rule_id": "RS-018", "verdict": "malicious|suspicious|benign", "evidence": "..."}`
- 成本控制：每条技能最多 N 次调用（默认 4，对应 4 条 llm 规则）；可配置抽样
- LLM 判定的 finding 以 `detection: "llm"` 写入，权重打折（×0.8）计入评分

### 5.8 internal/sandbox — 沙箱执行器 [阶段二]

```go
type Config struct {
    NetworkOff     bool          // 默认 true（断网）
    DecoyCreds     bool          // 内置假 ~/.ssh/id_rsa、假 .env
    Timeout        time.Duration // 默认 30s
    CPULimit, MemLimit string
}
type Report struct {
    FileReads, FileWrites []string
    NetworkConnections    []string
    ProcessTree           []string
    EnvReads              []string
    ExitCode              int
}
func Run(packagePath string, cfg Config) (*Report, error)
```

**选型**：gVisor（Go 生态衔接最顺，AGENTS.md 已定）。

### 5.9 白名单模块 [待开发]

```json
{
  "domains": ["github.com", "pypi.org", "api.openai.com"],
  "users_confirmed": [{"path": "...", "reason": "..."}],
  "rule_exemptions": [{"rule_id": "RS-011", "scope": "diagnostic-tools"}]
}
```

- 命中白名单的域名/路径/规则 → finding 降权（weight ×0.3）或忽略
- 白名单文件路径：`~/.skillguard/whitelist.json`（用户级）+ `./skillguard.whitelist.json`（项目级）

---

## 6. 评分算法规格

### 6.1 五维加权

```
维度权重: 代码危害性 0.40 | 数据访问 0.25 | 网络行为 0.20 | 提示注入 0.10 | 供应链 0.05

score = Σ( dim(group_max_weight) × dim_weight )    # group_max_weight 为该维度下命中类别最高 weight
```

### 6.2 行为链加成

| 条件 | 加成 |
| :--- | :--- |
| 数据收集类(DATA_THEFT/CREDENTIAL_HUNT) 且 外联类(NETWORK_EXFIL/_V2) 均命中 | +10 |
| DESTRUCTIVE 最高 weight ≥ 90（勒索/批量删除） | score = max(score, 85) |
| DESTRUCTIVE 最高 weight ≥ 80（挖矿） | score = max(score, 75) |

最终 `score = min(100, score + bonus)`，保留 1 位小数。

### 6.3 分级

| 区间 | 等级 | 动作 |
| :--- | :--- | :--- |
| 0-20 | 安全 ✅ | 可安装，颁发徽章（阶段二） |
| 21-50 | 低风险 ⚠️ | 人工复核 |
| 51-80 | 高风险 🔴 | 不建议安装 |
| 81-100 | 恶意 ☠️ | 拦截，禁止安装 |

### 6.4 约束

- LLM 判定的发现权重 ×0.8
- 白名单降权 ×0.3
- 单条 medium（≤60）命中不单独定级，需组合或加成

---

## 7. 数据流示例（字段级）

以恶意示例 `install.sh` 为例：

```text
parser.CollectFiles → files=[SKILL.md, install.sh], root=examples/malicious-skill
analyzer.Analyze   → install.sh 命中 RS-003/RS-006/RS-009/... (17 条)
                     SKILL.md 命中 RS-017/RS-026
                     llm_review = [RS-018, RS-019, RS-021, RS-036]
analyzer.Score     → cat_max = {CODE_EXECUTION:100, PERSISTENCE:85, DATA_THEFT:95,
                                NETWORK_EXFIL:85, PROMPT_INJECTION:90, LLM_SPECIFIC:90,
                                SUPPLY_CHAIN:90, PRIVILEGE_ABUSE:90, DESTRUCTIVE:85, ...}
                     score = 40 + 23.8 + 17 + 9 + 4.5 + bonus10 = 100.0
report.Render      → md/json 报告；退出码 2
```

---

## 8. 扩展点与演进路径

| 扩展点 | 方式 | 状态 |
| :--- | :--- | :--- |
| 新增规则 | 在 `rules/rules.yaml` 追加条目（校验 ID 唯一、weight 0-100、patterns 可编译） | 待开发 |
| 新增类别 | 加 category 值 + 在 analyzer.Score 的维度映射表注册 | 待开发 |
| 接入 LLM | 实现 `internal/llm.LLMClient`，feature flag 开启 | 待开发 |
| 接入沙箱 | 实现 `internal/sandbox`，编排层增加阶段 5 | 阶段二 |
| 平台 API | cmd/server 增加路由（§5.6） | 待开发 |
| Web SaaS | cmd/server 增加上传页，复用内核 | 待开发 |
| 样本库/情报 | L4 增加样本留档（审计输入哈希存储）+ 威胁情报导出 | 待开发 |

---

## 9. 质量与验收标准

### 9.1 指标

| 指标 | 目标 | 测量方式 |
| :--- | :--- | :--- |
| 恶意检出率 | ≥ 85% | ClawHavoc 341 样本回归 |
| 误报率 | ≤ 15% | 良性技能集回归 |
| 单包审计耗时 | ≤ 10s（≤50 文件） | 本地计时 |
| 规则库可追溯 | 规则版本号随报告输出 | 已实现 |

### 9.2 回归测试

- `internal/analyzer/analyzer_test.go`：良性示例评分 ≤20、恶意示例 ≥81
- 规则自检：加载 rules.yaml 时校验 ID 唯一、权重 0-100、patterns 可编译
- 新规则必须附带正反样本（`testdata/`）

### 9.3 性能预算（静态分析）

- 文件大小上限 2MB，超过跳过
- 正则编译缓存（RuleSet 初始化时预编译 regexp2）
- 单文件规则全扫描 ≤ 100ms（40 条规则 × 平均 2 patterns）

---

## 10. 开发任务清单（对照本规格）

### 阶段一剩余（P0）

- [ ] P0-1 `internal/rules` 规则引擎（加载 rules.yaml + regexp2 匹配）
- [ ] P0-2 `internal/parser` 技能包解析（CollectFiles + ParseSkillMD）
- [ ] P0-3 `internal/analyzer` 静态分析器（Analyze + Score + Grade）
- [ ] P0-4 `internal/report` 报告生成（Markdown/JSON）
- [ ] P0-5 `cmd/audit` CLI（Cobra）打通端到端
- [ ] P0-6 `internal/llm` 实现 + 模型接入（DeepSeek/通义 OpenAI 兼容）
- [ ] P0-7 白名单模块（§5.9）
- [ ] P0-8 1000+ 真实样本回归，校准权重与误报（§9.1 指标）

### 阶段二（P1）

- [ ] P1-1 `internal/sandbox` 沙箱执行器（gVisor，§5.8）
- [ ] P1-2 `cmd/server` REST API 层（Gin + asynq，§5.6）
- [ ] P1-3 徽章体系（评分 ≤20 自动颁发）
- [ ] P1-4 报告修复建议字段（rule → remediation 映射）

### 阶段三（P2）

- [ ] P2-1 企业版（私有化 + 合规报告 + 白名单管理界面）
- [ ] P2-2 公开样本库与威胁情报月报

---

## 附：规则库 V2 与 Go 引擎的迁移说明

- 规则库权威文档：`docs/规则库V2.md`（40 条规则说明）
- 机器可读文件：`rules/rules.yaml`（Go 引擎加载，与文档同源生成）
- 规则 JSON/文档 ↔ YAML 转换由 `scripts/` 工具生成，保证文档与引擎一致（新增规则时同步更新两处）
