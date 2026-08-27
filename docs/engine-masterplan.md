# SkillGuard 引擎总体规划（Master Plan）

> 目标：把 SkillGuard 打造成**全球数一数二的 Agent 技能安全引擎**——"Agent 技能安全的 Semgrep"
> 更新时间：2026-08-27

## 赛道判断：第一名还没出现

- ClawHavoc 事件 2026-02 爆发：ClawHub 341→824 个恶意技能，AMOS 窃密木马分发（Koi Security）
- Snyk ToxicSkills：扫描 3,984 技能，13.4% 含 critical 问题，76 个确认恶意载荷（**研究论文，非产品**）
- Clawdex：IOC 查表工具（**查表，非分析引擎**）；mcp-scan：研究引擎（**无商业产品**）
- **结论：Agent 技能安全是 2026 年刚起步的垂直赛道，尚无分析引擎产品——第一名虚位以待**

## 四层纵深架构

```
┌─────────────────────────────────────────────────┐
│ 产品层：CI/CD 集成 + 市场预扫描 + 报告 + SDK       │
├─────────────────────────────────────────────────┤
│ 知识层：IOC 数据库 + 指纹白名单 + 社区威胁情报      │
├─────────────────────────────────────────────────┤
│ 引擎层：静态规则 → AST 数据流 → LLM 意图 → 沙箱行为 │
├─────────────────────────────────────────────────┤
│ 基准层：恶意样本集 + 良性样本集 + 量化门禁          │
└─────────────────────────────────────────────────┘
```

### 引擎层四层纵深（每层补上一层盲区）

| 层 | 技术 | 检出能力 | 状态 |
|---|---|---|---|
| 静态规则 | regexp2，24→100+ 条（Snyk 8 类威胁分类） | 已知模式 | ✅ 已有，扩充中 |
| AST 数据流 | tree-sitter 5+ 语言，危险调用链 | 区分 `subprocess(curl\|bash)` vs `subprocess(soffice)` | 未做（阶段 B） |
| LLM 意图 | 全量命中复核 + Unicode 走私/同形字/伪 prompt | 文本干净但意图恶意 | ⚠️ 部分（仅 2 条规则） |
| 沙箱行为 | gVisor 动态执行：文件/网络/进程观察 | 换皮变体（AV 级能力） | 未做（阶段 D） |

### 威胁分类（对齐 Snyk ToxicSkills 8 类）

prompt injection / malicious code / suspicious download / credential handling /
secret detection / third-party content exposure / unverifiable dependencies / direct money access

## 数据飞轮（真正壁垒）

```
扫描越多 → 样本越多 → 规则越准 → 用户越多 → 扫描更多
```

- 开源引擎获客 + 闭源规则库/情报变现（Semgrep/Snyk 验证模式）
- IOC 查表比分析快 1000 倍（ClawHavoc C2 IP 一个查表拦 335 个技能）
- 用户上报 + 自动爬新技能 → 新样本进基准 → 半自动提规则

## 量化目标（可测量，非口号）

| 指标 | 当前基线 | 阶段 A 目标 | 顶级目标 |
|---|---|---|---|
| 真实样本检出率 | 91.7%（44/48） | **100%（48/48）✅** | ≥95%（持续新样本） |
| 误报率 | 60.6%（20/33） | ≤30% | ≤10% |
| 规则库 | 24 条 | **32 条**（进行中） | 100+ |
| 扫描速度 | 39ms/包 | — | <10s（大包） |
| 生态 | 私有 | 开源发布 | GitHub Action + ClawHub 预扫描 |

## 分级设计（专业安全产品标准）

- 高置信恶意 → 直接标红
- 低置信可疑 → 黄色提示人工复核
- 灰色地带交给人和 LLM，引擎负责把确定的事做绝

## 分阶段路线图

### 阶段 A：静态层强化（当前）
- [x] 4 个漏检样本逐个攻破（样本集冲 100%）
  - [x] snyk-testing-guidelines：ASCII/Unicode smuggling 新规则（RS-026）
  - [x] nano-banana-pro：17.5 分差一点，补权重（RS-025 zip 分发包）
  - [x] snyk-skill-with-commands：分析命中源（RS-027 bang 命令）
  - [x] progressive-memory：静态干净 → 标记为 LLM 层检测对象（RS-025 zip 分发包，代码执行维 w=85）
- [ ] 规则库 24→40+（进行中：32 条——secret 检测 RS-028~031、注释隐藏注入 RS-032 已加）
- [x] LLM 二次裁决：静态命中 → 意图复核 → 压误报（ReviewFindings + ApplyReview + bench --llm，真实基准验证中）
- [ ] 基准门禁：每次改动跑 cmd/bench，检出率/误报率变化进 commit message

### 阶段 B：AST 数据流层
- [x] tree-sitter 集成（Python 起步，internal/astscan）
- [ ] 危险调用链：subprocess 字面量参数（RS-037 ✅）→ 变量跟踪数据流（进行中）
- [ ] 混淆检测：多层编码、随机变量名

### 阶段 C：IOC 情报层 + 开源发布
- [ ] IOC 表：已知恶意作者/域名/IP/哈希（ClawHavoc 公开 IOC）
- [ ] 技能指纹白名单（Anthropic 官方等可信源 hash）
- [ ] GitHub 公开仓库 + CI 基准门禁 + 社区规则贡献流程

### 阶段 D：沙箱行为层 + 市场集成
- [ ] gVisor 沙箱动态执行（阶段二 AGENTS.md 已定）
- [ ] ClawHub/LobeHub 安装前预扫描集成
- [ ] GitHub Action / 预提交钩子

## 参考基准

- 基线报告：`docs/benchmark-baseline.md`（2026-08-27）
- 样本集：`internal/bench/testdata/`（恶意 48 / 良性 33，`scripts/fetch-bench-samples.sh` 复现）
- 规则库：`rules/rules.yaml`（24 条）+ `docs/规则库V1.md`
