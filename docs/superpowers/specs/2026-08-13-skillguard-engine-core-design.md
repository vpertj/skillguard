# SkillGuard 引擎内核设计（阶段一 · 仅内核）

**日期**：2026-08-13
**状态**：已获用户批准
**范围**：`internal/rules` + `internal/parser` + `internal/analyzer` + `internal/report` 四个包 + `rules/rules.yaml`（V1 24 条规则）+ 单元测试与正反样本。
**上游规格**：`docs/ARCHITECTURE.md` V1.1（接口签名、评分算法、报告 Schema 以此为准）。

## 1. 已确认的决策（用户拍板）

| 决策点 | 结论 |
| :--- | :--- |
| 交付边界 | 仅引擎内核；CLI / Web / LLM 实现 / 白名单 / 沙箱均不在本次范围 |
| 规则库 | 先做 V1 24 条（7 类攻击面），由 AI 起草，V2（40 条）后补 |
| 开发顺序 | 自底向上：rules.yaml+引擎 → parser → analyzer → report → 端到端验证 |
| Git | 本次初始化仓库，Conventional Commits，每里程碑一个 commit |

## 2. 非目标（明确不做）

- 不实现 `cmd/audit`、`cmd/server`
- 不接入 LLM（引擎支持 `detection: llm` 规则进 `llm_review_rules` 队列输出，但无调用方）
- 不做白名单、沙箱、样本回归（P0-8）——后续里程碑

## 3. 规则库 V1（rules/rules.yaml，version: "1.0"）

### 3.1 24 条规则总表

| ID | 名称 | 类别 | 严重度 | 权重 | 检测 | Pattern 意图 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| RS-001 | 动态代码执行 | CODE_EXECUTION | critical | 95 | regex | `eval(` / `exec(` / `compile(`（py/js） |
| RS-002 | Shell 命令执行 | CODE_EXECUTION | critical | 90 | regex | `bash -c` / `sh -c` / `os.system` / `subprocess` / `Runtime.exec` / `ProcessBuilder` |
| RS-003 | 远程脚本拉取执行 | CODE_EXECUTION | critical | 95 | regex | `curl\|sh` / `wget\|bash` / `iwr\|iex` / `Invoke-Expression` |
| RS-004 | 命令替换执行 | CODE_EXECUTION | high | 80 | regex | 反引号 / `$(...)` 命令替换 |
| RS-005 | 解释器调用执行 | CODE_EXECUTION | high | 75 | regex | `python3 -c` / `node -e` / `powershell -Command` / `perl -e` |
| RS-006 | 计划任务与服务持久化 | PERSISTENCE | critical | 90 | regex | `crontab` / `launchd` / `systemd` / `schtasks` / `at` |
| RS-007 | Shell 配置写入 | PERSISTENCE | high | 85 | regex | 写入 `.bashrc` / `.zshrc` / `.profile` / `rc.local` |
| RS-008 | 登录项自启动 | PERSISTENCE | high | 80 | regex | LaunchAgent plist / 注册表 Run 键 |
| RS-009 | 敏感文件读取 | DATA_THEFT | critical | 95 | regex | `~/.ssh` / `~/.aws` / `id_rsa` / `.env` / `credentials` |
| RS-010 | 环境变量转储 | DATA_THEFT | high | 70 | regex | `env` / `os.environ` / `process.env` / `printenv` |
| RS-011 | 浏览器与密码库数据 | DATA_THEFT | high | 85 | regex | Chrome cookies / keychain / cookies.sqlite / LastPass |
| RS-012 | 剪贴板与键盘记录 | DATA_THEFT | medium | 60 | regex | `pbcopy` / `pbpaste` / `xclip` / `Get-Clipboard` / keylogger |
| RS-013 | HTTP 数据外传 | NETWORK_EXFIL | high | 85 | regex | `curl -d` / `requests.post` / `fetch` 带 body 上传 |
| RS-014 | DNS 外传通道 | NETWORK_EXFIL | high | 80 | regex | `dig` / `nslookup` 带编码数据 / DNS 隧道特征 |
| RS-015 | 反向 Shell 与 C2 | NETWORK_EXFIL | critical | 95 | regex | `nc -e` / `/dev/tcp` / reverse shell / socket connect |
| RS-016 | 明文协议外传 | NETWORK_EXFIL | high | 70 | regex | `ftp` / `telnet` / 明文 `http://` 传输数据 |
| RS-017 | 提示注入指令 | PROMPT_INJECTION | high | 80 | regex | "ignore previous instructions" / "忽略以上指令" / system prompt 覆盖 |
| RS-018 | 角色伪装 | PROMPT_INJECTION | medium | 55 | llm | 声称官方/系统级身份与行为不符 |
| RS-019 | 声明-行为不一致 | PROMPT_INJECTION | medium | 60 | llm | 文档声称无害但含危险操作 |
| RS-020 | 未校验来源下载安装 | SUPPLY_CHAIN | critical | 90 | regex | `pip install <URL>` / `npm install <github>` / 下载后直接执行 |
| RS-021 | 依赖投毒特征 | SUPPLY_CHAIN | high | 75 | regex | 全局安装 / 篡改 lock 文件 / 安装不受信源 |
| RS-022 | 二进制载荷分发 | SUPPLY_CHAIN | medium | 60 | regex | base64 解码写出 ELF/PE + `chmod +x` |
| RS-023 | 解码执行链 | OBFSUSCATION | high | 70 | regex | `base64 -d \| sh` / eval + decode 链 |
| RS-024 | 编码载荷 | OBFSUSCATION | medium | 55 | regex | 超长 base64/hex 字符串（`[A-Za-z0-9+/=]{200,}` / `[0-9A-Fa-f]{200,}`） |

统计：critical 7 / high 12 / medium 5；类别分布 5/3/4/4/3/3/2 = 24。

### 3.2 rules.yaml Schema

```yaml
version: "1.0"          # 顶层版本字段，报告 rules_version 来源；V2 升级时改版本号
rules:
  - id: RS-001           # 唯一，格式 RS-\d{3}
    name: 动态代码执行
    category: CODE_EXECUTION
    severity: critical   # critical | high | medium | low
    weight: 95           # 0-100
    detection: regex     # regex | heuristic | llm；regex 与 heuristic 引擎同等对待（自动扫描 patterns）
    patterns: []         # regexp2 语法；V1 的 24 条规则全为 regex/llm，无 heuristic
    rationale: 攻击原理说明
    false_positive_note: 误报提示
```

### 3.3 起草原则

- **检出优先于精确**（AGENTS.md）：宁可误报不可漏报，权重向 critical 倾斜
- 每条规则附正反样本（见 §7），后续用 ClawHavoc 样本回归校准
- 2 条 llm 规则不参与自动评分，进入 `llm_review_rules` 队列

## 4. 包接口与依赖

```
internal/rules   （叶子）rules.yaml 加载 + regexp2 预编译 + 校验
internal/parser  （叶子）文件采集 + SKILL.md frontmatter 解析
internal/analyzer（依赖 rules + parser）扫描 + 评分 + 分级
internal/report  （依赖 analyzer + rules）报告构建 + Markdown/JSON 渲染
```

依赖方向单一：rules、parser → analyzer → report，无循环（AGENTS.md 约定）。

### 4.1 internal/rules（接口见 ARCHITECTURE §5.2）

- `LoadRules(path)`：解析 YAML → 校验 → 预编译
- 校验规则：ID 唯一（`RS-\d{3}`）、severity 枚举、weight 0-100、category 非空、detection 枚举、regex/heuristic 规则 patterns 非空
- 编译策略：`regexp2.Compile(p, regexp2.RE2)` → 失败退化为 .NET 语法（支持 lookahead）→ 仍失败跳过该规则并记日志（§4.3 降级）
- 提供 `Version`（rules_version）与 `Summary`（加载规则数/编译失败数）

### 4.2 internal/parser（接口见 ARCHITECTURE §5.1）

- `CollectFiles(path)`：支持目录（递归）/ 单文件 / zip（解压到 `os.MkdirTemp`，返回 root 供调用方 `os.RemoveAll` 清理）
- `ParseSkillMD(content)`：YAML frontmatter（`---` 分隔）→ `Frontmatter{Name, Description, AllowedTools}` + body；无 frontmatter 时容忍（零值 + 全文为 body），YAML 损坏返回 error
- `IsScannable(path, size)`：≤2MB、非二进制（扩展名黑名单 + 前 512 字节 NUL 嗅探）、跳过 `.git`
- `FindSkillMD(files)`：大小写不敏感匹配 `SKILL.md`

### 4.3 internal/analyzer（接口见 ARCHITECTURE §5.3）

- `Analyze(files, root, rs)`：定位 SKILL.md → 解析 frontmatter → 遍历可扫描文件 × AutoDetectable 规则 → `Findings`；llm 规则 → `LLMReview`；返回 `Result{Findings, LLMReview, SkillMD, ScannedFiles, SkippedFiles}`
- `ScanContent(content, rules, fileLabel)`：每条规则每文件只报首个命中（§3.1 约定），含行号 + 截断片段（≤200 字符）
- `Score(findings)` 直接由 findings 携带的 (category, weight) 派生各维度 group_max_weight，无需额外统计

### 4.4 评分算法（ARCHITECTURE §6，完整实现）

五维权重与类别映射（**通用表**，V2 新增类别零引擎改动，未知类别落入代码危害性并告警）：

| 维度 | 权重 | 类别 |
| :--- | :--- | :--- |
| 代码危害性 | 0.40 | CODE_EXECUTION, PERSISTENCE, OBFSUSCATION, PRIVILEGE_ABUSE*, DESTRUCTIVE* |
| 数据访问 | 0.25 | DATA_THEFT, CREDENTIAL_HUNT* |
| 网络行为 | 0.20 | NETWORK_EXFIL, NETWORK_EXFIL_V2* |
| 提示注入 | 0.10 | PROMPT_INJECTION, LLM_SPECIFIC* |
| 供应链 | 0.05 | SUPPLY_CHAIN, SUPPLY_CHAIN_V2* |

（\* 为 V2 类别，本次规则库不含，映射已预留）

```
score = Σ( dim(group_max_weight) × dim_weight )
group_max_weight = 该维度下命中类别最高 weight
```

行为链加成（§6.2）：数据收集类 ∩ 外联类均命中 → +10；DESTRUCTIVE 相关子句按规格实现（V1 无此类别，天然不触发）。最终 `min(100, score)`，保留 1 位小数。无命中 → 0 分。

分级（§6.3）：0-20 安全✅ safe / 21-50 低风险⚠️ low / 51-80 高风险🔴 high / 81-100 恶意☠️ malicious。

### 4.5 internal/report（接口见 ARCHITECTURE §5.4）

`AuditResult` JSON Schema 严格对齐 §3.4：`tool`、`version`(0.1.0)、`rules_version`、`target`、`scanned_files`、`skipped_files`、`skill_md{file,frontmatter,body_preview}`、`score{score,level,level_key,icon,breakdown,bonus,notes,hit_categories}`、`findings[]`、`llm_review_rules[]`。

- `RenderJSON`：JSON 可被 §3.4 示例结构解析（字段名 snake_case）
- `RenderMarkdown`：人读报告（严重度图标、命中片段引用、维度分解表、规则原文引用）

## 5. 测试策略（AGENTS.md 硬性要求）

| 包 | 测试内容 |
| :--- | :--- |
| rules | 加载成功/文件缺失/格式错误；校验（重复 ID、非法 weight/severity/detection、空 patterns）；RE2 回退；Version/Summary |
| parser | frontmatter 合法/缺失/损坏；CollectFiles 目录/单文件/zip；IsScannable 大小与二进制；FindSkillMD |
| analyzer | **48 个正反样本**（24 条规则 × 1 正例 + 1 反例，`testdata/positive/<rule-id>/` 与 `negative/`）；行号/片段正确性；评分边界（20/21、50/51、80/81）；行为链加成触发；llm 规则入队不评分 |
| report | JSON 字段完整性（对齐 §3.4）；Markdown 渲染；端到端链 |

端到端样本（§9.2）：`testdata/malicious-skill/` 合成恶意技能包 → 断言 score ≥81 且 findings 非空、报告含命中详情；`testdata/benign-skill/` → 断言 score ≤20。

## 6. 里程碑（自底向上，每步一个 commit）

| 里程碑 | 内容 | commit 前缀 |
| :--- | :--- | :--- |
| M0 | git init + .gitignore + 修正 AGENTS.md/README 过期引用 | chore/docs |
| M1 | `rules/rules.yaml`（24 条）+ `docs/规则库V1.md`（同源文档） | feat |
| M2 | `internal/rules` 引擎 + 单测 | feat |
| M3 | `internal/parser` + 单测 | feat |
| M4 | `internal/analyzer` + 48 正反样本 + 单测 | feat |
| M5 | `internal/report` + 端到端测试 | feat |
| M6 | 校准（跑通全量测试、修复误报漏报）+ gofmt/vet/test 收尾 | fix/docs |

## 7. 验收标准（本里程碑）

1. `go build ./...` 通过；`gofmt -l .` 为空；`go vet ./...` 无告警
2. `go test ./...` 全绿，含：24 条规则正反样本、评分边界、端到端（恶意 ≥81 / 良性 ≤20）
3. `rules/rules.yaml` 加载校验通过（ID 唯一、weight 合法、patterns 可编译）
4. 报告 JSON 可被 ARCHITECTURE §3.4 结构解析
5. 文档同步：`docs/规则库V1.md` 与 rules.yaml 一致；AGENTS.md/README 引用与实际文件一致
