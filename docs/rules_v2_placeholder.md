# 技能安全检测规则库 V2（Skill Security Detection Rules V2）

**版本**：V2.0
**日期**：2026年8月13日
**用途**：技能安全审计服务核心引擎——静态分析阶段的规则定义
**V2 变更**：新增 5 个类别 16 条规则（RS-025 ~ RS-040），总计 **40 条**。
**机器可读版本**：`rules/rules.yaml`（Go 引擎加载，与本文档同源）

## 规则统计（V2，共 40 条）

| 类别 | 规则数 | critical | high | medium |
| :--- | :--- | :--- | :--- | :--- |
| 代码执行 CODE_EXECUTION | 5 | 3 | 2 | 0 |
| 持久化 PERSISTENCE | 3 | 1 | 2 | 0 |
| 数据窃取 DATA_THEFT | 4 | 1 | 2 | 1 |
| 网络外联 NETWORK_EXFIL | 5 | 1 | 4 | 0 |
| 提示注入 PROMPT_INJECTION | 4 | 0 | 2 | 2 |
| 供应链 SUPPLY_CHAIN | 5 | 1 | 3 | 1 |
| 混淆 OBFSUSCATION | 2 | 0 | 1 | 1 |
| 权限提权 PRIVILEGE_ABUSE | 3 | 1 | 1 | 1 |
| 凭据猎取 CREDENTIAL_HUNT | 3 | 2 | 1 | 0 |
| 破坏性 DESTRUCTIVE | 3 | 2 | 1 | 0 |
| LLM 特定攻击 LLM_SPECIFIC | 3 | 1 | 2 | 0 |
| **合计** | **40** | **13** | **21** | **6** |

（完整规则说明见 Agent 文档《技能安全检测规则库 V2》，此处为目录占位，随后用完整版覆盖）
