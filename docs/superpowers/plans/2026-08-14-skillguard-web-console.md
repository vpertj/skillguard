# SkillGuard Web 管理控制台实施计划（N1-N5）

> **For agentic workers:** 沿用 M0-M6 风格分里程碑实施。每 task 结束前：`tsc` 无错误 + `npm run build` 通过 + commit。

**Goal:** 正式管理后台 SPA（React 19 + Ant Design 6 + TypeScript + Vite），对接现有 REST API（/v1/auth、/v1/keys、/v1/audit、/v1/audits、/v1/usage）。

**版本核实（2026-08-14 npm registry）：** react 19.2.8 / antd 6.6.0 / vite 8.2.1 / zustand 5.0.15 / @tanstack/react-query 5.101.4 / typescript 7.0.2 / react-router-dom 7.18.2

## 技术决策（2026-08-14 锁定）

- **目录**：仓库根 `web/`，独立 Vite SPA（与 Go 后端分离，AGENTS.md 技术栈决策）
- **状态**：zustand（auth store：token/user，localStorage 持久化）
- **数据请求**：@tanstack/react-query（hooks 缓存）+ fetch 封装（自动带 Bearer token）
- **路由**：react-router-dom v7（BrowserRouter），路由守卫（未登录跳 /login）
- **代理**：vite dev server proxy `/v1` → `http://localhost:8080`（避免 CORS；生产由 nginx/反代处理）
- **UI 语言**：中文（产品面向中文技能生态）
- **页面**：Login/Register（合一）、Dashboard（用量 + 最近审计）、Audit（上传→报告）、Keys、History

## 文件结构

```
web/
├── index.html
├── vite.config.ts          # react 插件 + proxy /v1 → 8080
├── package.json
├── tsconfig.json
└── src/
    ├── main.tsx            # 入口：ConfigProvider(zhCN) + QueryClientProvider + Router
    ├── App.tsx             # 路由表 + 守卫
    ├── api/client.ts       # fetch 封装（JSON + Bearer + 401 处理）
    ├── api/types.ts        # User/APIKey/AuditBrief/Report/ScoreResult 类型（对齐后端 JSON）
    ├── stores/auth.ts      # zustand：token/user/login/logout
    ├── components/AppLayout.tsx   # 侧边菜单 + 顶栏（用户名/退出）
    ├── components/ScoreCard.tsx   # 评分展示（Progress 环 + 等级徽标 + 维度分解）
    ├── components/FindingsTable.tsx # 命中明细表格
    └── pages/
        ├── LoginPage.tsx   # 登录/注册 Tab
        ├── DashboardPage.tsx # 用量卡片 + 最近 5 条审计
        ├── AuditPage.tsx   # zip 上传（Upload.Dragger）→ 报告渲染
        ├── KeysPage.tsx    # Key 创建（明文弹窗一次）/列表/吊销
        └── HistoryPage.tsx # 审计历史表格
```

## 任务分解

| 任务 | 内容 | 验收 |
| :--- | :--- | :--- |
| N1 | Vite+React19+TS 脚手架 + AntD6 接入 + 路由骨架 + Login/Register 页（调 /v1/auth） | 登录/注册联通后端（curl 冒烟 + build 通过） |
| N2 | zustand auth store + AppLayout（侧边菜单）+ 路由守卫 + API client 封装 | 未登录跳转登录页；登录后进入控制台 |
| N3 | Keys 页（创建显示明文一次/列表/吊销）+ Dashboard 用量 | Key 全生命周期可用 |
| N4 | Audit 页（拖拽上传 zip → 评分环 + 命中明细 + LLM 队列）+ History 页 | 上传恶意样本显示报告 |
| N5 | 联调收尾：build、与 server 联调冒烟、README/AGENTS 文档更新 | 全链路可操作 |

## 执行顺序

```
N1（脚手架+登录）→ N2（认证+布局）→ N3（Keys+Dashboard）→ N4（Audit+History）→ N5（收尾联调）
```
