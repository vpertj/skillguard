# SkillGuard — AI Agent Skill Security Audit Engine

> A security audit engine for AI Agent skills (SKILL.md packages). Scan a skill and get a 0-100 risk score with detailed findings — before it touches your agent.

The AI agent skill ecosystem is exploding (10K+ skills on ClawHub, 700K+ across marketplaces), and so are the attacks. In February 2026, the **ClawHavoc campaign** pushed 341→824 malicious skills onto ClawHub in 72 hours — professionally documented skills hiding Atomic Stealer credential theft, reverse shells, and prompt injection in their "prerequisites" sections.

SkillGuard is a **static + semantic audit engine** purpose-built for this threat: it catches the patterns ClawHavoc and its imitators actually use.

## Features

- **37 detection rules** across 8 attack surfaces (code execution / persistence / data theft / network exfiltration / prompt injection / supply chain / obfuscation / credential hunting)
- **AST-level analysis** (tree-sitter): distinguishes `subprocess.run(["soffice"])` (legitimate document conversion) from `subprocess.run(["bash","-c","curl|bash"])` (malware) — something regex alone cannot do
- **LLM semantic review**: static hits are re-adjudicated by an LLM for intent — legitimate uses (LibreOffice calls, `re.compile`) are removed from scoring, cutting false positives in half
- **0-100 risk score** in four grades (safe / low risk / high risk / malicious), with per-dimension breakdown
- **CLI + Web API + management console**: local audit, SaaS service, or embed via API
- **Open core**: the engine and 30 baseline rules are open source; 7 proprietary ClawHavoc-specific rules ship in the commercial edition

## Benchmark (real-world corpus)

| Metric | Open edition (30 rules) | Full edition (37 rules) |
|---|---|---|
| Malicious detection rate | **91.7%** (44/48 real ClawHavoc-related samples) | **95.8%** (46/48) |
| False positive rate | 42.1% (323 real ClawHub skills) | 44.0% |
| Avg scan time | ~50ms / skill package | ~50ms |

*LLM semantic review further cuts false positives to ~31% (full edition). Benchmark corpus is reproducible via `scripts/fetch-bench-samples.sh` + `scripts/fetch-clawhub-samples.py`.*

## Quick Start

```bash
# CLI: audit a skill package locally (directory / file / zip)
go run ./cmd/audit audit ./path/to/skill
go run ./cmd/audit audit skill.zip --json
```

```bash
# Web service (SaaS mode)
JWT_SECRET=<strong-secret> go run ./cmd/server
# → http://localhost:8080, console at http://localhost:5173 (cd web && pnpm dev)
```

## Architecture

```
┌─────────────────────────────────────────────┐
│ Product: CLI / Web API / Console / CI hook   │
├─────────────────────────────────────────────┤
│ Engine layers:                              │
│  1. Static rules (regexp2, 30 open rules)   │
│  2. AST dataflow (tree-sitter, Python)      │
│  3. LLM semantic review (DeepSeek)          │
│  4. Sandbox dynamic execution (Phase 2)     │
├─────────────────────────────────────────────┤
│ Benchmark: 48 malicious + 323 benign corpus │
└─────────────────────────────────────────────┘
```

## Open-core model

- **Open source**: engine, CLI, Web API, console, and 30 baseline rules (general security patterns)
- **Commercial**: 7 ClawHavoc-specific rules (Unicode smuggling, comment-hidden injection payloads, fake security-scanner impersonation, exfil targets, AST call chains) + continuous rule updates + threat intelligence feeds

## Roadmap

- [x] Static engine (30 open + 7 pro rules), risk scoring
- [x] LLM semantic review (RS-018/019 + hit re-adjudication)
- [x] AST dataflow (subprocess call chains, variable tracking)
- [x] Benchmark harness + real-world corpus (ClawHavoc + ClawHub)
- [ ] IOC lookup layer (C2 IPs / domains / publisher blacklists)
- [ ] Sandbox dynamic execution (gVisor)
- [ ] Rule pack distribution & licensing (signed, per-user)

## License

MIT (engine and open rules). Commercial rules are distributed separately.

## Disclaimer

SkillGuard is a detection tool, not a guarantee. No scanner catches everything — review high-risk findings before installing any skill. The benchmark corpus contains real malicious code; never execute it.
