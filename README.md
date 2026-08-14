# SkillGuard — Skill Security Audit Service

> A security inspection and trusted distribution middle layer for the AI Agent skill (SKILL.md) ecosystem.
> Every skill gets a "security checkup": upload a skill package and receive a 0-100 risk score report.

## Why

The skill ecosystem is booming (700K+ skills on SkillsMP, 10K+ on ClawHub), but security incidents are frequent (820 malicious skills were found on ClawHub). SkillGuard acts as a **neutral third-party audit layer** that helps platforms, enterprises, and individual users identify malicious skills and build trust.

## Features

- **Static analysis**: 24 rules covering 7 attack surfaces (code execution / persistence / data theft / network exfiltration / prompt injection / supply chain / obfuscation)
- **LLM semantic analysis**: detects soft risks where "the docs look harmless but the behavior is suspicious" (prompt injection, misleading claims)
- **Risk scoring**: 0-100 in four levels (safe / low risk / high risk / malicious)
- **Sandbox dynamic execution** (Phase 2): run scripts in an isolated environment and monitor real behavior

## Quick Start

```bash
# CLI: audit a skill package locally (directory / single file / zip), Markdown report by default
go build -o skillguard ./cmd/audit
./skillguard audit ./path/to/skill
./skillguard audit ./path/to/skill --json -o report.json

# Web API: register a user → create an API Key → upload a skill package for audit (pay-per-use)
# ADMIN_EMAILS=admin@example.com promotes that email to admin on startup (manage user quotas & DeepSeek Key in the admin console)
JWT_SECRET=<random-secret> DATABASE_URL=postgres://tianjun@localhost:5432/skillguard_dev go run ./cmd/server

# Web console (React 19 + AntD 6 SPA, open http://localhost:5173 in a browser)
cd web && pnpm install && pnpm dev

# Run all tests (engine core + data layer / API tests, requires local PostgreSQL)
go test ./...
```

## Docs

- [AI Collaboration Guide](AGENTS.md) — must-read for AI coding assistants
- [Product Plan](docs/产品方案.md) — background / customers / pricing / roadmap (draft)
- [Detection Rules V1](docs/规则库V1.md) — detailed docs for all 24 rules
- [Machine-readable rules](rules/rules.yaml) — rule definitions loaded by the Go engine
- [Architecture Spec](docs/ARCHITECTURE.md) — layered architecture, interface signatures, scoring algorithm

## Roadmap

- **Phase 1** (in progress): static audit MVP (parser → rule engine → analyzer → report)
- **Phase 2**: sandbox dynamic execution + subscription monetization + security certification badge
- **Phase 3**: enterprise private deployment + threat intelligence monthly report

## License

Private / TBD
