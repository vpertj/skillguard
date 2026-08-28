# Security Policy

SkillGuard is a security tool — its own security matters. We take vulnerabilities in SkillGuard seriously and appreciate the security community's help in keeping it safe.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.** Malicious skill authors monitor this project's issues; disclosing detection weaknesses publicly helps attackers bypass SkillGuard.

Please report privately instead:

- **GitHub Security Advisory**: use the "Report a vulnerability" button on the [Security tab](https://github.com/vpertj/skillguard/security/advisories)
- **Email**: `vpertj@users.noreply.github.com` (PGP preferred, on request)

### What to include

- Affected version / commit hash
- Steps to reproduce (skill package or snippet, scan command)
- Impact description (what an attacker can achieve)
- Suggested fix, if you have one

## Response Commitment

- **Acknowledgment**: within 48 hours of a valid report
- **Triage**: within 7 days (critical issues faster)
- **Fix**: critical issues are prioritized and released as soon as a fix is verified

## Scope

- The Go engine (`internal/`, `cmd/`)
- Detection rules and scoring logic
- The Web API and CLI surfaces

## Out of Scope

- Malicious skills themselves (report those to ClawHub / the relevant marketplace)
- Known limitations of static analysis (no static scanner catches everything)
- Rule bypass techniques that require local modification of the scanner binary

## Security Notes for Users

- SkillGuard is a **detection aid, not a guarantee** — always review high-risk findings manually before installing a skill
- The benchmark corpus (`internal/bench/testdata/`) contains real malware — never execute it
- Do not run SkillGuard as root; it requires only read access to the skill package being audited
