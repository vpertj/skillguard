#!/bin/bash
# 拉取并整理 SkillGuard 引擎基准样本集（恶意 + 良性）。
# 样本含真实恶意代码，仅作静态分析测试用——绝不执行其中任何脚本。
# 用法: bash scripts/fetch-bench-samples.sh

set -euo pipefail

cd "$(dirname "$0")/.."
TESTDATA="internal/bench/testdata"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "==> 拉取恶意样本：aztr0nutzs/NET_NiNjA（Snyk ToxicSkills 点名的恶意分发作者）"
git clone -q --depth 1 https://github.com/aztr0nutzs/NET_NiNjA.v1.2.git "$TMP/netninja"

echo "==> 拉取恶意样本：snyk-labs/toxicskills-goof（Snyk 官方演示，含 ASCII smuggling）"
git clone -q --depth 1 https://github.com/snyk-labs/toxicskills-goof.git "$TMP/toxicskills"

echo "==> 拉取良性样本：anthropics/skills（官方）"
git clone -q --depth 1 https://github.com/anthropics/skills.git "$TMP/anthropic"

echo "==> 拉取良性样本：obra/superpowers"
git clone -q --depth 1 https://github.com/obra/superpowers.git "$TMP/superpowers"

rm -rf "$TESTDATA/malicious" "$TESTDATA/benign"
mkdir -p "$TESTDATA/malicious" "$TESTDATA/benign"

for d in "$TMP/netninja"/skills/skills-folders/*/; do
  [ -f "$d/SKILL.md" ] || continue
  name=$(basename "$d")
  mkdir -p "$TESTDATA/malicious/$name"
  cp -r "$d/." "$TESTDATA/malicious/$name/"
done

for d in "$TMP/toxicskills"/.agents/skills/*/ "$TMP/toxicskills"/.gemini/skills/*/ "$TMP/toxicskills"/demos/skill-with-commands/; do
  [ -f "$d/SKILL.md" ] || continue
  name=$(basename "$d")
  mkdir -p "$TESTDATA/malicious/snyk-$name"
  cp -r "$d/." "$TESTDATA/malicious/snyk-$name/"
done

for d in "$TMP/anthropic"/skills/*/; do
  [ -f "$d/SKILL.md" ] || continue
  name=$(basename "$d")
  mkdir -p "$TESTDATA/benign/anthropic-$name"
  cp -r "$d/." "$TESTDATA/benign/anthropic-$name/"
done

for d in "$TMP/superpowers"/skills/*/; do
  [ -f "$d/SKILL.md" ] || continue
  name=$(basename "$d")
  mkdir -p "$TESTDATA/benign/obra-$name"
  cp -r "$d/." "$TESTDATA/benign/obra-$name/"
done

echo "==> 完成：恶意 $(ls "$TESTDATA/malicious" | wc -l | tr -d ' ') 个，良性 $(ls "$TESTDATA/benign" | wc -l | tr -d ' ') 个"
