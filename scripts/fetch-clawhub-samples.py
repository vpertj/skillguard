#!/usr/bin/env python3
"""从 ClawHub 公开 API 批量拉取技能样本（良性基准集扩充）。

用法: python3 scripts/fetch-clawhub-samples.py [--count 200] [--out internal/bench/testdata/benign]
注意: 拉取的是公开注册表的真实技能，仅作静态分析测试用。
"""
import argparse
import io
import json
import os
import sys
import time
import urllib.request
import zipfile

API = "https://clawhub.ai"
LIST_URL = f"{API}/api/v1/skills"
DL_URL = f"{API}/api/v1/download"

def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "skillguard-bench/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def fetch_zip(slug):
    url = f"{DL_URL}?slug={urllib.parse.quote(slug)}"
    req = urllib.request.Request(url, headers={"User-Agent": "skillguard-bench/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--out", default="internal/bench/testdata/benign")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cursor = None
    slugs = []
    while len(slugs) < args.count:
        url = LIST_URL + f"?limit=50"
        if cursor:
            url += f"&cursor={urllib.parse.quote(cursor)}"
        d = fetch_json(url)
        for it in d.get("items", []):
            slugs.append(it["slug"])
        cursor = d.get("nextCursor")
        if not cursor or not d.get("items"):
            break
        time.sleep(0.3)

    print(f"技能列表: {len(slugs)} 个（目标 {args.count}）", file=sys.stderr)
    ok, fail = 0, 0
    for i, slug in enumerate(slugs[:args.count]):
        out_dir = os.path.join(args.out, f"clawhub-{slug}")
        if os.path.exists(out_dir):
            ok += 1
            continue
        try:
            z = zipfile.ZipFile(io.BytesIO(fetch_zip(slug)))
            names = z.namelist()
            if not any(n.endswith("SKILL.md") for n in names):
                fail += 1
                continue
            os.makedirs(out_dir, exist_ok=True)
            # 解压全部（含 SKILL.md 与附属脚本），跳过图标/元数据
            for n in names:
                if n.endswith((".png", ".jpg", ".ico", "_meta.json")):
                    continue
                if n.endswith("/"):
                    continue
                dest = os.path.join(out_dir, os.path.basename(n))
                with z.open(n) as src, open(dest, "wb") as f:
                    f.write(src.read())
            ok += 1
            if (i + 1) % 25 == 0:
                print(f"进度: {i+1}/{min(len(slugs), args.count)}", file=sys.stderr)
        except Exception as e:
            fail += 1
            print(f"失败 {slug}: {e}", file=sys.stderr)
        time.sleep(0.2)

    print(f"完成: 成功 {ok}，失败 {fail}，输出 {args.out}")

if __name__ == "__main__":
    import urllib.parse
    main()
