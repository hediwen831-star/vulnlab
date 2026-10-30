#!/usr/bin/env python3
"""逐条重放负例变体，确认「该打不动的确实打不动」。

和 verify_lab.py 的分工：
  verify_lab  守住 13 个 high 档的**基础**安全属性（89 条断言，手写）
  本脚本       守住 52 条**绕过尝试**（表格驱动，请求与判定都写在 manifest 里）

为什么不用「响应里没有 marker」一句话打发：页面会把输入原样回填进表单，
marker 必然出现在响应里。所以判定支持三种方式，且优先用局部区域：

  region   只看结果区（例如「渲染结果」之后的 <pre>），避免把回填当执行
  forbid   该区域里不能出现的字符串
  require  必须出现的拒绝文案（证明确实走到了拒绝分支，而不是静默失败）

上传这类副作用不在响应里的场景，由 require 的拒绝文案兜底 ——
只要保存分支没走到，就不会有文件落地。

用法：
    python tests/verify_negatives.py --url http://127.0.0.1:8080
    python tests/verify_negatives.py --url http://127.0.0.1:8080 --json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "benchmark" / "manifest.yaml"
TIMEOUT = 20
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def read_yaml(path: Path):
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:
        print("[依赖缺失] 需要 PyYAML：pip install pyyaml", file=sys.stderr)
        raise SystemExit(2)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_request(base: str, case: dict) -> urllib.request.Request:
    """按 manifest 里的 request 描述构造请求。"""
    url = base.rstrip("/") + case["path"]
    method = case.get("method", "GET").upper()
    req = case.get("request") or {}
    headers = {"User-Agent": "VulnLab-NegativeCheck/1.0"}

    cookies = req.get("cookies") or {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    data: bytes | None = None
    if "multipart" in req:
        boundary = "----vulnlab" + uuid.uuid4().hex
        spec = req["multipart"]["file"]
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{spec["filename"]}"\r\n'
            f'Content-Type: {spec["content_type"]}\r\n\r\n'
            f"{spec['content']}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        data = body
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif "form" in req:
        data = urllib.parse.urlencode(req["form"]).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif "query" in req:
        url += "?" + urllib.parse.urlencode(req["query"])

    return urllib.request.Request(url, data=data, headers=headers, method=method)


def fetch(request: urllib.request.Request) -> tuple[int, str]:
    try:
        with OPENER.open(request, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"__CONNECTION_ERROR__: {exc}"


def region_of(body: str, keyword: str) -> str:
    """截取 keyword 到其后第一个 </pre> 之间的内容；找不到就返回空串。

    返回空串而不是整页：找不到结果区说明页面根本没进入执行分支，
    这时整页扫描只会扫到回填的 payload。
    """
    start = body.find(keyword)
    if start < 0:
        return ""
    end = body.find("</pre>", start)
    return body[start : end if end > 0 else start + 3000]


def check_case(base: str, case: dict) -> tuple[bool, str]:
    status, body = fetch(build_request(base, case))
    if status == 0:
        return False, f"环境错误：{body[:120]}"

    rules = case.get("expect_blocked") or {}
    target = body
    where = "整页"
    if rules.get("region"):
        target = region_of(body, rules["region"])
        where = f"结果区「{rules['region']}」"
        if not target:
            return False, f"未找到{where}，无法确认是否进入执行分支"

    hits = [item for item in (rules.get("forbid") or []) if item in target]
    if hits:
        return False, f"{where}出现禁止内容：{hits}（HTTP {status}）"

    missing = [item for item in [rules.get("require")] if item and item not in body]
    if missing:
        return False, f"未出现拒绝文案 {missing}（HTTP {status}）"

    return True, f"HTTP {status}，{where}未出现禁止内容"


def main() -> int:
    parser = argparse.ArgumentParser(description="重放负例变体，校验绕过尝试均被拒绝")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    status, _ = fetch(urllib.request.Request(f"{base}/index.php", headers={"User-Agent": "negcheck"}))
    if status != 200:
        print(f"[环境错误] {base}/index.php 返回 HTTP {status}，先起靶场", file=sys.stderr)
        return 2

    manifest = read_yaml(MANIFEST)
    cases = [
        c for c in manifest.get("cases") or []
        if c.get("variant") is not None or c.get("tier") == "decoy"
    ]

    results = []
    for case in cases:
        passed, detail = check_case(base, case)
        results.append({"id": case["id"], "name": f"负例 · {case['id']} 未被绕过", "passed": passed, "detail": detail})

    passed_count = sum(1 for r in results if r["passed"])
    failed = [r for r in results if not r["passed"]]

    if args.json:
        print(
            json.dumps(
                {"target": base, "total": len(results), "passed": passed_count, "checks": results},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print()
        print("=" * 78)
        print("  负例变体校验（绕过尝试应全部被拒绝）")
        print("=" * 78)
        for r in results:
            mark = "✓" if r["passed"] else "✗"
            print(f"  [{mark}] {r['id']:<32} {r['detail']}")
        print("-" * 78)
        print(f"结果: {passed_count} / {len(results)} 通过")
        print("-" * 78)
        print()

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
