#!/usr/bin/env python3
"""执行 benchmark/probes 下的探测用例，验证真值清单与靶场行为一致。

**为什么要有这个脚本**

`tests/verify_lab.py` 是「人和靶场」之间的契约：它证明某一档能不能打通。
但评测扫描器需要的是另一件事 —— **同一份载荷打到三档上，分别命中还是不命中**。
这两者的区别很关键：

  · verify_lab 用文件系统状态做判据（探针文件有没有落盘），稳定但不通用；
  · 扫描器只能用响应内容做判据（matcher），而这正是误报的来源。

所以探针直接复用 `pocs/` 里已经验证过的请求，只把路径里的档位换掉 ——
**载荷一字不改，唯一变化的变量就是防护档位**。这是控制变量。

期望结果由 `benchmark/manifest.yaml` 给出：
  · vulnerable 档 → 探针必须命中（检出率的分母）
  · safe 档       → 探针必须不命中（误报率的来源）

用法：
    python tests/run_probes.py                                 # 默认 127.0.0.1:8080
    python tests/run_probes.py --url http://127.0.0.1:8080
    python tests/run_probes.py --only sqli                     # 只跑某个场景
    python tests/run_probes.py --json

退出码：
    0  全部符合预期
    1  存在与预期不符的用例
    2  环境/依赖问题
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 求值实现只有一份，和评测框架共用：判据理解不一致是最难查的偏差。
from benchmark.harness.matchers import eval_matchers  # noqa: E402

PROBE_FILE = ROOT / "benchmark" / "probes.yaml"
MANIFEST = ROOT / "benchmark" / "manifest.yaml"

# 本地靶场必须绕开系统代理，否则请求会被代理吞掉（返回 502）。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

_TIMEOUT = 10


def load_yaml(path: Path) -> Any:
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:
        print("[依赖缺失] 需要 PyYAML：pip install pyyaml", file=sys.stderr)
        raise SystemExit(2)
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def manifest_cases() -> dict[str, dict]:
    data = load_yaml(MANIFEST)
    return {case["id"]: case for case in data.get("cases", [])}


def build_request(
    probe: dict, case: dict
) -> tuple[str, str, dict[str, str], bytes | None, list[dict], str]:
    """把探针展开成一次真实请求。

    探针有两种写法：
      1. from: {poc: ..., request: N}  —— 复用已有 PoC 的第 N 个请求，只换档位
      2. request: {...}                —— 自带请求（例如某档还没有 PoC 时）
    """
    if "from" in probe:
        src = probe["from"]
        poc = load_yaml(ROOT / src["poc"])
        req = poc["requests"][src.get("request", 0)]
        method = str(req.get("method", "GET")).upper()
        raw_path = req["path"][0] if isinstance(req["path"], list) else req["path"]
        headers = dict(req.get("headers") or {})
        body = req.get("body")
        matchers = probe.get("matchers") or req.get("matchers") or []
        condition = probe.get("matchers_condition") or req.get("matchers-condition", "and")
    else:
        req = probe["request"]
        method = str(req.get("method", "GET")).upper()
        raw_path = req["path"][0] if isinstance(req["path"], list) else req["path"]
        headers = dict(req.get("headers") or {})
        body = req.get("body")
        matchers = probe.get("matchers") or []
        condition = probe.get("matchers_condition", "and")

    # 只替换「场景 + 档位」两段，其余路径与查询串原样保留。
    target = case["path"]
    path_only = raw_path.split("?")[0].replace("{{BaseURL}}", "")
    query = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    path_only = re.sub(
        r"/[a-z-]+/(?:low|medium|high)\.php$",
        target,
        path_only,
    )
    url = probe.get("_base", "") + path_only + (f"?{query}" if query else "")

    payload = body.encode("utf-8") if isinstance(body, str) else body
    return url, method, headers, payload, matchers, condition


def run_probe(probe: dict, case: dict, base: str) -> dict:
    probe = dict(probe)
    probe["_base"] = base
    url, method, headers, payload, matchers, condition = build_request(probe, case)
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)

    try:
        with _OPENER.open(request, timeout=_TIMEOUT) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.headers)
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", errors="replace")
        resp_headers = dict(exc.headers)
    except urllib.error.URLError as exc:
        return {
            "id": probe["id"],
            "ok": False,
            "error": f"请求失败：{exc.reason}",
            "expect": probe["expect"],
        }

    matched, detail = eval_matchers(
        matchers or [{"type": "status", "status": [200]}],
        condition,
        status,
        body,
        resp_headers,
    )

    expect = probe["expect"]
    ok = matched if expect == "match" else not matched
    return {
        "id": probe["id"],
        "case": probe["case"],
        "expect": expect,
        "observed": "match" if matched else "no_match",
        "ok": ok,
        "url": url,
        "matcher_detail": detail,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="执行真值探针")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--only", default="", help="只跑 id 前缀匹配的探针")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    probes = load_yaml(PROBE_FILE).get("probes") or []
    if not probes:
        print("[环境错误] benchmark/probes.yaml 里没有探针", file=sys.stderr)
        return 2

    cases = manifest_cases()
    results = []
    for probe in probes:
        if args.only and not probe["id"].startswith(args.only):
            continue
        case = cases.get(probe["case"])
        if not case:
            results.append(
                {"id": probe["id"], "ok": False, "error": f"清单里没有用例 {probe['case']}"}
            )
            continue
        results.append(run_probe(probe, case, args.url.rstrip("/")))

    passed = sum(1 for r in results if r.get("ok"))
    failed = [r for r in results if not r.get("ok")]

    if args.json:
        print(json.dumps({"total": len(results), "passed": passed, "results": results}, ensure_ascii=False, indent=2))
    else:
        print()
        print("=" * 78)
        print("  真值探针执行结果")
        print(f"  目标: {args.url}")
        print("=" * 78)
        for r in results:
            mark = "[ 符合 ]" if r.get("ok") else "[ 不符 ]"
            if r.get("error"):
                print(f"{mark}  {r['id']}  {r['error']}")
                continue
            print(f"{mark}  {r['id']:<24} 预期 {r['expect']:<8} 实测 {r['observed']}")
        print("-" * 78)
        print(f"结果: {passed} / {len(results)} 符合预期")
        if failed:
            print()
            print("不符合预期的用例：")
            for r in failed:
                print(f"  ✗ {r['id']}")
                for line in r.get("matcher_detail") or []:
                    print(f"      {line}")
        print("-" * 78)
        print()

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
