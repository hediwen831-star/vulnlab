"""适配器：naive marker（基线，不是真实工具）。

**它的存在是为了量化「不做任何校验会发生什么」。**

规则只有一条：把载荷打出去，只要响应里出现载荷中的标记串（`VULNLAB_*` /
通关凭证），就报漏洞。这正是大量快速脚本、以及不少商业扫描器的早期版本
在做的事 —— 判据停留在「输入反射」这一层。

预期表现（也是本基线要证明的命题）：
  · 在 low / medium 档上检出率不低（载荷确实会回显）；
  · 在 high 档上**大量误报** —— 因为已修复页面照样会把输入回填到表单/错误提示里。

它不联网、不依赖外部工具，纯标准库实现，跑一次几秒钟。
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from pathlib import Path

from ..loader import build_case_request, load_manifest, load_probes

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_TIMEOUT = 10

#: 载荷里可能出现的标记串。只认这些，避免把普通回显当成证据。
MARKER_RE = re.compile(r"VULNLAB(?:_[A-Z]+)*\{?[A-Za-z0-9_{}]*")


def _send(url: str, method: str, headers: dict, body: bytes | None) -> str:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with OPENER.open(request, timeout=_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def run(base: str, *, root: Path, **_: object) -> dict:
    manifest = load_manifest(root)
    probes = {p["case"]: p for p in load_probes(root)}
    cases = manifest["cases"]

    findings = []
    for case in cases:
        probe = probes.get(case["id"])
        req = build_case_request(root, case, probe=probe, base=base)
        if req is None:
            continue
        body = _send(req["url"], req["method"], req["headers"], req["payload"])

        # 标记来自载荷本身；响应里出现即判「漏洞」
        haystack = req["url"] + (req["payload"].decode("utf-8", "replace") if req["payload"] else "")
        markers = {m for m in MARKER_RE.findall(haystack) if m}
        hit = [m for m in markers if m in body]
        if hit:
            findings.append(
                {
                    "url": req["url"],
                    "rule": f"naive-marker:{case['id']}",
                    "severity": "high",
                    "source": "naive",
                    "verified": False,
                }
            )

    return {"tool": "naive", "reachable": True, "poc_count": len(cases), "findings": findings, "meta": {}}
