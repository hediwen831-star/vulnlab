"""适配器 naive：只查载荷反射，作为「不做校验」的基线。

载荷打出去，响应里出现载荷中的标记串就报漏洞。low/medium 档能中，
high 档会大量误报，因为已修复页面照样把输入回填到表单和错误提示里。
纯标准库，几秒跑完。
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
