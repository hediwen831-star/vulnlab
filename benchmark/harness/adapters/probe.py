"""适配器 probe：用例自带的判据，作为检测能力上限。

不是真实工具。判据与真值一致时应当 TPR 100%、FPR 0%，用来验证评测链路
本身；任何偏离都说明清单、判据或映射有问题。high 档没有 PoC，用的是
探针里收紧过的判据（例如 sqli 锚定到结果单元格）。
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

from ..loader import build_case_request, load_manifest, load_probes, _yaml
from ..matchers import eval_matchers

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_TIMEOUT = 10


def _request_matchers(root: Path, case: dict, probe: dict | None) -> tuple[list[dict], str]:
    if probe:
        if probe.get("matchers"):
            return probe["matchers"], probe.get("matchers_condition", "and")
        if "from" in probe:
            poc = _yaml().safe_load((root / probe["from"]["poc"]).read_text(encoding="utf-8"))
            req = poc["requests"][probe["from"].get("request", 0)]
            return req.get("matchers") or [], req.get("matchers-condition", "and")
        return probe.get("matchers") or [], probe.get("matchers_condition", "and")

    if case.get("poc"):
        poc = _yaml().safe_load((root / case["poc"]).read_text(encoding="utf-8"))
        reqs = poc.get("requests") or []
        chosen = None
        for req in reqs:
            paths = req.get("path")
            candidates = paths if isinstance(paths, list) else [paths]
            if any(case["path"] in (p or "") for p in candidates):
                chosen = req
                break
        # 没有正好打在本档的请求时，退回第一条：
        # 载荷相同、只换档位，判据可以复用（这正是探针的做法）。
        chosen = chosen or (reqs[0] if reqs else None)
        if chosen:
            return chosen.get("matchers") or [], chosen.get("matchers-condition", "and")
    return [], "and"


def _send(url: str, method: str, headers: dict, body: bytes | None) -> tuple[int, str, dict]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with OPENER.open(request, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, "", {}


def run(base: str, *, root: Path, **_: object) -> dict:
    manifest = load_manifest(root)
    probes = {p["case"]: p for p in load_probes(root)}

    findings = []
    for case in manifest["cases"]:
        probe = probes.get(case["id"])
        req = build_case_request(root, case, probe=probe, base=base)
        if req is None:
            continue
        matchers, condition = _request_matchers(root, case, probe)
        if not matchers:
            continue

        status, body, headers = _send(req["url"], req["method"], req["headers"], req["payload"])
        matched, _ = eval_matchers(matchers, condition, status, body, headers)
        if matched:
            findings.append(
                {
                    "url": req["url"],
                    "rule": f"probe:{case['id']}",
                    "severity": "high",
                    "source": "probe",
                    "verified": True,
                }
            )

    return {"tool": "probe", "reachable": True, "poc_count": len(manifest["cases"]), "findings": findings, "meta": {}}
