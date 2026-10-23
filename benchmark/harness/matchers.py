"""matcher 求值：Nuclei 风格的最小子集（status / word / regex）。

这是**唯一**一份求值实现：`tests/run_probes.py`、`adapters/probe.py` 都用它，
避免「探针脚本和评测脚本对同一条判据理解不一致」这种最隐蔽的偏差。
"""

from __future__ import annotations

import re

SUPPORTED = ("status", "word", "regex")


def get_part(body: str, headers: dict[str, str], part: str) -> str:
    if part == "body":
        return body
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    return body


def eval_matchers(
    matchers: list[dict],
    condition: str,
    status: int,
    body: str,
    headers: dict[str, str],
) -> tuple[bool, list[str]]:
    results: list[bool] = []
    detail: list[str] = []
    for matcher in matchers:
        mtype = matcher.get("type")
        negative = bool(matcher.get("negative"))
        if mtype == "status":
            hit = status in (matcher.get("status") or [])
            detail.append(f"status={status} in {matcher.get('status')} -> {hit}")
        elif mtype == "word":
            haystack = get_part(body, headers, matcher.get("part", "body"))
            words = matcher.get("words") or []
            sub = matcher.get("condition", "or")
            hits = [w for w in words if w in haystack]
            hit = all(w in haystack for w in words) if sub == "and" else bool(hits)
            detail.append(f"word({sub})={words} 命中 {len(hits)} 个 -> {hit}")
        elif mtype == "regex":
            haystack = get_part(body, headers, matcher.get("part", "body"))
            patterns = matcher.get("regex") or []
            sub = matcher.get("condition", "or")
            hits = [p for p in patterns if re.search(p, haystack, re.MULTILINE)]
            hit = len(hits) == len(patterns) if sub == "and" else bool(hits)
            detail.append(f"regex 命中 {len(hits)}/{len(patterns)} -> {hit}")
        else:
            raise SystemExit(f"[不支持] matcher type={mtype}（仅支持 {'/'.join(SUPPORTED)}）")

        results.append(not hit if negative else hit)

    return (all(results) if condition == "and" else any(results)), detail
