"""适配器：generic JSON（接入任意第三方扫描器的导出结果）。

用途：Nuclei / Xray / ZAP / AWVS 等工具的输出格式各不相同，但都能导出成
「一条命中 = 一个 URL（+ 规则名）」。只要转成下面两种形状之一，就能用本适配器评测：

形状 A（推荐，最简）::

    [
      {"url": "http://127.0.0.1:8080/sqli/low.php", "rule": "sqli-union", "severity": "high"},
      ...
    ]

形状 B（Nuclei `-jsonl` 原样，逐行一个对象）::

    {"template-id": "...", "matched-at": "http://...", "info": {"severity": "high"}}

也接受 `{"target": ...}` / `{"host": ...}` 作为 URL 字段。

命令行：``--scanner json --findings path/to/result.json``
"""

from __future__ import annotations

import json
from pathlib import Path


def _normalize(item: dict, source: str) -> dict:
    url = item.get("url") or item.get("matched-at") or item.get("target") or item.get("host") or ""
    rule = (
        item.get("rule")
        or item.get("template-id")
        or item.get("templateID")
        or item.get("name")
        or item.get("plugin")
        or ""
    )
    severity = item.get("severity") or (item.get("info") or {}).get("severity") or ""
    return {"url": url, "rule": rule, "severity": severity, "source": source, "verified": False}


def run(base: str, *, findings: Path, **_: object) -> dict:
    path = Path(findings)
    if not path.is_file():
        raise SystemExit(f"[json] 找不到结果文件：{path}")

    text = path.read_text(encoding="utf-8", errors="replace").strip()
    items: list[dict] = []

    # 先按「整个文件是一个 JSON」解析；失败则按 JSONL 逐行解析。
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("findings") or data.get("vulns") or data.get("results") or []
        items = [x for x in data if isinstance(x, dict)]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                items.append(obj)

    findings_out = [_normalize(item, "json") for item in items]
    findings_out = [f for f in findings_out if f["url"]]
    return {
        "tool": "json",
        "reachable": True,
        "poc_count": len(findings_out),
        "findings": findings_out,
        "meta": {"source_file": str(path)},
    }
