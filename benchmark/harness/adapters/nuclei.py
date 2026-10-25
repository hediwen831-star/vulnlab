"""适配器 nuclei：调用 ProjectDiscovery Nuclei，读它的 JSONL 输出。

和 asp / naive 不同，这里不自己发请求，而是把整个靶站交给外部引擎：

    nuclei -u <base> -t benchmark/nuclei/templates -jsonl -o <tmp>

模板是我们自己写的（13 个，对应 13 个 low 档），原因见
`benchmark/nuclei/README.md`：Nuclei 的官方模板库不覆盖这个靶场的路径，
直接跑官方模板只会得到 0 命中，那不叫「Nuclei 的检出率」，叫「模板没写」。

`-ni`（no-stdin）是必须的：不加时 Nuclei 会等 stdin 输入目标，
在脚本里表现为「打完 banner 就没动静」，超时后什么也拿不到。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TEMPLATES = ROOT / "benchmark" / "nuclei" / "templates"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

#: 候选二进制位置：环境变量优先，其次 PATH，最后是本机工具目录
CANDIDATES = [
    os.environ.get("NUCLEI_BIN", ""),
    "nuclei",
    str(Path.home() / "WorkBuddy" / "tools" / "nuclei.exe"),
    r"C:\Users\hediwen\WorkBuddy\2026-10-23-17-17-16\tools\nuclei.exe",
]


def _binary() -> str | None:
    for candidate in CANDIDATES:
        if not candidate:
            continue
        found = shutil.which(candidate)
        if found:
            return found
        if Path(candidate).is_file():
            return candidate
    return None


def _reachable(base: str) -> bool:
    try:
        with OPENER.open(f"{base.rstrip('/')}/index.php", timeout=10) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def run(base: str, **_: object) -> dict:
    binary = _binary()
    if binary is None:
        return {
            "tool": "nuclei",
            "reachable": _reachable(base),
            "findings": [],
            "meta": {"error": "nuclei 未安装：设置 NUCLEI_BIN 或把 nuclei 放进 PATH"},
        }
    if not _reachable(base):
        return {"tool": "nuclei", "reachable": False, "findings": [], "meta": {}}

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "nuclei.jsonl"
        cmd = [
            binary,
            "-u", base,
            "-t", str(TEMPLATES),
            "-jsonl",
            "-o", str(out),
            "-silent",
            "-nc",              # 无颜色
            "-duc",             # 不检查更新（离线环境）
            "-ni",              # 不读 stdin
            "-rate-limit", "50",
            "-timeout", "10",
            "-retries", "1",
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL
        )
        if not out.is_file():
            return {
                "tool": "nuclei",
                "reachable": True,
                "findings": [],
                "meta": {
                    "error": "nuclei 未产出结果文件",
                    "stderr": (proc.stderr or "")[-500:],
                },
            }
        findings = []
        for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info") or {}
            findings.append(
                {
                    "url": item.get("matched-at") or item.get("host") or "",
                    "rule": item.get("template-id") or "",
                    "severity": info.get("severity") or "info",
                    "source": "nuclei",
                    "verified": False,
                }
            )

    return {
        "tool": "nuclei",
        "reachable": True,
        # Nuclei 是站点级扫描：是否「尝试」某个用例取决于模板是否覆盖，
        # 这里没有可靠的逐用例计数，交给报告说明覆盖范围。
        "attempted_cases": None,
        "findings": findings,
        "meta": {"templates": len(list(TEMPLATES.glob("*.yaml")))},
    }
