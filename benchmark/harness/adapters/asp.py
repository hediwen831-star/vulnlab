"""适配器：attack-surface（自研引擎）。

调用 `asp poc run <base> --dir <vulnlab/pocs> --json`，把命中记录转成统一 findings。

为什么用 CLI 而不是 import：
  · 评测要测的是「工具原本的行为」，走 CLI 等同于用户实际使用路径；
  · 不把被测工具的内部数据结构绑进基准，换版本时只改这一层。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def _resolve_python(explicit: str | None) -> str:
    if explicit:
        return explicit
    # 优先用当前解释器；若它缺少依赖，调用方应显式传 --asp-python
    return sys.executable


def run(
    base: str,
    *,
    poc_dir: Path,
    asp_repo: Path,
    python: str | None = None,
    timeout: int = 300,
    **_: object,
) -> dict:
    py = _resolve_python(python)
    if not asp_repo.is_dir():
        raise SystemExit(f"[asp] 仓库路径不存在：{asp_repo}")

    cmd = [
        py,
        "-m",
        "asp.cli",
        "poc",
        "run",
        base,
        "--dir",
        str(poc_dir),
        "--json",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(asp_repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )

    # 退出码约定：1 = 有命中；2 = 目标不可达；0 = 无命中。都算正常结束。
    if proc.returncode not in (0, 1, 2):
        raise SystemExit(
            f"[asp] 执行失败（exit={proc.returncode}）\n"
            f"stdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}"
        )

    text = proc.stdout.strip()
    if not text:
        raise SystemExit(
            "[asp] 没有输出。检查 asp 解释器是否装齐依赖（--asp-python 指向项目 venv）。\n"
            f"stderr:\n{proc.stderr[-1000:]}"
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # CLI 可能把日志混进 stdout：取最后一个 JSON 对象
        start = text.find("{")
        data = json.loads(text[start:])

    findings = [
        {
            "url": vuln.get("target", ""),
            "rule": vuln.get("poc_id", ""),
            "severity": vuln.get("severity", ""),
            "source": "asp",
            "verified": vuln.get("verified", False),
        }
        for vuln in data.get("vulns", [])
    ]

    return {
        "tool": "asp",
        "reachable": data.get("target_reachable", True),
        "poc_count": data.get("poc_count", 0),
        "findings": findings,
        "meta": {
            "python": py,
            "repo": str(asp_repo),
            "exit_code": proc.returncode,
        },
    }


def available(asp_repo: Path) -> bool:
    return (asp_repo / "asp" / "cli.py").is_file() and shutil.which("python") is not None
