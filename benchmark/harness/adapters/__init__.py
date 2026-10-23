"""评测适配器：把不同扫描器的输出统一成 findings 列表。

统一格式（每条）::

    {"url": "http://127.0.0.1:8080/sqli/low.php?id=1", "rule": "vulnlab-sqli-low-union",
     "severity": "high", "source": "asp"}

`evaluate.py` 只依赖这个格式，所以新增一个被测工具只需要加一个适配器，
不需要改指标计算。
"""

from __future__ import annotations

from . import asp, json_import, naive, probe  # noqa: F401  （供 evaluate 动态取用）

ADAPTERS = {
    "asp": asp.run,
    "naive": naive.run,
    "probe": probe.run,
    "json": json_import.run,
}
