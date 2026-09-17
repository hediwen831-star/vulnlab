#!/usr/bin/env python3
"""VulnLab 回归验证脚本。

**它解决的问题**：靶场里的「已修复」档位（`high.php`）是一种资产 ——
它的价值在于「打不动」。但如果后来有人改代码时不小心把参数化查询改回拼接，
这个资产就悄悄失效了，而没有人会发现。

这个脚本把「哪些档位应该能打通、哪些应该打不通」变成**可执行的断言**，
挂到 CI 上。任何一次改动只要破坏了预期行为，CI 立刻变红。

换句话说：**它守护的不是功能，是安全属性。**

用法：
    python tests/verify_lab.py                          # 默认 127.0.0.1:8080
    python tests/verify_lab.py --url http://lab:8080
    python tests/verify_lab.py --json

退出码：
    0  全部断言通过
    1  有断言失败（CI 会红）
    2  靶场不可达（环境问题，不是代码问题）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

TIMEOUT = 10

#: 通关凭证的正则。只有真正注入成功才能读到。
SECRET_PATTERN = re.compile(r"VULNLAB\{[^}]+\}")


# --------------------------------------------------------------------- HTTP


def http_get(url: str, timeout: float = TIMEOUT) -> tuple[int, str]:
    """发 GET 请求，返回 (状态码, 正文)。连接失败返回 (0, 错误信息)。"""
    request = urllib.request.Request(
        url, headers={"User-Agent": "VulnLab-CI/1.0 (regression-check)"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"__CONNECTION_ERROR__: {exc}"


def build_url(base: str, path: str, params: dict[str, str]) -> str:
    """构造带查询参数的 URL。"""
    query = urllib.parse.urlencode(params)
    return f"{base.rstrip('/')}{path}?{query}"


# ------------------------------------------------------------------- 断言


@dataclass
class CheckResult:
    """单条断言的执行结果。"""

    name: str
    passed: bool
    expectation: str
    detail: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "expectation": self.expectation,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class LabCheck:
    """一条检查项的完整定义。"""

    name: str
    expectation: str
    run: Callable[[str], tuple[bool, str, str]]
    """返回 (是否通过, 说明, 证据)。"""


# ------------------------------------------------------------ 各档位断言


def check_low_union_injectable(base: str) -> tuple[bool, str, str]:
    """low 档：数字型 UNION 注入应该能读到 secret。"""
    payload = "-1 UNION SELECT 1,username,secret,role FROM users"
    status, body = http_get(build_url(base, "/sqli/low.php", {"id": payload}))

    if status != 200:
        return False, f"HTTP {status}，期望 200", ""

    match = SECRET_PATTERN.search(body)
    if match:
        return True, "UNION 注入成功并读取到 secret", match.group(0)
    return False, "未读到 secret —— 注入可能被意外阻断", ""


def check_low_column_count(base: str) -> tuple[bool, str, str]:
    """low 档：原查询应仍是 4 列。

    列数是注入的前提（UNION 两侧必须一致）。如果有人改了 SELECT 的列，
    所有现成 payload 会失效，而这是很容易被忽略的破坏性改动。
    """
    marker = "CI_COLMARK_4"
    payload = f"-1 UNION SELECT '{marker}','{marker}','{marker}','{marker}'"
    status, body = http_get(build_url(base, "/sqli/low.php", {"id": payload}))

    if status == 200 and marker in body and "数据库错误" not in body:
        return True, "确认原查询为 4 列", marker
    return False, "4 列 UNION 未能成功 —— 查询列数可能已变更", ""


def check_medium_raw_payload_blocked(base: str) -> tuple[bool, str, str]:
    """medium 档：直接照抄 low 档的 payload 应该【打不通】。

    这条断言守护的是「过滤确实在生效」。如果哪天黑名单被删掉，
    这个断言会失败 —— 提醒我们 medium 档的难度设计已经名存实亡。
    """
    payload = "1' union select 1,username,secret,role from users-- "
    status, body = http_get(build_url(base, "/sqli/medium.php", {"id": payload}))

    if SECRET_PATTERN.search(body):
        return False, "裸 payload 竟然成功了 —— 黑名单过滤可能已失效", ""

    blocked = ("数据库错误" in body) or ("过滤器检测到敏感关键字" in body)
    if blocked:
        return True, "裸 payload 被过滤阻断（符合预期）", "过滤器生效"
    return False, f"未观察到过滤阻断迹象（HTTP {status}）", ""


def check_medium_bypass_works(base: str) -> tuple[bool, str, str]:
    """medium 档：双写绕过（ununionion / seselectlect / frfromom）应该能读到 secret。"""
    payload = "1' ununionion seselectlect 1,username,secret,role frfromom users-- "
    status, body = http_get(build_url(base, "/sqli/medium.php", {"id": payload}))

    if status != 200:
        return False, f"HTTP {status}，期望 200", ""

    match = SECRET_PATTERN.search(body)
    if match:
        return True, "双写绕过后成功读取 secret", match.group(0)
    return False, "双写绕过失败 —— 过滤实现可能已变更（例如换成递归替换）", ""


def check_high_rejects_injection(base: str) -> tuple[bool, str, str]:
    """high 档：注入 payload 应被类型校验拒绝，且【绝不能】读到 secret。

    ⚠️ 这是整个 CI 里最重要的一条。它守护的是「修复没有被回退」。
    """
    payload = "-1 UNION SELECT 1,username,secret,role FROM users"
    status, body = http_get(build_url(base, "/sqli/high.php", {"id": payload}))

    if SECRET_PATTERN.search(body):
        return False, "★ 严重：high 档被注入成功 —— 修复已失效！", ""

    rejected = ("输入被拒绝" in body) or ("必须是纯数字" in body)
    if rejected:
        return True, "注入被类型校验拒绝，未到达数据库", "类型校验生效"
    return False, "未观察到明确的拒绝提示 —— 校验逻辑可能被改动", ""


def check_high_normal_query_still_works(base: str) -> tuple[bool, str, str]:
    """high 档：正常查询（id=1）必须仍然可用。

    这条是**反向保护**：防止有人为了「修得更安全」而把功能改坏。
    安全修复不该以牺牲功能为代价 —— 这是常见的过度修复。
    """
    status, body = http_get(build_url(base, "/sqli/high.php", {"id": "1"}))

    if status != 200:
        return False, f"HTTP {status}，期望 200", ""
    if "admin" in body:
        return True, "正常查询返回 admin，功能完好", "admin"
    return False, "正常查询未返回预期数据 —— 修复可能过度，破坏了功能", ""


def check_no_error_dump_in_high(base: str) -> tuple[bool, str, str]:
    """high 档：不应回显数据库错误信息。

    错误信息会泄漏表名/列名/数据库版本，是攻击者构造 payload 的重要依据。
    """
    payload = "1'"
    status, body = http_get(build_url(base, "/sqli/high.php", {"id": payload}))

    leaked = re.search(r"SQLSTATE\[|syntax error|unrecognized token", body, re.I)
    if leaked:
        return False, "high 档回显了数据库错误 —— 错误信息收敛已失效", leaked.group(0)
    return True, "未回显数据库错误信息", ""


def check_low_error_visible_by_design(base: str) -> tuple[bool, str, str]:
    """low 档：**应该**回显数据库错误（这是刻意保留的教学信息）。

    同样属于「守护设计意图」：如果有人「顺手」把 low 档的报错也关掉了，
    报错型注入的教学价值就没了，但功能测试不会发现。
    """
    payload = "1'"
    status, body = http_get(build_url(base, "/sqli/low.php", {"id": payload}))

    if re.search(r"SQLSTATE\[|syntax error|unrecognized token|数据库错误", body, re.I):
        return True, "low 档按设计回显数据库错误", "报错可见"
    return False, "low 档未回显数据库错误 —— 报错型注入的教学场景可能已被破坏", ""


CHECKS: list[LabCheck] = [
    LabCheck("low 档 · UNION 注入可读到 secret", "应成功", check_low_union_injectable),
    LabCheck("low 档 · 原查询为 4 列", "应成功", check_low_column_count),
    LabCheck("low 档 · 按设计回显数据库错误", "应回显", check_low_error_visible_by_design),
    LabCheck("medium 档 · 裸 payload 被阻断", "应阻断", check_medium_raw_payload_blocked),
    LabCheck("medium 档 · 双写绕过可利用", "应成功", check_medium_bypass_works),
    LabCheck("high 档 · 注入被拒绝", "应拒绝", check_high_rejects_injection),
    LabCheck("high 档 · 不回显数据库错误", "应不回显", check_no_error_dump_in_high),
    LabCheck("high 档 · 正常查询仍可用", "应可用", check_high_normal_query_still_works),
]


# ------------------------------------------------------------------ 主流程


def find_secret(base: str) -> str:
    """从任意档位尝试取一个 secret，用于确认靶场数据已初始化。"""
    payload = "-1 UNION SELECT 1,username,secret,role FROM users"
    _, body = http_get(build_url(base, "/sqli/low.php", {"id": payload}))
    match = SECRET_PATTERN.search(body)
    return match.group(0) if match else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VulnLab 回归验证 —— 断言各档位的安全属性未被破坏"
    )
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="靶场地址")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args(argv)

    base = args.url.rstrip("/")

    # 先探活。环境问题要和代码问题区分开 —— 否则 CI 红了却找不到原因。
    status, _ = http_get(f"{base}/index.php")
    if status == 0:
        print(f"[环境错误] 无法连接 {base}", file=sys.stderr)
        print("           请先启动靶场：./start.sh 或 php -S 127.0.0.1:8080 -t html", file=sys.stderr)
        return 2
    if status != 200:
        print(f"[环境错误] {base}/index.php 返回 HTTP {status}", file=sys.stderr)
        return 2

    results: list[CheckResult] = []
    for check in CHECKS:
        try:
            passed, detail, evidence = check.run(base)
        except Exception as exc:  # noqa: BLE001 - 单条检查异常不该中断整体
            passed, detail, evidence = False, f"检查执行异常: {exc}", ""
        results.append(
            CheckResult(
                name=check.name,
                passed=passed,
                expectation=check.expectation,
                detail=detail,
                evidence=evidence,
            )
        )

    passed_count = sum(1 for r in results if r.passed)
    failed = [r for r in results if not r.passed]

    if args.json:
        print(
            json.dumps(
                {
                    "target": base,
                    "total": len(results),
                    "passed": passed_count,
                    "failed": len(failed),
                    "checks": [r.to_dict() for r in results],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print()
        print("=" * 78)
        print("  VulnLab 回归验证")
        print(f"  目标: {base}")
        print("=" * 78)
        print()

        for result in results:
            mark = "[ 通过 ]" if result.passed else "[ 失败 ]"
            print(f"{mark}  {result.name}")
            print(f"          预期: {result.expectation}")
            print(f"          实际: {result.detail}")
            if result.evidence:
                print(f"          证据: {result.evidence}")
            print()

        print("-" * 78)
        print(f"结果: {passed_count} / {len(results)} 通过")
        if failed:
            print()
            print("失败的断言:")
            for result in failed:
                print(f"  ✗ {result.name}")
                print(f"    {result.detail}")
        print("-" * 78)
        print()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
