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
