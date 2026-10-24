"""为一条命中构造研判证据：重新请求一次，截取命中标记附近的上下文。

为什么要重放而不是用扫描时缓存的响应：评测框架拿到的是扫描器的输出
（URL + 规则名），不包含响应体。要让 LLM 判断"这条命中是不是误报"，
必须给它看页面内容。重放一次最省事，也不会被扫描器的内部结构绑住。

**URL 会把档位（low/medium/high）暴露给模型**，而档位直接等于答案：
high 就是修好的。所以送进模型前要把档位段抹掉，规则名同理。
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_TIMEOUT = 10
SNIPPET = 400

_TIER = re.compile(r"/(low|medium|high)\.php")
#: 页面标题里也写着「难度 low」，同样是答案泄漏，一并抹掉。
_TIER_WORD = re.compile(r"(low|medium|high)")
_MARKER = re.compile(r"VULNLAB[A-Za-z0-9_{}]*")


def mask_tier(text: str) -> str:
    """把 URL、规则名、页面文案里的档位抹掉，避免把答案泄漏给模型。"""
    text = _TIER.sub("/target.php", text)
    text = text.replace("（已修复）", "").replace("(已修复)", "")
    return _TIER_WORD.sub("tier", text)


def _fetch(url: str, method: str = "GET", payload: bytes | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, data=payload, method=method)
    try:
        with OPENER.open(request, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, ""


_RESULT_HINTS = ("命令输出", "查询结果", "渲染结果", "订单号", "已修改", "写入成功", "响应体")
_REFLECTION_HINTS = ("你的输入", "拼接结果", "过滤后", "placeholder")


def _score(window: str, index: int, body: str) -> int:
    """给一处出现打分：结果区加分，回显/说明减分。"""
    score = 0
    for hint in _RESULT_HINTS:
        if hint in window:
            score += 3
    for hint in _REFLECTION_HINTS:
        if hint in window:
            score -= 2
    if "<pre" in window or "<td" in window:
        score += 1

    before = body[max(0, index - 120) : index]
    # 位于输入框的 value 属性里：几乎一定是回填
    if before.rfind('value="') > before.rfind(">"):
        score -= 4
    # 整段都在 <form> 里：说明是表单区，不是结果区
    if before.rfind("<form") > before.rfind("</form"):
        score -= 3
    return score


def _marker(name: str, body: str = "") -> str:
    """从 URL / 规则名里挑出真正的载荷标记。

    注意不能直接用 "VULNLAB"：站点的 <title> 里就写着 VulnLab，
    从那里截上下文只会拿到 <head> 和一堆 CSS，等于没给证据。
    """
    tokens = sorted(_MARKER.findall(name), key=len, reverse=True)
    for token in tokens:
        if token in body and len(token) > 6:
            return token
    # POST 场景 payload 不在 URL 里，只能从正文反查。
    # 排除裸 "VULNLAB"：标题里就有这个词。
    body_tokens = sorted(
        {tok for tok in _MARKER.findall(body) if len(tok) > 10}, key=len, reverse=True
    )
    return body_tokens[0] if body_tokens else ""


def build_evidence(
    url: str,
    rule: str,
    marker_hint: str = "",
    *,
    method: str = "GET",
    payload: bytes | None = None,
) -> str:
    """抓一次页面，返回给模型看的证据文本。

    截取策略：优先取命中标记前后各 SNIPPET 字符，标记不在页面里就取开头。
    这样模型能看到"标记出现在什么位置"——输入框回填和查询结果行的区别，
    正是判定反射型误报的关键。
    """
    status, body = _fetch(url, method, payload)
    if status == 0 and not body:
        return f"重放请求失败（连接未建立）\nURL: {mask_tier(url)}\n规则: {mask_tier(rule)}"

    title = ""
    match = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()

    marker = _marker(f"{url} {rule}", body) or marker_hint
    occurrences = []
    if marker:
        start_at = 0
        while len(occurrences) < 8:
            idx = body.find(marker, start_at)
            if idx < 0:
                break
            occurrences.append(idx)
            start_at = idx + len(marker)

    if occurrences:
        # 标记在页面里会出现多次：表单回填、拼接结果展示、真正的输出。
        # 只按顺序取前三处，往往全是回显；这里按「像不像结果区」打分排序。
        scored = []
        for idx in occurrences:
            lo = max(0, idx - SNIPPET // 2)
            window = body[lo : idx + SNIPPET // 2]
            scored.append((_score(window, idx, body), idx, window))
        scored.sort(key=lambda item: item[0], reverse=True)

        # 同一段 <pre> 里的多次出现会给出几乎相同的窗口，去重后再取。
        picked = []
        for item in scored:
            if any(abs(item[1] - chosen[1]) < SNIPPET // 2 for chosen in picked):
                continue
            picked.append(item)
            if len(picked) == 2:
                break
        picked.sort(key=lambda item: item[1])
        snippet = " … ".join(
            f"[第 {order} 处] {window}" for order, (_, _, window) in enumerate(picked, 1)
        )
    else:
        snippet = body[: SNIPPET]

    snippet = re.sub(r"\s+", " ", snippet).strip()
    return (
        f"HTTP {status}\nURL: {mask_tier(url)}\n规则: {mask_tier(rule)}\n"
        f"页面标题: {mask_tier(title) or '(无)'}\n响应片段: {mask_tier(snippet)}"
    )
