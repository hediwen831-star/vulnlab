"""基准数据的读取与请求构造（供适配器与评测脚本共用）。"""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any


def _yaml():
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:
        raise SystemExit("[依赖缺失] 需要 PyYAML：pip install pyyaml")
    return yaml


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "benchmark" / "manifest.yaml"
    return _yaml().safe_load(path.read_text(encoding="utf-8"))


def load_probes(root: Path) -> list[dict[str, Any]]:
    path = root / "benchmark" / "probes.yaml"
    if not path.is_file():
        return []
    return _yaml().safe_load(path.read_text(encoding="utf-8")).get("probes") or []


def _read_poc(root: Path, rel: str) -> dict[str, Any]:
    return _yaml().safe_load((root / rel).read_text(encoding="utf-8"))


def _rewrite_path(raw: str, case_path: str) -> tuple[str, str]:
    path_only = raw.split("?")[0].replace("{{BaseURL}}", "")
    query = raw.split("?", 1)[1] if "?" in raw else ""
    path_only = re.sub(r"/[a-z-]+/(?:low|medium|high)\.php$", case_path, path_only)
    return path_only, query


def build_case_request(
    root: Path,
    case: dict[str, Any],
    *,
    probe: dict[str, Any] | None,
    base: str,
) -> dict[str, Any] | None:
    """为某个用例构造一次请求。

    优先级：用例自带的 request（负例变体） > 探针 > 探针引用 PoC > 用例 PoC。
    变体把请求直接写在 manifest 里，不依赖 PoC 文件，这样 52 条绕过尝试
    才能被任意适配器重放。
    """
    if case.get("request"):
        return _build_from_case(base, case)

    req: dict[str, Any] | None = None
    if probe:
        if "from" in probe:
            poc = _read_poc(root, probe["from"]["poc"])
            reqs = poc.get("requests") or []
            idx = probe["from"].get("request", 0)
            if 0 <= idx < len(reqs):
                req = reqs[idx]
        else:
            req = probe.get("request")

    if req is None and case.get("poc"):
        poc = _read_poc(root, case["poc"])
        reqs = poc.get("requests") or []
        # 选第一个打在本档路径上的请求；没有就退回第一个
        chosen = None
        for item in reqs:
            paths = item.get("path")
            first = paths[0] if isinstance(paths, list) else paths
            if case["path"] in first:
                chosen = item
                break
        req = chosen or (reqs[0] if reqs else None)

    if req is None:
        return None

    paths = req.get("path")
    raw = paths[0] if isinstance(paths, list) else paths
    path_only, query = _rewrite_path(raw, case["path"])
    url = base.rstrip("/") + path_only + (f"?{query}" if query else "")

    body = req.get("body")
    return {
        "url": url,
        "method": str(req.get("method", "GET")).upper(),
        "headers": dict(req.get("headers") or {}),
        "payload": body.encode("utf-8") if isinstance(body, str) else body,
    }


def _build_from_case(base: str, case: dict[str, Any]) -> dict[str, Any]:
    """按用例自带的 request 描述构造请求。"""
    import uuid
    from urllib.parse import urlencode

    spec = case["request"]
    url = base.rstrip("/") + case["path"]
    method = str(case.get("method", "GET")).upper()
    headers: dict[str, str] = {}
    payload: bytes | None = None

    cookies = spec.get("cookies") or {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    if "multipart" in spec:
        boundary = "----vulnlab" + uuid.uuid4().hex
        item = spec["multipart"]["file"]
        payload = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{item["filename"]}"\r\n'
            f'Content-Type: {item["content_type"]}\r\n\r\n'
            f"{item['content']}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif "form" in spec:
        payload = urlencode(spec["form"]).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif "query" in spec:
        url += "?" + urlencode(spec["query"])

    return {"url": url, "method": method, "headers": headers, "payload": payload}


def normalize_path(url: str) -> str:
    """把一个 URL 归一成用于匹配清单的路径（去掉 scheme/host/query/尾斜杠）。"""
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path
