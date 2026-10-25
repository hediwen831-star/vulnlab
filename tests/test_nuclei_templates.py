"""Nuclei 模板的离线校验。

Nuclei 本身不在 CI 里（Windows 二进制、几十 MB），但模板是我们的资产：
id 与文件名不一致、路径写错、YAML 坏掉，都会让「Nuclei 覆盖率」悄悄归零。
这几条用例只做静态检查，不需要装 Nuclei。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "benchmark" / "nuclei" / "templates"
MANIFEST = ROOT / "benchmark" / "manifest.yaml"


def load_all() -> list[tuple[Path, dict]]:
    return [(p, yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(TEMPLATES.glob("*.yaml"))]


def target_paths(doc: dict) -> list[str]:
    """从 http 块里抽出请求路径（兼容 path 列表与 raw 首行）。"""
    paths: list[str] = []
    for item in doc.get("http") or []:
        for raw in item.get("raw") or []:
            first = raw.strip().splitlines()[0]
            m = re.match(r"[A-Z]+ (\S+) HTTP/1\.[01]", first)
            if m:
                paths.append(m.group(1))
        for path in item.get("path") or []:
            paths.append(str(path).replace("{{BaseURL}}", ""))
    return paths


def test_templates_are_valid_and_named_consistently() -> None:
    items = load_all()
    assert items, "模板目录为空"
    ids = set()
    for path, doc in items:
        assert doc.get("id") == path.stem, f"{path.name}: id 与文件名不一致（{doc.get('id')}）"
        assert doc["id"] not in ids, f"模板 id 重复：{doc['id']}"
        ids.add(doc["id"])
        assert doc.get("http"), f"{path.name}: 缺少 http 块"
        assert (doc.get("info") or {}).get("severity"), f"{path.name}: 缺少 severity"


def test_every_template_targets_a_known_positive_case() -> None:
    """模板必须打在清单里的正例路径（low/medium）上，否则命中无法归属。"""
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    positive_paths = {c["path"] for c in manifest["cases"] if c["tier"] in ("low", "medium")}
    for path, doc in load_all():
        targets = [t.split("?")[0] for t in target_paths(doc)]
        assert targets, f"{path.name}: 找不到请求路径"
        # 首个请求必须落在 low 档上；后续请求可以是证据地址（如反序列化落地文件）
        assert targets[0] in positive_paths, (
            f"{path.name}: 首个请求 {targets[0]} 不在 low/medium 正例清单里"
        )
        for extra in targets[1:]:
            assert extra.startswith("/uploads/"), (
                f"{path.name}: 多步请求的后续目标 {extra} 只能是落地文件"
            )


def test_template_count_matches_documented_scope() -> None:
    """24 个模板 = 12 个 low + 12 个 medium；数字变了要同步 README，避免文档吹牛。"""
    assert len(load_all()) == 24
