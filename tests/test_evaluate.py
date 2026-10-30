"""评测归属逻辑的测试（离线）。

同一个 high 页现在挂着 5 条用例（基础 + 4 条绕过尝试）。只按路径归属会把
它们混成一条，误报要么算错地方、要么被吞掉。这三个用例守的就是这条链路。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.harness.evaluate import _resolve_case, evaluate  # noqa: E402
from benchmark.harness.loader import load_manifest  # noqa: E402


def by_maps():
    manifest = load_manifest(ROOT)
    by_id = {c["id"]: c for c in manifest["cases"]}
    by_path: dict[str, list[dict]] = {}
    for case in manifest["cases"]:
        by_path.setdefault(case["path"], []).append(case)
    return manifest, by_id, by_path


def test_rule_case_id_wins_when_path_is_shared() -> None:
    """naive 用 naive-marker:<case-id> 报命中，必须落到那一条变体上。"""
    _, by_id, by_path = by_maps()
    finding = {
        "url": "http://x/sqli/high.php?id=-1+UNION+SELECT+1",
        "rule": "naive-marker:sqli-high-bypass-1",
    }
    case = _resolve_case(finding, by_id, by_path)
    assert case["id"] == "sqli-high-bypass-1"


def test_query_matches_variant_when_rule_has_no_id() -> None:
    """第三方工具的规则名不带 case id 时，用查询参数区分变体。"""
    _, by_id, by_path = by_maps()
    finding = {
        "url": "http://x/sqli/high.php?id=1+OR+1%3D1",
        "rule": "custom-rule",
    }
    case = _resolve_case(finding, by_id, by_path)
    assert case["id"] == "sqli-high-bypass-2"


def test_path_only_falls_back_to_base_case() -> None:
    """只拿到路径时归到基础负例，不能把误报摊到四条变体上重复计数。"""
    _, by_id, by_path = by_maps()
    finding = {"url": "http://x/sqli/high.php", "rule": "some-scanner"}
    case = _resolve_case(finding, by_id, by_path)
    assert case["id"] == "sqli-high"


def test_poc_attribution_for_off_manifest_path() -> None:
    """upload 的 PoC 第二步会访问 /uploads/xxx，路径不在清单里，按 PoC 归属。"""
    _, by_id, by_path = by_maps()
    finding = {
        "url": "http://x/uploads/evil.php",
        "rule": "vulnlab-upload-unrestricted",
    }
    case = _resolve_case(finding, by_id, by_path)
    assert case is not None and case["id"] == "upload-low"


def test_fpr_denominator_is_all_negative_cases() -> None:
    """FPR 分母是全部 95 条负例（13 基础 + 52 变体 + 30 诱饵页），不是 13。"""
    manifest, _, _ = by_maps()
    result = evaluate([], manifest, "http://x")
    assert result["totals"]["vulnerable"] == 26
    assert result["totals"]["safe"] == 95
    assert result["totals"]["FPR"] == 0.0


def test_false_alarm_on_variant_counts_once() -> None:
    """同一条变体被报多次，只算一条误报。"""
    manifest, _, _ = by_maps()
    finding = {
        "url": "http://x/sqli/high.php?id=1+OR+1%3D1",
        "rule": "naive-marker:sqli-high-bypass-2",
        "severity": "high",
    }
    result = evaluate([finding, dict(finding)], manifest, "http://x")
    assert result["totals"]["FP"] == 1
    assert result["cases"]["FP"] == ["sqli-high-bypass-2"]


def test_denoise_uses_same_attribution() -> None:
    """降噪阶段必须和评测阶段归到同一条用例，否则剔除数会对不上。"""
    from benchmark.harness.denoise import map_findings_to_cases

    manifest, _, _ = by_maps()
    finding = {
        "url": "http://x/cmdi/high.php?ip=127.0.0.1+%60echo+VULNLAB_CMDI_MARKER%60",
        "rule": "naive-marker:cmdi-high-bypass-3",
    }
    pairs = map_findings_to_cases([finding], manifest)
    assert len(pairs) == 1
    assert pairs[0][1]["id"] == "cmdi-high-bypass-3"
