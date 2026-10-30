#!/usr/bin/env python3
"""校验 benchmark/manifest.yaml 与源码、CI 断言、PoC 的对应关系。

评测脚本只读清单，不读靶场源码。清单一旦漂了，算出来的误报率全是错的，
而且没人会发现。所以这里把四者的对应关系做成静态检查：

  1. 13 个场景 × 3 个档位，不重不漏
  2. expected 与 tiers 声明一致
  3. path 指向的 php 文件存在
  4. ci_checks 里的断言名在 verify_lab.py 中真实存在
  5. poc 文件存在，且确实请求了这一档
  6. cause_tags 取自 cause_taxonomy
  7. 负例变体：每个 high 档恰好 4 条，带绕过手法与 expect_blocked

覆盖缺口默认只报告不判失败，加 --strict 才当硬门槛。不需要起靶场。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "benchmark" / "manifest.yaml"
PROBES = ROOT / "benchmark" / "probes.yaml"
VERIFY_LAB = ROOT / "tests" / "verify_lab.py"
HTML = ROOT / "html"

TIERS = ("low", "medium", "high")
DECOY_TIER = "decoy"
EXPECTED_BY_TIER = {
    "low": "vulnerable",
    "medium": "vulnerable",
    "high": "safe",
    DECOY_TIER: "safe",
}


def load_manifest():
    return read_yaml(MANIFEST)


def read_yaml(path: Path):
    try:
        import yaml  # noqa: PLC0415 - 延迟导入，缺依赖时给出可执行的提示
    except ModuleNotFoundError:
        print(
            "[依赖缺失] 需要 PyYAML：pip install pyyaml",
            file=sys.stderr,
        )
        raise SystemExit(2)
    with Path(path).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def lab_check_names() -> set[str]:
    """从 verify_lab.py 里抽出所有 LabCheck 的名称。

    直接解析源码而不是 import：verify_lab 是脚本不是模块，
    import 会触发 argparse 与网络请求。
    """
    src = VERIFY_LAB.read_text(encoding="utf-8")
    return set(re.findall(r'LabCheck\(\s*"([^"]+)"\s*,', src))


def scenario_dirs() -> set[str]:
    return {
        p.name
        for p in HTML.iterdir()
        if p.is_dir() and p.name not in {"data", "lib", "uploads", "internal", "decoy"}
    }


def poc_tier_paths(text: str) -> set[str]:
    return set(re.findall(r"/([a-z-]+)/(low|medium|high)\.php", text))


def main() -> int:
    parser = argparse.ArgumentParser(description="校验 benchmark/manifest.yaml")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="把覆盖缺口（缺 CI 断言 / 缺 PoC）也当作失败",
    )
    args = parser.parse_args()

    manifest = load_manifest()
    cases = manifest.get("cases") or []
    taxonomy = set(manifest.get("cause_taxonomy") or {})
    declared_tiers = manifest.get("tiers") or {}

    errors: list[str] = []
    gaps: list[str] = []
    check_names = lab_check_names()

    # 1) 档位映射自检：manifest 里的 tiers 必须与校验器内置的一致
    for tier in (*TIERS, DECOY_TIER):
        if tier not in declared_tiers:
            errors.append(f"tiers 缺少档位 {tier}")
        elif declared_tiers[tier].get("expected") != EXPECTED_BY_TIER[tier]:
            errors.append(
                f"tiers.{tier}.expected 应为 {EXPECTED_BY_TIER[tier]}，"
                f"实际 {declared_tiers[tier].get('expected')}"
            )

    # 2) 用例结构
    seen: dict[str, int] = {}
    by_scenario: dict[str, set[str]] = {}
    variants: dict[str, list[int]] = {}
    for idx, case in enumerate(cases):
        cid = case.get("id") or f"<第 {idx + 1} 条无 id>"
        seen[cid] = seen.get(cid, 0) + 1

        scenario = case.get("scenario")
        tier = case.get("tier")
        variant = case.get("variant")
        if tier not in (*TIERS, DECOY_TIER):
            errors.append(f"{cid}: tier 非法（{tier}）")
            continue
        if case.get("expected") != EXPECTED_BY_TIER[tier]:
            errors.append(
                f"{cid}: expected={case.get('expected')} 与 tier={tier} 的语义不符"
                f"（应为 {EXPECTED_BY_TIER[tier]}）"
            )

        # 路径与文件存在性
        path = case.get("path") or ""
        if tier == DECOY_TIER:
            m = re.fullmatch(r"/decoy/([a-z-]+)\.php", path)
            if not m:
                errors.append(f"{cid}: 诱饵页 path 格式异常（{path}）")
            elif not (HTML / "decoy" / f"{m.group(1)}.php").is_file():
                errors.append(f"{cid}: 诱饵页源码不存在 html/decoy/{m.group(1)}.php")
        else:
            m = re.fullmatch(r"/([a-z-]+)/(low|medium|high)\.php", path)
            if not m:
                errors.append(f"{cid}: path 格式异常（{path}）")
            else:
                if m.group(1) != scenario:
                    errors.append(f"{cid}: path 的场景段 {m.group(1)} 与 scenario {scenario} 不一致")
                if m.group(2) != tier:
                    errors.append(f"{cid}: path 的档位段 {m.group(2)} 与 tier {tier} 不一致")
                if not (HTML / m.group(1) / f"{m.group(2)}.php").is_file():
                    errors.append(f"{cid}: 源码文件不存在 html/{m.group(1)}/{m.group(2)}.php")

        if tier == DECOY_TIER:
            if not case.get("request"):
                errors.append(f"{cid}: 诱饵页缺少 request（无法重放）")
            blocked = case.get("expect_blocked") or {}
            if not (blocked.get("forbid") or blocked.get("require")):
                errors.append(f"{cid}: 诱饵页缺少 expect_blocked")
            variants.setdefault("decoy", []).append(1)
        elif variant is not None:
            if not isinstance(variant, int) or not 1 <= variant <= 4:
                errors.append(f"{cid}: variant 必须是 1..4 的整数")
            variants.setdefault(scenario, []).append(variant)

            if not case.get("request"):
                errors.append(f"{cid}: 负例变体缺少 request（无法重放）")
            blocked = case.get("expect_blocked") or {}
            if not (blocked.get("forbid") or blocked.get("require")):
                errors.append(f"{cid}: expect_blocked 至少要有一条 forbid 或 require")
            bypass = case.get("bypass") or {}
            for field in ("technique", "basis", "reference"):
                if not bypass.get(field):
                    errors.append(f"{cid}: bypass 缺少 {field}")
            if case.get("poc"):
                errors.append(f"{cid}: 负例变体不应挂 PoC")
        else:
            # 只对基础用例做探针/断言名锚定
            for name in case.get("ci_checks") or []:
                if name not in check_names:
                    errors.append(f"{cid}: CI 断言 '{name}' 在 tests/verify_lab.py 中不存在")

        by_scenario.setdefault(scenario, set()).add(tier)

        # 归因标签
        tags = case.get("cause_tags") or []
        if not tags:
            errors.append(f"{cid}: 缺少 cause_tags，误报无法归因")
        for tag in tags:
            if tag not in taxonomy:
                errors.append(f"{cid}: cause_tags 含未定义成因 '{tag}'")

        # CI 断言锚定（变体/诱饵页走 verify_negatives，单独校验）
        checks = case.get("ci_checks") or []
        if not checks:
            gaps.append(f"{cid}: 缺 CI 断言（真值无守门）")

        # PoC 锚定（正例没有 PoC 时，允许用自带请求的探针替代，见下方探针校验）
        poc = case.get("poc")
        if poc:
            poc_path = ROOT / poc
            if not poc_path.is_file():
                errors.append(f"{cid}: PoC 文件不存在 {poc}")
            else:
                text = poc_path.read_text(encoding="utf-8")
                targets = poc_tier_paths(text)
                if (scenario, tier) not in targets:
                    errors.append(
                        f"{cid}: PoC {poc} 未请求本档路径"
                        f"（实际请求：{sorted(f'{s}/{t}' for s, t in targets) or '无'}）"
                    )

    # 3) 重复 id
    for cid, count in seen.items():
        if count > 1:
            errors.append(f"id 重复：{cid} 出现 {count} 次")

    # 3.5) 探针：负例必须有「预期不命中」的探针，正例也允许有
    probe_ids: set[str] = set()
    probe_cases: set[str] = set()
    if PROBES.is_file():
        for probe in (read_yaml(PROBES).get("probes") or []):
            pid = probe.get("id")
            cid = probe.get("case")
            if not pid or not cid:
                errors.append("探针缺少 id 或 case 字段")
                continue
            if pid in probe_ids:
                errors.append(f"探针 id 重复：{pid}")
            probe_ids.add(pid)
            probe_cases.add(cid)

            case = next((c for c in cases if c.get("id") == cid), None)
            if case is None:
                errors.append(f"探针 {pid}: 引用了不存在的用例 {cid}")
                continue
            want = "match" if case.get("expected") == "vulnerable" else "no_match"
            if probe.get("expect") != want:
                errors.append(
                    f"探针 {pid}: expect={probe.get('expect')} 与用例预期冲突（应为 {want}）"
                )
            src = probe.get("from")
            if src:
                poc_path = ROOT / (src.get("poc") or "")
                if not poc_path.is_file():
                    errors.append(f"探针 {pid}: 引用的 PoC 不存在 {src.get('poc')}")
                else:
                    poc_data = read_yaml(poc_path)
                    reqs = poc_data.get("requests") or []
                    idx = src.get("request", 0)
                    if not isinstance(idx, int) or not (0 <= idx < len(reqs)):
                        errors.append(
                            f"探针 {pid}: request 下标 {idx} 超出范围（0..{len(reqs) - 1}）"
                        )
    else:
        errors.append("缺少 benchmark/probes.yaml")

    for case in cases:
        expected = case.get("expected")
        if case.get("variant") is not None or case.get("tier") == DECOY_TIER:
            continue
        if expected == "safe" and case.get("id") not in probe_cases:
            errors.append(f"{case.get('id')}: 负例缺探针，无法证明「不该被检出」")
        if expected == "vulnerable" and not (case.get("poc") or case.get("id") in probe_cases):
            errors.append(
                f"{case.get('id')}: 正例既无 PoC 也无探针，检出率无法测量"
            )
        if case.get("probe") and case["probe"] not in probe_ids:
            errors.append(f"{case.get('id')}: probe 字段指向不存在的探针 {case['probe']}")

    # 3.8) 负例变体：每个场景恰好 4 条，编号 1..4 不重复
    high_scenarios = {c.get("scenario") for c in cases if c.get("tier") == "high"}
    for name in sorted(high_scenarios):
        nums = sorted(variants.get(name, []))
        if nums != [1, 2, 3, 4]:
            errors.append(f"场景 {name} 的负例变体应为 1..4 各一条，实际 {nums}")

    # 3.85) 诱饵页：10 个页面、每页 3 条
    decoys = [c for c in cases if c.get("tier") == DECOY_TIER]
    if len(decoys) != 30:
        errors.append(f"诱饵页应为 30 条，实际 {len(decoys)}")
    pages: dict[str, int] = {}
    for c in decoys:
        key = (c.get("path") or "").split("/")[-1]
        pages[key] = pages.get(key, 0) + 1
    for name, count in sorted(pages.items()):
        if count != 3 and count != 6:  # 允许将来扩到 6 条/页
            errors.append(f"诱饵页 {name} 条数异常：{count}")

    # 3.9) 声明计数与实际一致
    declared = (manifest.get("benchmark") or {}).get("cases")
    if declared is not None and declared != len(cases):
        errors.append(f"benchmark.cases 声明 {declared}，实际 {len(cases)} 条")

    # 4) 场景覆盖：13 个目录，每个都必须有 3 档用例
    dirs = scenario_dirs()
    for name in sorted(dirs):
        tiers = by_scenario.get(name, set())
        missing = set(TIERS) - tiers
        if missing:
            errors.append(f"场景 {name} 缺少档位用例：{sorted(missing)}")
    for name in sorted(set(by_scenario) - dirs):
        if name == "decoy":
            continue  # 诱饵页不是「场景 × 三档」结构，单独校验
        errors.append(f"manifest 里的场景 {name} 在 html/ 下不存在目录")

    # 5) 统计
    total = len(cases)
    vulnerable = sum(1 for c in cases if c.get("expected") == "vulnerable")
    safe = total - vulnerable
    with_checks = sum(1 for c in cases if c.get("ci_checks"))
    with_poc = sum(1 for c in cases if c.get("poc"))

    summary = {
        "manifest": str(MANIFEST.relative_to(ROOT)),
        "scenarios": len(dirs),
        "cases": total,
        "vulnerable_cases": vulnerable,
        "safe_cases": safe,
        "with_ci_checks": with_checks,
        "with_poc": with_poc,
        "probes": len(probe_ids),
        "cases_with_probe": len(probe_cases),
        "errors": errors,
        "coverage_gaps": gaps,
    }

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print()
        print("=" * 78)
        print("  VulnLab 真值基准校验")
        print("=" * 78)
        print(f"  场景 {len(dirs)} / 用例 {total}（正例 {vulnerable}、负例 {safe}）")
        print(f"  有 CI 断言 {with_checks} / 有机读 PoC {with_poc}")
        print(f"  探针 {len(probe_ids)} 条，覆盖 {len(probe_cases)} 个用例")
        print()

        if gaps:
            print(f"  覆盖缺口 {len(gaps)} 条：")
            for gap in gaps:
                print(f"    · {gap}")
            print()

        if errors:
            print(f"  [失败] {len(errors)} 条错误：")
            for err in errors:
                print(f"    ✗ {err}")
            print()
        else:
            print("  [通过] 清单与源码、断言、PoC 的对应关系一致")
            print()

    if errors:
        return 1
    if args.strict and gaps:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
