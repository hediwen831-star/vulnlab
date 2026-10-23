#!/usr/bin/env python3
"""VulnLab 真值基准清单校验器（静态检查，不需要起靶场）。

**它解决的问题**：`benchmark/manifest.yaml` 是误报量化的「标准答案」。
一旦清单与实际代码脱节（某个场景删了档位、改了路径、PoC 指向别的档位），
后续所有误报率数字都会失真，而且**不会有人察觉** —— 因为评测脚本
只读清单，不读靶场源码。

所以这里把「清单 ↔ 靶场源码 ↔ CI 断言 ↔ 机读 PoC」四者的对应关系
变成可执行检查，挂进 CI。

检查项：
  1. 结构：13 个场景 × 3 个档位，无重复、无遗漏
  2. 一致性：expected 必须等于 tiers 里该档位的声明
  3. 存在性：path 指向的 php 文件真实存在
  4. 断言锚定：每条 ci_checks 都能在 tests/verify_lab.py 里找到同名 LabCheck
  5. PoC 锚定：poc 字段指向的文件存在，且该 PoC 确实请求了这一档的路径
  6. 归因标签：cause_tags 取自 cause_taxonomy

覆盖缺口（某档缺 CI 断言或机读 PoC）默认只报告、不判失败 ——
缺口本身是需要被记录的研究状态，不该让 CI 常红；
需要当作硬门槛时加 `--strict`。

用法：
    python tests/verify_benchmark.py
    python tests/verify_benchmark.py --strict
    python tests/verify_benchmark.py --json

退出码：
    0  通过（可能带覆盖缺口警告）
    1  存在结构/一致性错误，或 --strict 下存在覆盖缺口
    2  依赖缺失（未安装 PyYAML）
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
EXPECTED_BY_TIER = {"low": "vulnerable", "medium": "vulnerable", "high": "safe"}


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

    直接解析源码而不是 import —— verify_lab 是脚本不是模块，
    import 会触发 argparse 与网络请求。
    """
    src = VERIFY_LAB.read_text(encoding="utf-8")
    return set(re.findall(r'LabCheck\(\s*"([^"]+)"\s*,', src))


def scenario_dirs() -> set[str]:
    return {
        p.name
        for p in HTML.iterdir()
        if p.is_dir() and p.name not in {"data", "lib", "uploads", "internal"}
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
    for tier in TIERS:
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
    for idx, case in enumerate(cases):
        cid = case.get("id") or f"<第 {idx + 1} 条无 id>"
        seen[cid] = seen.get(cid, 0) + 1

        scenario = case.get("scenario")
        tier = case.get("tier")
        if tier not in TIERS:
            errors.append(f"{cid}: tier 非法（{tier}）")
            continue
        if case.get("expected") != EXPECTED_BY_TIER[tier]:
            errors.append(
                f"{cid}: expected={case.get('expected')} 与 tier={tier} 的语义不符"
                f"（应为 {EXPECTED_BY_TIER[tier]}）"
            )

        # 路径与文件存在性
        path = case.get("path") or ""
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

        by_scenario.setdefault(scenario, set()).add(tier)

        # 归因标签
        tags = case.get("cause_tags") or []
        if not tags:
            errors.append(f"{cid}: 缺少 cause_tags，误报无法归因")
        for tag in tags:
            if tag not in taxonomy:
                errors.append(f"{cid}: cause_tags 含未定义成因 '{tag}'")

        # CI 断言锚定
        checks = case.get("ci_checks") or []
        for name in checks:
            if name not in check_names:
                errors.append(f"{cid}: CI 断言 '{name}' 在 tests/verify_lab.py 中不存在")
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
        if expected == "safe" and case.get("id") not in probe_cases:
            errors.append(f"{case.get('id')}: 负例缺探针，无法证明「不该被检出」")
        if expected == "vulnerable" and not (case.get("poc") or case.get("id") in probe_cases):
            errors.append(
                f"{case.get('id')}: 正例既无 PoC 也无探针，检出率无法测量"
            )
        if case.get("probe") and case["probe"] not in probe_ids:
            errors.append(f"{case.get('id')}: probe 字段指向不存在的探针 {case['probe']}")

    # 4) 场景覆盖：13 个目录，每个都必须有 3 档用例
    dirs = scenario_dirs()
    for name in sorted(dirs):
        tiers = by_scenario.get(name, set())
        missing = set(TIERS) - tiers
        if missing:
            errors.append(f"场景 {name} 缺少档位用例：{sorted(missing)}")
    for name in sorted(set(by_scenario) - dirs):
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
