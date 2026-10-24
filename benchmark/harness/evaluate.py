#!/usr/bin/env python3
"""误报量化评测入口：把扫描器输出换算成 TPR / FPR / 分项误报率。

    python benchmark/harness/evaluate.py --scanner naive --url http://127.0.0.1:8080
    python benchmark/harness/evaluate.py --scanner asp --url http://127.0.0.1:8080 \
        --asp-repo ../attack-surface --asp-python <python>

结果写到 benchmark/results/，同时打印一份表格。指标定义见 docs/BENCHMARK.md。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.harness import adapters  # noqa: E402
from benchmark.harness.loader import (  # noqa: E402
    load_manifest,
    load_probes,
    normalize_path,
)


def _match_by_query(url: str, candidates: list[dict]) -> dict | None:
    """按查询参数精确匹配变体。

    同一个 high 页现在挂着 5 条用例（基础 1 条 + 4 条绕过尝试），
    只看路径会把它们混成一条。扫描器若把 payload 放在 URL 上，
    query 就是最可靠的区分依据。
    """
    from urllib.parse import parse_qs, urlsplit

    query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    if not query:
        return None
    for case in candidates:
        expected = (case.get("request") or {}).get("query") or {}
        if expected and query == {k: str(v) for k, v in expected.items()}:
            return case
    return None


def _resolve_case(finding: dict, by_id: dict, by_path: dict) -> dict | None:
    """命中 → 用例，三级优先：规则里的 case id → 查询参数 → 路径（取基础用例）。"""
    rule = finding.get("rule") or ""

    # 1) 规则名里直接带 case id（naive 适配器就是这么写的）
    if ":" in rule:
        suffix = rule.rsplit(":", 1)[-1]
        if suffix in by_id:
            return by_id[suffix]
    if rule in by_id:
        return by_id[rule]

    # 2) 同一路径多条用例时，按查询参数区分变体
    path = normalize_path(finding.get("url", ""))
    candidates = by_path.get(path, [])
    if len(candidates) > 1:
        matched = _match_by_query(finding.get("url", ""), candidates)
        if matched:
            return matched

    # 3) 落到基础用例（变体是基础用例的加强尝试，不单独承接误报）
    for case in candidates:
        if case.get("variant") is None:
            return case

    # 4) 路径不在清单里：用 PoC 归属（upload 第二步会访问 /uploads/xxx）
    if rule:
        owners = [
            c for c in by_id.values()
            if (c.get("poc") or "").endswith(f"/{rule}.yaml")
        ]
        if len(owners) == 1:
            return owners[0]
    return None


def evaluate(findings: list[dict], manifest: dict, base: str) -> dict:
    cases = manifest["cases"]
    by_id = {c["id"]: c for c in cases}
    by_path: dict[str, list[dict]] = {}
    for case in cases:
        by_path.setdefault(case["path"], []).append(case)

    # findings → 用例。映射不上的单独统计，不进指标。
    reported: dict[str, list[dict]] = {}
    unattributed: list[dict] = []
    for finding in findings:
        case = _resolve_case(finding, by_id, by_path)
        if case is None:
            unattributed.append(finding)
            continue
        reported.setdefault(case["id"], []).append(finding)

    vulnerable = [c for c in cases if c["expected"] == "vulnerable"]
    safe = [c for c in cases if c["expected"] == "safe"]

    tp = [c["id"] for c in vulnerable if c["id"] in reported]
    fn = [c["id"] for c in vulnerable if c["id"] not in reported]
    fp = [c["id"] for c in safe if c["id"] in reported]
    tn = [c["id"] for c in safe if c["id"] not in reported]

    tpr = len(tp) / len(vulnerable) if vulnerable else 0.0
    fpr = len(fp) / len(safe) if safe else 0.0

    # 分项误报率：分母是「负例中带该成因标签的用例数」
    taxonomy = manifest.get("cause_taxonomy") or {}
    per_cause = {}
    for cause in taxonomy:
        if cause == "none":
            continue
        denom = [c["id"] for c in safe if cause in (c.get("cause_tags") or [])]
        hits = [cid for cid in fp if cid in denom]
        per_cause[cause] = {
            "fp_cases": len(hits),
            "safe_cases": len(denom),
            "rate": (len(hits) / len(denom)) if denom else None,
        }

    # 分场景表现（便于看「误报集中在哪类漏洞」）
    per_scenario = {}
    for case in cases:
        bucket = per_scenario.setdefault(
            case["scenario"], {"vulnerable": 0, "detected": 0, "safe": 0, "false_alarm": 0}
        )
        if case["expected"] == "vulnerable":
            bucket["vulnerable"] += 1
            bucket["detected"] += 1 if case["id"] in reported else 0
        else:
            bucket["safe"] += 1
            bucket["false_alarm"] += 1 if case["id"] in reported else 0

    return {
        "target": base,
        "totals": {
            "cases": len(cases),
            "vulnerable": len(vulnerable),
            "safe": len(safe),
            "TP": len(tp),
            "FN": len(fn),
            "FP": len(fp),
            "TN": len(tn),
            "TPR": round(tpr, 4),
            "FPR": round(fpr, 4),
        },
        "cases": {
            "TP": tp,
            "FN": fn,
            "FP": fp,
            "TN": tn,
        },
        "per_cause": per_cause,
        "per_scenario": per_scenario,
        "findings_total": len(findings),
        "unattributed": unattributed,
        "reported_detail": {
            cid: [
                {"rule": f.get("rule"), "severity": f.get("severity"), "source": f.get("source")}
                for f in items
            ]
            for cid, items in reported.items()
        },
    }


def render_markdown(label: str, result: dict) -> str:
    t = result["totals"]
    lines = [
        f"# 评测结果：{label}",
        "",
        f"- 目标：`{result['target']}`",
        f"- 用例：{t['cases']}（正例 {t['vulnerable']} / 负例 {t['safe']}）",
        f"- 检出率 TPR：**{t['TPR'] * 100:.1f}%**（{t['TP']}/{t['vulnerable']}）",
        f"- 误报率 FPR：**{t['FPR'] * 100:.1f}%**（{t['FP']}/{t['safe']}）",
        f"- 原始命中 {result['findings_total']} 条，其中无法归属到用例 {len(result['unattributed'])} 条",
        (
            f"- 尝试用例 {result['attempted_cases']}/{t['cases']}（仅展示，不进 FPR 分母）"
            if result.get("attempted_cases") is not None
            else "- 尝试用例：该工具未上报（黑盒调用，无法统计）"
        ),
        "",
        "## 分项误报率（按成因）",
        "",
        "| 成因 | 误报用例 | 该成因负例总数 | 分项误报率 |",
        "|---|---:|---:|---:|",
    ]
    name_map = {
        "wildcard_dns": "泛解析",
        "identity_dependency": "身份依赖",
        "dynamic_content": "动态内容",
        "stateful_side_effect": "有状态副作用",
        "signature_collision": "特征自污染",
        "none": "未归因",
    }
    for cause, stat in result["per_cause"].items():
        rate = "—" if stat["rate"] is None else f"{stat['rate'] * 100:.1f}%"
        lines.append(f"| {name_map.get(cause, cause)} | {stat['fp_cases']} | {stat['safe_cases']} | {rate} |")

    lines += [
        "",
        "## 分场景",
        "",
        "| 场景 | 正例检出 | 负例误报 |",
        "|---|---|---|",
    ]
    for scenario, stat in sorted(result["per_scenario"].items()):
        lines.append(
            f"| {scenario} | {stat['detected']}/{stat['vulnerable']} | "
            f"{stat['false_alarm']}/{stat['safe']} |"
        )

    if result["cases"]["FP"]:
        lines += ["", "## 误报明细", ""]
        for cid in result["cases"]["FP"]:
            rules = ", ".join(r["rule"] or "?" for r in result["reported_detail"].get(cid, []))
            lines.append(f"- `{cid}` ← {rules}")

    if result["cases"]["FN"]:
        lines += ["", "## 漏检明细", ""]
        lines += [f"- `{cid}`" for cid in result["cases"]["FN"]]

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnLab 误报量化评测")
    parser.add_argument("--scanner", required=True, choices=sorted(adapters.ADAPTERS))
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--label", default="")
    parser.add_argument("--asp-repo", default=str(ROOT.parent / "attack-surface"))
    parser.add_argument("--asp-python", default=None)
    parser.add_argument("--out-dir", default=str(ROOT / "benchmark" / "results"))
    parser.add_argument("--findings", default="", help="json 适配器：第三方结果文件路径")
    parser.add_argument("--json", action="store_true", help="只打印 JSON")
    args = parser.parse_args()

    manifest = load_manifest(ROOT)
    probes = {p["case"]: p for p in load_probes(ROOT)}

    kwargs = {
        "root": ROOT,
        "poc_dir": ROOT / "pocs",
        "asp_repo": Path(args.asp_repo),
        "python": args.asp_python,
        "probes": probes,
    }
    # naive / probe 只需要 root；asp 需要 poc_dir / repo / python
    if args.scanner in {"naive", "probe"}:
        kwargs = {"root": ROOT}
    elif args.scanner == "json":
        kwargs = {"root": ROOT, "findings": Path(args.findings)}

    started = time.time()
    payload = adapters.ADAPTERS[args.scanner](args.url, **kwargs)
    elapsed = time.time() - started

    if not payload.get("reachable", True):
        print("[环境错误] 目标不可达，本次结果无效（不能据此判断「没有漏洞」）", file=sys.stderr)
        return 2

    result = evaluate(payload["findings"], manifest, args.url)
    result["scanner"] = args.scanner
    result["findings"] = payload["findings"]
    result["elapsed_sec"] = round(elapsed, 2)
    result["tool_meta"] = payload.get("meta", {})
    # 尝试覆盖只展示、不进分母：部分工具不逐条打用例，
    # 用它去调整 FPR 反而会奖励「少测少错」。
    result["attempted_cases"] = payload.get("attempted_cases")
    label = args.label or args.scanner

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
    base_name = f"{label}-{stamp}"
    (out_dir / f"{base_name}.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md = render_markdown(label, result)
    (out_dir / f"{base_name}.md").write_text(md, encoding="utf-8")

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print()
        print("=" * 78)
        print(f"  评测：{label}   目标：{args.url}   耗时 {elapsed:.1f}s")
        print("=" * 78)
        t = result["totals"]
        print(f"  用例 {t['cases']}（正例 {t['vulnerable']} / 负例 {t['safe']}）")
        print(f"  TPR {t['TPR'] * 100:5.1f}%  ({t['TP']}/{t['vulnerable']})"
              f"      FPR {t['FPR'] * 100:5.1f}%  ({t['FP']}/{t['safe']})")
        print(f"  原始命中 {result['findings_total']} 条，未归属 {len(result['unattributed'])} 条")
        if result.get("attempted_cases") is not None:
            print(f"  尝试用例 {result['attempted_cases']}/{t['cases']}（仅展示，不进 FPR 分母）")
        print()
        print("  分项误报率：")
        for cause, stat in result["per_cause"].items():
            if stat["safe_cases"] == 0:
                continue
            rate = "—" if stat["rate"] is None else f"{stat['rate'] * 100:5.1f}%"
            print(f"    {cause:<22} {rate}  ({stat['fp_cases']}/{stat['safe_cases']})")
        if result["cases"]["FP"]:
            print()
            print("  误报用例：" + ", ".join(result["cases"]["FP"]))
        if result["cases"]["FN"]:
            print("  漏检用例：" + ", ".join(result["cases"]["FN"]))
        print()
        print(f"  明细已写入 {out_dir}/{base_name}.json / .md")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
