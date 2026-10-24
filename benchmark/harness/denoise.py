#!/usr/bin/env python3
"""降噪效果量化：把「加了复核之后误报降多少、漏检增多少、花多少钱」算出来。

流程（每轮）：

    扫描器 → 命中列表 → 逐条重放取证据 → 复核（LLM / 启发式）
           → 剔除被判为误报的 → 再算一次指标

指标沿用 docs/BENCHMARK.md：TPR / FPR 及分项。另外记录复核调用次数、
送入模型的字符数，用来估算成本。

用法：

    # 启发式复核，跑 3 轮
    python benchmark/harness/denoise.py --scanner naive --url http://127.0.0.1:8080 \
        --asp-repo ../attack-surface --provider heuristic --rounds 3

    # DeepSeek 复核（需要 ASP_LLM_API_KEY）
    ASP_LLM_API_KEY=... python benchmark/harness/denoise.py --scanner naive \
        --url http://127.0.0.1:8080 --asp-repo ../attack-surface \
        --provider openai --rounds 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.harness import adapters  # noqa: E402
from benchmark.harness.evaluate import evaluate  # noqa: E402
from benchmark.harness.evidence import build_evidence, mask_tier  # noqa: E402
from benchmark.harness.loader import (  # noqa: E402
    build_case_request,
    load_manifest,
    load_probes,
    normalize_path,
)


def _load_llm(asp_repo: Path):
    if not (asp_repo / "asp" / "llm.py").is_file():
        raise SystemExit(f"[denoise] 找不到 {asp_repo}/asp/llm.py，--asp-repo 指错了？")
    sys.path.insert(0, str(asp_repo))
    from asp.llm import Finding, build_provider  # noqa: PLC0415

    return Finding, build_provider


def _replay_spec(root, case: dict, finding: dict, probes: dict) -> tuple[str, bytes | None]:
    """决定重放这条命中时用什么方法和 body。

    GET 场景 URL 里已经带参数；POST 场景必须带原 body，否则抓到的是空表单。
    但命中的 URL 未必就是用例路径（比如 upload 的 PoC 第二步会去访问
    /uploads/xxx 验证落地），这种情况按 GET 原样回放，不能把 POST body
    打到落地文件上。
    """
    if normalize_path(finding["url"]) != case["path"]:
        return "GET", None

    parsed = urllib.parse.urlsplit(finding["url"])
    base = f"{parsed.scheme}://{parsed.netloc}"
    req = build_case_request(root, case, probe=probes.get(case["id"]), base=base)
    if not req:
        return "GET", None
    return req["method"], req["payload"]


def map_findings_to_cases(findings: list[dict], manifest: dict) -> list[tuple[dict, dict]]:
    """把命中映射到用例，并把证据 URL 换成实际命中的地址。"""
    cases = manifest["cases"]
    by_path = {c["path"]: c for c in cases}
    pairs: list[tuple[dict, dict]] = []
    for finding in findings:
        path = normalize_path(finding.get("url", ""))
        case = by_path.get(path)
        if case is None and finding.get("rule"):
            owners = [
                c for c in cases
                if (c.get("poc") or "").endswith(f"/{finding['rule']}.yaml")
            ]
            if len(owners) == 1:
                case = owners[0]
        if case is None:
            continue
        pairs.append((finding, case))
    return pairs


async def review(
    pairs: list[tuple[dict, dict]],
    provider,
    Finding,
    *,
    root,
    probes: dict,
    cache: dict | None = None,
) -> tuple[list[dict], list[dict], int, int]:
    """逐条复核，返回（保留的命中、被剔除的命中、送入模型字符数）。"""
    kept: list[dict] = []
    dropped: list[dict] = []
    chars = 0
    cache_hits = 0

    for finding, case in pairs:
        method, payload = _replay_spec(root, case, finding, probes)
        evidence_text = build_evidence(
            finding["url"], finding.get("rule", ""), method=method, payload=payload
        )
        item = Finding(
            poc_id=mask_tier(finding.get("rule", "unknown")),
            name="Web 漏洞扫描命中",
            severity=finding.get("severity", "") or "unknown",
            target=mask_tier(finding["url"]),
            evidence=evidence_text,
            verified=bool(finding.get("verified")),
        )
        prompt_text = item.to_prompt_text()
        chars += len(prompt_text)

        # 温度固定为 0，同一份证据的结论可复用：省掉跨轮的重复调用。
        key = hash((prompt_text, item.target))
        cached = (cache or {}).get(key)
        if cached is not None:
            verdict = cached
            cache_hits += 1
        else:
            verdict = await provider.judge(item)
            if cache is not None:
                cache[key] = verdict

        record = {
            "case": case["id"],
            "url": finding["url"],
            "rule": finding.get("rule", ""),
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        }
        if verdict.is_false_positive:
            dropped.append(record)
        else:
            kept.append(finding | {"review": record})

    return kept, dropped, chars, cache_hits


def summarize_round(before: dict, after: dict, dropped: list[dict], chars: int) -> dict:
    return {
        "TPR_before": before["totals"]["TPR"],
        "TPR_after": after["totals"]["TPR"],
        "FPR_before": before["totals"]["FPR"],
        "FPR_after": after["totals"]["FPR"],
        "delta_TPR": round(before["totals"]["TPR"] - after["totals"]["TPR"], 4),
        "delta_FPR": round(before["totals"]["FPR"] - after["totals"]["FPR"], 4),
        "dropped": len(dropped),
        "kept": before["findings_total"] - len(dropped),
        "prompt_chars": chars,
        "false_negatives": after["cases"]["FN"],
        "remaining_fp": after["cases"]["FP"],
    }


def aggregate(rounds: list[dict]) -> dict:
    def stats(key: str) -> dict:
        values = [r[key] for r in rounds]
        return {
            "mean": round(statistics.fmean(values), 4),
            "min": min(values),
            "max": max(values),
        }

    return {
        "rounds": len(rounds),
        "TPR_before": stats("TPR_before"),
        "TPR_after": stats("TPR_after"),
        "FPR_before": stats("FPR_before"),
        "FPR_after": stats("FPR_after"),
        "delta_FPR": stats("delta_FPR"),
        "delta_TPR": stats("delta_TPR"),
        "dropped": stats("dropped"),
        "prompt_chars": stats("prompt_chars"),
        # 实际 API 调用要扣掉跨轮复用；缓存命中数单独报。
        "cost_calls": sum(
            r["dropped"] + r["kept"] - r.get("cache_hits", 0) for r in rounds
        ),
        "cache_hits": sum(r.get("cache_hits", 0) for r in rounds),
    }


def render_markdown(label: str, provider: str, agg: dict, rounds: list[dict], model: str) -> str:
    lines = [
        f"# 降噪效果：{label} + {provider}",
        "",
        f"- 模型：{model or '—'}",
        f"- 轮次：{agg['rounds']}",
        f"- 复核调用：{agg['cost_calls']} 次，平均送入 {agg['prompt_chars']['mean']:.0f} 字符/轮",
        "",
        "| 指标 | 降噪前 | 降噪后 | 变化 |",
        "|---|---|---|---|",
        (
            f"| TPR | {agg['TPR_before']['mean'] * 100:.1f}% | {agg['TPR_after']['mean'] * 100:.1f}% "
            f"| {agg['delta_TPR']['mean'] * 100:+.1f}pp |"
        ),
        (
            f"| FPR | {agg['FPR_before']['mean'] * 100:.1f}% | {agg['FPR_after']['mean'] * 100:.1f}% "
            f"| {agg['delta_FPR']['mean'] * 100:+.1f}pp |"
        ),
        "",
        "各轮明细：",
        "",
        "| 轮次 | 命中 | 剔除 | TPR 前→后 | FPR 前→后 | 新增漏检 |",
        "|---|---:|---:|---|---|---|",
    ]
    for idx, r in enumerate(rounds, 1):
        lines.append(
            f"| {idx} | {r['kept'] + r['dropped']} | {r['dropped']} | "
            f"{r['TPR_before'] * 100:.1f}% → {r['TPR_after'] * 100:.1f}% | "
            f"{r['FPR_before'] * 100:.1f}% → {r['FPR_after'] * 100:.1f}% | "
            f"{len(r['false_negatives'])} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="降噪效果量化")
    parser.add_argument("--scanner", required=True, choices=sorted(adapters.ADAPTERS))
    parser.add_argument("--provider", default="heuristic", choices=["heuristic", "openai", "auto"])
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--label", default="")
    parser.add_argument("--asp-repo", default=str(ROOT.parent / "attack-surface"))
    parser.add_argument("--asp-python", default=None)
    parser.add_argument("--out-dir", default=str(ROOT / "benchmark" / "results"))
    parser.add_argument("--findings", default="", help="scanner=json 时必填：第三方结果文件")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest(ROOT)
    probes = {p["case"]: p for p in load_probes(ROOT)}
    asp_repo = Path(args.asp_repo)
    Finding, build_provider = _load_llm(asp_repo)

    provider = build_provider(
        args.provider,
        api_key=os.environ.get("ASP_LLM_API_KEY", ""),
        base_url=os.environ.get("ASP_LLM_BASE_URL", ""),
        model=os.environ.get("ASP_LLM_MODEL", ""),
    )

    kwargs = {"root": ROOT}
    if args.scanner == "json":
        if not args.findings:
            parser.error("--scanner json 需要同时给 --findings")
        kwargs = {"root": ROOT, "findings": Path(args.findings)}
    elif args.scanner == "asp":
        kwargs = {
            "root": ROOT,
            "poc_dir": ROOT / "pocs",
            "asp_repo": asp_repo,
            "python": args.asp_python,
        }

    cache: dict = {}
    rounds = []
    for index in range(1, args.rounds + 1):
        started = time.time()
        payload = adapters.ADAPTERS[args.scanner](args.url, **kwargs)
        if not payload.get("reachable", True):
            print("[环境错误] 目标不可达，本轮无效", file=sys.stderr)
            return 2

        before = evaluate(payload["findings"], manifest, args.url)
        pairs = map_findings_to_cases(payload["findings"], manifest)
        kept, dropped, chars, hits = asyncio.run(
            review(pairs, provider, Finding, root=ROOT, probes=probes, cache=cache)
        )
        after = evaluate(kept, manifest, args.url)

        record = summarize_round(before, after, dropped, chars)
        record["elapsed_sec"] = round(time.time() - started, 1)
        record["dropped_cases"] = [d["case"] for d in dropped]
        record["dropped_detail"] = [
            {"case": d["case"], "verdict": d["verdict"], "reason": d["reason"]} for d in dropped
        ]
        record["cache_hits"] = hits
        rounds.append(record)
        print(
            f"  第 {index} 轮：命中 {record['kept'] + record['dropped']}，"
            f"剔除 {record['dropped']}，TPR {record['TPR_before'] * 100:.1f}%→"
            f"{record['TPR_after'] * 100:.1f}%，FPR {record['FPR_before'] * 100:.1f}%→"
            f"{record['FPR_after'] * 100:.1f}%，耗时 {record['elapsed_sec']}s"
        )

    agg = aggregate(rounds)
    label = args.label or args.scanner
    model = os.environ.get("ASP_LLM_MODEL", "") if args.provider == "openai" else ""
    result = {
        "scanner": args.scanner,
        "provider": provider.name,
        "model": model,
        "aggregate": agg,
        "rounds": rounds,
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    base = f"denoise-{label}-{provider.name}-{stamp}"
    (out_dir / f"{base}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    md = render_markdown(label, provider.name, agg, rounds, model)
    (out_dir / f"{base}.md").write_text(md, encoding="utf-8")

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print()
        print("=" * 74)
        print(f"  降噪效果：{label} + {provider.name}")
        print("=" * 74)
        print(f"  TPR {agg['TPR_before']['mean'] * 100:.1f}% → {agg['TPR_after']['mean'] * 100:.1f}%"
              f"（{agg['delta_TPR']['mean'] * 100:+.1f}pp）")
        print(f"  FPR {agg['FPR_before']['mean'] * 100:.1f}% → {agg['FPR_after']['mean'] * 100:.1f}%"
              f"（{agg['delta_FPR']['mean'] * 100:+.1f}pp）")
        print(f"  调用 {agg['cost_calls']} 次，字符 {agg['prompt_chars']['mean']:.0f}/轮")
        print()
        print(f"  报告：{out_dir}/{base}.md")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
