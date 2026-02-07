#!/usr/bin/env python
"""
CodeGuard Action Eval Harness v3.0

Runs diff samples through the DiffAnalyzer -> RiskClassifier -> DecisionEngine
pipeline. Supports hand-crafted samples and open-source benchmark datasets.

Usage:
    python run_eval.py                          # Auto tier, hand-crafted samples
    python run_eval.py --tier L1                # Force L1 (1 model)
    python run_eval.py --tier L0                # Rules only, no API calls
    python run_eval.py --dataset cvefixes       # Run CVEFixes benchmark
    python run_eval.py --dataset all            # All datasets
    python run_eval.py --sample sqli_01.patch   # Single sample
    python run_eval.py -v                       # Verbose per-sample output
"""

import argparse
import json
import os
import sys
import time
import tomllib
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from src.analyzer import DiffAnalyzer
from src.risk_classifier import RiskClassifier
from code_guard.audit import Finding as AuditFinding
from decision.engine import DecisionEngine, render_decision_card

# Thresholds (from pre-mortem plan)
THRESHOLD_FP = 5.0
THRESHOLD_FN = 5.0
THRESHOLD_NOISE = 10.0

TIER_MODEL_COUNT = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 3}

# Dataset directories under eval/samples/
DATASETS = {
    "hand-crafted": "hand-crafted",
    "python-cwe": "python-cwe",
    "cvefixes": "cvefixes",
    "juliet": "juliet",
    "castle": "castle",
}


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class Result:
    sample: str
    dataset: str
    category: str          # vulnerable | clean
    expected_flag: bool
    tier_preliminary: str
    tier_final: str
    zones: int
    findings: int
    severities: dict[str, int]
    decision: str          # merge | merge-with-conditions | block
    models_used: int
    consensus: str
    agreement: float
    elapsed: float
    errors: list[str]
    forced_tier: str

    @property
    def flagged(self) -> bool:
        return self.decision in ("block", "merge-with-conditions")

    @property
    def correct(self) -> bool:
        return self.flagged == self.expected_flag

    @property
    def false_positive(self) -> bool:
        return not self.expected_flag and self.flagged

    @property
    def false_negative(self) -> bool:
        return self.expected_flag and not self.flagged


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def make_analyzer(openrouter_key: str, tier: str | None) -> DiffAnalyzer:
    """Create a DiffAnalyzer configured for a specific tier."""
    if tier == "L0":
        return DiffAnalyzer(openrouter_key=openrouter_key, ai_review=False)
    return DiffAnalyzer(openrouter_key=openrouter_key, ai_review=bool(openrouter_key))


def run_sample(
    sample_path: Path,
    dataset_name: str,
    analyzer: DiffAnalyzer,
    classifier: RiskClassifier,
    engine: DecisionEngine,
    forced_tier: str | None = None,
) -> Result:
    """Run one diff sample through the full pipeline."""
    errors = []
    start = time.monotonic()

    diff_content = sample_path.read_text(encoding="utf-8")
    category = sample_path.parent.name
    expected_flag = category == "vulnerable"

    # 1. Analyze
    try:
        analysis = analyzer.analyze(diff_content, rubric="default")
    except Exception as e:
        errors.append(f"Analyzer: {e}")
        analysis = {
            "files_changed": 0, "lines_added": 0, "lines_removed": 0,
            "files": [], "sensitive_zones": [], "preliminary_tier": "L0",
        }

    tier_preliminary = analysis.get("preliminary_tier", "L0")
    if forced_tier:
        analysis["preliminary_tier"] = forced_tier

    # 2. Classify
    try:
        risk = classifier.classify(analysis)
    except Exception as e:
        errors.append(f"Classifier: {e}")
        risk = {"risk_tier": forced_tier or tier_preliminary, "findings": []}

    tier_final = risk.get("risk_tier", "L0")
    findings = risk.get("findings", [])

    # 3. Decide
    audit_findings = _map_findings(findings)
    try:
        packet = engine.decide(audit_findings)
    except Exception as e:
        errors.append(f"DecisionEngine: {e}")
        packet = _empty_packet()

    # Severity counts
    sevs: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "medium") if isinstance(f, dict) else getattr(f, "severity", "medium")
        sevs[s] = sevs.get(s, 0) + 1

    return Result(
        sample=sample_path.name,
        dataset=dataset_name,
        category=category,
        expected_flag=expected_flag,
        tier_preliminary=tier_preliminary,
        tier_final=tier_final,
        zones=len(analysis.get("sensitive_zones", [])),
        findings=len(findings),
        severities=sevs,
        decision=packet.decision,
        models_used=analysis.get("models_used", 0) if isinstance(analysis.get("models_used"), int) else 0,
        consensus=analysis.get("consensus_risk", ""),
        agreement=analysis.get("agreement_score", 0.0),
        elapsed=round(time.monotonic() - start, 2),
        errors=errors,
        forced_tier=forced_tier or "auto",
    )


def _map_findings(finding_dicts: list) -> list[AuditFinding]:
    mapped = []
    for fd in finding_dicts:
        if not isinstance(fd, dict):
            continue
        loc = fd.get("file", "")
        if fd.get("line"):
            loc += f":{fd['line']}"
        mapped.append(AuditFinding(
            severity=fd.get("severity", "medium"),
            category=fd.get("zone", "general"),
            location=loc or None,
            description=fd.get("message", ""),
            recommendation=f"Review {fd.get('rule_id', 'finding')}",
            provable=bool(fd.get("rule_id")),
        ))
    return mapped


class _EmptyPacket:
    decision = "merge"
    hard_blocks = []
    conditions = []
    advisory = []
    total_findings = 0

def _empty_packet():
    return _EmptyPacket()


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def compute_stats(results: list[Result]) -> dict:
    total = len(results)
    if total == 0:
        return {"total": 0}

    vuln = [r for r in results if r.expected_flag]
    clean = [r for r in results if not r.expected_flag]

    fp = sum(1 for r in results if r.false_positive)
    fn = sum(1 for r in results if r.false_negative)
    correct = sum(1 for r in results if r.correct)

    detect_rate = sum(1 for r in vuln if r.flagged) / len(vuln) * 100 if vuln else 0
    fp_rate = fp / len(clean) * 100 if clean else 0
    fn_rate = fn / len(vuln) * 100 if vuln else 0

    return {
        "total": total,
        "correct": correct,
        "accuracy_pct": round(correct / total * 100, 1),
        "vuln_count": len(vuln),
        "clean_count": len(clean),
        "detect_rate_pct": round(detect_rate, 1),
        "fp": fp, "fp_rate_pct": round(fp_rate, 1),
        "fn": fn, "fn_rate_pct": round(fn_rate, 1),
        "fp_pass": fp_rate < THRESHOLD_FP,
        "fn_pass": fn_rate < THRESHOLD_FN,
        "tier_dist": dict(Counter(r.tier_final for r in results)),
    }


def print_report(results: list[Result], stats: dict, elapsed: float, verbose: bool):
    print("\n" + "=" * 60)
    print("EVAL SUMMARY")
    print("=" * 60)

    print(f"Accuracy:        {stats['correct']}/{stats['total']} ({stats['accuracy_pct']}%)")
    print(f"Detection rate:  {stats['detect_rate_pct']}% ({stats['vuln_count']} vulnerable samples)")
    print(f"FP rate:         {stats['fp']}/{stats['clean_count']} ({stats['fp_rate_pct']}%)")
    print(f"FN rate:         {stats['fn']}/{stats['vuln_count']} ({stats['fn_rate_pct']}%)")
    print(f"Time:            {elapsed:.1f}s")

    print()
    fp_ok = "PASS" if stats["fp_pass"] else "FAIL"
    fn_ok = "PASS" if stats["fn_pass"] else "FAIL"
    print(f"Threshold FP (<{THRESHOLD_FP}%): {fp_ok} ({stats['fp_rate_pct']}%)")
    print(f"Threshold FN (<{THRESHOLD_FN}%): {fn_ok} ({stats['fn_rate_pct']}%)")

    # Tier distribution
    print()
    for tier in sorted(stats["tier_dist"]):
        print(f"  {tier}: {stats['tier_dist'][tier]}")

    # By category
    print()
    for cat in ("vulnerable", "clean"):
        cat_r = [r for r in results if r.category == cat]
        cat_ok = sum(1 for r in cat_r if r.correct)
        print(f"  {cat:12s}: {cat_ok}/{len(cat_r)}")

    # By dataset
    datasets = sorted(set(r.dataset for r in results))
    if len(datasets) > 1:
        print()
        for ds in datasets:
            ds_r = [r for r in results if r.dataset == ds]
            ds_stats = compute_stats(ds_r)
            print(f"  {ds:16s}: {ds_stats['accuracy_pct']}% acc, FP={ds_stats['fp_rate_pct']}%, FN={ds_stats['fn_rate_pct']}%")

    # Failures
    failures = [r for r in results if not r.correct]
    if failures and verbose:
        print()
        print("FAILURES:")
        for r in failures:
            label = "FP" if r.false_positive else "FN"
            print(f"  [{label}] {r.dataset}/{r.category}/{r.sample} -> {r.decision}")


def write_results(results: list[Result], stats: dict, forced_tier: str | None, elapsed: float):
    results_dir = _EVAL / "results"
    results_dir.mkdir(exist_ok=True)

    ts = time.strftime("%Y%m%d-%H%M%S")
    tier_label = forced_tier or "auto"
    out_path = results_dir / f"eval-{tier_label}-{ts}.json"

    output = {
        "meta": {
            "timestamp": ts,
            "forced_tier": forced_tier,
            "thresholds": {"fp": THRESHOLD_FP, "fn": THRESHOLD_FN, "noise": THRESHOLD_NOISE},
            **{k: v for k, v in stats.items() if k != "tier_dist"},
        },
        "results": [asdict(r) for r in results],
    }

    out_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"\nResults: {out_path}")
    return out_path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if key:
        return key
    secrets_path = _EVAL / ".codeguard" / ".secrets.toml"
    if secrets_path.exists():
        with open(secrets_path, "rb") as f:
            data = tomllib.load(f)
        return data.get("openrouter_api_key", "")
    return ""


def collect_samples(samples_dir: Path, dataset: str, sample_filter: str | None) -> list[tuple[Path, str]]:
    """Return list of (path, dataset_name) tuples."""
    pairs = []

    if sample_filter:
        matches = list(samples_dir.rglob(sample_filter))
        if not matches:
            print(f"ERROR: Sample not found: {sample_filter}")
            sys.exit(1)
        for m in matches:
            ds = _guess_dataset(m, samples_dir)
            pairs.append((m, ds))
        return pairs

    if dataset == "all":
        target_dirs = [samples_dir]
    elif dataset in DATASETS:
        d = samples_dir / DATASETS[dataset]
        if not d.exists():
            print(f"ERROR: Dataset dir not found: {d}")
            print(f"  Run: python eval/datasets/fetch_{dataset}.py")
            sys.exit(1)
        target_dirs = [d]
    else:
        print(f"ERROR: Unknown dataset: {dataset}")
        print(f"  Available: {', '.join(DATASETS)} or 'all'")
        sys.exit(1)

    for d in target_dirs:
        for p in sorted(d.rglob("*.patch")):
            ds = _guess_dataset(p, samples_dir)
            pairs.append((p, ds))

    return pairs


def _guess_dataset(path: Path, samples_dir: Path) -> str:
    try:
        rel = path.relative_to(samples_dir)
        first_part = rel.parts[0] if rel.parts else "unknown"
        if first_part in ("vulnerable", "clean"):
            return "hand-crafted"
        return first_part
    except ValueError:
        return "unknown"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="CodeGuard Action Eval Harness v3.0")
    p.add_argument("--tier", choices=["L0", "L1", "L2", "L3"], default=None,
                    help="Force a specific tier (default: auto)")
    p.add_argument("--dry-run", action="store_const", const="L0", dest="tier",
                    help="Alias for --tier L0 (rules only)")
    p.add_argument("--dataset", default="hand-crafted",
                    help="Dataset to run: hand-crafted, cvefixes, juliet, castle, all")
    p.add_argument("--sample", default=None,
                    help="Run a single sample by filename")
    p.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose per-sample output")
    return p.parse_args()


def main():
    args = parse_args()

    print("CodeGuard Action Eval Harness v3.0")
    print("=" * 60)

    # API key
    api_key = load_api_key()
    print(f"OpenRouter key: {'set' if api_key else 'MISSING'}")

    # Components
    analyzer = make_analyzer(api_key, args.tier)
    classifier = RiskClassifier(rubric="default")
    engine = DecisionEngine(policy="standard")

    print(f"Models: {len(analyzer.models)}")
    print(f"Tier:   {args.tier or 'auto'}")

    # Samples
    samples_dir = _EVAL / "samples"
    samples = collect_samples(samples_dir, args.dataset, args.sample)
    print(f"Samples: {len(samples)} ({args.dataset})")
    print("=" * 60)

    # Run
    results = []
    t0 = time.monotonic()

    for i, (path, ds_name) in enumerate(samples, 1):
        try:
            rel = path.relative_to(samples_dir)
        except ValueError:
            rel = path.name
        print(f"\n[{i}/{len(samples)}] {rel}")

        r = run_sample(path, ds_name, analyzer, classifier, engine, args.tier)
        results.append(r)

        label = "OK" if r.correct else ("FP" if r.false_positive else "FN")
        print(f"  {r.tier_preliminary}->{r.tier_final}  zones={r.zones}  findings={r.findings}  "
              f"decision={r.decision}  [{label}]")
        if r.models_used > 0:
            print(f"  AI: {r.models_used} models  consensus={r.consensus}  agreement={r.agreement:.2f}")
        if r.errors:
            for e in r.errors:
                print(f"  ERROR: {e}")

    elapsed = time.monotonic() - t0

    # Report
    stats = compute_stats(results)
    print_report(results, stats, elapsed, args.verbose)
    write_results(results, stats, args.tier, elapsed)

    # Exit code
    passed = stats.get("fp_pass", False) and stats.get("fn_pass", False)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
