# PirateShield Endpoint Layer Ablation Evaluation
# Runs four layer configurations against attack scenarios and normal events:
#   - L1 only (rule-based)
#   - L1 + L2 (rules + autoencoder)
#   - L1 + L3 (rules + chain detection)
#   - L1 + L2 + L3 (full composite)
#
# Produces a comparison table showing detection rate and false positive rate
# per configuration, plus a per-scenario breakdown of the full model.
# Output saved to data/risk_scores/endpoint/layer_evaluation.json
#
# Usage:
#   cd pirateshield/scripts/device_model
#   python evaluate_layers.py
#   python evaluate_layers.py --attack-input /path/to/attack.json --normal-input /path/to/normal.json

import json
import copy
import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

DEFAULT_ATTACK_FILE  = BASE_DIR / "data" / "synthetic_events" / "synthetic_deviceAttack_scenarios.json"
DEFAULT_NORMAL_FILE  = BASE_DIR / "data" / "synthetic_events" / "synthetic_device_events.json"
DEFAULT_BASELINE_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_device_baseline.json"
OUTPUT_FILE = BASE_DIR / "data" / "risk_scores" / "endpoint" / "layer_evaluation.json"

# import from endpoint_model in the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from endpoint_model import compute_chain_scores

SEVERITY_THRESHOLDS = [
    ("CRITICAL", 85),
    ("HIGH", 60),
    ("MEDIUM", 35),
    ("LOW", 15),
]

CONFIGS = [
    ("L1 only",      False, False),
    ("L1 + L2",      True,  False),
    ("L1 + L3",      False, True),
    ("L1 + L2 + L3", True,  True),
]


# METRICS ----------------------------------------

def detection_rates(results, thresholds):
    """Return detection count and rate at each threshold for a set of results."""
    n = len(results)
    rates = {}
    for label, thresh in thresholds:
        count = sum(1 for r in results if r["composite_score"] >= thresh)
        rates[label] = {"count": count, "total": n, "rate": count / n if n > 0 else 0.0}
    return rates


def mean_score(results):
    if not results:
        return 0.0
    return round(sum(r["composite_score"] for r in results) / len(results), 2)


def run_config(events, use_layer2, use_layer3):
    """Deep copy events and score under the given layer configuration."""
    events_copy = copy.deepcopy(events)
    return compute_chain_scores(events_copy, use_layer2=use_layer2, use_layer3=use_layer3)


# PRINTING ----------------------------------------

def print_separator(width=80):
    print("-" * width)


def print_detection_table(config_results, attack_count, normal_count):
    """Print the main detection rate vs false positive rate comparison table."""
    col_w = 16

    print(f"\n{'=' * 80}")
    print("PIRATESHIELD ENDPOINT - LAYER ABLATION RESULTS")
    print(f"{'=' * 80}")
    print(f"Attack scenario events : {attack_count}")
    print(f"Normal events          : {normal_count}")

    # attack detection rates
    print(f"\n--- DETECTION RATE ON ATTACK EVENTS ---\n")
    header = f"{'Configuration':<16}  {'MEDIUM+(>=35)':>14}  {'HIGH+(>=60)':>12}  {'CRITICAL(>=85)':>14}  {'Mean Score':>10}"
    print(header)
    print_separator(len(header))

    for cfg_name, use_l2, use_l3 in CONFIGS:
        results = config_results[cfg_name]["attack"]
        n = len(results)
        med = sum(1 for r in results if r["composite_score"] >= 35)
        hi  = sum(1 for r in results if r["composite_score"] >= 60)
        crit = sum(1 for r in results if r["composite_score"] >= 85)
        avg = mean_score(results)
        print(f"{cfg_name:<16}  {med:>5}/{n:<8}  {hi:>4}/{n:<7}  {crit:>5}/{n:<8}  {avg:>10.2f}")

    # false positive rates on normal events
    print(f"\n--- FALSE POSITIVE RATE ON NORMAL EVENTS ---\n")
    header = f"{'Configuration':<16}  {'FP@MEDIUM':>10}  {'FP@HIGH':>8}  {'FP@CRITICAL':>12}  {'Mean Score':>10}"
    print(header)
    print_separator(len(header))

    for cfg_name, use_l2, use_l3 in CONFIGS:
        results = config_results[cfg_name]["baseline"]
        n = len(results)
        fp_med  = sum(1 for r in results if r["composite_score"] >= 35)
        fp_hi   = sum(1 for r in results if r["composite_score"] >= 60)
        fp_crit = sum(1 for r in results if r["composite_score"] >= 85)
        avg = mean_score(results)
        print(f"{cfg_name:<16}  {fp_med:>4}/{n:<5}  {fp_hi:>3}/{n:<4}  {fp_crit:>4}/{n:<7}  {avg:>10.2f}")


def print_per_scenario_breakdown(full_results, l1_results):
    """Print per-event detail for each attack scenario under the full model vs L1 alone."""
    print(f"\n{'=' * 80}")
    print("PER-SCENARIO BREAKDOWN  (Full Model: L1+L2+L3  vs  L1 only)")
    print(f"{'=' * 80}")

    # index L1-only results by event_id for side-by-side comparison
    l1_by_id = {r["event_id"]: r for r in l1_results}

    # group full model results by scenario
    scenarios = {}
    for r in full_results:
        sc = r.get("scenario") or "no_scenario"
        scenarios.setdefault(sc, []).append(r)

    for sc_name, events in sorted(scenarios.items()):
        events_sorted = sorted(events, key=lambda e: e.get("scenario_step") or 0)
        device = events_sorted[0]["device_id"]
        print(f"\nScenario: {sc_name}  ({device})")
        print(f"  {'Step':<5}  {'Event Type':<18}  {'Process':<12}  "
              f"{'L1':>4}  {'L2':>5}  {'L3':>5}  {'Composite':>9}  {'Severity':<8}  "
              f"{'L1-alone':>8}  {'Boost':>6}")
        print(f"  {'-'*5}  {'-'*18}  {'-'*12}  "
              f"{'-'*4}  {'-'*5}  {'-'*5}  {'-'*9}  {'-'*8}  "
              f"{'-'*8}  {'-'*6}")

        detected_full = 0
        detected_l1 = 0

        for e in events_sorted:
            l1_r = l1_by_id.get(e["event_id"])
            l1_alone = l1_r["composite_score"] if l1_r else e["layer1_rule_score"]
            boost = round(e["composite_score"] - l1_alone, 2)
            proc = (e.get("process_name") or "-")[:12]
            step = e.get("scenario_step") or "-"
            print(f"  {str(step):<5}  {e['event_type']:<18}  {proc:<12}  "
                  f"{e['layer1_rule_score']:>4}  {e['layer2_anomaly_score']:>5.1f}  "
                  f"{e['layer3_chain_points']:>5.1f}  {e['composite_score']:>9.2f}  "
                  f"{e['severity']:<8}  {l1_alone:>8.2f}  {boost:>+6.2f}")

            if e["composite_score"] >= 35:
                detected_full += 1
            if l1_alone >= 35:
                detected_l1 += 1

        n = len(events_sorted)
        print(f"  -> Full model: {detected_full}/{n} events >= MEDIUM  |  "
              f"L1 alone: {detected_l1}/{n} events >= MEDIUM")


# MAIN ----------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PirateShield layer ablation evaluation")
    parser.add_argument("--attack-input", type=Path, default=DEFAULT_ATTACK_FILE,
                        help="Attack scenario events JSON")
    parser.add_argument("--normal-input", type=Path, default=DEFAULT_NORMAL_FILE,
                        help="Realistic mixed normal events JSON (used for operational context)")
    parser.add_argument("--baseline-input", type=Path, default=DEFAULT_BASELINE_FILE,
                        help="Clean benign-only events JSON (used for true FP measurement)")
    args = parser.parse_args()

    # load data
    if not args.attack_input.exists():
        print(f"Attack input not found: {args.attack_input}")
        print("Run generate_attack_scenarios.py first.")
        sys.exit(1)
    if not args.baseline_input.exists():
        print(f"Clean baseline not found: {args.baseline_input}")
        print("Run: python generate_device_events.py 100 --clean-baseline --adfa-dir <path>")
        print("     (rename output to synthetic_device_baseline.json)")
        sys.exit(1)

    with open(args.attack_input) as f:
        attack_events = json.load(f)
    with open(args.baseline_input) as f:
        baseline_events = json.load(f)

    # load mixed normal events too if available (for operational context table)
    mixed_events = []
    if args.normal_input.exists():
        with open(args.normal_input) as f:
            mixed_events = json.load(f)

    print(f"Loaded {len(attack_events)} attack events")
    print(f"Loaded {len(baseline_events)} clean baseline events (for FP measurement)")
    if mixed_events:
        print(f"Loaded {len(mixed_events)} mixed normal events (operational context)")
    print("Running four layer configurations - this will load the autoencoder once...\n")

    # run all four configurations
    config_results = {}
    for cfg_name, use_l2, use_l3 in CONFIGS:
        print(f"Scoring: {cfg_name}")
        config_results[cfg_name] = {
            "attack":   run_config(attack_events,   use_l2, use_l3),
            "baseline": run_config(baseline_events, use_l2, use_l3),
        }

    # print tables
    print_detection_table(config_results, len(attack_events), len(baseline_events))

    full_attack = config_results["L1 + L2 + L3"]["attack"]
    l1_attack   = config_results["L1 only"]["attack"]
    print_per_scenario_breakdown(full_attack, l1_attack)

    # build output summary
    summary = {}
    for cfg_name, use_l2, use_l3 in CONFIGS:
        atk = config_results[cfg_name]["attack"]
        base = config_results[cfg_name]["baseline"]
        summary[cfg_name] = {
            "use_layer2": use_l2,
            "use_layer3": use_l3,
            "attack_events": len(atk),
            "baseline_events": len(base),
            "attack_detection": {
                "medium_plus": sum(1 for r in atk if r["composite_score"] >= 35),
                "high_plus":   sum(1 for r in atk if r["composite_score"] >= 60),
                "critical":    sum(1 for r in atk if r["composite_score"] >= 85),
                "mean_score":  mean_score(atk),
            },
            "baseline_false_positives": {
                "at_medium":  sum(1 for r in base if r["composite_score"] >= 35),
                "at_high":    sum(1 for r in base if r["composite_score"] >= 60),
                "at_critical": sum(1 for r in base if r["composite_score"] >= 85),
                "mean_score": mean_score(base),
            },
            "full_attack_results": atk if cfg_name == "L1 + L2 + L3" else None,
        }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n{'=' * 80}")
    print(f"Full results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
