"""Run: python run_client_defense.py [--markdown | --overhead]  (no third-party packages required).

Evaluates client defense v2 (minivac/client_defense.py) in client_only /
server_only / combined modes:
  1. Andrew's 21 client-attack scenarios, starter guard vs v2 guard
  2. 11 new scenarios written against v2 (defense-aware attacks and controls)
  3. a scan-interval sweep for the modify-then-restore timing attack
Writes client_defense_results.csv and client_defense_scan_sweep.csv.

--markdown  print the results table for docs/CLIENT_DEFENSE_LOG.md instead
--overhead  print the measured cost of one scan (machine-dependent, not saved)
"""
import csv
import sys
from pathlib import Path
from minivac.client_defense_eval import (LEGACY_IDS, MODES, SCENARIOS, evaluate_defense,
                                         evaluate_starter, markdown_catalogue,
                                         measure_scan_cost, scan_window_sweep)
from minivac.experiments import metrics


def _marks(results: dict, index: int) -> str:
    return "  ".join("X" if results[mode][index]["detected"] else "." for mode in MODES)


def _metric_line(label: str, rows: list[dict]) -> str:
    m = metrics(rows)
    return (f"  {label:<24} TP={m['TP']:<2} FP={m['FP']:<2} FN={m['FN']:<2} TN={m['TN']:<2} "
            f"TPR={m['TPR']:.0%} FPR={m['FPR']:.0%}")


def main() -> None:
    if "--markdown" in sys.argv:
        print(markdown_catalogue())
        return
    if "--overhead" in sys.argv:
        print("Cost of one scan on this machine (wall clock, mean of 20):")
        for row in measure_scan_cost():
            print(f"  asset {row['asset_bytes']:>10,} bytes   {row['ms_per_scan']:.3f} ms")
        return

    starter, defended = evaluate_starter(), evaluate_defense()
    legacy = len(LEGACY_IDS)
    print("MiniVAC client defense v2 (toy model, not VAC performance)")
    print("Columns C S B = client only, server only, combined.  X = flagged, . = not flagged")
    print("-" * 92)

    print("\n1. Andrew's catalogue: starter guard vs v2 guard")
    print(f"  {'ID':<5} {'scenario':<34} {'truth':<10} {'starter':<9} {'v2':<9}")
    print(f"  {'':<5} {'':<34} {'':<10} {'C  S  B':<9} {'C  S  B':<9}")
    for i, scenario in enumerate(SCENARIOS[:legacy]):
        truth = "violation" if scenario.violation else "legit"
        before, after = _marks(starter, i), _marks(defended, i)
        note = "  <- changed" if before != after else ""
        print(f"  {scenario.id:<5} {scenario.name:<34} {truth:<10} {before:<9} {after:<9}{note}")
    for mode in MODES:
        print(f"\n  {mode}")
        print(_metric_line("  starter guard", starter[mode]))
        print(_metric_line("  v2 guard", defended[mode][:legacy]))

    print("\n2. New scenarios written against v2")
    print(f"  {'ID':<5} {'scenario':<34} {'truth':<10} {'C  S  B':<9} server-side evidence (combined)")
    for i, scenario in enumerate(SCENARIOS[legacy:], start=legacy):
        truth = "violation" if scenario.violation else "legit"
        row = defended["combined"][i]
        evidence = ", ".join(row["server_rejections"] + row["server_findings"]) or "none"
        print(f"  {scenario.id:<5} {scenario.name:<34} {truth:<10} {_marks(defended, i):<9} {evidence}")
    print(f"\n  v2 guard on all {len(SCENARIOS)} scenarios")
    for mode in MODES:
        print(_metric_line(f"  {mode}", defended[mode]))

    sweep = scan_window_sweep()
    print("\n3. Scan-interval sweep: tamper with the asset, restore it later (CA05)")
    print(f"  {'attacker':<15} {'scan every':>10} {'window':>8} {'caught':>9} "
          f"{'rate':>6} {'predicted':>10} {'scans/min':>10} {'session tampered':>17}")
    for row in sweep:
        window = "" if row["tamper_window_s"] is None else f"{row['tamper_window_s']} s"
        predicted = "" if row["predicted_rate"] is None else f"{row['predicted_rate']:.0%}"
        print(f"  {row['strategy']:<15} {str(row['scan_interval_s']) + ' s':>10} {window:>8} "
              f"{str(row['caught']) + '/' + str(row['trials']):>9} {row['detection_rate']:>6.0%} "
              f"{predicted:>10} {row['scans_per_minute']:>10} "
              f"{row['share_of_session_tampered']:>17.1%}")

    results_path = Path("client_defense_results.csv")
    fields = ["configuration", "id", "scenario", "category", "policy_violation",
              "starter_detected", "detected", "client_alerts", "server_rejections",
              "server_findings", "scans", "reports", "actions", "latency_s"]
    with results_path.open("w", newline="", encoding="utf8") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        for mode in MODES:
            for i, row in enumerate(defended[mode]):
                before = starter[mode][i]["detected"] if i < legacy else ""
                latency = "" if row["latency_s"] is None else row["latency_s"]
                writer.writerow({"configuration": mode, **row,
                                 "starter_detected": before, "latency_s": latency})

    sweep_path = Path("client_defense_scan_sweep.csv")
    with sweep_path.open("w", newline="", encoding="utf8") as out:
        writer = csv.DictWriter(out, fieldnames=list(sweep[0]))
        writer.writeheader()
        writer.writerows({k: "" if v is None else v for k, v in row.items()} for row in sweep)
    print(f"\nSaved {results_path}  ({len(SCENARIOS)} scenarios x {len(MODES)} configurations)")
    print(f"Saved {sweep_path}  ({len(sweep)} rows)")


if __name__ == "__main__":
    main()
