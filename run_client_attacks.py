"""Run: python run_client_attacks.py [--markdown]  (no third-party packages required).

Runs the client-attack scenarios in client_only / server_only / combined modes,
prints a summary and writes client_attack_results.csv. With --markdown it prints
the catalogue table for the attack log instead.
"""
import csv
import sys
from pathlib import Path
from minivac.client_attacks import SCENARIOS, evaluate_client_attacks, markdown_catalogue
from minivac.experiments import metrics


def main() -> None:
    if "--markdown" in sys.argv:
        print(markdown_catalogue())
        return
    results = evaluate_client_attacks()
    print("MiniVAC client-attack scenarios (toy model, not VAC performance)")
    print("-" * 76)
    for mode, rows in results.items():
        print(f"\n{mode.upper()}")
        for row in rows:
            truth = "violation" if row["policy_violation"] else "legit    "
            verdict = "FLAGGED" if row["detected"] else "not flagged"
            print(f"  {row['id']}  {row['scenario']:<34} {truth}  {verdict}")
        m = metrics(rows)
        print(f"  TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} "
              f"TPR={m['TPR']:.0%} FPR={m['FPR']:.0%}")

    outpath = Path("client_attack_results.csv")
    fields = ["configuration", "id", "scenario", "category", "policy_violation",
              "detected", "client_alerts", "server_rejections", "scans", "actions"]
    with outpath.open("w", newline="", encoding="utf8") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        for mode, rows in results.items():
            for row in rows:
                writer.writerow({"configuration": mode, **row})
    print(f"\nSaved {outpath}  ({len(SCENARIOS)} scenarios x {len(results)} configurations)")


if __name__ == "__main__":
    main()
