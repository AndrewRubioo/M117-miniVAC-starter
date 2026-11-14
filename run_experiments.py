"""Run: python run_experiments.py  (no third-party packages required)."""
import csv
from pathlib import Path
from minivac.experiments import evaluate_all, metrics


def main() -> None:
    results = evaluate_all()
    print("MiniVAC controlled scenarios (illustrative, not VAC performance)")
    print("-" * 76)
    for name, rows in results.items():
        print(f"\n{name.upper()}")
        for row in rows:
            verdict = "FLAGGED" if row["detected"] else "not flagged"
            print(f"  {row['scenario']:<26} {verdict}")
        m = metrics(rows)
        print(f"  TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} "
              f"TPR={m['TPR']:.0%} FPR={m['FPR']:.0%}")

    outpath = Path("experiment_results.csv")
    with outpath.open("w", newline="", encoding="utf8") as out:
        writer = csv.DictWriter(out, fieldnames=["configuration", "scenario", "policy_violation", "detected", "client_alerts", "server_rejections"])
        writer.writeheader()
        for mode, rows in results.items():
            for row in rows:
                writer.writerow({"configuration": mode, **row})
    print(f"\nSaved {outpath}")


if __name__ == "__main__":
    main()
