"""
BlueOps Hypothetical Scenario Fixture Summary Calculator
Computes static detection accuracy metrics over offline test fixtures only.
Use `node test-lab/run_simulations.js` for live regex/pattern smoke checks.
"""

import json
import os
import time

SCENARIOS = [
    {"code": "T001", "name": "SSH Brute-Force Simulation (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T002", "name": "Successful SSH Login After Failures (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T003", "name": "Linux Privilege Escalation Activity (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T004", "name": "Linux User Creation (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T005", "name": "Windows Suspicious PowerShell (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T006", "name": "Suspicious Process Chain (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T007", "name": "Scheduled Task Creation (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T008", "name": "Security Log Clearing (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T009", "name": "Known Threat Intel IOC Communication (Hypothetical)", "tp": True, "fp": 0},
    {"code": "T010", "name": "Controlled Hypothetical Response Simulation", "tp": True, "fp": 0}
]

BENIGN_TEST_COUNT = 50


def calculate_metrics():
    total_tp = sum(1 for s in SCENARIOS if s.get("tp"))
    total_fn = sum(1 for s in SCENARIOS if not s.get("tp"))
    total_fp = sum(s.get("fp", 0) for s in SCENARIOS)
    total_tn = BENIGN_TEST_COUNT - total_fp

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "HYPOTHETICAL_OFFLINE_FIXTURES",
        "totalAdversaryScenarios": len(SCENARIOS),
        "benignTests": BENIGN_TEST_COUNT,
        "truePositives": total_tp,
        "falsePositives": total_fp,
        "falseNegatives": total_fn,
        "trueNegatives": total_tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "falsePositiveRate": round(fpr, 4),
        "meanTimeToDetectSeconds": None,
        "meanTimeToRespondSeconds": None,
        "scenarios": SCENARIOS
    }

    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_file = os.path.join(results_dir, "benchmark_report.json")
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)

    print("=================================================================")
    print("      BLUEOPS HYPOTHETICAL FIXTURE SUMMARY REPORT (OFFLINE)      ")
    print("=================================================================")
    print(f"  True Positives (TP):          {total_tp}/{len(SCENARIOS)}")
    print(f"  False Positives (FP):         {total_fp}")
    print(f"  Precision:                    {precision * 100:.2f}%")
    print(f"  Recall:                       {recall * 100:.2f}%")
    print(f"  False Positive Rate (FPR):    {fpr * 100:.2f}%")
    print("  Mean Time to Detect (MTTD):   Not measured (null)")
    print("  Mean Time to Respond (MTTR):  Not measured (null)")
    print("=================================================================")
    print(f"Hypothetical fixture report exported to: {out_file}")


if __name__ == "__main__":
    calculate_metrics()
