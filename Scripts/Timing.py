"""Times a real scan step by step (E-6 S-13-1, S-13-2, S-13-5).

Run from the repo root with the read-only scanner profile and your AI key set:

    set AWS_PROFILE=cg-scanner
    python scripts/timing.py --runs 3 --ai

Prints the computer, the resource counts and one row per step, so the output
can be pasted into the test record. The 5-minute target excludes AI time, so
AI is timed on its own.
"""

import argparse
import math
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.getcwd())

import coordinator  # noqa: E402
from ai import client  # noqa: E402
from collectors import iam, s3  # noqa: E402
from detection import findings  # noqa: E402

STEPS = {}


def timed(label, function):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        try:
            return function(*args, **kwargs)
        finally:
            STEPS[label] = STEPS.get(label, 0) + time.perf_counter() - start
    return wrapper


s3.collect_s3 = timed("S3 collection", s3.collect_s3)
findings.check_s3 = timed("S3 rules", findings.check_s3)
iam.collect_iam = timed("IAM collection", iam.collect_iam)
findings.check_iam = timed("IAM rules", findings.check_iam)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--ai", action="store_true", help="also time the AI explanations")
    args = parser.parse_args()

    print(f"Computer: {platform.platform()}, {os.cpu_count()} CPUs, Python {platform.python_version()}")
    rows, scan = [], None
    for run in range(1, args.runs + 1):
        STEPS.clear()
        start = time.perf_counter()
        scan = coordinator.run_scan(["S3", "IAM"], None, lambda *a: None)
        total = time.perf_counter() - start
        steps = dict(STEPS)
        steps["Other (login check, account settings)"] = total - sum(steps.values())
        steps["TOTAL"] = total
        rows.append(steps)

    buckets = {c["resource_id"] for c in scan["checks"] if c["service"] == "S3"}
    users = {c["resource_id"] for c in scan["checks"] if c["service"] == "IAM"
             and c["rule_id"] in ("iam_user_mfa", "iam_admin_wildcard", "iam_unused_access_key")}
    print(f"Scanned {len(buckets)} buckets and {len(users)} users: "
          f"{len(scan['checks'])} checks, {len(scan['findings'])} findings, {len(scan['errors'])} errors\n")

    print("| Step | " + " | ".join(f"Run {n}" for n in range(1, args.runs + 1)) + " | Average |")
    print("|---|" + "---|" * (args.runs + 1))
    for label in rows[0]:
        values = [row[label] for row in rows]
        print(f"| {label} | " + " | ".join(f"{v:.1f} s" for v in values) + f" | {statistics.mean(values):.1f} s |")
    slowest = max((k for k in rows[0] if k != "TOTAL"), key=lambda k: statistics.mean(r[k] for r in rows))
    worst = max(row["TOTAL"] for row in rows)
    print(f"\nSlowest step: {slowest}. Slowest run: {worst:.1f} s -> "
          + ("PASS (under 300 s)" if worst < 300 else "FAIL (over 300 s, record the slowest step)"))

    if args.ai and scan["findings"]:
        start = time.perf_counter()
        explanations = client.explain_scan(scan)
        elapsed = time.perf_counter() - start
        requests = math.ceil(len(scan["findings"]) / client.BATCH_SIZE)
        available = sum(1 for e in explanations if e["explanation_status"] == "available")
        print(f"\nAI: {len(scan['findings'])} findings in {requests} requests took {elapsed:.1f} s "
              f"({elapsed / requests:.1f} s per request, target under 30 s). "
              f"{available} available, {len(explanations) - available} unavailable.")


if __name__ == "__main__":
    main()
