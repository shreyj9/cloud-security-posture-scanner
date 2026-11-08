from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import posture_metrics, scan_path


def build_report(path: str) -> dict:
    findings = scan_path(path)
    return {
        "target": str(Path(path)),
        "metrics": posture_metrics(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="posture-scan",
        description="Static security posture scanner for Terraform configurations.",
    )
    parser.add_argument("path", help="Terraform file or directory to scan")
    parser.add_argument("--json", dest="json_path", help="Write the full report to a JSON file")
    parser.add_argument(
        "--fail-on",
        choices=("none", "critical", "high", "medium", "low"),
        default="critical",
        help="Return exit code 1 when findings at or above this severity exist (default: critical)",
    )
    args = parser.parse_args()

    report = build_report(args.path)
    metrics = report["metrics"]

    print(f"Posture score: {metrics['posture_score']}/100")
    print(f"Findings: {metrics['total_findings']}")
    for severity, count in metrics["by_severity"].items():
        print(f"  {severity:<8} {count}")

    for finding in report["findings"]:
        print(
            f"\n[{finding['severity']}] {finding['rule_id']} {finding['title']}\n"
            f"  Resource: {finding['resource_type']}.{finding['resource_name']}\n"
            f"  Location: {finding['file']}:{finding['line']}\n"
            f"  Evidence: {finding['evidence']}\n"
            f"  Fix: {finding['remediation']}"
        )

    if args.json_path:
        output = Path(args.json_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {output}")

    if args.fail_on == "none":
        return 0

    threshold = {"low": 1, "medium": 2, "high": 3, "critical": 4}[args.fail_on]
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return 1 if any(rank[f["severity"]] >= threshold for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
