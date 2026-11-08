from __future__ import annotations

from pathlib import Path

from .models import Finding, SEVERITY_WEIGHT, Severity
from .parser import extract_resource_blocks, terraform_files
from .rules import RULES


def scan_path(path: str | Path) -> list[Finding]:
    root = Path(path)
    findings: list[Finding] = []
    for tf_file in terraform_files(root):
        for block in extract_resource_blocks(tf_file):
            for rule in RULES:
                finding = rule.evaluate(block)
                if finding:
                    findings.append(finding)
    return sorted(findings, key=lambda f: (-SEVERITY_WEIGHT[f.severity], f.file, f.line, f.rule_id))


def posture_metrics(findings: list[Finding]) -> dict:
    by_severity = {severity.value: 0 for severity in Severity}
    by_rule: dict[str, int] = {}
    penalty = 0
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        penalty += SEVERITY_WEIGHT[finding.severity]

    score = max(0, 100 - penalty)
    return {
        "posture_score": score,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_rule": dict(sorted(by_rule.items())),
    }
