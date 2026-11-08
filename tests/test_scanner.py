from pathlib import Path

from posture_scanner.scanner import posture_metrics, scan_path


ROOT = Path(__file__).resolve().parents[1]


def test_insecure_example_detects_expected_controls():
    findings = scan_path(ROOT / "examples" / "insecure")
    rule_ids = {f.rule_id for f in findings}

    assert "CSPM-001" in rule_ids  # public S3
    assert "CSPM-002" in rule_ids  # open SG
    assert "CSPM-003" in rule_ids  # public RDS
    assert "CSPM-004" in rule_ids  # unencrypted RDS
    assert "CSPM-005" in rule_ids  # wildcard IAM
    assert "CSPM-006" in rule_ids  # hardcoded secret
    assert "CSPM-007" in rule_ids  # public EC2
    assert "CSPM-008" in rule_ids  # disabled CloudTrail


def test_secure_example_has_no_findings():
    findings = scan_path(ROOT / "examples" / "secure")
    assert findings == []


def test_metrics_are_consistent():
    findings = scan_path(ROOT / "examples" / "insecure")
    metrics = posture_metrics(findings)

    assert metrics["total_findings"] == len(findings)
    assert sum(metrics["by_severity"].values()) == len(findings)
    assert 0 <= metrics["posture_score"] < 100


def test_findings_include_actionable_metadata():
    findings = scan_path(ROOT / "examples" / "insecure")
    assert findings
    for finding in findings:
        assert finding.rule_id.startswith("CSPM-")
        assert finding.resource_type
        assert finding.resource_name
        assert finding.file.endswith(".tf")
        assert finding.line >= 1
        assert finding.evidence
        assert finding.remediation
