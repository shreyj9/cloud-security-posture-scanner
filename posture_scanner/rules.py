from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .models import Finding, Severity
from .parser import ResourceBlock


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    resource_types: tuple[str, ...]
    remediation: str
    detector: Callable[[ResourceBlock], str | None]

    def evaluate(self, block: ResourceBlock) -> Finding | None:
        if block.resource_type not in self.resource_types:
            return None
        evidence = self.detector(block)
        if not evidence:
            return None
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            resource_type=block.resource_type,
            resource_name=block.resource_name,
            file=str(block.file),
            line=block.start_line,
            evidence=evidence,
            remediation=self.remediation,
        )


def _contains(pattern: str, body: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, body, flags=flags) is not None


def public_s3_acl(block: ResourceBlock) -> str | None:
    if _contains(r'\bacl\s*=\s*"(public-read|public-read-write|authenticated-read)"', block.body):
        return "S3 bucket uses a public or broadly accessible ACL"
    return None


def missing_s3_encryption(block: ResourceBlock) -> str | None:
    # For modern Terraform, encryption is often represented in a separate
    # aws_s3_bucket_server_side_encryption_configuration resource. This rule
    # intentionally flags an explicit insecure setting only, avoiding false claims.
    if _contains(r'\bserver_side_encryption_configuration\s*\{[^}]*\benabled\s*=\s*false', block.body):
        return "S3 bucket explicitly disables server-side encryption"
    return None


def open_security_group(block: ResourceBlock) -> str | None:
    if _contains(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', block.body):
        if _contains(r'from_port\s*=\s*(0|22|3389)', block.body) or _contains(r'to_port\s*=\s*(0|22|3389)', block.body):
            return "Security group allows world-accessible ingress to all or administrative ports"
        return "Security group allows ingress from 0.0.0.0/0"
    return None


def public_rds(block: ResourceBlock) -> str | None:
    if _contains(r'\bpublicly_accessible\s*=\s*true', block.body):
        return "RDS instance is publicly accessible"
    return None


def unencrypted_rds(block: ResourceBlock) -> str | None:
    if _contains(r'\bstorage_encrypted\s*=\s*false', block.body):
        return "RDS storage encryption is explicitly disabled"
    return None


def wildcard_iam(block: ResourceBlock) -> str | None:
    if _contains(r'"Action"\s*:\s*"\*"', block.body) or _contains(r'"Action"\s*:\s*\[\s*"\*"', block.body):
        return "IAM policy grants wildcard actions"
    if _contains(r'actions\s*=\s*\[[^\]]*"\*"', block.body):
        return "IAM policy grants wildcard actions"
    return None


def hardcoded_secret(block: ResourceBlock) -> str | None:
    patterns = [
        r'(?i)\b(password|secret|api_key|access_key)\s*=\s*"[^"${}][^"]{5,}"',
        r'AKIA[0-9A-Z]{16}',
    ]
    if any(_contains(p, block.body) for p in patterns):
        return "Resource contains a likely hardcoded credential or secret"
    return None


def public_ec2_ip(block: ResourceBlock) -> str | None:
    if _contains(r'\bassociate_public_ip_address\s*=\s*true', block.body):
        return "EC2 instance explicitly receives a public IP address"
    return None


def disabled_cloudtrail(block: ResourceBlock) -> str | None:
    if _contains(r'\benable_logging\s*=\s*false', block.body):
        return "CloudTrail logging is explicitly disabled"
    return None


RULES: tuple[Rule, ...] = (
    Rule(
        "CSPM-001",
        "Public S3 bucket ACL",
        Severity.CRITICAL,
        ("aws_s3_bucket",),
        "Use a private ACL and configure S3 Public Access Block controls.",
        public_s3_acl,
    ),
    Rule(
        "CSPM-002",
        "World-accessible security group ingress",
        Severity.CRITICAL,
        ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"),
        "Restrict ingress CIDRs to explicitly trusted networks and minimize exposed ports.",
        open_security_group,
    ),
    Rule(
        "CSPM-003",
        "Publicly accessible database",
        Severity.CRITICAL,
        ("aws_db_instance",),
        "Set publicly_accessible = false and place the database in private subnets.",
        public_rds,
    ),
    Rule(
        "CSPM-004",
        "Database storage encryption disabled",
        Severity.HIGH,
        ("aws_db_instance",),
        "Set storage_encrypted = true and use an approved KMS key where appropriate.",
        unencrypted_rds,
    ),
    Rule(
        "CSPM-005",
        "Wildcard IAM permissions",
        Severity.HIGH,
        ("aws_iam_policy", "aws_iam_role_policy"),
        "Replace wildcard actions with the minimum required actions and resources.",
        wildcard_iam,
    ),
    Rule(
        "CSPM-006",
        "Hardcoded secret",
        Severity.CRITICAL,
        (
            "aws_db_instance",
            "aws_instance",
            "aws_lambda_function",
            "aws_ecs_task_definition",
            "aws_iam_access_key",
        ),
        "Move secrets to a secret manager or encrypted CI/CD secret store and rotate exposed credentials.",
        hardcoded_secret,
    ),
    Rule(
        "CSPM-007",
        "EC2 instance assigned a public IP",
        Severity.MEDIUM,
        ("aws_instance",),
        "Prefer private subnets and controlled ingress through a load balancer, VPN, or bastion when needed.",
        public_ec2_ip,
    ),
    Rule(
        "CSPM-008",
        "CloudTrail logging disabled",
        Severity.HIGH,
        ("aws_cloudtrail",),
        "Enable CloudTrail logging and protect the destination log storage.",
        disabled_cloudtrail,
    ),
    Rule(
        "CSPM-009",
        "S3 server-side encryption explicitly disabled",
        Severity.HIGH,
        ("aws_s3_bucket",),
        "Enable server-side encryption using an approved encryption configuration.",
        missing_s3_encryption,
    ),
)
