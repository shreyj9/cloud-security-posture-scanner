from dataclasses import asdict, dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 10,
    Severity.CRITICAL: 20,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_name: str
    file: str
    line: int
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
