"""Core engine for CSPM.

Real detection logic over a normalized cloud config export. The export is a
JSON document with optional top-level keys: ``buckets``, ``security_groups``,
``iam_users``, ``iam_policies``. Each check is deterministic and offline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Iterable

# Severity ranking (higher = worse) used for sorting and exit decisions.
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# CIDRs that mean "the entire internet".
_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}

# Ports that should never be world-open.
_SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    1433: "MSSQL",
    2375: "Docker API",
}


@dataclass
class Finding:
    """A single posture finding."""

    check_id: str
    severity: str
    resource: str
    title: str
    detail: str
    recommendation: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def load_config(path: str) -> dict:
    """Load a config export from a JSON file path."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("config export must be a JSON object at top level")
    return data


def _ports_in_rule(rule: dict) -> Iterable[int]:
    """Yield the integer ports covered by a security-group ingress rule."""
    if "port" in rule and rule["port"] is not None:
        try:
            yield int(rule["port"])
        except (TypeError, ValueError):
            return
        return
    lo = rule.get("from_port")
    hi = rule.get("to_port")
    if lo is None and hi is None:
        return
    try:
        lo_i = int(lo if lo is not None else hi)
        hi_i = int(hi if hi is not None else lo)
    except (TypeError, ValueError):
        return
    if lo_i > hi_i:
        lo_i, hi_i = hi_i, lo_i
    # Cap the explicit enumeration; very wide ranges are summarized separately.
    if hi_i - lo_i > 1024:
        return
    yield from range(lo_i, hi_i + 1)


def _check_buckets(buckets: list) -> list[Finding]:
    findings: list[Finding] = []
    for b in buckets:
        if not isinstance(b, dict):
            continue
        name = str(b.get("name", "<unknown-bucket>"))
        acl = str(b.get("acl", "")).lower()
        public_access_block = bool(b.get("public_access_block", False))
        policy_public = bool(b.get("policy_public", False))
        encrypted = b.get("encryption") not in (None, "", "none", "None", False)
        versioning = bool(b.get("versioning", False))
        logging = bool(b.get("logging", False))

        is_public_acl = acl in {"public-read", "public-read-write", "public"}
        if (is_public_acl or policy_public) and not public_access_block:
            sev = "CRITICAL" if acl == "public-read-write" or policy_public else "HIGH"
            findings.append(Finding(
                check_id="S3_PUBLIC",
                severity=sev,
                resource=name,
                title="Storage bucket is publicly accessible",
                detail=(
                    f"Bucket '{name}' is exposed to the public internet "
                    f"(acl={acl or 'n/a'}, policy_public={policy_public})."
                ),
                recommendation=(
                    "Enable Public Access Block and remove public ACLs/policy "
                    "grants unless the bucket is an intentional CDN origin."
                ),
                evidence={"acl": acl, "policy_public": policy_public},
            ))
        if not encrypted:
            findings.append(Finding(
                check_id="S3_NO_ENCRYPTION",
                severity="MEDIUM",
                resource=name,
                title="Storage bucket has no default encryption",
                detail=f"Bucket '{name}' does not declare server-side encryption.",
                recommendation="Enable SSE (SSE-S3 or SSE-KMS) as the default.",
                evidence={"encryption": b.get("encryption")},
            ))
        if not versioning:
            findings.append(Finding(
                check_id="S3_NO_VERSIONING",
                severity="LOW",
                resource=name,
                title="Storage bucket versioning disabled",
                detail=f"Bucket '{name}' has versioning disabled (no ransomware/rollback safety).",
                recommendation="Enable object versioning for recovery and tamper resistance.",
                evidence={"versioning": versioning},
            ))
        if not logging:
            findings.append(Finding(
                check_id="S3_NO_LOGGING",
                severity="LOW",
                resource=name,
                title="Storage bucket access logging disabled",
                detail=f"Bucket '{name}' has no access logging configured.",
                recommendation="Enable server access logging to a dedicated log bucket.",
                evidence={"logging": logging},
            ))
    return findings


def _check_security_groups(groups: list) -> list[Finding]:
    findings: list[Finding] = []
    for sg in groups:
        if not isinstance(sg, dict):
            continue
        sg_id = str(sg.get("id", sg.get("name", "<unknown-sg>")))
        for rule in sg.get("ingress", []) or []:
            if not isinstance(rule, dict):
                continue
            cidr = str(rule.get("cidr", rule.get("source", "")))
            if cidr not in _WORLD_CIDRS:
                continue
            proto = str(rule.get("protocol", "tcp")).lower()
            ports = list(_ports_in_rule(rule))
            sensitive_hits = {p: _SENSITIVE_PORTS[p] for p in ports if p in _SENSITIVE_PORTS}
            wide_range = not ports and (rule.get("from_port") is not None or proto in {"-1", "all", "any"})
            if proto in {"-1", "all", "any"} or wide_range:
                findings.append(Finding(
                    check_id="SG_OPEN_ALL",
                    severity="CRITICAL",
                    resource=sg_id,
                    title="Security group allows all traffic from the internet",
                    detail=f"Ingress rule on '{sg_id}' opens all/many ports to {cidr}.",
                    recommendation="Restrict ingress to known CIDRs and specific ports.",
                    evidence={"cidr": cidr, "protocol": proto, "rule": rule},
                ))
                continue
            if sensitive_hits:
                for port, svc in sensitive_hits.items():
                    findings.append(Finding(
                        check_id="SG_OPEN_SENSITIVE",
                        severity="CRITICAL",
                        resource=sg_id,
                        title=f"{svc} port open to the internet",
                        detail=f"'{sg_id}' allows {cidr} to reach {svc} (port {port}/{proto}).",
                        recommendation=f"Limit port {port} to a VPN/bastion CIDR; never expose {svc} publicly.",
                        evidence={"cidr": cidr, "port": port, "service": svc},
                    ))
            elif ports:
                findings.append(Finding(
                    check_id="SG_OPEN_PORT",
                    severity="MEDIUM",
                    resource=sg_id,
                    title="Non-standard port open to the internet",
                    detail=f"'{sg_id}' allows {cidr} to ports {sorted(ports)} ({proto}).",
                    recommendation="Confirm these ports must be world-reachable; otherwise scope the CIDR.",
                    evidence={"cidr": cidr, "ports": sorted(ports)},
                ))
    return findings


def _statement_is_wildcard(stmt: dict) -> bool:
    if str(stmt.get("Effect", "")).lower() != "allow":
        return False
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    has_star_action = any(a == "*" or str(a).endswith(":*") for a in actions)
    has_star_resource = any(r == "*" for r in resources)
    return has_star_action and has_star_resource


def _check_iam(users: list, policies: list) -> list[Finding]:
    findings: list[Finding] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        name = str(u.get("name", "<unknown-user>"))
        if u.get("mfa_enabled") is False and u.get("console_access", True):
            findings.append(Finding(
                check_id="IAM_NO_MFA",
                severity="HIGH",
                resource=name,
                title="IAM user has console access without MFA",
                detail=f"User '{name}' can log in to the console but has no MFA device.",
                recommendation="Enforce MFA for all console users via an IAM policy.",
                evidence={"mfa_enabled": False},
            ))
        keys = u.get("access_keys", []) or []
        active = [k for k in keys if isinstance(k, dict) and k.get("active", True)]
        if len(active) >= 2:
            findings.append(Finding(
                check_id="IAM_MULTI_KEYS",
                severity="MEDIUM",
                resource=name,
                title="IAM user has multiple active access keys",
                detail=f"User '{name}' has {len(active)} active access keys.",
                recommendation="Keep at most one active key per user; rotate and remove extras.",
                evidence={"active_keys": len(active)},
            ))
        for k in active:
            age = k.get("age_days")
            if isinstance(age, (int, float)) and age > 90:
                findings.append(Finding(
                    check_id="IAM_STALE_KEY",
                    severity="MEDIUM",
                    resource=name,
                    title="IAM access key older than 90 days",
                    detail=f"User '{name}' has an access key {int(age)} days old.",
                    recommendation="Rotate access keys at least every 90 days.",
                    evidence={"age_days": age, "key_id": k.get("id")},
                ))
        if u.get("admin") and not (u.get("mfa_enabled")):
            findings.append(Finding(
                check_id="IAM_ADMIN_NO_MFA",
                severity="CRITICAL",
                resource=name,
                title="Administrator without MFA",
                detail=f"User '{name}' has admin privileges and no MFA.",
                recommendation="Immediately enforce MFA on all privileged identities.",
                evidence={"admin": True, "mfa_enabled": u.get("mfa_enabled")},
            ))

    for p in policies:
        if not isinstance(p, dict):
            continue
        pname = str(p.get("name", "<unknown-policy>"))
        doc = p.get("document", {}) or {}
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if isinstance(stmt, dict) and _statement_is_wildcard(stmt):
                findings.append(Finding(
                    check_id="IAM_WILDCARD_POLICY",
                    severity="HIGH",
                    resource=pname,
                    title="IAM policy grants Action:* on Resource:*",
                    detail=f"Policy '{pname}' allows all actions on all resources.",
                    recommendation="Scope the policy to least-privilege actions and resources.",
                    evidence={"statement": stmt},
                ))
                break
    return findings


def scan(config: dict) -> list[Finding]:
    """Run all checks over a config export and return sorted findings."""
    findings: list[Finding] = []
    findings += _check_buckets(config.get("buckets", []) or [])
    findings += _check_security_groups(config.get("security_groups", []) or [])
    findings += _check_iam(
        config.get("iam_users", []) or [],
        config.get("iam_policies", []) or [],
    )
    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.check_id, f.resource)
    )
    return findings


def summarize(findings: list[Finding]) -> dict:
    """Aggregate counts by severity."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "by_severity": counts,
        "worst": max((f.severity for f in findings),
                     key=lambda s: SEVERITY_ORDER.get(s, 0), default="INFO"),
    }
