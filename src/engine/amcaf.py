"""
AMCAF — Automated Multi-Cloud Compliance Assurance Framework
============================================================
Rule-based compliance validation engine for AWS, Azure and GCP.
Implements 9 control rules across IAM, encryption, logging and network domains.
Evaluated against 6 synthetic configuration scenarios (SC-01 to SC-06).

Usage:
    python amcaf.py                          # run all scenarios
    python amcaf.py --scenario SC-02         # run single scenario
    python amcaf.py --all --format json      # run all, output JSON to results/
    python amcaf.py --scenario SC-05 --format json
"""

import argparse
import json
import os
from datetime import datetime
from typing import Any

# ─────────────────────────────────────────────
# CONTROL LIBRARY
# ─────────────────────────────────────────────

CONTROL_LIBRARY = {
    "IAM-01": {
        "domain": "Identity & Access Management",
        "objective": "Privileged access restricted; least-privilege enforced",
        "regulatory_refs": ["NIST CSF PR.AC-4", "ISO 27001 A.9.2", "DORA Art. 9"],
    },
    "IAM-02": {
        "domain": "Identity & Access Management",
        "objective": "MFA enforced for all administrative access",
        "regulatory_refs": ["FCA PS21/3", "NIST CSF PR.AC-7", "ISO 27001 A.9.4"],
    },
    "IAM-03": {
        "domain": "Identity & Access Management",
        "objective": "Periodic access review enforced; dormant accounts disabled",
        "regulatory_refs": ["DORA Art. 9", "FCA PS21/3", "ISO 27001 A.9.2.5", "NIST CSF PR.AC-1"],
    },
    "ENC-01": {
        "domain": "Data Protection & Encryption",
        "objective": "Data at rest encrypted by default for all storage resources",
        "regulatory_refs": ["UK GDPR Art. 32", "ISO 27001 A.10.1", "NIST CSF PR.DS-1"],
    },
    "ENC-02": {
        "domain": "Data Protection & Encryption",
        "objective": "Data in transit protected; unencrypted protocols disabled",
        "regulatory_refs": ["UK GDPR Art. 32", "ISO 27001 A.10.1", "NIST CSF PR.DS-2"],
    },
    "LOG-01": {
        "domain": "Logging & Monitoring",
        "objective": "Management plane audit logging enabled in all regions",
        "regulatory_refs": ["DORA Art. 10", "FCA PS21/3", "ISO 27001 A.12.4"],
    },
    "LOG-02": {
        "domain": "Logging & Monitoring",
        "objective": "Audit log retention meets minimum period; tamper protection enabled",
        "regulatory_refs": ["DORA Art. 10", "FCA PS21/3", "ISO 27001 A.12.4.1", "UK GDPR Art. 5(2)"],
    },
    "NET-01": {
        "domain": "Network Security",
        "objective": "Default-deny network access; no unrestricted inbound rules",
        "regulatory_refs": ["NIST CSF PR.AC-5", "ISO 27001 A.13.1", "DORA Art. 9"],
    },
    "NET-03": {
        "domain": "Network Security",
        "objective": "Public management interfaces restricted to authorised sources",
        "regulatory_refs": ["FCA PS21/3", "NIST CSF PR.AC-5", "ISO 27001 A.9.1.2"],
    },
}

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

DORMANCY_THRESHOLD_DAYS   = 90   # accounts inactive beyond this are flagged
AWS_MIN_LOG_RETENTION     = 365  # minimum CloudTrail retention in days
AZURE_MIN_LOG_RETENTION   = 90   # minimum Log Analytics retention in days
MANAGEMENT_PORTS          = {22, 3389}

# ─────────────────────────────────────────────
# VALIDATION ENGINE — AWS
# ─────────────────────────────────────────────

def validate_aws(config: dict[str, Any]) -> list[dict]:
    results = []
    iam = config.get("iam", {})
    ct  = config.get("cloudtrail", {})
    ec2 = config.get("ec2", {})
    s3  = config.get("s3", {})

    # IAM-01: no wildcard actions in IAM policies
    has_wildcard = any(
        "*" in p.get("actions", [])
        for p in iam.get("policies", [])
    )
    results.append({
        "control_id": "IAM-01", "provider": "AWS",
        "status": "FAIL" if has_wildcard else "PASS",
        "detail": (
            "Wildcard (*) action found in IAM policy"
            if has_wildcard else
            "IAM policies comply with least-privilege requirement"
        ),
        "config_attribute": "iam.policies[].actions",
    })

    # IAM-02: MFA enabled for all IAM users
    mfa_disabled = [
        u["username"] for u in iam.get("users", [])
        if not u.get("mfa_enabled", False)
    ]
    results.append({
        "control_id": "IAM-02", "provider": "AWS",
        "status": "FAIL" if mfa_disabled else "PASS",
        "detail": (
            f"MFA not enabled for: {mfa_disabled}"
            if mfa_disabled else
            "MFA enabled for all IAM users"
        ),
        "config_attribute": "iam.users[].mfa_enabled",
    })

    # IAM-03: dormant account detection (>90 days or never used)
    dormant = [
        u["username"] for u in iam.get("users", [])
        if u.get("last_used_days") is None
        or u.get("last_used_days", 0) > DORMANCY_THRESHOLD_DAYS
    ]
    results.append({
        "control_id": "IAM-03", "provider": "AWS",
        "status": "FAIL" if dormant else "PASS",
        "detail": (
            f"Dormant or unused accounts detected: {dormant}"
            if dormant else
            "No dormant accounts found; all users active within 90 days"
        ),
        "config_attribute": "iam.users[].last_used_days",
    })

    # ENC-01: S3 default encryption enabled
    unencrypted = [
        b["name"] for b in s3.get("buckets", [])
        if not b.get("default_encryption_enabled", False)
    ]
    results.append({
        "control_id": "ENC-01", "provider": "AWS",
        "status": "FAIL" if unencrypted else "PASS",
        "detail": (
            f"Encryption disabled on buckets: {unencrypted}"
            if unencrypted else
            "All S3 buckets have default encryption enabled"
        ),
        "config_attribute": "s3.buckets[].default_encryption_enabled",
    })

    # LOG-01: CloudTrail logging active on all trails
    inactive = [
        t["name"] for t in ct.get("trails", [])
        if not t.get("is_logging", False)
    ]
    results.append({
        "control_id": "LOG-01", "provider": "AWS",
        "status": "FAIL" if inactive else "PASS",
        "detail": (
            f"CloudTrail logging inactive for: {inactive}"
            if inactive else
            "CloudTrail logging active across all configured trails"
        ),
        "config_attribute": "cloudtrail.trails[].is_logging",
    })

    # LOG-02: log file validation + S3 Object Lock + retention >= 365 days
    log02_failures = []
    if not ct.get("log_file_validation_enabled", False):
        log02_failures.append("log file validation not enabled")
    if not ct.get("s3_object_lock_enabled", False):
        log02_failures.append("S3 Object Lock not configured on log bucket")
    retention = ct.get("retention_days", 0)
    if retention < AWS_MIN_LOG_RETENTION:
        log02_failures.append(
            f"retention period {retention} days is below {AWS_MIN_LOG_RETENTION}-day minimum"
        )
    results.append({
        "control_id": "LOG-02", "provider": "AWS",
        "status": "FAIL" if log02_failures else "PASS",
        "detail": (
            f"Log integrity/retention failures: {'; '.join(log02_failures)}"
            if log02_failures else
            "Log file validation enabled; S3 Object Lock configured; retention >= 365 days"
        ),
        "config_attribute": (
            "cloudtrail.log_file_validation_enabled | "
            "cloudtrail.s3_object_lock_enabled | "
            "cloudtrail.retention_days"
        ),
    })

    # NET-01 / NET-03: no security group permits 0.0.0.0/0 inbound
    open_sgs, open_mgmt_sgs = [], []
    for sg in ec2.get("security_groups", []):
        for rule in sg.get("inbound_rules", []):
            if rule.get("cidr") == "0.0.0.0/0":
                open_sgs.append(sg["group_id"])
                if rule.get("port") in MANAGEMENT_PORTS:
                    open_mgmt_sgs.append(f"{sg['group_id']} port {rule['port']}")

    results.append({
        "control_id": "NET-01", "provider": "AWS",
        "status": "FAIL" if open_sgs else "PASS",
        "detail": (
            f"Unrestricted inbound (0.0.0.0/0) on SGs: {open_sgs}"
            if open_sgs else
            "No security groups permit unrestricted inbound access"
        ),
        "config_attribute": "ec2.security_groups[].inbound_rules",
    })
    results.append({
        "control_id": "NET-03", "provider": "AWS",
        "status": "FAIL" if open_mgmt_sgs else "PASS",
        "detail": (
            f"Public management port exposure: {open_mgmt_sgs}"
            if open_mgmt_sgs else
            "No management ports (22/3389) exposed to 0.0.0.0/0"
        ),
        "config_attribute": "ec2.security_groups[].inbound_rules[port=22|3389]",
    })

    return results


# ─────────────────────────────────────────────
# VALIDATION ENGINE — AZURE
# ─────────────────────────────────────────────

def validate_azure(config: dict[str, Any]) -> list[dict]:
    results = []
    ca      = config.get("conditional_access", {})
    storage = config.get("storage_accounts", [])
    diag    = config.get("diagnostic_settings", {})

    # IAM-02: MFA via Conditional Access policy
    mfa_active = ca.get("mfa_policy_enabled", False)
    results.append({
        "control_id": "IAM-02", "provider": "Azure",
        "status": "PASS" if mfa_active else "FAIL",
        "detail": (
            "Conditional Access MFA policy is active"
            if mfa_active else
            "No active Conditional Access policy enforcing MFA"
        ),
        "config_attribute": "conditional_access.mfa_policy_enabled",
    })

    # ENC-02: minimum TLS 1.2 on storage accounts
    weak_tls = [
        s["name"] for s in storage
        if s.get("minimum_tls_version", "TLS1_0") in ("TLS1_0", "TLS1_1")
    ]
    results.append({
        "control_id": "ENC-02", "provider": "Azure",
        "status": "FAIL" if weak_tls else "PASS",
        "detail": (
            f"Weak TLS (<1.2) on storage accounts: {weak_tls}"
            if weak_tls else
            "All storage accounts enforce minimum TLS 1.2"
        ),
        "config_attribute": "storage_accounts[].minimum_tls_version",
    })

    # LOG-01: Activity Log diagnostic settings configured
    activity_log = diag.get("activity_log_enabled", False)
    results.append({
        "control_id": "LOG-01", "provider": "Azure",
        "status": "PASS" if activity_log else "FAIL",
        "detail": (
            "Activity Log diagnostic settings configured"
            if activity_log else
            "Azure Activity Log not routed to Log Analytics Workspace"
        ),
        "config_attribute": "diagnostic_settings.activity_log_enabled",
    })

    # LOG-02: retention >= 90 days + immutable storage
    log02_failures = []
    retention = diag.get("log_retention_days", 0)
    if retention < AZURE_MIN_LOG_RETENTION:
        log02_failures.append(
            f"Log Analytics retention {retention} days is below {AZURE_MIN_LOG_RETENTION}-day minimum"
        )
    if not diag.get("immutable_storage_enabled", False):
        log02_failures.append("immutable log storage not enabled on workspace")
    results.append({
        "control_id": "LOG-02", "provider": "Azure",
        "status": "FAIL" if log02_failures else "PASS",
        "detail": (
            f"Log retention/integrity failures: {'; '.join(log02_failures)}"
            if log02_failures else
            "Log Analytics retention >= 90 days; immutable storage enabled"
        ),
        "config_attribute": (
            "diagnostic_settings.log_retention_days | "
            "diagnostic_settings.immutable_storage_enabled"
        ),
    })

    return results


# ─────────────────────────────────────────────
# VALIDATION ENGINE — GCP
# ─────────────────────────────────────────────

def validate_gcp(config: dict[str, Any]) -> list[dict]:
    results = []
    gcs   = config.get("cloud_storage", {})
    audit = config.get("audit_logs", {})
    iam   = config.get("iam", {})
    vpc   = config.get("vpc", {})

    # NET-01: no GCS buckets with public access enabled
    # Note: classified as NET-01 rather than ENC-01 because
    # public_access_prevention is a network-layer boundary control
    # in GCP's service model, not an encryption control.
    public_buckets = [
        b["name"] for b in gcs.get("buckets", [])
        if b.get("public_access_prevention") != "enforced"
        and not b.get("uniform_bucket_level_access", False)
    ]
    results.append({
        "control_id": "NET-01", "provider": "GCP",
        "status": "FAIL" if public_buckets else "PASS",
        "detail": (
            f"Buckets with potential public access: {public_buckets}"
            if public_buckets else
            "All GCS buckets have public access prevention enforced"
        ),
        "config_attribute": "cloud_storage.buckets[].public_access_prevention",
    })

    # LOG-01: Admin Activity audit logs enabled
    admin_logs = audit.get("admin_activity_enabled", False)
    results.append({
        "control_id": "LOG-01", "provider": "GCP",
        "status": "PASS" if admin_logs else "FAIL",
        "detail": (
            "Admin Activity audit logging is enabled"
            if admin_logs else
            "Admin Activity audit logs are disabled or not configured"
        ),
        "config_attribute": "audit_logs.admin_activity_enabled",
    })

    # IAM-03: dormant service account detection
    dormant_sa = [
        sa["name"] for sa in iam.get("service_accounts", [])
        if sa.get("last_used_days") is None
        or sa.get("last_used_days", 0) > DORMANCY_THRESHOLD_DAYS
    ]
    results.append({
        "control_id": "IAM-03", "provider": "GCP",
        "status": "FAIL" if dormant_sa else "PASS",
        "detail": (
            f"Dormant service accounts detected: {dormant_sa}"
            if dormant_sa else
            "No dormant service accounts; all active within 90 days"
        ),
        "config_attribute": "iam.service_accounts[].last_used_days",
    })

    # NET-03: no VPC firewall rules permitting all inbound traffic
    open_rules = [
        r["name"] for r in vpc.get("firewall_rules", [])
        if r.get("source_ranges") == ["0.0.0.0/0"]
        and r.get("action") == "allow"
        and r.get("ports") in ([], ["all"])
    ]
    results.append({
        "control_id": "NET-03", "provider": "GCP",
        "status": "FAIL" if open_rules else "PASS",
        "detail": (
            f"Overly permissive firewall rules: {open_rules}"
            if open_rules else
            "No firewall rules permitting all inbound traffic"
        ),
        "config_attribute": "vpc.firewall_rules[].source_ranges + action",
    })

    return results


# ─────────────────────────────────────────────
# REPORTING MODULE
# ─────────────────────────────────────────────

def generate_report(all_results: list[dict]) -> dict:
    total  = len(all_results)
    passed = sum(1 for r in all_results if r["status"] == "PASS")
    failed = total - passed

    findings = []
    for r in all_results:
        ctrl = CONTROL_LIBRARY.get(r["control_id"], {})
        findings.append({
            "control_id":       r["control_id"],
            "provider":         r["provider"],
            "domain":           ctrl.get("domain", "Unknown"),
            "objective":        ctrl.get("objective", "Unknown"),
            "regulatory_refs":  ctrl.get("regulatory_refs", []),
            "status":           r["status"],
            "detail":           r["detail"],
            "config_attribute": r.get("config_attribute", ""),
        })

    return {
        "report_metadata": {
            "framework":       "AMCAF v1.0",
            "generated_at":    datetime.utcnow().isoformat() + "Z",
            "total_checks":    total,
            "passed":          passed,
            "failed":          failed,
            "compliance_rate": f"{round((passed / total) * 100, 1)}%" if total else "0%",
        },
        "findings": findings,
    }


# ─────────────────────────────────────────────
# SCENARIO RUNNER
# ─────────────────────────────────────────────

def run_scenario(
    scenario_id: str,
    aws_cfg: dict,
    azure_cfg: dict,
    gcp_cfg: dict,
) -> dict:
    print(f"\n{'='*60}")
    print(f"  Scenario: {scenario_id}")
    print(f"{'='*60}")

    all_results = (
        validate_aws(aws_cfg)
        + validate_azure(azure_cfg)
        + validate_gcp(gcp_cfg)
    )

    report = generate_report(all_results)
    meta   = report["report_metadata"]

    print(f"  Total checks : {meta['total_checks']}")
    print(f"  Passed       : {meta['passed']}")
    print(f"  Failed       : {meta['failed']}")
    print(f"  Compliance   : {meta['compliance_rate']}")
    print()

    for f in report["findings"]:
        flag = "✓" if f["status"] == "PASS" else "✗"
        print(
            f"  {flag} [{f['control_id']}] {f['provider']:6s} "
            f"{f['status']:4s}  {f['detail']}"
        )
        if f["status"] == "FAIL":
            print(f"       Regulatory refs: {', '.join(f['regulatory_refs'])}")
            print(f"       Config attr    : {f['config_attribute']}")

    return report


# ─────────────────────────────────────────────
# SCENARIO DATA
# ─────────────────────────────────────────────

sc01_aws = {
    "iam": {
        "policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}],
        "users": [
            {"username": "ops-user",   "mfa_enabled": True, "last_used_days": 5},
            {"username": "admin-user", "mfa_enabled": True, "last_used_days": 12},
        ],
    },
    "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]},
    "cloudtrail": {
        "trails": [{"name": "mgmt-trail", "is_logging": True}],
        "log_file_validation_enabled": True,
        "s3_object_lock_enabled": True,
        "retention_days": 365,
    },
    "ec2": {"security_groups": []},
}
sc01_azure = {
    "conditional_access": {"mfa_policy_enabled": True},
    "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}],
    "diagnostic_settings": {
        "activity_log_enabled": True,
        "log_retention_days": 90,
        "immutable_storage_enabled": True,
    },
}
sc01_gcp = {
    "cloud_storage": {"buckets": [{"name": "gs-prod", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]},
    "audit_logs": {"admin_activity_enabled": True},
    "iam": {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 14}]},
    "vpc": {"firewall_rules": []},
}

sc02_aws = {
    "iam": {
        "policies": [{"name": "AdminPolicy", "actions": ["*"]}],
        "users": [
            {"username": "svc-deploy", "mfa_enabled": True, "last_used_days": 3},
            {"username": "admin-user", "mfa_enabled": True, "last_used_days": 7},
        ],
    },
    "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]},
    "cloudtrail": {
        "trails": [{"name": "mgmt-trail", "is_logging": True}],
        "log_file_validation_enabled": True,
        "s3_object_lock_enabled": True,
        "retention_days": 365,
    },
    "ec2": {"security_groups": []},
}
sc02_azure = {
    "conditional_access": {"mfa_policy_enabled": False},
    "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}],
    "diagnostic_settings": {"activity_log_enabled": True, "log_retention_days": 90, "immutable_storage_enabled": True},
}
sc02_gcp = {
    "cloud_storage": {"buckets": [{"name": "gs-prod", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]},
    "audit_logs": {"admin_activity_enabled": True},
    "iam": {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 10}]},
    "vpc": {"firewall_rules": []},
}

sc03_aws = {
    "iam": {
        "policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}],
        "users": [{"username": "ops-user", "mfa_enabled": True, "last_used_days": 4}],
    },
    "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": False}]},
    "cloudtrail": {
        "trails": [{"name": "mgmt-trail", "is_logging": True}],
        "log_file_validation_enabled": True,
        "s3_object_lock_enabled": True,
        "retention_days": 365,
    },
    "ec2": {"security_groups": []},
}
sc03_azure = {
    "conditional_access": {"mfa_policy_enabled": True},
    "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_0"}],
    "diagnostic_settings": {"activity_log_enabled": True, "log_retention_days": 90, "immutable_storage_enabled": True},
}
sc03_gcp = {
    "cloud_storage": {"buckets": [{"name": "gs-prod", "public_access_prevention": "unspecified", "uniform_bucket_level_access": False}]},
    "audit_logs": {"admin_activity_enabled": True},
    "iam": {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 20}]},
    "vpc": {"firewall_rules": []},
}

sc04_aws = {
    "iam": {
        "policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}],
        "users": [{"username": "ops-user", "mfa_enabled": True, "last_used_days": 5}],
    },
    "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]},
    "cloudtrail": {
        "trails": [{"name": "mgmt-trail", "is_logging": False}],
        "log_file_validation_enabled": True,
        "s3_object_lock_enabled": True,
        "retention_days": 365,
    },
    "ec2": {"security_groups": []},
}
sc04_azure = {
    "conditional_access": {"mfa_policy_enabled": True},
    "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}],
    "diagnostic_settings": {"activity_log_enabled": False, "log_retention_days": 90, "immutable_storage_enabled": True},
}
sc04_gcp = {
    "cloud_storage": {"buckets": [{"name": "gs-prod", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]},
    "audit_logs": {"admin_activity_enabled": False},
    "iam": {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 8}]},
    "vpc": {"firewall_rules": []},
}

sc05_aws = {
    "iam": {
        "policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}],
        "users": [{"username": "ops-user", "mfa_enabled": True, "last_used_days": 6}],
    },
    "s3": {"buckets": [{"name": "logs", "default_encryption_enabled": True}]},
    "cloudtrail": {
        "trails": [{"name": "all-regions", "is_logging": True}],
        "log_file_validation_enabled": True,
        "s3_object_lock_enabled": True,
        "retention_days": 365,
    },
    "ec2": {
        "security_groups": [{
            "group_id": "sg-0abc123",
            "inbound_rules": [
                {"cidr": "0.0.0.0/0", "port": 22,  "protocol": "tcp"},
                {"cidr": "10.0.0.0/8","port": 443, "protocol": "tcp"},
            ],
        }]
    },
}
sc05_azure = {
    "conditional_access": {"mfa_policy_enabled": True},
    "storage_accounts": [{"name": "auditlogs01", "minimum_tls_version": "TLS1_2"}],
    "diagnostic_settings": {"activity_log_enabled": True, "log_retention_days": 90, "immutable_storage_enabled": True},
}
sc05_gcp = {
    "cloud_storage": {"buckets": [{"name": "backup-bucket", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]},
    "audit_logs": {"admin_activity_enabled": True},
    "iam": {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 15}]},
    "vpc": {
        "firewall_rules": [{
            "name": "allow-all-inbound",
            "source_ranges": ["0.0.0.0/0"],
            "action": "allow",
            "ports": ["all"],
        }]
    },
}

sc06_aws = {
    "iam": {
        "policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}],
        "users": [
            {"username": "ops-user",     "mfa_enabled": True, "last_used_days": 12},
            {"username": "svc-legacy",   "mfa_enabled": True, "last_used_days": 142},
            {"username": "audit-reader", "mfa_enabled": True, "last_used_days": None},
        ],
    },
    "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]},
    "cloudtrail": {
        "trails": [{"name": "mgmt-trail", "is_logging": True}],
        "log_file_validation_enabled": True,
        "s3_object_lock_enabled": False,
        "retention_days": 180,
    },
    "ec2": {"security_groups": []},
}
sc06_azure = {
    "conditional_access": {"mfa_policy_enabled": True},
    "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}],
    "diagnostic_settings": {"activity_log_enabled": True, "log_retention_days": 60, "immutable_storage_enabled": True},
}
sc06_gcp = {
    "cloud_storage": {"buckets": [{"name": "gs-prod", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]},
    "audit_logs": {"admin_activity_enabled": True},
    "iam": {
        "service_accounts": [
            {"name": "svc-dataflow@proj.iam", "last_used_days": 30},
            {"name": "svc-archive@proj.iam",  "last_used_days": 210},
        ]
    },
    "vpc": {"firewall_rules": []},
}


# ─────────────────────────────────────────────
# SCENARIO REGISTRY
# Add new scenarios here — no other changes needed.
# ─────────────────────────────────────────────

SCENARIOS: dict[str, tuple] = {
    "SC-01": ("SC-01: Fully Compliant Baseline",                                              sc01_aws, sc01_azure, sc01_gcp),
    "SC-02": ("SC-02: Over-privileged IAM (AWS) / MFA Disabled (Azure)",                      sc02_aws, sc02_azure, sc02_gcp),
    "SC-03": ("SC-03: Encryption Disabled (AWS) / Weak TLS (Azure) / Public Bucket (GCP)",    sc03_aws, sc03_azure, sc03_gcp),
    "SC-04": ("SC-04: Logging Disabled (All Providers)",                                       sc04_aws, sc04_azure, sc04_gcp),
    "SC-05": ("SC-05: Open SSH (AWS) / Permissive Firewall (GCP)",                            sc05_aws, sc05_azure, sc05_gcp),
    "SC-06": ("SC-06: Dormant Accounts (AWS, GCP) / Insufficient Log Retention (AWS, Azure)", sc06_aws, sc06_azure, sc06_gcp),
}


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AMCAF — Automated Multi-Cloud Compliance Assurance Framework"
    )
    parser.add_argument(
        "--scenario",
        default="ALL",
        choices=["ALL"] + list(SCENARIOS.keys()),
        help="Scenario to run (default: ALL)",
    )
    parser.add_argument(
        "--format",
        default="console",
        choices=["console", "json"],
        help="Output format: console (default) or json",
    )
    args = parser.parse_args()

    to_run = (
        list(SCENARIOS.values())
        if args.scenario == "ALL"
        else [SCENARIOS[args.scenario]]
    )

    if args.format == "json":
        os.makedirs("results", exist_ok=True)

    for label, aws_cfg, azure_cfg, gcp_cfg in to_run:
        report = run_scenario(label, aws_cfg, azure_cfg, gcp_cfg)

        if args.format == "json":
            sc_id    = label.split(":")[0].strip().lower()  # e.g. "sc-01"
            out_path = f"results/{sc_id}.json"
            with open(out_path, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"  Results written to {out_path}\n")

    # write a combined summary file for the dashboard
    if args.format == "json" and args.scenario == "ALL":
        summary = []
        for sc_id in [k.lower() for k in SCENARIOS.keys()]:
            path = f"results/{sc_id}.json"
            if os.path.exists(path):
                with open(path) as fh:
                    summary.append(json.load(fh))
        with open("results/summary.json", "w") as fh:
            json.dump(summary, fh, indent=2)
        print("  Combined summary written to results/summary.json")