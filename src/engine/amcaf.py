"""
AMCAF — Automated Multi-Cloud Compliance Assurance Framework
============================================================
Rule-based compliance validation engine for AWS, Azure and GCP.
Implements all 15 control rules across IAM, encryption, logging,
network and operational resilience domains.
Evaluated against 8 synthetic configuration scenarios (SC-01 to SC-08).

Usage:
    python amcaf.py                          # run all scenarios
    python amcaf.py --scenario SC-02         # run single scenario
    python amcaf.py --scenario CUSTOM        # run custom scenario
    python amcaf.py --all --format json      # run all, output JSON to results/
"""

import argparse
import json
import os
import sys
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
    "ENC-03": {
        "domain": "Data Protection & Encryption",
        "objective": "Customer-managed key rotation enforced across all key management services",
        "regulatory_refs": ["UK GDPR Art. 32", "ISO 27001 A.10.1", "NIST CSF PR.DS-1"],
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
    "LOG-03": {
        "domain": "Logging & Monitoring",
        "objective": "Real-time alerting configured for security events and anomalies",
        "regulatory_refs": ["DORA Art. 10", "FCA PS21/3", "ISO 27001 A.12.4", "NIST CSF DE.AE-1"],
    },
    "NET-01": {
        "domain": "Network Security",
        "objective": "Default-deny network access; no unrestricted inbound rules",
        "regulatory_refs": ["NIST CSF PR.AC-5", "ISO 27001 A.13.1", "DORA Art. 9"],
    },
    "NET-02": {
        "domain": "Network Security",
        "objective": "Network segmentation enforced by workload sensitivity classification",
        "regulatory_refs": ["NIST CSF PR.AC-5", "ISO 27001 A.13.1", "DORA Art. 9"],
    },
    "NET-03": {
        "domain": "Network Security",
        "objective": "Public management interfaces restricted to authorised sources",
        "regulatory_refs": ["FCA PS21/3", "NIST CSF PR.AC-5", "ISO 27001 A.9.1.2"],
    },
    "RES-01": {
        "domain": "Operational Resilience",
        "objective": "Automated backups configured with defined retention and RPO",
        "regulatory_refs": ["DORA Art. 12", "FCA PS21/3", "ISO 27001 A.17.1", "NIST CSF PR.IP-4"],
    },
    "RES-02": {
        "domain": "Operational Resilience",
        "objective": "Infrastructure-as-code enforced; configuration drift continuously detected",
        "regulatory_refs": ["DORA Art. 9", "FCA PS21/3", "ISO 27001 A.12.1", "NIST CSF PR.IP-1"],
    },
    "RES-03": {
        "domain": "Operational Resilience",
        "objective": "Centralised security findings aggregation and remediation tracking enabled",
        "regulatory_refs": ["DORA Art. 10", "FCA PS21/3", "ISO 27001 A.16.1", "NIST CSF RS.AN-1"],
    },
}

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

DORMANCY_THRESHOLD_DAYS = 90
AWS_MIN_LOG_RETENTION   = 365
AZURE_MIN_LOG_RETENTION = 90
MIN_BACKUP_RETENTION    = 30
MIN_VPCS                = 2
MANAGEMENT_PORTS        = {22, 3389}

# ─────────────────────────────────────────────
# VALIDATION ENGINE — AWS
# ─────────────────────────────────────────────

def validate_aws(config: dict[str, Any]) -> list[dict]:
    results = []
    iam        = config.get("iam", {})
    ct         = config.get("cloudtrail", {})
    ec2        = config.get("ec2", {})
    s3         = config.get("s3", {})
    kms        = config.get("kms", {})
    monitoring = config.get("monitoring", {})
    vpc        = config.get("vpc", {})
    backup     = config.get("backup", {})
    aws_config = config.get("aws_config", {})
    sec_hub    = config.get("security_hub", {})

    # IAM-01: no wildcard actions in IAM policies
    has_wildcard = any("*" in p.get("actions", []) for p in iam.get("policies", []))
    results.append({
        "control_id": "IAM-01", "provider": "AWS",
        "status": "FAIL" if has_wildcard else "PASS",
        "detail": ("Wildcard (*) action found in IAM policy" if has_wildcard
                   else "IAM policies comply with least-privilege requirement"),
        "config_attribute": "iam.policies[].actions",
    })

    # IAM-02: MFA enabled for all IAM users
    mfa_disabled = [u["username"] for u in iam.get("users", [])
                    if not u.get("mfa_enabled", False)]
    results.append({
        "control_id": "IAM-02", "provider": "AWS",
        "status": "FAIL" if mfa_disabled else "PASS",
        "detail": (f"MFA not enabled for: {mfa_disabled}" if mfa_disabled
                   else "MFA enabled for all IAM users"),
        "config_attribute": "iam.users[].mfa_enabled",
    })

    # IAM-03: dormant account detection
    dormant = [u["username"] for u in iam.get("users", [])
               if u.get("last_used_days") is None
               or u.get("last_used_days", 0) > DORMANCY_THRESHOLD_DAYS]
    results.append({
        "control_id": "IAM-03", "provider": "AWS",
        "status": "FAIL" if dormant else "PASS",
        "detail": (f"Dormant or unused accounts detected: {dormant}" if dormant
                   else "No dormant accounts found; all users active within 90 days"),
        "config_attribute": "iam.users[].last_used_days",
    })

    # ENC-01: S3 default encryption
    unencrypted = [b["name"] for b in s3.get("buckets", [])
                   if not b.get("default_encryption_enabled", False)]
    results.append({
        "control_id": "ENC-01", "provider": "AWS",
        "status": "FAIL" if unencrypted else "PASS",
        "detail": (f"Encryption disabled on buckets: {unencrypted}" if unencrypted
                   else "All S3 buckets have default encryption enabled"),
        "config_attribute": "s3.buckets[].default_encryption_enabled",
    })

    # ENC-02 — not evaluated on AWS in this mapping (Azure handles TLS)

    # ENC-03: KMS key rotation
    rotation_disabled = [k["key_id"] for k in kms.get("keys", [])
                         if not k.get("rotation_enabled", False)]
    results.append({
        "control_id": "ENC-03", "provider": "AWS",
        "status": "FAIL" if rotation_disabled else "PASS",
        "detail": (f"Key rotation disabled for KMS keys: {rotation_disabled}" if rotation_disabled
                   else "Key rotation enabled for all customer-managed KMS keys"),
        "config_attribute": "kms.keys[].rotation_enabled",
    })

    # LOG-01: CloudTrail active on all trails
    inactive = [t["name"] for t in ct.get("trails", []) if not t.get("is_logging", False)]
    results.append({
        "control_id": "LOG-01", "provider": "AWS",
        "status": "FAIL" if inactive else "PASS",
        "detail": (f"CloudTrail logging inactive for: {inactive}" if inactive
                   else "CloudTrail logging active across all configured trails"),
        "config_attribute": "cloudtrail.trails[].is_logging",
    })

    # LOG-02: log file validation + S3 Object Lock + retention
    log02 = []
    if not ct.get("log_file_validation_enabled", False):
        log02.append("log file validation not enabled")
    if not ct.get("s3_object_lock_enabled", False):
        log02.append("S3 Object Lock not configured on log bucket")
    retention = ct.get("retention_days", 0)
    if retention < AWS_MIN_LOG_RETENTION:
        log02.append(f"retention {retention} days below {AWS_MIN_LOG_RETENTION}-day minimum")
    results.append({
        "control_id": "LOG-02", "provider": "AWS",
        "status": "FAIL" if log02 else "PASS",
        "detail": (f"Log integrity/retention failures: {'; '.join(log02)}" if log02
                   else "Log file validation enabled; S3 Object Lock configured; retention >= 365 days"),
        "config_attribute": "cloudtrail.log_file_validation_enabled | cloudtrail.s3_object_lock_enabled | cloudtrail.retention_days",
    })

    # LOG-03: CloudWatch alarms + Security Hub
    log03 = []
    if not monitoring.get("cloudwatch_alarms_enabled", False):
        log03.append("CloudWatch metric alarms not configured")
    if not monitoring.get("security_hub_enabled", False):
        log03.append("AWS Security Hub not enabled")
    results.append({
        "control_id": "LOG-03", "provider": "AWS",
        "status": "FAIL" if log03 else "PASS",
        "detail": (f"Real-time alerting gaps: {'; '.join(log03)}" if log03
                   else "CloudWatch alarms and Security Hub enabled for real-time alerting"),
        "config_attribute": "monitoring.cloudwatch_alarms_enabled | monitoring.security_hub_enabled",
    })

    # NET-01 + NET-03: no security group permits 0.0.0.0/0 inbound
    open_sgs, open_mgmt = [], []
    for sg in ec2.get("security_groups", []):
        for rule in sg.get("inbound_rules", []):
            if rule.get("cidr") == "0.0.0.0/0":
                open_sgs.append(sg["group_id"])
                if rule.get("port") in MANAGEMENT_PORTS:
                    open_mgmt.append(f"{sg['group_id']} port {rule['port']}")
    results.append({
        "control_id": "NET-01", "provider": "AWS",
        "status": "FAIL" if open_sgs else "PASS",
        "detail": (f"Unrestricted inbound (0.0.0.0/0) on SGs: {open_sgs}" if open_sgs
                   else "No security groups permit unrestricted inbound access"),
        "config_attribute": "ec2.security_groups[].inbound_rules",
    })
    results.append({
        "control_id": "NET-03", "provider": "AWS",
        "status": "FAIL" if open_mgmt else "PASS",
        "detail": (f"Public management port exposure: {open_mgmt}" if open_mgmt
                   else "No management ports (22/3389) exposed to 0.0.0.0/0"),
        "config_attribute": "ec2.security_groups[].inbound_rules[port=22|3389]",
    })

    # NET-02: VPC segmentation
    vpc_count = len(vpc.get("vpcs", []))
    results.append({
        "control_id": "NET-02", "provider": "AWS",
        "status": "FAIL" if vpc_count < MIN_VPCS else "PASS",
        "detail": (f"Only {vpc_count} VPC(s) found; minimum {MIN_VPCS} required for workload segmentation"
                   if vpc_count < MIN_VPCS
                   else f"{vpc_count} VPCs present; workload segmentation requirements met"),
        "config_attribute": "vpc.vpcs[]",
    })

    # RES-01: AWS Backup plan
    res01 = []
    if not backup.get("backup_plan_enabled", False):
        res01.append("no AWS Backup plan configured")
    if backup.get("retention_days", 0) < MIN_BACKUP_RETENTION:
        res01.append(f"retention {backup.get('retention_days',0)} days below {MIN_BACKUP_RETENTION}-day minimum")
    results.append({
        "control_id": "RES-01", "provider": "AWS",
        "status": "FAIL" if res01 else "PASS",
        "detail": (f"Backup configuration failures: {'; '.join(res01)}" if res01
                   else f"AWS Backup plan active; retention >= {MIN_BACKUP_RETENTION} days"),
        "config_attribute": "backup.backup_plan_enabled | backup.retention_days",
    })

    # RES-02: AWS Config + drift detection
    res02 = []
    if not aws_config.get("config_rules_enabled", False):
        res02.append("AWS Config rules not enabled")
    if not aws_config.get("drift_detection_enabled", False):
        res02.append("CloudFormation drift detection not enabled")
    results.append({
        "control_id": "RES-02", "provider": "AWS",
        "status": "FAIL" if res02 else "PASS",
        "detail": (f"Configuration drift gaps: {'; '.join(res02)}" if res02
                   else "AWS Config rules active; CloudFormation drift detection enabled"),
        "config_attribute": "aws_config.config_rules_enabled | aws_config.drift_detection_enabled",
    })

    # RES-03: Security Hub centralised findings
    results.append({
        "control_id": "RES-03", "provider": "AWS",
        "status": "PASS" if sec_hub.get("enabled", False) else "FAIL",
        "detail": ("AWS Security Hub enabled; centralised findings aggregation active"
                   if sec_hub.get("enabled", False)
                   else "AWS Security Hub not enabled; no centralised findings aggregation"),
        "config_attribute": "security_hub.enabled",
    })

    return results


# ─────────────────────────────────────────────
# VALIDATION ENGINE — AZURE
# ─────────────────────────────────────────────

def validate_azure(config: dict[str, Any]) -> list[dict]:
    results = []
    ca        = config.get("conditional_access", {})
    storage   = config.get("storage_accounts", [])
    diag      = config.get("diagnostic_settings", {})
    key_vault = config.get("key_vault", {})
    defender  = config.get("defender_for_cloud", {})
    network   = config.get("network", {})
    backup    = config.get("backup", {})
    policy    = config.get("azure_policy", {})

    # IAM-02: MFA via Conditional Access
    mfa = ca.get("mfa_policy_enabled", False)
    results.append({
        "control_id": "IAM-02", "provider": "Azure",
        "status": "PASS" if mfa else "FAIL",
        "detail": ("Conditional Access MFA policy is active" if mfa
                   else "No active Conditional Access policy enforcing MFA"),
        "config_attribute": "conditional_access.mfa_policy_enabled",
    })

    # ENC-02: minimum TLS 1.2
    weak_tls = [s["name"] for s in storage
                if s.get("minimum_tls_version", "TLS1_0") in ("TLS1_0", "TLS1_1")]
    results.append({
        "control_id": "ENC-02", "provider": "Azure",
        "status": "FAIL" if weak_tls else "PASS",
        "detail": (f"Weak TLS (<1.2) on storage accounts: {weak_tls}" if weak_tls
                   else "All storage accounts enforce minimum TLS 1.2"),
        "config_attribute": "storage_accounts[].minimum_tls_version",
    })

    # ENC-03: Key Vault rotation policy
    rot_disabled = [k["name"] for k in key_vault.get("keys", [])
                    if not k.get("rotation_policy_enabled", False)]
    results.append({
        "control_id": "ENC-03", "provider": "Azure",
        "status": "FAIL" if rot_disabled else "PASS",
        "detail": (f"Key rotation policy not configured for: {rot_disabled}" if rot_disabled
                   else "Key rotation policy configured for all Key Vault keys"),
        "config_attribute": "key_vault.keys[].rotation_policy_enabled",
    })

    # LOG-01: Activity Log diagnostic settings
    activity = diag.get("activity_log_enabled", False)
    results.append({
        "control_id": "LOG-01", "provider": "Azure",
        "status": "PASS" if activity else "FAIL",
        "detail": ("Activity Log diagnostic settings configured" if activity
                   else "Azure Activity Log not routed to Log Analytics Workspace"),
        "config_attribute": "diagnostic_settings.activity_log_enabled",
    })

    # LOG-02: retention + immutable storage
    log02 = []
    retention = diag.get("log_retention_days", 0)
    if retention < AZURE_MIN_LOG_RETENTION:
        log02.append(f"Log Analytics retention {retention} days below {AZURE_MIN_LOG_RETENTION}-day minimum")
    if not diag.get("immutable_storage_enabled", False):
        log02.append("immutable log storage not enabled on workspace")
    results.append({
        "control_id": "LOG-02", "provider": "Azure",
        "status": "FAIL" if log02 else "PASS",
        "detail": (f"Log retention/integrity failures: {'; '.join(log02)}" if log02
                   else "Log Analytics retention >= 90 days; immutable storage enabled"),
        "config_attribute": "diagnostic_settings.log_retention_days | diagnostic_settings.immutable_storage_enabled",
    })

    # LOG-03: Defender alerts + Sentinel
    log03 = []
    if not defender.get("alerts_enabled", False):
        log03.append("Defender for Cloud alerts not enabled")
    if not defender.get("sentinel_integration", False):
        log03.append("Microsoft Sentinel integration not configured")
    results.append({
        "control_id": "LOG-03", "provider": "Azure",
        "status": "FAIL" if log03 else "PASS",
        "detail": (f"Real-time alerting gaps: {'; '.join(log03)}" if log03
                   else "Defender for Cloud alerts active; Sentinel integration configured"),
        "config_attribute": "defender_for_cloud.alerts_enabled | defender_for_cloud.sentinel_integration",
    })

    # NET-02: VNet segmentation
    vnet_count = len(network.get("vnets", []))
    results.append({
        "control_id": "NET-02", "provider": "Azure",
        "status": "FAIL" if vnet_count < MIN_VPCS else "PASS",
        "detail": (f"Only {vnet_count} VNet(s) found; minimum {MIN_VPCS} required for workload segmentation"
                   if vnet_count < MIN_VPCS
                   else f"{vnet_count} VNets present; workload segmentation requirements met"),
        "config_attribute": "network.vnets[]",
    })

    # RES-01: Azure Backup vault
    res01 = []
    if not backup.get("backup_vault_enabled", False):
        res01.append("no Azure Backup vault configured")
    if backup.get("retention_days", 0) < MIN_BACKUP_RETENTION:
        res01.append(f"retention {backup.get('retention_days',0)} days below {MIN_BACKUP_RETENTION}-day minimum")
    results.append({
        "control_id": "RES-01", "provider": "Azure",
        "status": "FAIL" if res01 else "PASS",
        "detail": (f"Backup configuration failures: {'; '.join(res01)}" if res01
                   else f"Azure Backup vault active; retention >= {MIN_BACKUP_RETENTION} days"),
        "config_attribute": "backup.backup_vault_enabled | backup.retention_days",
    })

    # RES-02: Azure Policy + Defender posture
    res02 = []
    if not policy.get("policy_assignments_enabled", False):
        res02.append("no Azure Policy assignments configured")
    if not policy.get("defender_posture_enabled", False):
        res02.append("Defender for Cloud posture management not enabled")
    results.append({
        "control_id": "RES-02", "provider": "Azure",
        "status": "FAIL" if res02 else "PASS",
        "detail": (f"Configuration drift gaps: {'; '.join(res02)}" if res02
                   else "Azure Policy assignments active; Defender posture management enabled"),
        "config_attribute": "azure_policy.policy_assignments_enabled | azure_policy.defender_posture_enabled",
    })

    # RES-03: Defender for Cloud centralised findings
    res03 = []
    if not defender.get("enabled", False):
        res03.append("Microsoft Defender for Cloud not enabled")
    if not defender.get("secure_score_enabled", False):
        res03.append("Defender secure score not configured")
    results.append({
        "control_id": "RES-03", "provider": "Azure",
        "status": "FAIL" if res03 else "PASS",
        "detail": (f"Centralised findings gaps: {'; '.join(res03)}" if res03
                   else "Microsoft Defender for Cloud enabled; secure score active"),
        "config_attribute": "defender_for_cloud.enabled | defender_for_cloud.secure_score_enabled",
    })

    return results


# ─────────────────────────────────────────────
# VALIDATION ENGINE — GCP
# ─────────────────────────────────────────────

def validate_gcp(config: dict[str, Any]) -> list[dict]:
    results = []
    gcs        = config.get("cloud_storage", {})
    audit      = config.get("audit_logs", {})
    iam        = config.get("iam", {})
    vpc        = config.get("vpc", {})
    kms        = config.get("cloud_kms", {})
    scc        = config.get("security_command_center", {})
    vpc_nets   = config.get("vpc_networks", {})
    backup     = config.get("backup", {})
    org_policy = config.get("org_policy", {})

    # NET-01: no GCS buckets with public access
    public_buckets = [b["name"] for b in gcs.get("buckets", [])
                      if b.get("public_access_prevention") != "enforced"
                      and not b.get("uniform_bucket_level_access", False)]
    results.append({
        "control_id": "NET-01", "provider": "GCP",
        "status": "FAIL" if public_buckets else "PASS",
        "detail": (f"Buckets with potential public access: {public_buckets}" if public_buckets
                   else "All GCS buckets have public access prevention enforced"),
        "config_attribute": "cloud_storage.buckets[].public_access_prevention",
    })

    # LOG-01: Admin Activity audit logs
    admin_logs = audit.get("admin_activity_enabled", False)
    results.append({
        "control_id": "LOG-01", "provider": "GCP",
        "status": "PASS" if admin_logs else "FAIL",
        "detail": ("Admin Activity audit logging is enabled" if admin_logs
                   else "Admin Activity audit logs are disabled or not configured"),
        "config_attribute": "audit_logs.admin_activity_enabled",
    })

    # IAM-03: dormant service account detection
    dormant_sa = [sa["name"] for sa in iam.get("service_accounts", [])
                  if sa.get("last_used_days") is None
                  or sa.get("last_used_days", 0) > DORMANCY_THRESHOLD_DAYS]
    results.append({
        "control_id": "IAM-03", "provider": "GCP",
        "status": "FAIL" if dormant_sa else "PASS",
        "detail": (f"Dormant service accounts detected: {dormant_sa}" if dormant_sa
                   else "No dormant service accounts; all active within 90 days"),
        "config_attribute": "iam.service_accounts[].last_used_days",
    })

    # NET-03: no VPC firewall rules permitting all inbound
    open_rules = [r["name"] for r in vpc.get("firewall_rules", [])
                  if r.get("source_ranges") == ["0.0.0.0/0"]
                  and r.get("action") == "allow"
                  and r.get("ports") in ([], ["all"])]
    results.append({
        "control_id": "NET-03", "provider": "GCP",
        "status": "FAIL" if open_rules else "PASS",
        "detail": (f"Overly permissive firewall rules: {open_rules}" if open_rules
                   else "No firewall rules permitting all inbound traffic"),
        "config_attribute": "vpc.firewall_rules[].source_ranges + action",
    })

    # ENC-03: Cloud KMS rotation schedule
    rot_disabled = [k["name"] for k in kms.get("keys", [])
                    if not k.get("rotation_schedule_enabled", False)]
    results.append({
        "control_id": "ENC-03", "provider": "GCP",
        "status": "FAIL" if rot_disabled else "PASS",
        "detail": (f"No rotation schedule for Cloud KMS keys: {rot_disabled}" if rot_disabled
                   else "Rotation schedule configured for all Cloud KMS keys"),
        "config_attribute": "cloud_kms.keys[].rotation_schedule_enabled",
    })

    # LOG-03: Security Command Center findings + alerting
    log03 = []
    if not scc.get("findings_enabled", False):
        log03.append("Security Command Center findings not enabled")
    if not scc.get("alerting_policies_enabled", False):
        log03.append("Cloud Monitoring alerting policies not configured")
    results.append({
        "control_id": "LOG-03", "provider": "GCP",
        "status": "FAIL" if log03 else "PASS",
        "detail": (f"Real-time alerting gaps: {'; '.join(log03)}" if log03
                   else "Security Command Center findings and alerting policies active"),
        "config_attribute": "security_command_center.findings_enabled | security_command_center.alerting_policies_enabled",
    })

    # NET-02: VPC network segmentation
    net_count = len(vpc_nets.get("networks", []))
    results.append({
        "control_id": "NET-02", "provider": "GCP",
        "status": "FAIL" if net_count < MIN_VPCS else "PASS",
        "detail": (f"Only {net_count} VPC network(s) found; minimum {MIN_VPCS} required for workload segmentation"
                   if net_count < MIN_VPCS
                   else f"{net_count} VPC networks present; workload segmentation requirements met"),
        "config_attribute": "vpc_networks.networks[]",
    })

    # RES-01: Cloud SQL automated backups
    res01 = []
    if not backup.get("automated_backups_enabled", False):
        res01.append("Cloud SQL automated backups not enabled")
    if backup.get("retention_days", 0) < MIN_BACKUP_RETENTION:
        res01.append(f"retention {backup.get('retention_days',0)} days below {MIN_BACKUP_RETENTION}-day minimum")
    results.append({
        "control_id": "RES-01", "provider": "GCP",
        "status": "FAIL" if res01 else "PASS",
        "detail": (f"Backup configuration failures: {'; '.join(res01)}" if res01
                   else f"Cloud SQL automated backups active; retention >= {MIN_BACKUP_RETENTION} days"),
        "config_attribute": "backup.automated_backups_enabled | backup.retention_days",
    })

    # RES-02: Organisation Policy + Security Health Analytics
    res02 = []
    if not org_policy.get("constraints_enabled", False):
        res02.append("Organisation Policy constraints not configured")
    if not org_policy.get("security_health_analytics_enabled", False):
        res02.append("Security Health Analytics drift detection not enabled")
    results.append({
        "control_id": "RES-02", "provider": "GCP",
        "status": "FAIL" if res02 else "PASS",
        "detail": (f"Configuration drift gaps: {'; '.join(res02)}" if res02
                   else "Organisation Policy constraints active; Security Health Analytics enabled"),
        "config_attribute": "org_policy.constraints_enabled | org_policy.security_health_analytics_enabled",
    })

    # RES-03: Security Command Center Premium
    res03 = []
    if not scc.get("premium_enabled", False):
        res03.append("Security Command Center Premium not enabled")
    if not scc.get("asset_inventory_enabled", False):
        res03.append("Cloud Asset Inventory not configured")
    results.append({
        "control_id": "RES-03", "provider": "GCP",
        "status": "FAIL" if res03 else "PASS",
        "detail": (f"Centralised findings gaps: {'; '.join(res03)}" if res03
                   else "Security Command Center Premium active; Cloud Asset Inventory configured"),
        "config_attribute": "security_command_center.premium_enabled | security_command_center.asset_inventory_enabled",
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
            "compliance_rate": f"{round((passed/total)*100,1)}%" if total else "0%",
        },
        "findings": findings,
    }


# ─────────────────────────────────────────────
# SCENARIO RUNNER
# ─────────────────────────────────────────────

def run_scenario(scenario_id: str, aws_cfg: dict, azure_cfg: dict, gcp_cfg: dict) -> dict:
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
        print(f"  {flag} [{f['control_id']}] {f['provider']:6s} {f['status']:4s}  {f['detail']}")
        if f["status"] == "FAIL":
            print(f"       Regulatory refs: {', '.join(f['regulatory_refs'])}")
            print(f"       Config attr    : {f['config_attribute']}")
    return report


# ─────────────────────────────────────────────
# SCENARIO LOADER
# ─────────────────────────────────────────────

def load_scenario_from_file(sc_id: str) -> tuple | None:
    num  = sc_id.lower().replace("sc-", "")
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "configs", f"scenario-{num}.json"
    )
    try:
        with open(path) as f:
            data = json.load(f)
        label = f"{data['scenario_id']}: {data['description']}"
        return label, data["aws"], data["azure"], data["gcp"]
    except (FileNotFoundError, KeyError):
        return None

def load_custom_scenario() -> tuple | None:
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "configs", "scenario-custom.json"
    )
    try:
        with open(path) as f:
            data = json.load(f)
        label = f"SC-CUSTOM: {data.get('description', 'Custom scenario')}"
        return label, data["aws"], data["azure"], data["gcp"]
    except (FileNotFoundError, KeyError):
        return None


# ─────────────────────────────────────────────
# SCENARIO DATA — SC-01 through SC-08
# ─────────────────────────────────────────────

# Shared compliant baseline components
_base_aws_iam = {
    "policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}],
    "users": [
        {"username": "ops-user",   "mfa_enabled": True, "last_used_days": 5},
        {"username": "admin-user", "mfa_enabled": True, "last_used_days": 12},
    ],
}
_base_aws_ct = {
    "trails": [{"name": "mgmt-trail", "is_logging": True}],
    "log_file_validation_enabled": True,
    "s3_object_lock_enabled": True,
    "retention_days": 365,
}
_base_azure_diag = {
    "activity_log_enabled": True,
    "log_retention_days": 90,
    "immutable_storage_enabled": True,
}
_base_gcp_storage = {"buckets": [{"name": "gs-prod", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]}
_base_gcp_sa = {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 14}]}

# Extended compliant components (new controls)
_ext_aws = {
    "kms":        {"keys": [{"key_id": "key-prod-01", "rotation_enabled": True}]},
    "monitoring": {"cloudwatch_alarms_enabled": True, "security_hub_enabled": True},
    "vpc":        {"vpcs": [{"vpc_id": "vpc-prod", "name": "production"}, {"vpc_id": "vpc-staging", "name": "staging"}]},
    "backup":     {"backup_plan_enabled": True, "retention_days": 35},
    "aws_config": {"config_rules_enabled": True, "drift_detection_enabled": True},
    "security_hub": {"enabled": True},
}
_ext_azure = {
    "key_vault":         {"keys": [{"name": "prod-key-01", "rotation_policy_enabled": True}]},
    "defender_for_cloud":{"alerts_enabled": True, "sentinel_integration": True, "enabled": True, "secure_score_enabled": True},
    "network":           {"vnets": [{"name": "vnet-prod"}, {"name": "vnet-dmz"}]},
    "backup":            {"backup_vault_enabled": True, "retention_days": 35},
    "azure_policy":      {"policy_assignments_enabled": True, "defender_posture_enabled": True},
}
_ext_gcp = {
    "cloud_kms":              {"keys": [{"name": "prod-key-01", "rotation_schedule_enabled": True}]},
    "security_command_center":{"findings_enabled": True, "alerting_policies_enabled": True, "premium_enabled": True, "asset_inventory_enabled": True},
    "vpc_networks":           {"networks": [{"name": "vpc-prod"}, {"name": "vpc-restricted"}]},
    "backup":                 {"automated_backups_enabled": True, "retention_days": 35},
    "org_policy":             {"constraints_enabled": True, "security_health_analytics_enabled": True},
}

# SC-01: Fully compliant baseline (9 original controls)
sc01_aws   = {**{"iam": _base_aws_iam, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]}, "cloudtrail": _base_aws_ct, "ec2": {"security_groups": []}}, **_ext_aws}
sc01_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": _base_azure_diag, **_ext_azure}
sc01_gcp   = {"cloud_storage": _base_gcp_storage, "audit_logs": {"admin_activity_enabled": True}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": []}, **_ext_gcp}

# SC-02: Over-privileged IAM (AWS) + MFA disabled (Azure)
sc02_aws   = {**{"iam": {"policies": [{"name": "AdminPolicy", "actions": ["*"]}], "users": [{"username": "svc-deploy", "mfa_enabled": True, "last_used_days": 3}, {"username": "admin-user", "mfa_enabled": True, "last_used_days": 7}]}, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]}, "cloudtrail": _base_aws_ct, "ec2": {"security_groups": []}}, **_ext_aws}
sc02_azure = {"conditional_access": {"mfa_policy_enabled": False}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": _base_azure_diag, **_ext_azure}
sc02_gcp   = {"cloud_storage": _base_gcp_storage, "audit_logs": {"admin_activity_enabled": True}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": []}, **_ext_gcp}

# SC-03: Encryption disabled (AWS) + weak TLS (Azure) + public bucket (GCP)
sc03_aws   = {**{"iam": _base_aws_iam, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": False}]}, "cloudtrail": _base_aws_ct, "ec2": {"security_groups": []}}, **_ext_aws}
sc03_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_0"}], "diagnostic_settings": _base_azure_diag, **_ext_azure}
sc03_gcp   = {"cloud_storage": {"buckets": [{"name": "gs-prod", "public_access_prevention": "unspecified", "uniform_bucket_level_access": False}]}, "audit_logs": {"admin_activity_enabled": True}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": []}, **_ext_gcp}

# SC-04: Logging disabled across all providers
sc04_aws   = {**{"iam": _base_aws_iam, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]}, "cloudtrail": {"trails": [{"name": "mgmt-trail", "is_logging": False}], "log_file_validation_enabled": True, "s3_object_lock_enabled": True, "retention_days": 365}, "ec2": {"security_groups": []}}, **_ext_aws}
sc04_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": {"activity_log_enabled": False, "log_retention_days": 90, "immutable_storage_enabled": True}, **_ext_azure}
sc04_gcp   = {"cloud_storage": _base_gcp_storage, "audit_logs": {"admin_activity_enabled": False}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": []}, **_ext_gcp}

# SC-05: Open SSH (AWS) + permissive firewall (GCP)
sc05_aws   = {**{"iam": _base_aws_iam, "s3": {"buckets": [{"name": "logs", "default_encryption_enabled": True}]}, "cloudtrail": _base_aws_ct, "ec2": {"security_groups": [{"group_id": "sg-0abc123", "inbound_rules": [{"cidr": "0.0.0.0/0", "port": 22, "protocol": "tcp"}, {"cidr": "10.0.0.0/8", "port": 443, "protocol": "tcp"}]}]}}, **_ext_aws}
sc05_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "auditlogs01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": _base_azure_diag, **_ext_azure}
sc05_gcp   = {"cloud_storage": {"buckets": [{"name": "backup-bucket", "public_access_prevention": "enforced", "uniform_bucket_level_access": True}]}, "audit_logs": {"admin_activity_enabled": True}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": [{"name": "allow-all-inbound", "source_ranges": ["0.0.0.0/0"], "action": "allow", "ports": ["all"]}]}, **_ext_gcp}

# SC-06: Dormant accounts (AWS, GCP) + insufficient log retention (AWS, Azure)
sc06_aws   = {**{"iam": {"policies": [{"name": "ReadOnlyPolicy", "actions": ["s3:GetObject"]}], "users": [{"username": "ops-user", "mfa_enabled": True, "last_used_days": 12}, {"username": "svc-legacy", "mfa_enabled": True, "last_used_days": 142}, {"username": "audit-reader", "mfa_enabled": True, "last_used_days": None}]}, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]}, "cloudtrail": {"trails": [{"name": "mgmt-trail", "is_logging": True}], "log_file_validation_enabled": True, "s3_object_lock_enabled": False, "retention_days": 180}, "ec2": {"security_groups": []}}, **_ext_aws}
sc06_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": {"activity_log_enabled": True, "log_retention_days": 60, "immutable_storage_enabled": True}, **_ext_azure}
sc06_gcp   = {"cloud_storage": _base_gcp_storage, "audit_logs": {"admin_activity_enabled": True}, "iam": {"service_accounts": [{"name": "svc-dataflow@proj.iam", "last_used_days": 30}, {"name": "svc-archive@proj.iam", "last_used_days": 210}]}, "vpc": {"firewall_rules": []}, **_ext_gcp}

# SC-07: Full 15-control compliant baseline
sc07_aws   = {**{"iam": _base_aws_iam, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]}, "cloudtrail": _base_aws_ct, "ec2": {"security_groups": []}}, **_ext_aws}
sc07_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": _base_azure_diag, **_ext_azure}
sc07_gcp   = {"cloud_storage": _base_gcp_storage, "audit_logs": {"admin_activity_enabled": True}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": []}, **_ext_gcp}

# SC-08: Full 15-control failure (all new controls failing)
sc08_aws   = {**{"iam": _base_aws_iam, "s3": {"buckets": [{"name": "prod-data", "default_encryption_enabled": True}]}, "cloudtrail": _base_aws_ct, "ec2": {"security_groups": []}}, "kms": {"keys": [{"key_id": "key-prod-01", "rotation_enabled": False}]}, "monitoring": {"cloudwatch_alarms_enabled": False, "security_hub_enabled": False}, "vpc": {"vpcs": [{"vpc_id": "vpc-default", "name": "default"}]}, "backup": {"backup_plan_enabled": False, "retention_days": 0}, "aws_config": {"config_rules_enabled": False, "drift_detection_enabled": False}, "security_hub": {"enabled": False}}
sc08_azure = {"conditional_access": {"mfa_policy_enabled": True}, "storage_accounts": [{"name": "prodstore01", "minimum_tls_version": "TLS1_2"}], "diagnostic_settings": _base_azure_diag, "key_vault": {"keys": [{"name": "prod-key-01", "rotation_policy_enabled": False}]}, "defender_for_cloud": {"alerts_enabled": False, "sentinel_integration": False, "enabled": False, "secure_score_enabled": False}, "network": {"vnets": [{"name": "vnet-default"}]}, "backup": {"backup_vault_enabled": False, "retention_days": 0}, "azure_policy": {"policy_assignments_enabled": False, "defender_posture_enabled": False}}
sc08_gcp   = {"cloud_storage": _base_gcp_storage, "audit_logs": {"admin_activity_enabled": True}, "iam": _base_gcp_sa, "vpc": {"firewall_rules": []}, "cloud_kms": {"keys": [{"name": "prod-key-01", "rotation_schedule_enabled": False}]}, "security_command_center": {"findings_enabled": False, "alerting_policies_enabled": False, "premium_enabled": False, "asset_inventory_enabled": False}, "vpc_networks": {"networks": [{"name": "vpc-default"}]}, "backup": {"automated_backups_enabled": False, "retention_days": 0}, "org_policy": {"constraints_enabled": False, "security_health_analytics_enabled": False}}


# ─────────────────────────────────────────────
# SCENARIO REGISTRY
# ─────────────────────────────────────────────

_HARDCODED: dict[str, tuple] = {
    "SC-01": ("SC-01: Fully Compliant Baseline",                                                  sc01_aws, sc01_azure, sc01_gcp),
    "SC-02": ("SC-02: Over-privileged IAM (AWS) / MFA Disabled (Azure)",                          sc02_aws, sc02_azure, sc02_gcp),
    "SC-03": ("SC-03: Encryption Disabled (AWS) / Weak TLS (Azure) / Public Bucket (GCP)",        sc03_aws, sc03_azure, sc03_gcp),
    "SC-04": ("SC-04: Logging Disabled (All Providers)",                                           sc04_aws, sc04_azure, sc04_gcp),
    "SC-05": ("SC-05: Open SSH (AWS) / Permissive Firewall (GCP)",                                sc05_aws, sc05_azure, sc05_gcp),
    "SC-06": ("SC-06: Dormant Accounts (AWS, GCP) / Insufficient Log Retention (AWS, Azure)",     sc06_aws, sc06_azure, sc06_gcp),
    "SC-07": ("SC-07: Full 15-Control Compliant Baseline",                                        sc07_aws, sc07_azure, sc07_gcp),
    "SC-08": ("SC-08: Full 15-Control Failure Scenario (All New Controls Failing)",               sc08_aws, sc08_azure, sc08_gcp),
}

SCENARIOS: dict[str, tuple] = {}
for _id, _fallback in _HARDCODED.items():
    _from_file = load_scenario_from_file(_id)
    SCENARIOS[_id] = _from_file if _from_file else _fallback

_custom = load_custom_scenario()
if _custom:
    SCENARIOS["CUSTOM"] = _custom


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AMCAF — Automated Multi-Cloud Compliance Assurance Framework"
    )
    parser.add_argument(
        "--scenario", default="ALL",
        help="Scenario to run: ALL, SC-01 through SC-08, or CUSTOM (default: ALL)",
    )
    parser.add_argument(
        "--format", default="console", choices=["console", "json"],
        help="Output format: console (default) or json",
    )
    args = parser.parse_args()
    sc   = args.scenario.upper()

    if sc == "ALL":
        to_run = list(SCENARIOS.values())
    elif sc == "CUSTOM":
        custom = load_custom_scenario()
        if not custom:
            print("ERROR: CUSTOM selected but configs/scenario-custom.json not found.")
            sys.exit(1)
        to_run = [custom]
    elif sc in SCENARIOS:
        to_run = [SCENARIOS[sc]]
    else:
        print(f"ERROR: Unknown scenario '{sc}'. Valid: ALL, CUSTOM, {', '.join(SCENARIOS.keys())}")
        sys.exit(1)

    if args.format == "json":
        os.makedirs("results", exist_ok=True)

    for label, aws_cfg, azure_cfg, gcp_cfg in to_run:
        report = run_scenario(label, aws_cfg, azure_cfg, gcp_cfg)
        if args.format == "json":
            sc_id    = "sc-custom" if sc == "CUSTOM" else label.split(":")[0].strip().lower()
            out_path = f"results/{sc_id}.json"
            with open(out_path, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"  Results written to {out_path}\n")

    if args.format == "json" and sc == "ALL":
        summary = []
        for sid in [k.lower() for k in SCENARIOS.keys()]:
            p = f"results/{sid}.json"
            if os.path.exists(p):
                with open(p) as fh:
                    summary.append(json.load(fh))
        with open("results/summary.json", "w") as fh:
            json.dump(summary, fh, indent=2)
        print("  Combined summary written to results/summary.json")
