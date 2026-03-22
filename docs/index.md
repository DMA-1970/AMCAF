<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh;padding:24px}
  h1{font-size:22px;font-weight:600;color:#f0f6fc;margin-bottom:4px}
  .subtitle{font-size:13px;color:#8b949e;margin-bottom:24px}
  .meta-row{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
  .meta-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;min-width:130px;flex:1}
  .meta-card .val{font-size:28px;font-weight:600;line-height:1}
  .meta-card .lbl{font-size:12px;color:#8b949e;margin-top:4px}
  .meta-card.pass .val{color:#3fb950}
  .meta-card.fail .val{color:#f85149}
  .meta-card.rate .val{color:#58a6ff}
  .meta-card.total .val{color:#e6edf3}
  .scenario-grid{display:flex;flex-direction:column;gap:12px}
  .sc-card{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
  .sc-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;cursor:pointer;user-select:none;gap:12px}
  .sc-header:hover{background:#1c2128}
  .sc-title{font-size:14px;font-weight:500;color:#f0f6fc;flex:1}
  .sc-badges{display:flex;gap:8px;align-items:center;flex-shrink:0}
  .badge{font-size:11px;font-weight:500;padding:2px 8px;border-radius:12px}
  .badge.pass{background:#1a3a2a;color:#3fb950;border:1px solid #2ea043}
  .badge.fail{background:#3a1a1a;color:#f85149;border:1px solid #da3633}
  .badge.rate{background:#1a2a3a;color:#58a6ff;border:1px solid #1f6feb}
  .chevron{color:#8b949e;font-size:12px;transition:transform .2s;flex-shrink:0}
  .chevron.open{transform:rotate(90deg)}
  .sc-body{display:none;border-top:1px solid #30363d}
  .sc-body.open{display:block}
  .findings-table{width:100%;border-collapse:collapse;font-size:12px}
  .findings-table th{background:#0d1117;color:#8b949e;font-weight:500;text-align:left;padding:8px 16px;border-bottom:1px solid #30363d}
  .findings-table td{padding:8px 16px;border-bottom:1px solid #21262d;vertical-align:top}
  .findings-table tr:last-child td{border-bottom:none}
  .findings-table tr.fail-row td{background:#1a0d0d}
  .status-pass{color:#3fb950;font-weight:600}
  .status-fail{color:#f85149;font-weight:600}
  .ctrl-id{font-family:ui-monospace,monospace;font-size:11px;background:#21262d;padding:2px 6px;border-radius:4px;color:#e6edf3}
  .provider{font-size:11px;padding:2px 6px;border-radius:4px;font-weight:500}
  .provider.aws{background:#1a2a1a;color:#3fb950}
  .provider.azure{background:#1a1a3a;color:#58a6ff}
  .provider.gcp{background:#2a1a1a;color:#ffa657}
  .ref-list{color:#8b949e;font-size:11px;line-height:1.6}
  .attr{font-family:ui-monospace,monospace;font-size:10px;color:#8b949e}
  .detail{color:#e6edf3;font-size:12px}
  .fail-detail{color:#f85149;font-size:12px}
  .legend{display:flex;gap:16px;margin-bottom:16px;font-size:12px;color:#8b949e;flex-wrap:wrap}
  .legend span{display:flex;align-items:center;gap:6px}
  .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
  .dot.pass{background:#3fb950}
  .dot.fail{background:#f85149}
  footer{margin-top:24px;font-size:11px;color:#484f58;text-align:center}
</style>

<h1>AMCAF — Automated Multi-Cloud Compliance Assurance Framework</h1>
<p class="subtitle">Rule-based compliance validation across AWS · Azure · GCP &nbsp;|&nbsp; v1.0 &nbsp;|&nbsp; 9 controls · 6 scenarios</p>

<div class="meta-row" id="meta"></div>

<div class="legend">
  <span><span class="dot pass"></span>PASS — control satisfied</span>
  <span><span class="dot fail"></span>FAIL — misconfiguration detected</span>
</div>

<div class="scenario-grid" id="scenarios"></div>

<footer>AMCAF v1.0 &nbsp;·&nbsp; MSc Enterprise IT Management, University of Essex Online &nbsp;·&nbsp; Design Science Research artefact</footer>

<script>
const data = [
  {id:"SC-01",title:"Fully compliant baseline",checks:16,passed:16,failed:0,rate:100.0,findings:[
    {ctrl:"IAM-01",provider:"AWS",status:"PASS",detail:"IAM policies comply with least-privilege requirement",refs:["NIST CSF PR.AC-4","ISO 27001 A.9.2","DORA Art. 9"],attr:"iam.policies[].actions"},
    {ctrl:"IAM-02",provider:"AWS",status:"PASS",detail:"MFA enabled for all IAM users",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"iam.users[].mfa_enabled"},
    {ctrl:"IAM-03",provider:"AWS",status:"PASS",detail:"No dormant accounts found; all users active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.users[].last_used_days"},
    {ctrl:"ENC-01",provider:"AWS",status:"PASS",detail:"All S3 buckets have default encryption enabled",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-1"],attr:"s3.buckets[].default_encryption_enabled"},
    {ctrl:"LOG-01",provider:"AWS",status:"PASS",detail:"CloudTrail logging active across all configured trails",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"cloudtrail.trails[].is_logging"},
    {ctrl:"LOG-02",provider:"AWS",status:"PASS",detail:"Log file validation enabled; S3 Object Lock configured; retention >= 365 days",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"cloudtrail.log_file_validation_enabled"},
    {ctrl:"NET-01",provider:"AWS",status:"PASS",detail:"No security groups permit unrestricted inbound access",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"ec2.security_groups[].inbound_rules"},
    {ctrl:"NET-03",provider:"AWS",status:"PASS",detail:"No management ports (22/3389) exposed to 0.0.0.0/0",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"ec2.security_groups[].inbound_rules[port=22|3389]"},
    {ctrl:"IAM-02",provider:"Azure",status:"PASS",detail:"Conditional Access MFA policy is active",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"conditional_access.mfa_policy_enabled"},
    {ctrl:"ENC-02",provider:"Azure",status:"PASS",detail:"All storage accounts enforce minimum TLS 1.2",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-2"],attr:"storage_accounts[].minimum_tls_version"},
    {ctrl:"LOG-01",provider:"Azure",status:"PASS",detail:"Activity Log diagnostic settings configured",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"diagnostic_settings.activity_log_enabled"},
    {ctrl:"LOG-02",provider:"Azure",status:"PASS",detail:"Log Analytics retention >= 90 days; immutable storage enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"diagnostic_settings.log_retention_days"},
    {ctrl:"NET-01",provider:"GCP",status:"PASS",detail:"All GCS buckets have public access prevention enforced",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"cloud_storage.buckets[].public_access_prevention"},
    {ctrl:"LOG-01",provider:"GCP",status:"PASS",detail:"Admin Activity audit logging is enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"audit_logs.admin_activity_enabled"},
    {ctrl:"IAM-03",provider:"GCP",status:"PASS",detail:"No dormant service accounts; all active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.service_accounts[].last_used_days"},
    {ctrl:"NET-03",provider:"GCP",status:"PASS",detail:"No firewall rules permitting all inbound traffic",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"vpc.firewall_rules[].source_ranges + action"},
  ]},
  {id:"SC-02",title:"Over-privileged IAM (AWS) / MFA disabled (Azure)",checks:16,passed:14,failed:2,rate:87.5,findings:[
    {ctrl:"IAM-01",provider:"AWS",status:"FAIL",detail:"Wildcard (*) action found in IAM policy",refs:["NIST CSF PR.AC-4","ISO 27001 A.9.2","DORA Art. 9"],attr:"iam.policies[].actions"},
    {ctrl:"IAM-02",provider:"AWS",status:"PASS",detail:"MFA enabled for all IAM users",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"iam.users[].mfa_enabled"},
    {ctrl:"IAM-03",provider:"AWS",status:"PASS",detail:"No dormant accounts found; all users active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.users[].last_used_days"},
    {ctrl:"ENC-01",provider:"AWS",status:"PASS",detail:"All S3 buckets have default encryption enabled",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-1"],attr:"s3.buckets[].default_encryption_enabled"},
    {ctrl:"LOG-01",provider:"AWS",status:"PASS",detail:"CloudTrail logging active across all configured trails",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"cloudtrail.trails[].is_logging"},
    {ctrl:"LOG-02",provider:"AWS",status:"PASS",detail:"Log file validation enabled; S3 Object Lock configured; retention >= 365 days",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"cloudtrail.log_file_validation_enabled"},
    {ctrl:"NET-01",provider:"AWS",status:"PASS",detail:"No security groups permit unrestricted inbound access",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"ec2.security_groups[].inbound_rules"},
    {ctrl:"NET-03",provider:"AWS",status:"PASS",detail:"No management ports (22/3389) exposed to 0.0.0.0/0",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"ec2.security_groups[].inbound_rules[port=22|3389]"},
    {ctrl:"IAM-02",provider:"Azure",status:"FAIL",detail:"No active Conditional Access policy enforcing MFA",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"conditional_access.mfa_policy_enabled"},
    {ctrl:"ENC-02",provider:"Azure",status:"PASS",detail:"All storage accounts enforce minimum TLS 1.2",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-2"],attr:"storage_accounts[].minimum_tls_version"},
    {ctrl:"LOG-01",provider:"Azure",status:"PASS",detail:"Activity Log diagnostic settings configured",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"diagnostic_settings.activity_log_enabled"},
    {ctrl:"LOG-02",provider:"Azure",status:"PASS",detail:"Log Analytics retention >= 90 days; immutable storage enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"diagnostic_settings.log_retention_days"},
    {ctrl:"NET-01",provider:"GCP",status:"PASS",detail:"All GCS buckets have public access prevention enforced",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"cloud_storage.buckets[].public_access_prevention"},
    {ctrl:"LOG-01",provider:"GCP",status:"PASS",detail:"Admin Activity audit logging is enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"audit_logs.admin_activity_enabled"},
    {ctrl:"IAM-03",provider:"GCP",status:"PASS",detail:"No dormant service accounts; all active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.service_accounts[].last_used_days"},
    {ctrl:"NET-03",provider:"GCP",status:"PASS",detail:"No firewall rules permitting all inbound traffic",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"vpc.firewall_rules[].source_ranges + action"},
  ]},
  {id:"SC-03",title:"Encryption disabled (AWS) / Weak TLS (Azure) / Public bucket (GCP)",checks:16,passed:13,failed:3,rate:81.2,findings:[
    {ctrl:"IAM-01",provider:"AWS",status:"PASS",detail:"IAM policies comply with least-privilege requirement",refs:["NIST CSF PR.AC-4","ISO 27001 A.9.2","DORA Art. 9"],attr:"iam.policies[].actions"},
    {ctrl:"IAM-02",provider:"AWS",status:"PASS",detail:"MFA enabled for all IAM users",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"iam.users[].mfa_enabled"},
    {ctrl:"IAM-03",provider:"AWS",status:"PASS",detail:"No dormant accounts found; all users active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.users[].last_used_days"},
    {ctrl:"ENC-01",provider:"AWS",status:"FAIL",detail:"Encryption disabled on buckets: ['prod-data']",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-1"],attr:"s3.buckets[].default_encryption_enabled"},
    {ctrl:"LOG-01",provider:"AWS",status:"PASS",detail:"CloudTrail logging active across all configured trails",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"cloudtrail.trails[].is_logging"},
    {ctrl:"LOG-02",provider:"AWS",status:"PASS",detail:"Log file validation enabled; S3 Object Lock configured; retention >= 365 days",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"cloudtrail.log_file_validation_enabled"},
    {ctrl:"NET-01",provider:"AWS",status:"PASS",detail:"No security groups permit unrestricted inbound access",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"ec2.security_groups[].inbound_rules"},
    {ctrl:"NET-03",provider:"AWS",status:"PASS",detail:"No management ports (22/3389) exposed to 0.0.0.0/0",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"ec2.security_groups[].inbound_rules[port=22|3389]"},
    {ctrl:"IAM-02",provider:"Azure",status:"PASS",detail:"Conditional Access MFA policy is active",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"conditional_access.mfa_policy_enabled"},
    {ctrl:"ENC-02",provider:"Azure",status:"FAIL",detail:"Weak TLS (<1.2) on storage accounts: ['prodstore01']",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-2"],attr:"storage_accounts[].minimum_tls_version"},
    {ctrl:"LOG-01",provider:"Azure",status:"PASS",detail:"Activity Log diagnostic settings configured",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"diagnostic_settings.activity_log_enabled"},
    {ctrl:"LOG-02",provider:"Azure",status:"PASS",detail:"Log Analytics retention >= 90 days; immutable storage enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"diagnostic_settings.log_retention_days"},
    {ctrl:"NET-01",provider:"GCP",status:"FAIL",detail:"Buckets with potential public access: ['gs-prod']",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"cloud_storage.buckets[].public_access_prevention"},
    {ctrl:"LOG-01",provider:"GCP",status:"PASS",detail:"Admin Activity audit logging is enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"audit_logs.admin_activity_enabled"},
    {ctrl:"IAM-03",provider:"GCP",status:"PASS",detail:"No dormant service accounts; all active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.service_accounts[].last_used_days"},
    {ctrl:"NET-03",provider:"GCP",status:"PASS",detail:"No firewall rules permitting all inbound traffic",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"vpc.firewall_rules[].source_ranges + action"},
  ]},
  {id:"SC-04",title:"Logging disabled across all providers",checks:16,passed:13,failed:3,rate:81.2,findings:[
    {ctrl:"IAM-01",provider:"AWS",status:"PASS",detail:"IAM policies comply with least-privilege requirement",refs:["NIST CSF PR.AC-4","ISO 27001 A.9.2","DORA Art. 9"],attr:"iam.policies[].actions"},
    {ctrl:"IAM-02",provider:"AWS",status:"PASS",detail:"MFA enabled for all IAM users",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"iam.users[].mfa_enabled"},
    {ctrl:"IAM-03",provider:"AWS",status:"PASS",detail:"No dormant accounts found; all users active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.users[].last_used_days"},
    {ctrl:"ENC-01",provider:"AWS",status:"PASS",detail:"All S3 buckets have default encryption enabled",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-1"],attr:"s3.buckets[].default_encryption_enabled"},
    {ctrl:"LOG-01",provider:"AWS",status:"FAIL",detail:"CloudTrail logging inactive for: ['mgmt-trail']",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"cloudtrail.trails[].is_logging"},
    {ctrl:"LOG-02",provider:"AWS",status:"PASS",detail:"Log file validation enabled; S3 Object Lock configured; retention >= 365 days",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"cloudtrail.log_file_validation_enabled"},
    {ctrl:"NET-01",provider:"AWS",status:"PASS",detail:"No security groups permit unrestricted inbound access",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"ec2.security_groups[].inbound_rules"},
    {ctrl:"NET-03",provider:"AWS",status:"PASS",detail:"No management ports (22/3389) exposed to 0.0.0.0/0",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"ec2.security_groups[].inbound_rules[port=22|3389]"},
    {ctrl:"IAM-02",provider:"Azure",status:"PASS",detail:"Conditional Access MFA policy is active",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"conditional_access.mfa_policy_enabled"},
    {ctrl:"ENC-02",provider:"Azure",status:"PASS",detail:"All storage accounts enforce minimum TLS 1.2",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-2"],attr:"storage_accounts[].minimum_tls_version"},
    {ctrl:"LOG-01",provider:"Azure",status:"FAIL",detail:"Azure Activity Log not routed to Log Analytics Workspace",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"diagnostic_settings.activity_log_enabled"},
    {ctrl:"LOG-02",provider:"Azure",status:"PASS",detail:"Log Analytics retention >= 90 days; immutable storage enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"diagnostic_settings.log_retention_days"},
    {ctrl:"NET-01",provider:"GCP",status:"PASS",detail:"All GCS buckets have public access prevention enforced",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"cloud_storage.buckets[].public_access_prevention"},
    {ctrl:"LOG-01",provider:"GCP",status:"FAIL",detail:"Admin Activity audit logs are disabled or not configured",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"audit_logs.admin_activity_enabled"},
    {ctrl:"IAM-03",provider:"GCP",status:"PASS",detail:"No dormant service accounts; all active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.service_accounts[].last_used_days"},
    {ctrl:"NET-03",provider:"GCP",status:"PASS",detail:"No firewall rules permitting all inbound traffic",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"vpc.firewall_rules[].source_ranges + action"},
  ]},
  {id:"SC-05",title:"Open SSH (AWS) / Permissive firewall (GCP)",checks:16,passed:13,failed:3,rate:81.2,findings:[
    {ctrl:"IAM-01",provider:"AWS",status:"PASS",detail:"IAM policies comply with least-privilege requirement",refs:["NIST CSF PR.AC-4","ISO 27001 A.9.2","DORA Art. 9"],attr:"iam.policies[].actions"},
    {ctrl:"IAM-02",provider:"AWS",status:"PASS",detail:"MFA enabled for all IAM users",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"iam.users[].mfa_enabled"},
    {ctrl:"IAM-03",provider:"AWS",status:"PASS",detail:"No dormant accounts found; all users active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.users[].last_used_days"},
    {ctrl:"ENC-01",provider:"AWS",status:"PASS",detail:"All S3 buckets have default encryption enabled",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-1"],attr:"s3.buckets[].default_encryption_enabled"},
    {ctrl:"LOG-01",provider:"AWS",status:"PASS",detail:"CloudTrail logging active across all configured trails",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"cloudtrail.trails[].is_logging"},
    {ctrl:"LOG-02",provider:"AWS",status:"PASS",detail:"Log file validation enabled; S3 Object Lock configured; retention >= 365 days",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"cloudtrail.log_file_validation_enabled"},
    {ctrl:"NET-01",provider:"AWS",status:"FAIL",detail:"Unrestricted inbound (0.0.0.0/0) on SGs: ['sg-0abc123']",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"ec2.security_groups[].inbound_rules"},
    {ctrl:"NET-03",provider:"AWS",status:"FAIL",detail:"Public management port exposure: ['sg-0abc123 port 22']",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"ec2.security_groups[].inbound_rules[port=22|3389]"},
    {ctrl:"IAM-02",provider:"Azure",status:"PASS",detail:"Conditional Access MFA policy is active",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"conditional_access.mfa_policy_enabled"},
    {ctrl:"ENC-02",provider:"Azure",status:"PASS",detail:"All storage accounts enforce minimum TLS 1.2",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-2"],attr:"storage_accounts[].minimum_tls_version"},
    {ctrl:"LOG-01",provider:"Azure",status:"PASS",detail:"Activity Log diagnostic settings configured",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"diagnostic_settings.activity_log_enabled"},
    {ctrl:"LOG-02",provider:"Azure",status:"PASS",detail:"Log Analytics retention >= 90 days; immutable storage enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"diagnostic_settings.log_retention_days"},
    {ctrl:"NET-01",provider:"GCP",status:"PASS",detail:"All GCS buckets have public access prevention enforced",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"cloud_storage.buckets[].public_access_prevention"},
    {ctrl:"LOG-01",provider:"GCP",status:"PASS",detail:"Admin Activity audit logging is enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"audit_logs.admin_activity_enabled"},
    {ctrl:"IAM-03",provider:"GCP",status:"PASS",detail:"No dormant service accounts; all active within 90 days",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.service_accounts[].last_used_days"},
    {ctrl:"NET-03",provider:"GCP",status:"FAIL",detail:"Overly permissive firewall rules: ['allow-all-inbound']",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"vpc.firewall_rules[].source_ranges + action"},
  ]},
  {id:"SC-06",title:"Dormant accounts (AWS, GCP) / Insufficient log retention (AWS, Azure)",checks:16,passed:12,failed:4,rate:75.0,findings:[
    {ctrl:"IAM-01",provider:"AWS",status:"PASS",detail:"IAM policies comply with least-privilege requirement",refs:["NIST CSF PR.AC-4","ISO 27001 A.9.2","DORA Art. 9"],attr:"iam.policies[].actions"},
    {ctrl:"IAM-02",provider:"AWS",status:"PASS",detail:"MFA enabled for all IAM users",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"iam.users[].mfa_enabled"},
    {ctrl:"IAM-03",provider:"AWS",status:"FAIL",detail:"Dormant or unused accounts detected: ['svc-legacy', 'audit-reader']",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.users[].last_used_days"},
    {ctrl:"ENC-01",provider:"AWS",status:"PASS",detail:"All S3 buckets have default encryption enabled",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-1"],attr:"s3.buckets[].default_encryption_enabled"},
    {ctrl:"LOG-01",provider:"AWS",status:"PASS",detail:"CloudTrail logging active across all configured trails",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"cloudtrail.trails[].is_logging"},
    {ctrl:"LOG-02",provider:"AWS",status:"FAIL",detail:"Log integrity/retention failures: S3 Object Lock not configured; retention 180 days below 365-day minimum",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"cloudtrail.s3_object_lock_enabled | cloudtrail.retention_days"},
    {ctrl:"NET-01",provider:"AWS",status:"PASS",detail:"No security groups permit unrestricted inbound access",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"ec2.security_groups[].inbound_rules"},
    {ctrl:"NET-03",provider:"AWS",status:"PASS",detail:"No management ports (22/3389) exposed to 0.0.0.0/0",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"ec2.security_groups[].inbound_rules[port=22|3389]"},
    {ctrl:"IAM-02",provider:"Azure",status:"PASS",detail:"Conditional Access MFA policy is active",refs:["FCA PS21/3","NIST CSF PR.AC-7","ISO 27001 A.9.4"],attr:"conditional_access.mfa_policy_enabled"},
    {ctrl:"ENC-02",provider:"Azure",status:"PASS",detail:"All storage accounts enforce minimum TLS 1.2",refs:["UK GDPR Art. 32","ISO 27001 A.10.1","NIST CSF PR.DS-2"],attr:"storage_accounts[].minimum_tls_version"},
    {ctrl:"LOG-01",provider:"Azure",status:"PASS",detail:"Activity Log diagnostic settings configured",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"diagnostic_settings.activity_log_enabled"},
    {ctrl:"LOG-02",provider:"Azure",status:"FAIL",detail:"Log Analytics retention 60 days is below 90-day minimum",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4.1","UK GDPR Art. 5(2)"],attr:"diagnostic_settings.log_retention_days"},
    {ctrl:"NET-01",provider:"GCP",status:"PASS",detail:"All GCS buckets have public access prevention enforced",refs:["NIST CSF PR.AC-5","ISO 27001 A.13.1","DORA Art. 9"],attr:"cloud_storage.buckets[].public_access_prevention"},
    {ctrl:"LOG-01",provider:"GCP",status:"PASS",detail:"Admin Activity audit logging is enabled",refs:["DORA Art. 10","FCA PS21/3","ISO 27001 A.12.4"],attr:"audit_logs.admin_activity_enabled"},
    {ctrl:"IAM-03",provider:"GCP",status:"FAIL",detail:"Dormant service accounts detected: ['svc-archive@proj.iam']",refs:["DORA Art. 9","FCA PS21/3","ISO 27001 A.9.2.5","NIST CSF PR.AC-1"],attr:"iam.service_accounts[].last_used_days"},
    {ctrl:"NET-03",provider:"GCP",status:"PASS",detail:"No firewall rules permitting all inbound traffic",refs:["FCA PS21/3","NIST CSF PR.AC-5","ISO 27001 A.9.1.2"],attr:"vpc.firewall_rules[].source_ranges + action"},
  ]},
];

const totalChecks = data.reduce((s,sc)=>s+sc.checks,0);
const totalPassed = data.reduce((s,sc)=>s+sc.passed,0);
const totalFailed = data.reduce((s,sc)=>s+sc.failed,0);
const overallRate = ((totalPassed/totalChecks)*100).toFixed(1);

document.getElementById('meta').innerHTML = `
  <div class="meta-card total"><div class="val">${totalChecks}</div><div class="lbl">Total checks</div></div>
  <div class="meta-card pass"><div class="val">${totalPassed}</div><div class="lbl">Passed</div></div>
  <div class="meta-card fail"><div class="val">${totalFailed}</div><div class="lbl">Failed</div></div>
  <div class="meta-card rate"><div class="val">${overallRate}%</div><div class="lbl">Overall compliance</div></div>
  <div class="meta-card total"><div class="val">0</div><div class="lbl">False positives</div></div>
`;

const grid = document.getElementById('scenarios');
data.forEach((sc,i) => {
  const card = document.createElement('div');
  card.className = 'sc-card';
  const rateCol = sc.rate === 100 ? 'pass' : sc.rate >= 80 ? 'rate' : 'fail';
  card.innerHTML = `
    <div class="sc-header" onclick="toggle(${i})">
      <span class="sc-title">${sc.id} — ${sc.title}</span>
      <div class="sc-badges">
        <span class="badge pass">${sc.passed} pass</span>
        ${sc.failed > 0 ? `<span class="badge fail">${sc.failed} fail</span>` : ''}
        <span class="badge rate">${sc.rate}%</span>
      </div>
      <span class="chevron" id="chev-${i}">&#9654;</span>
    </div>
    <div class="sc-body" id="body-${i}">
      <table class="findings-table">
        <thead><tr>
          <th>Control</th><th>Provider</th><th>Status</th>
          <th>Finding</th><th>Regulatory refs</th><th>Config attribute</th>
        </tr></thead>
        <tbody>
          ${sc.findings.map(f=>`
            <tr class="${f.status==='FAIL'?'fail-row':''}">
              <td><span class="ctrl-id">${f.ctrl}</span></td>
              <td><span class="provider ${f.provider.toLowerCase()}">${f.provider}</span></td>
              <td><span class="status-${f.status.toLowerCase()}">${f.status}</span></td>
              <td class="${f.status==='FAIL'?'fail-detail':'detail'}">${f.detail}</td>
              <td><div class="ref-list">${f.refs.join('<br>')}</div></td>
              <td><span class="attr">${f.attr}</span></td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
  grid.appendChild(card);
});

function toggle(i){
  const body = document.getElementById('body-'+i);
  const chev = document.getElementById('chev-'+i);
  body.classList.toggle('open');
  chev.classList.toggle('open');
}
</script>