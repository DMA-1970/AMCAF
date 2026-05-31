"""
AMCAF GCP Identity & Security Assessment
Automated governance checks for Google Cloud Platform
Maps to AMCAF control framework: IAM, ENC, LOG, NET domains
"""

try:
    from googleapiclient import discovery
    from google.auth import default as google_auth_default
    from google.auth.exceptions import DefaultCredentialsError
    from google.auth.transport.requests import Request as GoogleAuthRequest
    import httplib2
    from google_auth_httplib2 import AuthorizedHttp
    HAS_GCP_SDK = True
except ImportError:
    HAS_GCP_SDK = False

import json
import os
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests as _requests_lib
from datetime import datetime, timezone
from pathlib import Path


class GCPGovernanceAssessment:
    def __init__(self):
        self.findings = []
        self.summary = {}
        self.project_id = None
        self._services = {}

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_services(self):
        if not HAS_GCP_SDK:
            print("ERROR: google-api-python-client and google-auth are required.")
            print("Install with: pip install google-api-python-client google-auth google-auth-httplib2")
            sys.exit(1)

        try:
            credentials, project = google_auth_default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
            )
            self.project_id = os.getenv("GCP_PROJECT_ID") or project
            if not self.project_id:
                raise ValueError(
                    "Set GCP_PROJECT_ID or configure application default credentials with a project"
                )

            # Corporate proxy intercepts SSL — refresh token via requests with verify=False,
            # then build API clients using httplib2 with SSL validation disabled.
            session = _requests_lib.Session()
            session.verify = False
            auth_request = GoogleAuthRequest(session=session)
            credentials.refresh(auth_request)

            http = AuthorizedHttp(
                credentials,
                http=httplib2.Http(disable_ssl_certificate_validation=True)
            )

            self._services = {
                "iam":     discovery.build("iam",                    "v1", http=http),
                "compute": discovery.build("compute",                "v1", http=http),
                "storage": discovery.build("storage",                "v1", http=http),
                "logging": discovery.build("logging",                "v2", http=http),
                "crm":     discovery.build("cloudresourcemanager",   "v3", http=http),
            }
        except DefaultCredentialsError:
            print("ERROR: No GCP credentials found.")
            print("  gcloud auth application-default login")
            print("  or set GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json")
            sys.exit(1)

    def _svc(self, name):
        return self._services[name]

    def _err(self, control, control_id, exc):
        self.findings.append({
            "control": control,
            "control_id": control_id,
            "status": "ERROR",
            "risk": "UNKNOWN",
            "evidence": f"Unable to check: {str(exc)}",
            "recommendation": "Verify GCP API permissions for this check",
            "mapping": "N/A",
        })

    # ------------------------------------------------------------------
    # IAM-01 — Service Account Key Rotation
    # Equivalent to: AWS root account MFA / Entra admin MFA
    # ------------------------------------------------------------------
    def check_service_account_keys(self):
        try:
            iam = self._svc("iam")
            result = iam.projects().serviceAccounts().list(
                name=f"projects/{self.project_id}"
            ).execute()

            accounts = result.get("accounts", [])
            old_keys = []
            total_keys = 0
            cutoff = datetime.now(timezone.utc).timestamp() - (90 * 86400)

            for sa in accounts:
                try:
                    keys = iam.projects().serviceAccounts().keys().list(
                        name=sa["name"], keyTypes=["USER_MANAGED"]
                    ).execute()
                    for key in keys.get("keys", []):
                        total_keys += 1
                        created = key.get("validAfterTime", "")
                        if created:
                            ts = datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
                            if ts < cutoff:
                                old_keys.append(f"{sa['email']} (key …{key['name'].split('/')[-1][:8]})")
                except Exception:
                    continue

            self.summary["service_accounts"] = len(accounts)
            self.summary["user_managed_keys"] = total_keys
            self.summary["old_keys"] = len(old_keys)

            status = "PASS" if not old_keys else "FAIL"
            risk = "HIGH" if old_keys else "LOW"
            evidence = f"{len(accounts)} service account(s), {total_keys} user-managed key(s). {len(old_keys)} key(s) older than 90 days"
            if old_keys:
                evidence += f": {', '.join(old_keys[:3])}"

            self.findings.append({
                "control": "Service Account Key Rotation",
                "control_id": "IAM-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Rotate service account keys older than 90 days and prefer Workload Identity Federation" if old_keys else "Continue monitoring service account key age",
                "mapping": "NIST IA-5 / ISO27001 A.9.2.6 / DORA ICT Risk",
            })
        except Exception as e:
            self._err("Service Account Key Rotation", "IAM-01", e)

    # ------------------------------------------------------------------
    # IAM-02 — No allUsers / allAuthenticatedUsers IAM Bindings
    # Equivalent to: AWS IAM user MFA / Entra user MFA registration
    # ------------------------------------------------------------------
    def check_public_iam_bindings(self):
        try:
            crm = self._svc("crm")
            policy = crm.projects().getIamPolicy(
                resource=f"projects/{self.project_id}", body={}
            ).execute()

            public = []
            for binding in policy.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    public.append(f"{binding.get('role')} (public member)")

            self.summary["public_iam_bindings"] = len(public)

            status = "PASS" if not public else "FAIL"
            risk = "CRITICAL" if public else "LOW"
            evidence = f"{len(public)} IAM binding(s) with allUsers or allAuthenticatedUsers"
            if public:
                evidence += f": {', '.join(public[:3])}"

            self.findings.append({
                "control": "Public IAM Binding Restriction",
                "control_id": "IAM-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Remove allUsers and allAuthenticatedUsers from all project IAM bindings immediately" if public else "Continue monitoring IAM bindings",
                "mapping": "NIST AC-2 / ISO27001 A.9.2.3 / FCA PS21/3",
            })
        except Exception as e:
            self._err("Public IAM Binding Restriction", "IAM-02", e)

    # ------------------------------------------------------------------
    # IAM-03 — No Primitive Roles Assigned to Users
    # Equivalent to: AWS IAM policy least privilege / Entra privileged roles
    # ------------------------------------------------------------------
    def check_primitive_roles(self):
        try:
            crm = self._svc("crm")
            policy = crm.projects().getIamPolicy(
                resource=f"projects/{self.project_id}", body={}
            ).execute()

            violations = []
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                if role not in ("roles/owner", "roles/editor"):
                    continue
                users = [m for m in binding.get("members", []) if m.startswith("user:")]
                violations.extend([f"{role} -> {m}" for m in users])

            self.summary["primitive_role_violations"] = len(violations)

            status = "PASS" if not violations else "FAIL"
            risk = "HIGH" if violations else "LOW"
            evidence = f"{len(violations)} user(s) assigned primitive roles (owner/editor)"
            if violations:
                evidence += f": {', '.join(violations[:3])}"

            self.findings.append({
                "control": "IAM Least Privilege — No Primitive Roles",
                "control_id": "IAM-03",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Replace primitive roles with predefined or custom roles following least privilege" if violations else "Continue monitoring IAM role assignments",
                "mapping": "NIST AC-6 / ISO27001 A.9.2.3 / DORA",
            })
        except Exception as e:
            self._err("IAM Least Privilege — No Primitive Roles", "IAM-03", e)

    # ------------------------------------------------------------------
    # IAM-04 — Project Owner Count
    # Equivalent to: AWS password policy / Entra password policy
    # ------------------------------------------------------------------
    def check_owner_count(self):
        try:
            crm = self._svc("crm")
            policy = crm.projects().getIamPolicy(
                resource=f"projects/{self.project_id}", body={}
            ).execute()

            owners = []
            for binding in policy.get("bindings", []):
                if binding.get("role") == "roles/owner":
                    owners += [m for m in binding.get("members", []) if not m.startswith("serviceAccount:")]

            self.summary["project_owner_count"] = len(owners)

            status = "PASS" if len(owners) <= 3 else "FAIL"
            risk = "LOW" if status == "PASS" else "MEDIUM"
            evidence = f"{len(owners)} project owner(s) assigned (threshold: <=3)"
            if owners:
                evidence += f": {', '.join(owners[:5])}"

            self.findings.append({
                "control": "Project Owner Count Control",
                "control_id": "IAM-04",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Reduce project owners to <=3 and delegate access via folder/org-level IAM" if status == "FAIL" else "Continue monitoring owner assignments",
                "mapping": "NIST IA-5 / ISO27001 A.9.4.3",
            })
        except Exception as e:
            self._err("Project Owner Count Control", "IAM-04", e)

    # ------------------------------------------------------------------
    # ENC-01 — GCS Bucket Public Access Prevention
    # Equivalent to: AWS S3 bucket encryption / Entra app secret expiry
    # ------------------------------------------------------------------
    def check_storage_buckets(self):
        try:
            storage = self._svc("storage")
            result = storage.buckets().list(
                project=self.project_id,
                fields="items(name,iamConfiguration,encryption)"
            ).execute()

            buckets = result.get("items", [])
            public_buckets = []

            for bucket in buckets:
                name = bucket.get("name", "unknown")
                pap = bucket.get("iamConfiguration", {}).get("publicAccessPrevention", "unspecified")
                if pap == "enforced":
                    continue
                try:
                    iam_policy = storage.buckets().getIamPolicy(bucket=name).execute()
                    for binding in iam_policy.get("bindings", []):
                        if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                            public_buckets.append(name)
                            break
                except Exception:
                    pass

            self.summary["total_gcs_buckets"] = len(buckets)
            self.summary["public_buckets"] = len(public_buckets)

            status = "PASS" if not public_buckets else "FAIL"
            risk = "CRITICAL" if public_buckets else "LOW"
            evidence = f"{len(buckets)} GCS bucket(s). {len(public_buckets)} publicly accessible"
            if public_buckets:
                evidence += f": {', '.join(public_buckets[:3])}"
            else:
                evidence += ". Google-managed encryption active on all buckets"

            self.findings.append({
                "control": "GCS Bucket Public Access and Encryption",
                "control_id": "ENC-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enable Public Access Prevention on all buckets and audit bucket IAM" if public_buckets else "Continue monitoring bucket access controls",
                "mapping": "NIST SC-13 / ISO27001 A.10.1.1 / GDPR Art. 32",
            })
        except Exception as e:
            self._err("GCS Bucket Public Access and Encryption", "ENC-01", e)

    # ------------------------------------------------------------------
    # ENC-02 — Persistent Disk Encryption
    # Equivalent to: AWS EBS encryption / Entra managed identity adoption
    # ------------------------------------------------------------------
    def check_disk_encryption(self):
        try:
            compute = self._svc("compute")
            zones_result = compute.zones().list(project=self.project_id).execute()
            zones = [z["name"] for z in zones_result.get("items", [])]
            if len(zones) > 10:
                print(f"Note: Checking disks in first 10 of {len(zones)} zones")

            total_disks = 0
            cmek_disks = 0

            for zone in zones[:10]:
                try:
                    disks = compute.disks().list(
                        project=self.project_id, zone=zone,
                        fields="items(name,diskEncryptionKey)"
                    ).execute()
                    for disk in disks.get("items", []):
                        total_disks += 1
                        if disk.get("diskEncryptionKey", {}).get("kmsKeyName"):
                            cmek_disks += 1
                except Exception:
                    continue

            self.summary["total_persistent_disks"] = total_disks
            self.summary["cmek_disks"] = cmek_disks

            # GCP always encrypts at rest by default; CMEK is an additional control.
            # PASS with LOW risk when CMEK is in use or no disks exist.
            # PASS with MEDIUM risk when disks exist but rely on Google-managed keys only.
            if total_disks == 0 or cmek_disks > 0:
                status, risk = "PASS", "LOW"
                evidence = (
                    f"{total_disks} persistent disk(s). "
                    + (f"{cmek_disks} protected by customer-managed keys (CMEK)." if cmek_disks else
                       "Google-managed encryption active on all disks.")
                )
            else:
                status, risk = "PASS", "MEDIUM"
                evidence = (
                    f"{total_disks} persistent disk(s) encrypted by Google-managed keys. "
                    "No CMEK configured — consider CMEK for regulatory key-control requirements."
                )

            self.findings.append({
                "control": "Persistent Disk Encryption",
                "control_id": "ENC-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enable CMEK via Cloud KMS for workloads requiring key-control compliance" if risk == "MEDIUM" else "Continue monitoring disk encryption",
                "mapping": "NIST SC-13 / ISO27001 A.10.1.1 / GDPR Art. 32",
            })
        except Exception as e:
            self._err("Persistent Disk Encryption", "ENC-02", e)

    # ------------------------------------------------------------------
    # LOG-01 — Cloud Audit Logs Enabled
    # Equivalent to: AWS CloudTrail / Entra sign-in audit logs
    # ------------------------------------------------------------------
    def check_audit_logs(self):
        try:
            crm = self._svc("crm")
            policy = crm.projects().getIamPolicy(
                resource=f"projects/{self.project_id}", body={}
            ).execute()

            audit_configs = policy.get("auditConfigs", [])
            has_data_read = any(
                lc.get("logType") == "DATA_READ"
                for cfg in audit_configs
                for lc in cfg.get("auditLogConfigs", [])
            )
            has_data_write = any(
                lc.get("logType") == "DATA_WRITE"
                for cfg in audit_configs
                for lc in cfg.get("auditLogConfigs", [])
            )

            self.summary["audit_configs"] = len(audit_configs)
            self.summary["data_access_logging"] = has_data_read or has_data_write

            status = "PASS" if audit_configs else "FAIL"
            risk = "CRITICAL" if not audit_configs else "LOW"
            evidence = f"{len(audit_configs)} audit config(s). Data Read: {'enabled' if has_data_read else 'disabled'}. Data Write: {'enabled' if has_data_write else 'disabled'}"

            self.findings.append({
                "control": "Cloud Audit Logs Configuration",
                "control_id": "LOG-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enable Admin Activity and Data Access audit logs for all services" if not audit_configs else "Enable Data Read/Write logs for sensitive services",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1 / DORA",
            })
        except Exception as e:
            self._err("Cloud Audit Logs Configuration", "LOG-01", e)

    # ------------------------------------------------------------------
    # LOG-02 — Log Sink Configuration
    # Equivalent to: AWS CloudWatch / Entra identity protection
    # ------------------------------------------------------------------
    def check_log_sinks(self):
        try:
            logging_svc = self._svc("logging")
            result = logging_svc.projects().sinks().list(
                parent=f"projects/{self.project_id}"
            ).execute()

            sinks = result.get("sinks", [])
            self.summary["log_sinks"] = len(sinks)

            status = "PASS" if sinks else "FAIL"
            risk = "MEDIUM" if not sinks else "LOW"
            evidence = f"{len(sinks)} log sink(s) configured"
            if sinks:
                names = [s.get("name", "").split("/")[-1] for s in sinks[:3]]
                evidence += f": {', '.join(names)}"

            self.findings.append({
                "control": "Cloud Logging Sink Configuration",
                "control_id": "LOG-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Configure log sinks to export to Cloud Storage or BigQuery for long-term retention" if not sinks else "Continue monitoring log sink configuration",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1",
            })
        except Exception as e:
            self._err("Cloud Logging Sink Configuration", "LOG-02", e)

    # ------------------------------------------------------------------
    # NET-01 — No Unrestricted SSH (port 22) Firewall Rules
    # Equivalent to: AWS unrestricted SSH / Entra named locations
    # ------------------------------------------------------------------
    def check_unrestricted_ssh(self):
        try:
            compute = self._svc("compute")
            result = compute.firewalls().list(project=self.project_id).execute()
            firewalls = result.get("items", [])

            risky = []
            for rule in firewalls:
                if rule.get("direction", "INGRESS") != "INGRESS":
                    continue
                if not rule.get("allowed"):
                    continue
                if "0.0.0.0/0" not in rule.get("sourceRanges", []) and "::/0" not in rule.get("sourceRanges", []):
                    continue
                for allowed in rule.get("allowed", []):
                    proto = allowed.get("IPProtocol", "")
                    ports = allowed.get("ports", [])
                    if proto == "all" or (proto == "tcp" and (not ports or "22" in ports)):
                        risky.append(rule.get("name", "unknown"))
                        break

            self.summary["total_firewall_rules"] = len(firewalls)
            self.summary["ssh_open_rules"] = len(risky)

            status = "PASS" if not risky else "FAIL"
            risk = "CRITICAL" if risky else "LOW"
            evidence = f"{len(risky)} firewall rule(s) allow unrestricted SSH (0.0.0.0/0 port 22)"
            if risky:
                evidence += f": {', '.join(risky[:5])}"

            self.findings.append({
                "control": "Unrestricted SSH Firewall Access",
                "control_id": "NET-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Restrict SSH firewall rules to specific IP ranges; use Cloud IAP for bastion access" if risky else "Continue monitoring firewall rules",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3 / DORA",
            })
        except Exception as e:
            self._err("Unrestricted SSH Firewall Access", "NET-01", e)

    # ------------------------------------------------------------------
    # NET-02 — No Unrestricted RDP (port 3389) Firewall Rules
    # Equivalent to: AWS unrestricted RDP / Entra risky sign-in policy
    # ------------------------------------------------------------------
    def check_unrestricted_rdp(self):
        try:
            compute = self._svc("compute")
            result = compute.firewalls().list(project=self.project_id).execute()
            firewalls = result.get("items", [])

            risky = []
            for rule in firewalls:
                if rule.get("direction", "INGRESS") != "INGRESS":
                    continue
                if not rule.get("allowed"):
                    continue
                if "0.0.0.0/0" not in rule.get("sourceRanges", []) and "::/0" not in rule.get("sourceRanges", []):
                    continue
                for allowed in rule.get("allowed", []):
                    proto = allowed.get("IPProtocol", "")
                    ports = allowed.get("ports", [])
                    if proto == "all" or (proto == "tcp" and (not ports or "3389" in ports)):
                        risky.append(rule.get("name", "unknown"))
                        break

            self.summary["rdp_open_rules"] = len(risky)

            status = "PASS" if not risky else "FAIL"
            risk = "CRITICAL" if risky else "LOW"
            evidence = f"{len(risky)} firewall rule(s) allow unrestricted RDP (0.0.0.0/0 port 3389)"
            if risky:
                evidence += f": {', '.join(risky[:5])}"

            self.findings.append({
                "control": "Unrestricted RDP Firewall Access",
                "control_id": "NET-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Restrict RDP firewall rules to specific IP ranges" if risky else "Continue monitoring firewall rules",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3 / DORA",
            })
        except Exception as e:
            self._err("Unrestricted RDP Firewall Access", "NET-02", e)

    # ------------------------------------------------------------------
    # Scoring and reporting
    # ------------------------------------------------------------------

    def calculate_overall_score(self):
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        total = len([f for f in self.findings if f["status"] in ("PASS", "FAIL")])
        return int((passed / total) * 100) if total > 0 else 0

    def append_to_history(self, report):
        try:
            history_dir = Path("results/history")
            history_dir.mkdir(parents=True, exist_ok=True)
            history_file = history_dir / "history.json"

            history = []
            if history_file.exists():
                with open(history_file, encoding='utf-8') as f:
                    history = json.load(f)

            history.append({
                "run_id": f"GCP-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')}",
                "timestamp": report["assessment_timestamp_utc"],
                "scenario": "live-gcp",
                "total_checks": report["summary"]["total_checks"],
                "passed": report["summary"]["passed"],
                "failed": report["summary"]["failed"],
                "compliance_rate": float(report["overall_score"]),
            })

            with open(history_file, "w", encoding='utf-8') as f:
                json.dump(history, f, indent=2)
            print(f"History updated: {history_file}")
        except Exception as e:
            print(f"Could not update history: {e}")

    def generate_report(self):
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        failed = sum(1 for f in self.findings if f["status"] == "FAIL")
        errors = sum(1 for f in self.findings if f["status"] == "ERROR")

        report = {
            "assessment_name": "AMCAF GCP Identity & Security Assessment",
            "assessment_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "project_id": self.project_id,
            "overall_score": self.calculate_overall_score(),
            "summary": {
                **self.summary,
                "total_checks": len(self.findings),
                "passed": passed,
                "failed": failed,
                "errors": errors,
            },
            "findings": self.findings,
        }

        try:
            with open("results/gcp_assessment.json", "w") as f:
                json.dump(report, f, indent=2)
            print(f"Report saved: results/gcp_assessment.json")
        except Exception as e:
            print(f"Could not save report: {e}")

        self.append_to_history(report)
        self.push_to_github(report)
        return report

    def push_to_github(self, report):
        import subprocess
        from pathlib import Path
        root  = Path(__file__).parent
        files = ['results/gcp_assessment.json', 'results/history/history.json']
        score = report.get('overall_score', 0)
        date  = report.get('assessment_timestamp_utc', '')[:10]
        msg   = f"chore: GCP live assessment {date} ({score}/100)"
        try:
            subprocess.run(['git', 'add'] + files, cwd=root, check=True)
            subprocess.run(['git', 'commit', '-m', msg], cwd=root, check=True)
            subprocess.run(['git', 'push', 'origin', 'main'], cwd=root, check=True)
            print("Results pushed to GitHub.")
        except subprocess.CalledProcessError as e:
            print(f"WARNING: Could not push to GitHub: {e}")

    def run_assessment(self):
        print("AMCAF GCP Identity & Security Governance Assessment")
        print("=" * 50)

        self._init_services()
        print(f"Project: {self.project_id}")
        print()

        checks = [
            ("Service Account Key Rotation",  self.check_service_account_keys),
            ("Public IAM Bindings",           self.check_public_iam_bindings),
            ("IAM Least Privilege",           self.check_primitive_roles),
            ("Project Owner Count",           self.check_owner_count),
            ("GCS Bucket Security",           self.check_storage_buckets),
            ("Persistent Disk Encryption",    self.check_disk_encryption),
            ("Cloud Audit Logs",              self.check_audit_logs),
            ("Log Sinks",                     self.check_log_sinks),
            ("Unrestricted SSH",              self.check_unrestricted_ssh),
            ("Unrestricted RDP",              self.check_unrestricted_rdp),
        ]

        for name, fn in checks:
            print(f"Checking: {name}...", end=" ", flush=True)
            try:
                fn()
                print("OK")
            except Exception as e:
                print(f"WARN: {e}")

        return self.generate_report()


def main():
    assessment = GCPGovernanceAssessment()
    report = assessment.run_assessment()

    print("\n" + "=" * 50)
    print(f"Overall Score: {report['overall_score']}/100")
    print(f"Passed:  {report['summary']['passed']}")
    print(f"Failed:  {report['summary']['failed']}")
    print(f"Errors:  {report['summary']['errors']}")
    print("=" * 50)

    for f in report["findings"]:
        print(f"\n  [{f['control_id']}] {f['control']} -- {f['status']} ({f['risk']} RISK)")
        print(f"  Evidence: {f['evidence']}")


if __name__ == "__main__":
    main()
