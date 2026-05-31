"""
AMCAF Entra Identity & Security Assessment
Automated governance checks for Microsoft Entra ID (Azure AD)
Maps to AMCAF control framework: IAM, ENC, LOG, NET domains
"""

from graph_connector import GraphConnector
import json
from datetime import datetime, timezone
from pathlib import Path


class EntraGovernanceAssessment:
    def __init__(self):
        self.graph = GraphConnector()
        self.findings = []
        self.summary = {}
        self._cache = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch(self, path):
        if path in self._cache:
            return self._cache[path]
        try:
            result = self.graph.graph_get(f"https://graph.microsoft.com/v1.0/{path}")
            self._cache[path] = result
            return result
        except Exception:
            self._cache[path] = None
            return None

    def _val(self, path):
        r = self._fetch(path)
        return r.get("value", []) if r else []

    def _err(self, control, control_id, exc):
        self.findings.append({
            "control": control,
            "control_id": control_id,
            "status": "ERROR",
            "risk": "UNKNOWN",
            "evidence": f"Unable to check: {str(exc)}",
            "recommendation": "Verify API permissions for this check",
            "mapping": "N/A",
        })

    # ------------------------------------------------------------------
    # IAM-01 — Admin Account MFA Enforcement
    # Equivalent to: AWS root account MFA check
    # ------------------------------------------------------------------
    def check_admin_mfa(self):
        try:
            ca_policies = self._val("identity/conditionalAccess/policies")
            enabled = [p for p in ca_policies if str(p.get("state", "")).lower() == "enabled"]

            mfa_policies = []
            for p in enabled:
                grant = p.get("grantControls") or {}
                controls = grant.get("builtInControls", [])
                has_mfa = "mfa" in controls or "authenticationStrength" in grant

                if not has_mfa:
                    continue

                users_cond = p.get("conditions", {}).get("users", {})
                includes_all = "All" in users_cond.get("includeUsers", [])
                includes_roles = len(users_cond.get("includeRoles", [])) > 0

                if includes_all or includes_roles:
                    mfa_policies.append(p.get("displayName", "Unnamed"))

            status = "PASS" if mfa_policies else "FAIL"
            risk = "LOW" if status == "PASS" else "CRITICAL"
            evidence = f"{len(mfa_policies)} CA policy(ies) enforce MFA for admin/all accounts"
            if mfa_policies:
                evidence += f": {', '.join(mfa_policies[:3])}"

            self.findings.append({
                "control": "Admin Account MFA Enforcement",
                "control_id": "IAM-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Create a Conditional Access policy requiring MFA for all privileged roles" if status == "FAIL" else "Continue monitoring CA policies",
                "mapping": "NIST IA-2 / ISO27001 A.9.4.2 / DORA ICT Risk",
            })
        except Exception as e:
            self._err("Admin Account MFA Enforcement", "IAM-01", e)

    # ------------------------------------------------------------------
    # IAM-02 — User MFA Registration
    # Equivalent to: AWS IAM user MFA enforcement check
    # ------------------------------------------------------------------
    def check_user_mfa(self):
        try:
            report = self._val("reports/credentialUserRegistrationDetails")

            if report:
                total = len(report)
                with_mfa = sum(1 for u in report if u.get("isMfaRegistered") or u.get("isMfaCapable"))
                without = [u.get("userPrincipalName", "") for u in report if not (u.get("isMfaRegistered") or u.get("isMfaCapable"))]

                self.summary["users_with_mfa"] = with_mfa
                self.summary["users_without_mfa"] = len(without)

                status = "PASS" if not without else "FAIL"
                risk = "HIGH" if without else "LOW"
                evidence = f"{with_mfa}/{total} users have MFA registered"
                if without:
                    evidence += f". Without MFA: {', '.join(without[:5])}"
                    if len(without) > 5:
                        evidence += f" and {len(without) - 5} more"
            else:
                # Fallback: check whether any enabled CA policy requires MFA for all users
                ca_policies = self._val("identity/conditionalAccess/policies")
                enabled = [p for p in ca_policies if str(p.get("state", "")).lower() == "enabled"]
                all_user_mfa = [
                    p for p in enabled
                    if "All" in (p.get("conditions", {}).get("users", {}).get("includeUsers", []))
                    and "mfa" in ((p.get("grantControls") or {}).get("builtInControls", []))
                ]
                status = "PASS" if all_user_mfa else "FAIL"
                risk = "HIGH" if not all_user_mfa else "LOW"
                evidence = f"Registration report unavailable (Reports.Read.All may be missing). {len(all_user_mfa)} CA policy(ies) require MFA for all users"

            self.findings.append({
                "control": "User MFA Registration",
                "control_id": "IAM-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enforce MFA registration for all users via Conditional Access policy" if status == "FAIL" else "Continue monitoring MFA registration",
                "mapping": "NIST IA-2 / ISO27001 A.9.4.2 / FCA PS21/3",
            })
        except Exception as e:
            self._err("User MFA Registration", "IAM-02", e)

    # ------------------------------------------------------------------
    # IAM-03 — Privileged Role Least Privilege
    # Equivalent to: AWS IAM policy least privilege check
    # ------------------------------------------------------------------
    def check_privileged_roles(self):
        try:
            roles = self._val("directoryRoles")
            privileged = ["Global Administrator", "Privileged Role Administrator",
                          "Security Administrator", "Exchange Administrator"]

            global_admin_count = 0
            total_privileged = 0
            role_details = []

            for role in roles:
                if role.get("displayName") not in privileged:
                    continue
                members = self._val(f"directoryRoles/{role['id']}/members?$select=displayName,userPrincipalName")
                count = len(members)
                role_details.append(f"{role['displayName']}: {count}")
                total_privileged += count
                if role.get("displayName") == "Global Administrator":
                    global_admin_count = count

            self.summary["global_admin_count"] = global_admin_count
            self.summary["total_privileged_assignments"] = total_privileged

            status = "PASS" if global_admin_count <= 5 else "FAIL"
            risk = "LOW" if status == "PASS" else "HIGH"
            evidence = f"{global_admin_count} Global Administrator(s) assigned"
            if role_details:
                evidence += f". Privileged assignments — {'; '.join(role_details)}"

            self.findings.append({
                "control": "Privileged Role Least Privilege",
                "control_id": "IAM-03",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Reduce Global Administrator count to <=5 and use Privileged Identity Management (PIM) for just-in-time access" if status == "FAIL" else "Continue monitoring privileged role assignments",
                "mapping": "NIST AC-6 / ISO27001 A.9.2.3 / DORA",
            })
        except Exception as e:
            self._err("Privileged Role Least Privilege", "IAM-03", e)

    # ------------------------------------------------------------------
    # IAM-04 — Password Policy Configuration
    # Equivalent to: AWS IAM password policy strength check
    # ------------------------------------------------------------------
    def check_password_policy(self):
        try:
            domains = self._val("domains")
            default = next((d for d in domains if d.get("isDefault")), None)

            if default:
                validity = default.get("passwordValidityPeriodInDays", 2147483647)
                notification = default.get("passwordNotificationWindowInDays", 14)

                # 2147483647 = never expires → passwordless / cloud-only model → PASS
                passes = validity <= 90 or validity == 2147483647
                status = "PASS" if passes else "FAIL"
                risk = "LOW" if passes else "MEDIUM"

                if validity == 2147483647:
                    evidence = f"Password never expires (passwordless/managed auth model). Notification window: {notification} days"
                else:
                    evidence = f"Password validity: {validity} days. Notification: {notification} days"
            else:
                status = "FAIL"
                risk = "MEDIUM"
                evidence = "Could not retrieve domain password policy"

            self.findings.append({
                "control": "Password Policy Configuration",
                "control_id": "IAM-04",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Set password expiry <= 90 days or adopt passwordless authentication" if status == "FAIL" else "Continue monitoring password policy",
                "mapping": "NIST IA-5 / ISO27001 A.9.4.3",
            })
        except Exception as e:
            self._err("Password Policy Configuration", "IAM-04", e)

    # ------------------------------------------------------------------
    # ENC-01 — Application Secret / Credential Expiry
    # Equivalent to: AWS S3 bucket encryption check
    # ------------------------------------------------------------------
    def check_app_credentials(self):
        try:
            now = datetime.now(timezone.utc)
            apps = self._val("applications?$top=999&$select=displayName,passwordCredentials,keyCredentials")

            expired, near_expiry = [], []

            for app in apps:
                name = app.get("displayName", "Unknown")
                for cred in app.get("passwordCredentials", []):
                    end = cred.get("endDateTime")
                    if not end:
                        continue
                    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                    days_left = (end_dt - now).days
                    if days_left < 0:
                        expired.append(f"{name} (expired {abs(days_left)}d ago)")
                    elif days_left <= 30:
                        near_expiry.append(f"{name} ({days_left}d remaining)")

            self.summary["apps_with_expired_secrets"] = len(expired)
            self.summary["apps_near_expiry"] = len(near_expiry)

            status = "PASS" if not expired and not near_expiry else "FAIL"
            risk = "HIGH" if expired else ("MEDIUM" if near_expiry else "LOW")
            evidence = f"{len(expired)} expired, {len(near_expiry)} near-expiry (<=30d) app secrets"
            if expired:
                evidence += f". Expired: {', '.join(expired[:3])}"
            elif near_expiry:
                evidence += f". Near expiry: {', '.join(near_expiry[:3])}"

            self.findings.append({
                "control": "Application Secret Credential Management",
                "control_id": "ENC-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Rotate expired/near-expiry secrets immediately and implement automated rotation" if status == "FAIL" else "Continue monitoring app credential expiry",
                "mapping": "NIST SC-12 / ISO27001 A.10.1.2 / GDPR Art. 32",
            })
        except Exception as e:
            self._err("Application Secret Credential Management", "ENC-01", e)

    # ------------------------------------------------------------------
    # ENC-02 — Managed Identity Adoption
    # Equivalent to: AWS EBS volume encryption check
    # ------------------------------------------------------------------
    def check_managed_identity(self):
        try:
            sps = self._val("servicePrincipals?$top=999&$select=displayName,servicePrincipalType")
            managed = [sp for sp in sps if sp.get("servicePrincipalType") == "ManagedIdentity"]

            apps = self._val("applications?$top=999&$select=displayName,passwordCredentials")
            long_lived = []
            for app in apps:
                for cred in app.get("passwordCredentials", []):
                    start = cred.get("startDateTime")
                    end = cred.get("endDateTime")
                    if start and end:
                        s = datetime.fromisoformat(start.replace("Z", "+00:00"))
                        e = datetime.fromisoformat(end.replace("Z", "+00:00"))
                        if (e - s).days > 730:
                            long_lived.append(app.get("displayName", "Unknown"))

            self.summary["managed_identity_count"] = len(managed)
            self.summary["apps_with_long_lived_secrets"] = len(long_lived)

            status = "PASS" if not long_lived else "FAIL"
            risk = "LOW" if status == "PASS" else "MEDIUM"
            evidence = f"{len(managed)} managed identity(ies) in use. {len(long_lived)} app(s) with secrets valid >2 years"
            if long_lived:
                evidence += f": {', '.join(long_lived[:3])}"

            self.findings.append({
                "control": "Managed Identity Adoption",
                "control_id": "ENC-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Replace long-lived client secrets with managed identities where possible" if status == "FAIL" else "Continue monitoring credential lifespans",
                "mapping": "NIST SC-12 / ISO27001 A.10.1.2 / DORA",
            })
        except Exception as e:
            self._err("Managed Identity Adoption", "ENC-02", e)

    # ------------------------------------------------------------------
    # LOG-01 — Sign-in Audit Log Availability
    # Equivalent to: AWS CloudTrail multi-region logging check
    # ------------------------------------------------------------------
    def check_audit_logs(self):
        try:
            result = self._fetch("auditLogs/signIns?$top=1&$select=id,createdDateTime")

            if result is not None and "value" in result:
                available = len(result.get("value", [])) > 0
                status = "PASS" if available else "FAIL"
                risk = "LOW" if available else "HIGH"
                evidence = "Sign-in audit logs are active and accessible via Microsoft Graph" if available else "No sign-in log entries found — logs may not be enabled or retained"
            else:
                status = "FAIL"
                risk = "HIGH"
                evidence = "Sign-in audit log endpoint unavailable — AuditLog.Read.All permission may be missing"

            self.findings.append({
                "control": "Sign-in Audit Log Availability",
                "control_id": "LOG-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enable diagnostic settings for sign-in logs and configure Log Analytics retention ≥90 days" if status == "FAIL" else "Continue monitoring audit log availability",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1 / DORA",
            })
        except Exception as e:
            self._err("Sign-in Audit Log Availability", "LOG-01", e)

    # ------------------------------------------------------------------
    # LOG-02 — Identity Protection Risk Detection
    # Equivalent to: AWS CloudWatch logs configuration check
    # ------------------------------------------------------------------
    def check_identity_protection(self):
        try:
            result = self._fetch("identityProtection/riskyUsers?$top=10&$select=id,riskLevel,riskState")

            if result is not None:
                users = result.get("value", [])
                high_risk = [u for u in users if u.get("riskLevel") == "high"]
                medium_risk = [u for u in users if u.get("riskLevel") == "medium"]

                self.summary["high_risk_users"] = len(high_risk)
                self.summary["medium_risk_users"] = len(medium_risk)

                status = "PASS" if not high_risk else "FAIL"
                risk = "LOW" if not high_risk else "HIGH"
                evidence = f"Identity Protection active. {len(high_risk)} high-risk, {len(medium_risk)} medium-risk user(s) detected"

                self.findings.append({
                    "control": "Identity Protection Risk Detection",
                    "control_id": "LOG-02",
                    "status": status,
                    "risk": risk,
                    "evidence": evidence,
                    "recommendation": "Remediate high-risk users and configure risk-based Conditional Access policies" if status == "FAIL" else "Continue monitoring risk detections",
                    "mapping": "NIST AU-2 / ISO27001 A.12.4.1 / DORA",
                })
            else:
                self.findings.append({
                    "control": "Identity Protection Risk Detection",
                    "control_id": "LOG-02",
                    "status": "FAIL",
                    "risk": "MEDIUM",
                    "evidence": "Identity Protection endpoint unavailable — IdentityRiskyUser.Read.All permission or Entra ID P2 licence may be missing",
                    "recommendation": "Enable Microsoft Entra ID P2 and grant IdentityRiskyUser.Read.All permission",
                    "mapping": "NIST AU-2 / ISO27001 A.12.4.1",
                })
        except Exception as e:
            self._err("Identity Protection Risk Detection", "LOG-02", e)

    # ------------------------------------------------------------------
    # NET-01 — Named Location Network Controls
    # Equivalent to: AWS unrestricted SSH check
    # ------------------------------------------------------------------
    def check_named_locations(self):
        try:
            locations = self._val("identity/conditionalAccess/namedLocations")
            self.summary["named_locations"] = len(locations)

            status = "PASS" if locations else "FAIL"
            risk = "LOW" if status == "PASS" else "MEDIUM"
            evidence = f"{len(locations)} named location(s) defined for network-based access control"
            if locations:
                names = [l.get("displayName", "Unknown") for l in locations[:3]]
                evidence += f": {', '.join(names)}"

            self.findings.append({
                "control": "Named Location Network Controls",
                "control_id": "NET-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Define named locations (trusted IPs/ranges) and reference them in Conditional Access policies" if status == "FAIL" else "Continue monitoring named location usage",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3 / DORA",
            })
        except Exception as e:
            self._err("Named Location Network Controls", "NET-01", e)

    # ------------------------------------------------------------------
    # NET-02 — Risky Sign-in Detection Policy
    # Equivalent to: AWS unrestricted RDP check
    # ------------------------------------------------------------------
    def check_risky_signin_policy(self):
        try:
            ca_policies = self._val("identity/conditionalAccess/policies")
            enabled = [p for p in ca_policies if str(p.get("state", "")).lower() == "enabled"]

            risk_policies = []
            for p in enabled:
                conditions = p.get("conditions", {})
                if conditions.get("signInRiskLevels") or conditions.get("userRiskLevels"):
                    risk_policies.append(p.get("displayName", "Unknown"))

            status = "PASS" if risk_policies else "FAIL"
            risk = "LOW" if status == "PASS" else "HIGH"
            evidence = f"{len(risk_policies)} CA policy(ies) respond to risky sign-ins or user risk"
            if risk_policies:
                evidence += f": {', '.join(risk_policies[:3])}"

            self.findings.append({
                "control": "Risky Sign-in Detection Policy",
                "control_id": "NET-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Create Conditional Access policies that block or require MFA on high sign-in risk" if status == "FAIL" else "Continue monitoring risk-based CA policies",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3 / DORA",
            })
        except Exception as e:
            self._err("Risky Sign-in Detection Policy", "NET-02", e)

    # ------------------------------------------------------------------
    # Scoring and reporting
    # ------------------------------------------------------------------

    def calculate_overall_score(self):
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        total = len([f for f in self.findings if f["status"] in ("PASS", "FAIL")])
        return int((passed / total) * 100) if total > 0 else 0

    def append_to_history(self, report):
        try:
            # M-09: use __file__ so this works regardless of working directory
            history_dir = Path(__file__).parent.parent / "results" / "history"
            history_dir.mkdir(parents=True, exist_ok=True)
            history_file = history_dir / "history.json"

            history = []
            if history_file.exists():
                with open(history_file, encoding='utf-8') as f:
                    history = json.load(f)

            history.append({
                "run_id": f"ENTRA-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')}",
                "timestamp": report["assessment_timestamp_utc"],
                "scenario": "live-entra",
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

        all_users = self._val("users?$select=id,displayName,userPrincipalName,userType,accountEnabled&$top=999")
        enabled_users = [u for u in all_users if u.get("accountEnabled")]
        guest_users = [u for u in all_users if str(u.get("userType", "")).lower() == "guest"]
        apps = self._val("applications?$top=999")
        ca = self._val("identity/conditionalAccess/policies")

        report = {
            "assessment_name": "AMCAF Entra Identity Governance Assessment",
            "assessment_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "overall_score": self.calculate_overall_score(),
            "summary": {
                **self.summary,
                "total_users": len(all_users),
                "enabled_users": len(enabled_users),
                "guest_users": len(guest_users),
                "application_registrations": len(apps),
                "conditional_access_policies": len(ca),
                "enabled_conditional_access_policies": len([p for p in ca if str(p.get("state", "")).lower() == "enabled"]),
                "total_checks": len(self.findings),
                "passed": passed,
                "failed": failed,
                "errors": errors,
            },
            "findings": self.findings,
        }

        try:
            # M-09: resolve path relative to this file, not the working directory
            results_dir = Path(__file__).parent.parent / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            report_path = results_dir / "entra_assessment.json"
            with open(report_path, "w", encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved: {report_path}")
        except Exception as e:
            print(f"\nCould not save report: {e}")

        self.append_to_history(report)
        return report

    def run_assessment(self):
        print("AMCAF Entra Identity Governance Assessment")
        print("=" * 50)

        checks = [
            ("Admin Account MFA",           self.check_admin_mfa),
            ("User MFA Registration",        self.check_user_mfa),
            ("Privileged Role Least Privilege", self.check_privileged_roles),
            ("Password Policy",              self.check_password_policy),
            ("Application Secret Expiry",    self.check_app_credentials),
            ("Managed Identity Adoption",    self.check_managed_identity),
            ("Sign-in Audit Logs",           self.check_audit_logs),
            ("Identity Protection",          self.check_identity_protection),
            ("Named Locations",              self.check_named_locations),
            ("Risky Sign-in Policy",         self.check_risky_signin_policy),
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
    assessment = EntraGovernanceAssessment()
    report = assessment.run_assessment()

    print("\n" + "=" * 50)
    print(f"Overall Score: {report['overall_score']}/100")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Errors: {report['summary']['errors']}")
    print("=" * 50)

    for f in report["findings"]:
        print(f"\n  [{f['control_id']}] {f['control']} — {f['status']} ({f['risk']} RISK)")
        print(f"  Evidence: {f['evidence']}")


if __name__ == "__main__":
    main()
