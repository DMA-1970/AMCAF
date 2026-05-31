"""
AMCAF AWS Identity & Security Assessment
Automated governance checks for AWS environment
Maps to AMCAF control framework: IAM, ENC, LOG, NET domains
"""

import boto3
import json
import ssl
import urllib3
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError
import sys

# Corporate proxy intercepts SSL — disable verification globally for boto3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context

class AWSGovernanceAssessment:
    def __init__(self):
        self.session = boto3.Session()
        self.findings = []
        self.summary = {}

    def _client(self, service):
        return self.session.client(service, verify=False)
        
    def check_root_mfa(self):
        """IAM-01: Root account MFA enabled"""
        try:
            iam = self._client('iam')
            summary = iam.get_account_summary()
            
            mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
            
            self.findings.append({
                "control": "Root Account MFA",
                "control_id": "IAM-01",
                "status": "PASS" if mfa_enabled else "FAIL",
                "risk": "CRITICAL" if not mfa_enabled else "LOW",
                "evidence": f"Root MFA status: {'Enabled' if mfa_enabled else 'Disabled'}",
                "recommendation": "Enable MFA on root account immediately" if not mfa_enabled else "Continue monitoring root account access",
                "mapping": "NIST IA-2 / ISO27001 A.9.4.2 / DORA ICT Risk"
            })
        except Exception as e:
            self.findings.append({
                "control": "Root Account MFA",
                "control_id": "IAM-01",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify IAM permissions for assessment",
                "mapping": "NIST IA-2 / ISO27001 A.9.4.2"
            })
    
    def check_iam_user_mfa(self):
        """IAM-02: IAM users have MFA enabled"""
        try:
            iam = self._client('iam')
            # C-04: paginate — list_users caps at 100 without a paginator
            paginator = iam.get_paginator('list_users')
            users = []
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            total_users = len(users)
            users_with_mfa = 0
            users_without_mfa = []
            
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                if mfa_devices['MFADevices']:
                    users_with_mfa += 1
                else:
                    users_without_mfa.append(user['UserName'])
            
            self.summary['total_iam_users'] = total_users
            self.summary['users_with_mfa'] = users_with_mfa
            self.summary['users_without_mfa'] = len(users_without_mfa)
            
            status = "PASS" if len(users_without_mfa) == 0 else "FAIL"
            risk = "HIGH" if len(users_without_mfa) > 0 else "LOW"
            
            evidence = f"{users_with_mfa}/{total_users} users have MFA enabled"
            if users_without_mfa:
                evidence += f". Users without MFA: {', '.join(users_without_mfa[:5])}"
                if len(users_without_mfa) > 5:
                    evidence += f" and {len(users_without_mfa) - 5} more"
            
            self.findings.append({
                "control": "IAM User MFA Enforcement",
                "control_id": "IAM-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enforce MFA for all IAM users through IAM policy" if users_without_mfa else "Continue monitoring MFA compliance",
                "mapping": "NIST IA-2 / ISO27001 A.9.4.2 / FCA PS21/3"
            })
        except Exception as e:
            self.findings.append({
                "control": "IAM User MFA Enforcement",
                "control_id": "IAM-02",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify IAM permissions",
                "mapping": "NIST IA-2 / ISO27001 A.9.4.2"
            })
    
    def check_overly_permissive_policies(self):
        """IAM-03: No overly permissive IAM policies"""
        try:
            iam = self._client('iam')
            policies = iam.list_policies(Scope='Local')['Policies']
            
            risky_policies = []
            
            for policy in policies[:50]:  # Check first 50 custom policies
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    document = version['PolicyVersion']['Document']
                    statements = document.get('Statement', [])
                    
                    for statement in statements:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            # Check for wildcards
                            if '*' in actions or any(r == '*' for r in resources):
                                risky_policies.append(policy['PolicyName'])
                                break
                except Exception:
                    continue
            
            self.summary['custom_policies'] = len(policies)
            self.summary['risky_policies'] = len(risky_policies)
            
            status = "PASS" if len(risky_policies) == 0 else "FAIL"
            risk = "HIGH" if len(risky_policies) > 0 else "LOW"
            
            evidence = f"{len(risky_policies)} overly permissive policies found"
            if risky_policies:
                evidence += f": {', '.join(risky_policies[:3])}"
            
            self.findings.append({
                "control": "IAM Policy Least Privilege",
                "control_id": "IAM-03",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Review and restrict policies with wildcard actions/resources" if risky_policies else "Continue least privilege review",
                "mapping": "NIST AC-6 / ISO27001 A.9.2.3 / DORA"
            })
        except Exception as e:
            self.findings.append({
                "control": "IAM Policy Least Privilege",
                "control_id": "IAM-03",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify IAM permissions",
                "mapping": "NIST AC-6 / ISO27001 A.9.2.3"
            })
    
    def check_password_policy(self):
        """IAM-04: IAM password policy meets requirements"""
        try:
            iam = self._client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']
            
            requirements = {
                'MinimumPasswordLength': policy.get('MinimumPasswordLength', 0) >= 14,
                'RequireUppercaseCharacters': policy.get('RequireUppercaseCharacters', False),
                'RequireLowercaseCharacters': policy.get('RequireLowercaseCharacters', False),
                'RequireNumbers': policy.get('RequireNumbers', False),
                'RequireSymbols': policy.get('RequireSymbols', False),
                'MaxPasswordAge': policy.get('MaxPasswordAge', 999) <= 90
            }
            
            met = sum(requirements.values())
            total = len(requirements)
            
            status = "PASS" if met == total else "FAIL"
            risk = "MEDIUM" if met < total else "LOW"
            
            self.findings.append({
                "control": "Password Policy Strength",
                "control_id": "IAM-04",
                "status": status,
                "risk": risk,
                "evidence": f"Password policy meets {met}/{total} security requirements",
                "recommendation": "Strengthen password policy to meet all requirements" if met < total else "Continue monitoring password policy",
                "mapping": "NIST IA-5 / ISO27001 A.9.4.3"
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                self.findings.append({
                    "control": "Password Policy Strength",
                    "control_id": "IAM-04",
                    "status": "FAIL",
                    "risk": "HIGH",
                    "evidence": "No password policy configured",
                    "recommendation": "Configure IAM password policy immediately",
                    "mapping": "NIST IA-5 / ISO27001 A.9.4.3"
                })
            else:
                raise
    
    def check_s3_encryption(self):
        """ENC-01: S3 buckets have encryption enabled"""
        try:
            s3 = self._client('s3')
            buckets = s3.list_buckets()['Buckets']
            
            total_buckets = len(buckets)
            encrypted_buckets = 0
            unencrypted = []
            
            for bucket in buckets:
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encrypted_buckets += 1
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        unencrypted.append(bucket['Name'])
            
            self.summary['total_s3_buckets'] = total_buckets
            self.summary['encrypted_buckets'] = encrypted_buckets
            
            status = "PASS" if len(unencrypted) == 0 else "FAIL"
            risk = "HIGH" if len(unencrypted) > 0 else "LOW"
            
            evidence = f"{encrypted_buckets}/{total_buckets} buckets encrypted"
            if unencrypted:
                evidence += f". Unencrypted: {', '.join(unencrypted[:3])}"
            
            self.findings.append({
                "control": "S3 Bucket Encryption",
                "control_id": "ENC-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Enable default encryption on all S3 buckets" if unencrypted else "Continue monitoring encryption",
                "mapping": "NIST SC-13 / ISO27001 A.10.1.1 / GDPR Art. 32"
            })
        except Exception as e:
            self.findings.append({
                "control": "S3 Bucket Encryption",
                "control_id": "ENC-01",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify S3 permissions",
                "mapping": "NIST SC-13 / ISO27001 A.10.1.1"
            })
    
    def check_ebs_encryption(self):
        """ENC-02: EBS volumes are encrypted"""
        try:
            ec2 = self._client('ec2')
            volumes = ec2.describe_volumes()['Volumes']
            
            total_volumes = len(volumes)
            encrypted_volumes = sum(1 for v in volumes if v.get('Encrypted', False))
            
            self.summary['total_ebs_volumes'] = total_volumes
            self.summary['encrypted_volumes'] = encrypted_volumes
            
            status = "PASS" if encrypted_volumes == total_volumes else "FAIL"
            risk = "HIGH" if encrypted_volumes < total_volumes else "LOW"
            
            self.findings.append({
                "control": "EBS Volume Encryption",
                "control_id": "ENC-02",
                "status": status,
                "risk": risk,
                "evidence": f"{encrypted_volumes}/{total_volumes} EBS volumes encrypted",
                "recommendation": "Enable encryption for all EBS volumes" if encrypted_volumes < total_volumes else "Continue monitoring",
                "mapping": "NIST SC-13 / ISO27001 A.10.1.1 / GDPR Art. 32"
            })
        except Exception as e:
            self.findings.append({
                "control": "EBS Volume Encryption",
                "control_id": "ENC-02",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify EC2 permissions",
                "mapping": "NIST SC-13 / ISO27001 A.10.1.1"
            })
    
    def check_cloudtrail(self):
        """LOG-01: CloudTrail enabled in all regions"""
        try:
            cloudtrail = self._client('cloudtrail')
            trails = cloudtrail.describe_trails()['trailList']
            
            multi_region_trails = [t for t in trails if t.get('IsMultiRegionTrail', False)]
            
            self.summary['cloudtrail_trails'] = len(trails)
            self.summary['multi_region_trails'] = len(multi_region_trails)
            
            status = "PASS" if len(multi_region_trails) > 0 else "FAIL"
            risk = "CRITICAL" if len(multi_region_trails) == 0 else "LOW"
            
            self.findings.append({
                "control": "CloudTrail Multi-Region Logging",
                "control_id": "LOG-01",
                "status": status,
                "risk": risk,
                "evidence": f"{len(multi_region_trails)} multi-region CloudTrail(s) active",
                "recommendation": "Enable CloudTrail in all regions for comprehensive audit logging" if not multi_region_trails else "Continue monitoring CloudTrail",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1 / DORA"
            })
        except Exception as e:
            self.findings.append({
                "control": "CloudTrail Multi-Region Logging",
                "control_id": "LOG-01",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify CloudTrail permissions",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1"
            })
    
    def check_cloudwatch_logs(self):
        """LOG-02: CloudWatch logging configured"""
        try:
            logs = self._client('logs')
            log_groups = logs.describe_log_groups()['logGroups']
            
            self.summary['cloudwatch_log_groups'] = len(log_groups)
            
            status = "PASS" if len(log_groups) > 0 else "FAIL"
            risk = "MEDIUM" if len(log_groups) == 0 else "LOW"
            
            self.findings.append({
                "control": "CloudWatch Logs Configuration",
                "control_id": "LOG-02",
                "status": status,
                "risk": risk,
                "evidence": f"{len(log_groups)} CloudWatch log groups configured",
                "recommendation": "Configure CloudWatch logging for critical services" if not log_groups else "Continue monitoring logs",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1"
            })
        except Exception as e:
            self.findings.append({
                "control": "CloudWatch Logs Configuration",
                "control_id": "LOG-02",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify CloudWatch permissions",
                "mapping": "NIST AU-2 / ISO27001 A.12.4.1"
            })
    
    def check_unrestricted_ssh(self):
        """NET-01: No unrestricted SSH access"""
        try:
            ec2 = self._client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            
            risky_groups = []
            
            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    if rule.get('FromPort') == 22 or rule.get('ToPort') == 22:
                        open_ipv4 = any(r.get('CidrIp') == '0.0.0.0/0' for r in rule.get('IpRanges', []))
                        open_ipv6 = any(r.get('CidrIpv6') == '::/0' for r in rule.get('Ipv6Ranges', []))
                        if open_ipv4 or open_ipv6:
                            risky_groups.append(sg['GroupId'])
                            break
            
            self.summary['total_security_groups'] = len(security_groups)
            self.summary['ssh_open_security_groups'] = len(risky_groups)
            
            status = "PASS" if len(risky_groups) == 0 else "FAIL"
            risk = "CRITICAL" if len(risky_groups) > 0 else "LOW"
            
            evidence = f"{len(risky_groups)} security group(s) with unrestricted SSH"
            if risky_groups:
                evidence += f": {', '.join(risky_groups[:5])}"
            
            self.findings.append({
                "control": "Unrestricted SSH Access",
                "control_id": "NET-01",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Restrict SSH access to specific IP ranges" if risky_groups else "Continue monitoring network security",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3 / DORA"
            })
        except Exception as e:
            self.findings.append({
                "control": "Unrestricted SSH Access",
                "control_id": "NET-01",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify EC2 permissions",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3"
            })
    
    def check_unrestricted_rdp(self):
        """NET-02: No unrestricted RDP access"""
        try:
            ec2 = self._client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            
            risky_groups = []
            
            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    if rule.get('FromPort') == 3389 or rule.get('ToPort') == 3389:
                        open_ipv4 = any(r.get('CidrIp') == '0.0.0.0/0' for r in rule.get('IpRanges', []))
                        open_ipv6 = any(r.get('CidrIpv6') == '::/0' for r in rule.get('Ipv6Ranges', []))
                        if open_ipv4 or open_ipv6:
                            risky_groups.append(sg['GroupId'])
                            break
            
            self.summary['rdp_open_security_groups'] = len(risky_groups)
            
            status = "PASS" if len(risky_groups) == 0 else "FAIL"
            risk = "CRITICAL" if len(risky_groups) > 0 else "LOW"
            
            evidence = f"{len(risky_groups)} security group(s) with unrestricted RDP"
            if risky_groups:
                evidence += f": {', '.join(risky_groups[:5])}"
            
            self.findings.append({
                "control": "Unrestricted RDP Access",
                "control_id": "NET-02",
                "status": status,
                "risk": risk,
                "evidence": evidence,
                "recommendation": "Restrict RDP access to specific IP ranges" if risky_groups else "Continue monitoring network security",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3 / DORA"
            })
        except Exception as e:
            self.findings.append({
                "control": "Unrestricted RDP Access",
                "control_id": "NET-02",
                "status": "ERROR",
                "risk": "UNKNOWN",
                "evidence": f"Unable to check: {str(e)}",
                "recommendation": "Verify EC2 permissions",
                "mapping": "NIST SC-7 / ISO27001 A.13.1.3"
            })
    
    def append_to_history(self, report):
        """Append assessment to history.json"""
        try:
            import os
            from pathlib import Path

            history_dir = Path('results/history')
            history_dir.mkdir(parents=True, exist_ok=True)
            history_file = history_dir / 'history.json'

            if history_file.exists():
                with open(history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            else:
                history = []

            history_entry = {
                "run_id": f"AWS-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')}",
                "timestamp": report['assessment_timestamp_utc'],
                "scenario": "live-aws",
                "total_checks": report['summary']['total_checks'],
                "passed": report['summary']['passed'],
                "failed": report['summary']['failed'],
                "compliance_rate": float(report['overall_score'])
            }

            history.append(history_entry)

            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2)

            print(f"History updated: {history_file}")

        except Exception as e:
            print(f"WARNING: Could not update history: {e}")

    def calculate_overall_score(self):
        """Calculate overall governance score"""
        if not self.findings:
            return 0
        
        passed = sum(1 for f in self.findings if f['status'] == 'PASS')
        total = len([f for f in self.findings if f['status'] in ['PASS', 'FAIL']])
        
        if total == 0:
            return 0
        
        return int((passed / total) * 100)
    
    def run_assessment(self):
        """Run all governance checks"""
        print("AMCAF AWS Governance Assessment")
        print("=" * 50)
        
        try:
            # Get account info
            sts = self._client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            self.summary['account_id'] = account_id  # M-04
            print(f"Account ID: {account_id}")
            print(f"Region: {self.session.region_name or 'default'}")
            print()
        except NoCredentialsError:
            print("ERROR: No AWS credentials configured")
            print("Configure credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: {str(e)}")
            sys.exit(1)
        
        checks = [
            ("Root MFA", self.check_root_mfa),
            ("IAM User MFA", self.check_iam_user_mfa),
            ("Overly Permissive Policies", self.check_overly_permissive_policies),
            ("Password Policy", self.check_password_policy),
            ("S3 Encryption", self.check_s3_encryption),
            ("EBS Encryption", self.check_ebs_encryption),
            ("CloudTrail", self.check_cloudtrail),
            ("CloudWatch Logs", self.check_cloudwatch_logs),
            ("Unrestricted SSH", self.check_unrestricted_ssh),
            ("Unrestricted RDP", self.check_unrestricted_rdp)
        ]
        
        for name, check_func in checks:
            print(f"Checking: {name}...", end=" ")
            try:
                check_func()
                print("OK")
            except Exception as e:
                print(f"WARN: {str(e)}")
        
        print()
        print("Assessment complete!")
        print(f"Findings: {len(self.findings)}")
        
        return self.generate_report()
    
    def generate_report(self):
        """Generate JSON report"""
        passed = sum(1 for f in self.findings if f['status'] == 'PASS')
        failed = sum(1 for f in self.findings if f['status'] == 'FAIL')
        errors = sum(1 for f in self.findings if f['status'] == 'ERROR')
        
        report = {
            "assessment_name": "AMCAF AWS Identity & Security Assessment",
            "assessment_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "overall_score": self.calculate_overall_score(),
            "summary": {
                **self.summary,
                "total_checks": len(self.findings),
                "passed": passed,
                "failed": failed,
                "errors": errors
            },
            "findings": self.findings
        }
        
        # Save to results directory
        try:
            with open('results/aws_assessment.json', 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved: results/aws_assessment.json")
        except Exception as e:
            print(f"\nWARNING: Could not save report: {e}")

        # Append to history
        self.append_to_history(report)

        return report


def main():
    assessment = AWSGovernanceAssessment()
    report = assessment.run_assessment()
    
    print("\n" + "=" * 50)
    print(f"Overall Score: {report['overall_score']}/100")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Errors: {report['summary']['errors']}")
    print("=" * 50)


if __name__ == "__main__":
    main()
