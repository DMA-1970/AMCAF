import json
from datetime import datetime, timezone

INPUT_FILE = "results/entra_assessment.json"
OUTPUT_FILE = "results/live-entra-summary.json"

with open(INPUT_FILE, "r") as file:
    entra = json.load(file)

findings = []

mapping = {
    "Conditional Access Enforcement": {
        "control_id": "IAM-02",
        "domain": "Identity & Access Management",
        "objective": "MFA and Conditional Access enforced for administrative and user access"
    },
    "Guest User Exposure": {
        "control_id": "IAM-03",
        "domain": "Identity & Access Management",
        "objective": "External identities governed through guest access review and lifecycle control"
    },
    "Application Registration Inventory": {
        "control_id": "IAM-01",
        "domain": "Identity & Access Management",
        "objective": "Application registrations inventoried and governed"
    }
}

for item in entra.get("findings", []):
    control_name = item.get("control")
    meta = mapping.get(control_name, {})

    findings.append({
        "control_id": meta.get("control_id", "IAM-LIVE"),
        "provider": "Azure",
        "domain": meta.get("domain", "Identity & Access Management"),
        "objective": meta.get("objective", control_name),
        "regulatory_refs": [
            "DORA Art. 9",
            "FCA PS21/3",
            "ISO 27001 A.9",
            "NIST CSF PR.AC",
            "UK GDPR Art. 32"
        ],
        "status": item.get("status", "UNKNOWN"),
        "detail": item.get("evidence", ""),
        "config_attribute": item.get("mapping", "")
    })

passed = len([f for f in findings if f["status"] == "PASS"])
failed = len([f for f in findings if f["status"] == "FAIL"])
total = len(findings)
rate = round((passed / total) * 100, 1) if total else 0

dashboard_report = {
    "report_metadata": {
        "framework": "AMCAF v1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario": "LIVE-ENTRA",
        "source": "Microsoft Graph API",
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "compliance_rate": f"{rate}%"
    },
    "findings": findings
}

with open(OUTPUT_FILE, "w") as file:
    json.dump(dashboard_report, file, indent=2)

print(f"Dashboard-compatible report written to {OUTPUT_FILE}")