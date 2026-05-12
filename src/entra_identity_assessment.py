from graph_connector import GraphConnector
import json
from datetime import datetime, timezone

graph = GraphConnector()

print("Connected to Microsoft Graph")

# -------------------------------------------------
# Collect tenant data from Microsoft Graph
# -------------------------------------------------

users = graph.graph_get(
    "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled&$top=999"
)

groups = graph.graph_get(
    "https://graph.microsoft.com/v1.0/groups?$top=999"
)

applications = graph.graph_get(
    "https://graph.microsoft.com/v1.0/applications?$top=999"
)

conditional_access = graph.graph_get(
    "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
)

# -------------------------------------------------
# Process collected data
# -------------------------------------------------
all_users = users.get("value", [])

print("")
print("DEBUG USERS")
print("================================")

for user in all_users[:10]:
    print({
        "displayName": user.get("displayName"),
        "userType": user.get("userType"),
        "userPrincipalName": user.get("userPrincipalName")
    })

print("================================")
print("")
all_groups = groups.get("value", [])
all_apps = applications.get("value", [])
all_ca = conditional_access.get("value", [])

enabled_users = [
    user for user in all_users
    if user.get("accountEnabled") is True
]

guest_users = [
    user for user in all_users
    if str(user.get("userType", "")).lower() == "guest"
]

enabled_ca = [
    policy for policy in all_ca
    if str(policy.get("state", "")).lower() == "enabled"
]

# -------------------------------------------------
# Simple scoring engine
# -------------------------------------------------

score = 0

if len(enabled_ca) > 0:
    score += 25

if len(guest_users) == 0:
    score += 25

if len(all_apps) < 50:
    score += 25

if len(enabled_users) > 0:
    score += 25

# -------------------------------------------------
# Build findings
# -------------------------------------------------

findings = []

findings.append({
    "control": "Conditional Access Enforcement",
    "status": "PASS" if len(enabled_ca) > 0 else "FAIL",
    "risk": "LOW" if len(enabled_ca) > 0 else "HIGH",
    "evidence": f"{len(enabled_ca)} enabled Conditional Access policies identified.",
    "recommendation": (
        "Implement baseline Conditional Access policies "
        "for administrators, MFA and unmanaged devices."
    ),
    "mapping": "NIST IA-2 / ISO27001 Access Control / DORA"
})

guest_count = len(guest_users)

findings.append({
    "control": "Guest User Exposure",
    "status": "PASS" if guest_count == 0 else "FAIL",
    "risk": "LOW" if guest_count == 0 else "MEDIUM",
    "evidence": f"{guest_count} guest users identified.",
    "recommendation": (
        "Review B2B guest access regularly, enforce Conditional Access for external users, "
        "and implement lifecycle governance or access reviews."
    ),
    "mapping": "NIST AC-2 / GDPR Article 32"
})

findings.append({
    "control": "Application Registration Inventory",
    "status": "PASS" if len(all_apps) < 50 else "REVIEW",
    "risk": "LOW" if len(all_apps) < 50 else "MEDIUM",
    "evidence": f"{len(all_apps)} application registrations identified.",
    "recommendation": (
        "Review application ownership, permissions "
        "and credential expiry."
    ),
    "mapping": "NIST CM-8 / ISO27001 Asset Management"
})

# -------------------------------------------------
# Build assessment report
# -------------------------------------------------

report = {
    "assessment_name": "AMCAF Entra Identity Governance Assessment",
    "assessment_timestamp_utc": datetime.now(timezone.utc).isoformat(),

    "overall_score": score,

    "summary": {
        "total_users": len(all_users),
        "enabled_users": len(enabled_users),
        "guest_users": len(guest_users),
        "groups": len(all_groups),
        "application_registrations": len(all_apps),
        "conditional_access_policies": len(all_ca),
        "enabled_conditional_access_policies": len(enabled_ca)
    },

    "findings": findings
}

# -------------------------------------------------
# Save assessment output
# -------------------------------------------------

output_file = "results/entra_assessment.json"

with open(output_file, "w", encoding="utf-8") as file:
    json.dump(report, file, indent=4)

# -------------------------------------------------
# Console output
# -------------------------------------------------

print("")
print("====================================")
print("AMCAF Assessment Completed")
print("====================================")
print(f"Overall Score: {score}%")
print(f"Results written to: {output_file}")
print("====================================")
print("")

for finding in findings:
    print("------------------------------------")
    print(f"Control: {finding['control']}")
    print(f"Status : {finding['status']}")
    print(f"Risk   : {finding['risk']}")
    print(f"Evidence: {finding['evidence']}")