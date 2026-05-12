import json
from pathlib import Path
from datetime import datetime, timezone

INPUT_FILE = Path("results/entra_assessment.json")
OUTPUT_FILE = Path("results/live-entra-summary.json")
HISTORY_DIR = Path("results/history")
HISTORY_INDEX_FILE = HISTORY_DIR / "index.json"
HISTORY_TREND_FILE = HISTORY_DIR / "history.json"


def load_json(path, default):
    if not path.exists():
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def append_entra_to_history(dashboard_report):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    metadata = dashboard_report.get("report_metadata", {})

    raw_rate = metadata.get("compliance_rate", "0")
    compliance_rate = float(str(raw_rate).replace("%", ""))

    timestamp = datetime.now(timezone.utc).isoformat()
    run_id = "entra-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    entry = {
        "run_id": run_id,
        "timestamp": timestamp,
        "scenario": "LIVE-ENTRA",
        "triggered_by": "DMA-1970",
        "passed": int(metadata.get("passed", 0)),
        "failed": int(metadata.get("failed", 0)),
        "total_checks": int(metadata.get("total_checks", 0)),
        "compliance_rate": compliance_rate,
        "run_url": "#",
        "source": "live-entra-summary.json",
        "type": "live-governance-validation"
    }

    history_index = load_json(HISTORY_INDEX_FILE, [])
    if isinstance(history_index, dict):
        runs = history_index.get("runs", [])
    else:
        runs = history_index

    runs.insert(0, entry)
    write_json(HISTORY_INDEX_FILE, runs)

    history_trend = load_json(HISTORY_TREND_FILE, [])
    if isinstance(history_trend, dict):
        trend = history_trend.get("runs", [])
    else:
        trend = history_trend

    trend.append(entry)
    write_json(HISTORY_TREND_FILE, trend)


def main():
    entra = load_json(INPUT_FILE, {})

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

    write_json(OUTPUT_FILE, dashboard_report)
    append_entra_to_history(dashboard_report)

    print(f"Dashboard-compatible report written to {OUTPUT_FILE}")
    print(f"Live Entra run appended to {HISTORY_INDEX_FILE}")
    print(f"Live Entra trend appended to {HISTORY_TREND_FILE}")


if __name__ == "__main__":
    main()