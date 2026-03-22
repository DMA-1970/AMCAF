# AMCAF — Automated Multi-Cloud Compliance Assurance Framework

A provider-agnostic, rule-based compliance validation engine for financial services organisations operating across AWS, Azure and Google Cloud Platform.

Developed as the research artefact for an MSc Enterprise IT Management dissertation at the University of Essex Online, applying Design Science Research methodology.

---

## Overview

Financial institutions operating multi-cloud architectures must demonstrate consistent regulatory compliance across platforms that implement equivalent controls in technically different ways. Existing tooling is either provider-specific or insufficiently validated for cross-platform regulatory use.

AMCAF addresses this by providing a four-layer governance framework that:

1. Translates regulatory obligations (DORA, FCA PS21/3, UK GDPR, ISO 27001, NIST CSF) into **15 technology-neutral control objectives**
2. Maps those objectives to **equivalent technical implementations** across AWS, Azure and GCP
3. Validates cloud configurations against the mapped controls using a **deterministic rule-based engine**
4. Produces **structured, traceable compliance outputs** linking findings to specific regulatory clauses

---

## Architecture

```
Regulatory frameworks (DORA · FCA PS21/3 · UK GDPR · ISO 27001 · NIST CSF)
                              │
                              ▼
              Layer 1 — Regulatory interpretation
              15 technology-neutral control objectives
                              │
                              ▼
              Layer 2 — Cross-cloud control mapping
              AWS · Azure · GCP functional equivalences
                              │
                              ▼
              Layer 3 — Validation logic
              Rule-based Python engine
                              │
                              ▼
              Layer 4 — Reporting and evidence
              Structured JSON · regulatory traceability
```

---

## Control Coverage

| Control ID | Domain | Objective | Implemented |
|---|---|---|---|
| IAM-01 | Identity & Access Management | Least-privilege; no wildcard actions | ✓ |
| IAM-02 | Identity & Access Management | MFA for all administrative access | ✓ |
| IAM-03 | Identity & Access Management | Periodic access review; dormant account controls | ✓ |
| ENC-01 | Data Protection & Encryption | Encryption at rest for all storage resources | ✓ |
| ENC-02 | Data Protection & Encryption | Encryption in transit; minimum TLS 1.2 | ✓ |
| ENC-03 | Data Protection & Encryption | Customer-managed key management | — |
| LOG-01 | Logging & Monitoring | Management plane audit logging | ✓ |
| LOG-02 | Logging & Monitoring | Log retention and tamper protection | ✓ |
| LOG-03 | Logging & Monitoring | Real-time alerting for security events | — |
| NET-01 | Network Security | Default-deny network access controls | ✓ |
| NET-02 | Network Security | Network segmentation by workload sensitivity | — |
| NET-03 | Network Security | Restrict public management interface access | ✓ |
| RES-01 | Operational Resilience | Automated backups and RPO configuration | — |
| RES-02 | Operational Resilience | Infrastructure-as-code and configuration drift | — |
| RES-03 | Operational Resilience | Centralised findings and remediation tracking | — |

**9 of 15 controls implemented in v1.0**

---


## Evaluation Scenarios

| Scenario | Description | Checks | Passed | Failed | Compliance |
|---|---|---|---|---|---|
| SC-01 | Fully compliant baseline | 16 | 16 | 0 | 100.0% |
| SC-02 | Over-privileged IAM (AWS) / MFA disabled (Azure) | 16 | 14 | 2 | 87.5% |
| SC-03 | Encryption disabled (AWS) / Weak TLS (Azure) / Public bucket (GCP) | 16 | 13 | 3 | 81.2% |
| SC-04 | Logging disabled across all providers | 16 | 13 | 3 | 81.2% |
| SC-05 | Open SSH (AWS) / Permissive firewall (GCP) | 16 | 13 | 3 | 81.2% |
| SC-06 | Dormant accounts (AWS, GCP) / Insufficient log retention (AWS, Azure) | 16 | 12 | 4 | 75.0% |
| **Total** | | **96** | **81** | **15** | **84.4%** |

**Detection accuracy: 100% — 15/15 true positives, 0 false positives across all scenarios.**

---

## Regulatory Frameworks

| Framework | Obligations covered |
|---|---|
| DORA (EU Digital Operational Resilience Act) | Art. 9 (access control), Art. 10 (logging) |
| FCA PS21/3 | Operational resilience, MFA, audit logging |
| UK GDPR | Art. 32 (encryption), Art. 5(2) (accountability) |
| ISO/IEC 27001 | A.9 (access), A.10 (encryption), A.12 (logging), A.13 (network) |
| NIST CSF | PR.AC, PR.DS, PR.IP |

---

## Quick Start

**Requirements:** Python 3.10+

```bash
git clone https://github.com/yourusername/multi-cloud-compliance-framework.git
cd multi-cloud-compliance-framework
pip install -r requirements.txt
python src/engine/amcaf.py
```

To run a specific scenario:

```bash
python src/engine/amcaf.py --scenario SC-02
```

To run all scenarios and output JSON results:

```bash
python src/engine/amcaf.py --all --output results/
```

---

## Repository Structure

```
multi-cloud-compliance-framework/
│
├── docs/                        # GitHub Pages documentation
│   ├── index.md
│   ├── architecture/
│   ├── methodology/
│   └── evaluation/
│
├── src/
│   ├── engine/
│   │   ├── amcaf.py             # Main prototype (all rules + scenarios)
│   │   ├── rule_engine.py       # Validation engine
│   │   └── evaluator.py        # Report generation
│   ├── mappings/
│   │   ├── aws.json             # AWS control mappings
│   │   ├── azure.json           # Azure control mappings
│   │   └── gcp.json             # GCP control mappings
│   ├── taxonomy/
│   │   └── control_objectives.json   # 15-control taxonomy
│   └── utils/
│       └── parser.py            # Config ingestion utilities
│
├── configs/                     # Synthetic scenario configuration data
│   ├── scenario-01/
│   ├── scenario-02/
│   ├── scenario-03/
│   ├── scenario-04/
│   ├── scenario-05/
│   └── scenario-06/
│
├── results/                     # JSON compliance report outputs
│   ├── scenario-01.json
│   ├── scenario-02.json
│   ├── scenario-03.json
│   ├── scenario-04.json
│   ├── scenario-05.json
│   └── scenario-06.json
│
├── tests/
│   └── unit/
│
├── README.md
├── LICENSE
└── requirements.txt
```

---

## Output Format

Each compliance run produces a structured JSON report:

```json
{
  "report_metadata": {
    "framework": "AMCAF v1.0",
    "generated_at": "2025-08-01T10:00:00Z",
    "total_checks": 16,
    "passed": 14,
    "failed": 2,
    "compliance_rate": "87.5%"
  },
  "findings": [
    {
      "control_id": "IAM-01",
      "provider": "AWS",
      "domain": "Identity & Access Management",
      "objective": "Privileged access restricted; least-privilege enforced",
      "regulatory_refs": ["NIST CSF PR.AC-4", "ISO 27001 A.9.2", "DORA Art. 9"],
      "status": "FAIL",
      "detail": "Wildcard (*) action found in IAM policy",
      "config_attribute": "iam.policies[].actions"
    }
  ]
}
```

---

## Limitations

- **Prototype scope:** 9 of 15 control objectives are implemented as validation rules in v1.0
- **Synthetic data:** evaluated against synthetic JSON configurations, not live cloud APIs
- **Static mapping:** cross-cloud mappings reflect provider documentation at time of research and require ongoing maintenance

---

## Future Development

- Integrate live configuration ingestion via AWS Config, Azure Resource Graph and GCP Cloud Asset Inventory APIs
- Extend rule coverage to all 15 control objectives
- Add dynamic mapping versioning linked to provider change notifications
- Augment rule-based engine with AI-assisted anomaly detection for continuous monitoring controls

---

## Academic Context

This artefact was developed as part of an MSc Enterprise IT Management dissertation at the University of Essex Online.

**Research question:** How can regulatory control objectives be consistently mapped and validated across heterogeneous cloud platforms to improve compliance assurance within multi-cloud financial environments?

**Methodology:** Design Science Research (DSR)

---

## License

MIT License — see [LICENSE](LICENSE) for details.