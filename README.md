# AMCAF — Automated Multi-Cloud Compliance Assurance Framework

A provider-agnostic, rule-based compliance validation engine for financial services organisations operating across AWS, Azure and Google Cloud Platform.

Developed as the research artefact for an MSc Enterprise IT Management dissertation at the University of Essex Online, applying Design Science Research methodology.

---

## Overview

Financial institutions operating multi-cloud architectures must demonstrate consistent regulatory compliance across platforms that implement equivalent controls in technically different ways. Existing tooling is either provider-specific or insufficiently validated for cross-platform regulatory use.

AMCAF addresses this by providing a four-layer governance framework that:

1. Translates regulatory obligations (DORA, FCA PS21/3, UK GDPR, ISO 27001, NIST CSF, CSSF 22/806, NDPR, MAS TRM, PCI DSS v4.0, SOC 2) into **20 technology-neutral control objectives**
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
              20 technology-neutral control objectives
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

Source of truth: [`src/taxonomy/control_objectives.json`](src/taxonomy/control_objectives.json). All 20 objectives below are implemented as validation rules in [`src/engine/amcaf.py`](src/engine/amcaf.py).

| Control ID | Domain | Objective | Providers |
|---|---|---|---|
| IAM-01 | Identity & Access Management | Privileged access restricted; least-privilege enforced | AWS, Azure, GCP |
| IAM-02 | Identity & Access Management | MFA enforced for all administrative access | AWS, Azure |
| IAM-03 | Identity & Access Management | Periodic access review enforced; dormant accounts disabled | AWS, GCP |
| IAM-04 | Identity & Access Management | Privileged access workstations enforced; standing privilege eliminated | Org |
| ENC-01 | Data Protection & Encryption | Data at rest encrypted by default for all storage resources | AWS |
| ENC-02 | Data Protection & Encryption | Data in transit protected; unencrypted protocols disabled | Azure |
| ENC-03 | Data Protection & Encryption | Customer-managed key rotation enforced across all key management services | AWS, Azure, GCP |
| DAT-01 | Data Governance | Data classification enforced; regulated data inventoried and tagged | Org |
| DAT-02 | Data Governance | Data subject rights management; breach notification within required period | Org |
| LOG-01 | Logging & Monitoring | Management plane audit logging enabled in all regions | AWS, Azure, GCP |
| LOG-02 | Logging & Monitoring | Audit log retention meets minimum period; tamper protection enabled | AWS, Azure |
| LOG-03 | Logging & Monitoring | Real-time alerting configured for security events and anomalies | AWS, Azure, GCP |
| INC-01 | Incident Management | ICT incidents classified, escalated and notified to regulators within required timeframes | Org |
| NET-01 | Network Security | Default-deny network access; no unrestricted inbound rules | AWS, GCP |
| NET-02 | Network Security | Network segmentation enforced by workload sensitivity classification | AWS, Azure, GCP |
| NET-03 | Network Security | Public management interfaces restricted to authorised sources | AWS, GCP |
| TPM-01 | Third-Party Management | Critical ICT third-party providers identified, assessed and contractually governed | Org |
| RES-01 | Operational Resilience | Automated backups configured with defined retention and RPO | AWS, Azure, GCP |
| RES-02 | Operational Resilience | Infrastructure-as-code enforced; configuration drift continuously detected | AWS, Azure, GCP |
| RES-03 | Operational Resilience | Centralised security findings aggregation and remediation tracking enabled | AWS, Azure, GCP |

**20 of 20 technology-neutral control objectives implemented.**

"Org" controls (IAM-04, DAT-01, DAT-02, INC-01, TPM-01) are evaluated once per scenario from a single organisation-level config block rather than once per cloud provider — see the check-counting note under [Evaluation Scenarios](#evaluation-scenarios).

The engine also runs one meta-check, `COV-01` (cross-cloud coverage — confirms AWS, Azure and GCP configuration is present before evaluating the 20 controls above). COV-01 is an engine sanity check, not a regulatory control objective, so it is not listed in the taxonomy table but is included in the per-scenario check counts below.

---


## Evaluation Scenarios

Figures below are reproduced directly from `python src/engine/amcaf.py --scenario <SC-ID>` against the current engine: 40 checks per scenario, made up of 14 AWS + 10 Azure + 10 GCP + 1 COV-01 (cross-cloud coverage) + 5 Org checks. AWS, Azure and GCP each cover a different subset of the 20 controls — see the Providers column above — so the per-provider check count is not uniform.

| Scenario | Description | Checks | Passed | Failed | Compliance |
|---|---|---|---|---|---|
| SC-01 | Fully compliant baseline | 40 | 40 | 0 | 100.0% |
| SC-02 | Over-privileged IAM (AWS) / MFA disabled (Azure) | 40 | 38 | 2 | 95.0% |
| SC-03 | Encryption disabled (AWS) / Weak TLS (Azure) / Public bucket (GCP) | 40 | 37 | 3 | 92.5% |
| SC-04 | Logging disabled across all providers | 40 | 37 | 3 | 92.5% |
| SC-05 | Open SSH (AWS) / Permissive firewall (GCP) | 40 | 37 | 3 | 92.5% |
| SC-06 | Dormant accounts (AWS, GCP) / Insufficient log retention (AWS, Azure) | 40 | 36 | 4 | 90.0% |
| SC-07 | Full 20-control compliant baseline | 40 | 40 | 0 | 100.0% |
| SC-08 | Full 20-control failure scenario (all controls added since the original 15-control set failing, plus all 5 Org controls) | 40 | 17 | 23 | 42.5% |
| **Total** | | **320** | **282** | **38** | **88.1%** |

Note: SC-07 is configured with byte-identical AWS/Azure/GCP input to SC-01 (`src/engine/amcaf.py:1103-1105`) — it re-validates the same compliant baseline against the full 20-control set rather than exercising new input data, so its 40/40 result is not an independent data point.

**Detection accuracy: 38/38 true positives, 0 false positives** — every FAIL finding across SC-02–SC-06 and SC-08 was manually checked against that scenario's injected misconfiguration (e.g. SC-02's AWS wildcard IAM policy and disabled Azure Conditional Access MFA produce exactly `IAM-01 AWS FAIL` and `IAM-02 Azure FAIL`, no more and no fewer) and none were spurious.

**How a check is counted (known ambiguity):** in this engine, a "check" is one control evaluated once per applicable provider, not once per affected resource — e.g. SC-05's AWS security group `sg-0abc123` has an inbound rule opening both `0.0.0.0/0` and port 22, but this produces exactly one `NET-01` and one `NET-03` finding for AWS, regardless of how many security groups or rules are actually implicated. The **live cloud assessment scripts** (`aws_identity_assessment.py`, `gcp_identity_assessment.py`) count checks the same way (one finding per control method) but additionally introduce an `ERROR` status when a check cannot complete (e.g. an API/permissions failure): `ERROR` findings are included in `total_checks` but excluded from the denominator used to compute `compliance_rate` (`passed / (passed + failed)`, not `passed / total_checks`). This means a run can report `total_checks: 10, passed: 4, failed: 2` with a `compliance_rate` of 66% — the missing 4 checks errored rather than passed or failed, and do not count against the score. This is a genuine methodological limitation, not a display bug, and should be read as such wherever `compliance_rate` is quoted from a live-assessment run.

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

**Requirements:** Python 3.10+. The core engine (`src/engine/amcaf.py`) uses only the standard library; `requirements.txt` covers the live cloud assessment scripts and DOCX report generators.

```bash
git clone https://github.com/dma-1970/AMCAF.git
cd AMCAF
pip install -r requirements.txt
python src/engine/amcaf.py
```

This runs all 8 scenarios (`--scenario` defaults to `ALL`) and prints a console report.

To run a specific scenario:

```bash
python src/engine/amcaf.py --scenario SC-02
```

To run scenarios and write JSON results to `results/`:

```bash
python src/engine/amcaf.py --scenario ALL --format json
```

To filter a report down to a single regulatory framework:

```bash
python src/engine/amcaf.py --scenario SC-05 --format json --framework MASTRM
```

Valid `--framework` values: `ALL, DORA, FCA, UKGDPR, ISO27001, NISTCSF, CSSF, NDPR, MASTRM, PCIDSS, SOC2`.

---

## Repository Structure

```
AMCAF/
│
├── src/
│   ├── engine/
│   │   ├── amcaf.py              # The validation engine: control library, AWS/Azure/GCP/Org
│   │   │                         #   rule evaluation, scenario runner, CLI (this is the whole engine)
│   │   ├── rule_engine.py        # Placeholder — empty, not used
│   │   └── evaluator.py          # Placeholder — empty, not used
│   ├── mappings/
│   │   ├── aws.json              # AWS control-to-implementation mapping
│   │   ├── azure.json            # Azure control-to-implementation mapping
│   │   └── gcp.json              # GCP control-to-implementation mapping
│   ├── taxonomy/
│   │   └── control_objectives.json   # 20-control taxonomy
│   ├── utils/
│   │   └── parser.py             # Placeholder — empty, not used
│   ├── entra_identity_assessment.py  # Live Microsoft Entra ID assessment
│   └── graph_connector.py            # Microsoft Graph API client used by the above
│
├── configs/                     # Synthetic scenario configuration data
│   ├── scenario-01 … scenario-08      # Extensionless — see "Known limitation" note below
│   └── scenario-custom.json          # The only scenario file the engine currently loads from disk
│
├── results/                     # JSON compliance report outputs
│   ├── sc-01.json … sc-08.json, sc-custom.json   # One per scenario (per --format json run)
│   ├── sc-0N-{cssf,mastrm,ndpr}.json              # Per-framework filtered exports
│   ├── aws_assessment.json / gcp_assessment.json / entra_assessment.json  # Live cloud runs
│   └── history/
│       ├── history.json          # Flat run ledger — live cloud assessment runs
│       └── index.json            # Nested run ledger — CI/scenario-engine runs
│
├── aws_identity_assessment.py     # Live AWS assessment (own sensitive-port list; see Limitations)
├── gcp_identity_assessment.py     # Live GCP assessment
├── manage_aws_security_group.py, manage_gcp_firewall.py, manage_cloudtrail.py
│                                  # Helper scripts that create/remove the test-fixture
│                                  # resources the live assessments above are meant to detect
│
├── index.html, history.html, aws-results.html, gcp-results.html, entra-results.html
│                                  # Published dashboard, served from the repo root via GitHub Pages
├── docs/                         # Architecture diagram only — not the published site
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

Each compliance run produces a structured JSON report (illustrative excerpt — see [Evaluation Scenarios](#evaluation-scenarios) for actual current figures):

```json
{
  "report_metadata": {
    "framework": "AMCAF v1.0",
    "generated_at": "2025-08-01T10:00:00Z",
    "total_checks": 40,
    "passed": 38,
    "failed": 2,
    "compliance_rate": "95.0%"
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

- **Synthetic data:** the 8 scenarios above are evaluated against synthetic JSON configurations, not live cloud APIs. Separate scripts (`aws_identity_assessment.py`, `gcp_identity_assessment.py`, `src/entra_identity_assessment.py`) perform live assessments against real AWS/GCP/Entra environments, with their own findings and their own `results/history/history.json` ledger (see [Evaluation Scenarios](#evaluation-scenarios) for how their check-counting and `ERROR` status differ from the scenario engine).
- **Static mapping:** cross-cloud mappings reflect provider documentation at time of research and require ongoing maintenance.
- **Known limitation — on-disk scenario configs are not loaded:** `configs/scenario-01` … `scenario-08` are extensionless files, but `load_scenario_from_file()` in `src/engine/amcaf.py` looks for `configs/scenario-{NN}.json`. The lookup fails silently and the engine falls back to hardcoded scenario definitions baked into `amcaf.py` itself. `configs/scenario-custom.json` is the only scenario file the engine actually reads from disk (via `--scenario CUSTOM`). The results reported in this README reflect the current, actual (hardcoded-fallback) behaviour.
- **Two independent NET-03 definitions:** the scenario engine's `NET-03` (management ports 22/3389 only) and the live AWS/GCP scripts' `NET-03` ("Sensitive Port Public Exposure", covering 3306/5432/6379/etc.) share a control ID but check different things. The live AWS script does not consult `MANAGEMENT_PORTS` from `src/engine/amcaf.py` — it carries its own, broader `SENSITIVE_PORTS` table.

---

## Future Development

- Integrate live configuration ingestion via AWS Config, Azure Resource Graph and GCP Cloud Asset Inventory APIs directly into the scenario engine (the live assessment scripts already do this independently; unifying the two is future work)
- Fix the scenario config loader so `configs/scenario-01`–`scenario-08` are actually read from disk rather than falling back to hardcoded definitions
- Reconcile the two NET-03 definitions (or rename one) so the same control ID means the same check across the scenario engine and the live assessment scripts
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