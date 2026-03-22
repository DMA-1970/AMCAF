# AMCAF
My Capstone project for my MSc Enterprise IT Management
# Automated Multi‑Cloud Compliance Assurance Framework  
**Provider‑Agnostic Regulatory Control Mapping & Compliance‑as‑Code Prototype for Financial Services**

![License](https://img.shields.io/badge/License-MIT-green.svg)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen)
![Cloud](https://img.shields.io/badge/Cloud-AWS%20%7C%20Azure%20%7C%20GCP-blue)
![Status](https://img.shields.io/badge/Status-Research%20Project%20%7C%20MSc%20EITM-purple)

---

## 📌 Overview  
This repository contains the artefact developed for the MSc Enterprise IT Management capstone project: a **provider‑agnostic compliance assurance framework** and **lightweight prototype** designed to validate regulatory control objectives across **AWS, Azure, and Google Cloud Platform**.

The project addresses a critical governance challenge in financial services:  
> *How can regulatory control objectives be consistently mapped and validated across heterogeneous cloud platforms?*

The artefact includes:  
- A **technology‑neutral control objective taxonomy**  
- A **cross‑cloud control mapping model**  
- A **rule‑based compliance‑as‑code prototype**  
- Scenario‑based evaluation demonstrating detection accuracy and audit traceability  

---

## 🎯 Project Objectives  
- Translate regulatory requirements (DORA, FCA PS21/3, ISO 27001, NIST CSF, GDPR) into **provider‑agnostic control objectives**  
- Map these objectives to equivalent implementations across AWS, Azure, and GCP  
- Implement a **lightweight automated validation engine**  
- Evaluate the artefact using **synthetic multi‑cloud configurations**  

---

## 🏗️ Architecture  
The framework is structured into four layers:

1. **Regulatory Control Layer**  
   - Technology‑neutral regulatory objectives  
2. **Provider Mapping Layer**  
   - AWS / Azure / GCP control equivalence  
3. **Rule Engine Layer**  
   - Python‑based compliance‑as‑code rules  
4. **Evidence & Reporting Layer**  
   - JSON‑based compliance outputs  

A full architecture diagram is available in `/docs/architecture/`.

---

## 🚀 Prototype  
The prototype evaluates cloud configuration files against the unified control taxonomy.

### Features  
- Rule‑based validation engine  
- Cross‑provider control mapping  
- JSON input/output for auditability  
- High precision in scenario‑based testing  

### Example Command  
```bash
python3 validator.py --input configs/scenario-03/