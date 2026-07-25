# SOC-Home-Lab-Azure

Hands-on Microsoft Sentinel Incident Response & Threat Hunting Lab.

---

##  Project Overview

This repository documents real-world SOC investigations performed in a Microsoft Sentinel lab environment.

Each case follows the same investigation methodology used by Security Operations Center (SOC) analysts:

```text
Alert
 ↓
Triage
 ↓
Evidence Collection
 ↓
Investigation
 ↓
MITRE Mapping
 ↓
Incident Classification
 ↓
Lessons Learned
```

---

##  Lab Architecture

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Azure Monitor Agent (AMA)
- Sysmon
- Windows 11 Honeypot
- Atomic Red Team
- Kusto Query Language (KQL)

---

##  Technologies

| Technology | Purpose |
|------------|---------|
| Microsoft Sentinel | SIEM |
| Sysmon | Endpoint Telemetry |
| AMA | Log Collection |
| KQL | Threat Hunting |
| Atomic Red Team | Attack Simulation |
| PowerShell | Attack Execution |

---

#  Incident Cases

| ID | Case | MITRE | Status |
|----|------|--------|--------|
|001|PowerShell Encoded Command|T1059.001|✅|
|002|Coming Soon||🚧|
|003|Coming Soon||🚧|

---

#  Repository Structure

```
SOC-Incident-Response-Lab
│
├── README.md
│
├── docs
│   ├── Lab-Architecture.md
│   ├── Detection-Rules.md
│   ├── MITRE-Coverage.md
│   └── Playbooks.md
│
├── cases
│   ├── 001-PowerShell-EncodedCommand
│   │   ├── README.md
│   │   ├── screenshots
│   │   ├── queries
│   │   └── artifacts
│   │
│   ├── 002-...
│   └── ...
│
├── kql
│   ├── Detection
│   ├── Hunting
│   └── Dashboards
│
└── images
```
