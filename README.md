# Microsoft Sentinel SOC Investigation Lab

Hands-on Microsoft Sentinel investigations based on realistic attack simulations.

---

##  Project Goals

This repository contains end-to-end Microsoft Sentinel investigations based on realistic attack simulations performed in an isolated Azure lab. Each case documents the complete incident response workflow from detection to final classification.

The objective is to develop practical skills in:

- Incident Response
- Threat Hunting
- Detection Engineering
- Microsoft Sentinel
- Kusto Query Language (KQL)

Each investigation includes:

- Attack simulation
- Alert generation
- Evidence collection
- Incident investigation
- MITRE ATT&CK mapping
- Incident classification
- Lessons learned

---

##  Lab Environment

| Component | Configuration |
|-----------|---------------|
| Cloud Platform | Microsoft Azure |
| Operating System | Windows 11 Pro |
| VM Size | Standard B2s |
| Region | West Europe |
| SIEM | Microsoft Sentinel |
| Log Collection | Azure Monitor Agent (AMA) |
| Log Storage | Log Analytics Workspace |
| Endpoint Telemetry | Sysmon v15 |
| Attack Simulation | Atomic Red Team |
| Query Language | Kusto Query Language (KQL) |
| PowerShell | Windows PowerShell 5.1 |

---


##  Roadmap

### Current
![Azure](https://img.shields.io/badge/Azure-0078D4?logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4)
![Sysmon](https://img.shields.io/badge/Sysmon-v15-success)
![KQL](https://img.shields.io/badge/KQL-Queries-blue)
![Atomic Red Team](https://img.shields.io/badge/Atomic-Red%20Team-red)

- ✅ Microsoft Sentinel
- ✅ Azure Monitor Agent
- ✅ Sysmon
- ✅ Atomic Red Team

### Investigation Cases

| ID | Investigation | MITRE ATT&CK |Report | Status |
|----|---------------|--------------|--------|
| 001 | PowerShell Encoded Command Execution | T1059.001 | **[View Report](cases/001-PowerShell-EncodedCommand/)** | ✅ |
| 002 | Brute Force Authentication Attack | T1110 | - | In Progress |

### Planned

- ⬜ Microsoft Defender for Endpoint
- ⬜ Microsoft Defender XDR
- ⬜ Microsoft Defender for Identity
- ⬜ Active Directory
- ⬜ Windows Server
- ⬜ Windows Client
- ⬜ Kali Linux
- ⬜ Microsoft Entra ID

---

##  Disclaimer

This project is intended for educational purposes only.

All attack simulations were performed in an isolated Azure lab environment using authorized security testing tools. No production systems or third-party environments were targeted.
