# SOC Home Lab (Azure)

Hands-on Microsoft Sentinel Incident Response & Threat Hunting Lab.

---

##  Project Goals

This repository documents hands-on Security Operations Center (SOC) investigations performed in a controlled Azure lab environment.

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

#  Incident Cases

| ID | Case | MITRE | Status |
|----|------|--------|--------|
|001|PowerShell Encoded Command Execution|T1059.001|✅|
|002|Coming Soon||🚧|

---


##  Repository Structure

```text
cases/
    Individual incident investigations

docs/
    General documentation

kql/
    Detection and threat hunting queries

playbooks/
    Incident response playbooks

images/
    Shared screenshots
```


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
