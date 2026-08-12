# Case 002: SMB Password Spray Detection - NTLM Failed Logons
---

## Scenario
This case demonstrates the investigation of a Microsoft Sentinel alert triggered by an automated SMB Password Spraying attack executed during an authorized internal security infrastructure validation. 

The objective was to generate realistic network authentication telemetry using a custom user list, create a Microsoft Sentinel Analytics Rule, and inspect raw Windows Security Event fields (specifically Event ID 4625, Logon Type 3, and SubStatus codes).

## Executive Summary

Microsoft Sentinel generated a Medium-severity alert after detecting an automated SMB Password Spraying pattern targeting a Windows endpoint (`CORP-WS-001`). The investigation reconstructed the attack timeline using Windows Security Event telemetry (`EventID 4625`, `LogonType 3`) and confirmed that the primary high-velocity activity originated from an authorized internal laboratory machine (`10.0.0.5`). 

During the log investigation, two additional failed authentication attempts were observed from a different public IP address (37.63.00.000), separate from the primary attack source (10.0.0.0).

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1110.003 — Brute Force: Password Spraying |

## Lab Environment

| Component | Value |
|---|---|
| SIEM | Microsoft Sentinel |
| Telemetry | Windows Security Events (EventID 4625) |
| Log Collection | Log Analytics Workspace / AMA |
| Target Host | CORP-WS-001 |
| Attacking Host | Kali Linux |
| Simulation | Controlled Network Authentication Spray |
| Detection | Scheduled Analytics Rule (NTLM Failed Logons) |

---

## Timeline

## Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| Aug 11, 2026 16:32:18 | SMB authentication failures detected | Windows Security Event 4625 |
| Aug 11, 2026 16:47:18 | Password spraying activity observed | Microsoft Sentinel |
| Aug 11, 2026 16:53:12 | Incident created | Microsoft Sentinel |

---

## Objectives

- Trigger Controlled Password Spray
- Create Microsoft Sentinel Scheduled Analytics Rule for Network Logons
- Review Microsoft Sentinel incident entities
- Analyze Windows Security Event ID 4625 (Failed Logon)
- Inspect low-level authentication failure codes (`Status: 0xc000006d`, `SubStatus: 0xc0000064` / `0xc000006a`)
- Perform Source IP Analysis & Blast Radius Evaluation
- Classify the incident

  ---

## Detection Rule

### Objective

Detects SMB password spraying attempts using NTLM failed logons across multiple user accounts.

### Detection Logic

The analytics rule monitors Windows Security Logs (`SecurityEvent`) for:
- **Event ID 4625** (Failed Logon)
- **LogonType 3** (Network Logon, representing remote connections like SMB)
- **AuthenticationPackageName**: NTLM 
- High-velocity failure attempts from a single static source IP address across multiple distinct user accounts .


![17-analytics-rule.png](./screenshots/17-analytics-rule.png)

### KQL Query


[01-Detection-Rule.kql](./queries/01-Detection-Rule.kql)


---

## Attack Simulation

| Item | Value |
|-|-|
| Framework | Atomic Red Team |
| Technique | T1059.001 |
| Test | Atomic Test #17 |
| Description | PowerShell Command Execution |

![Atomic test](./screenshots/04-atomic-test-17.png)

---

## Alert Details

| Field | Value |
|-|-|
| Alert | PowerShell Encoded Command Execution |
| Severity | Medium |
| Source | Microsoft Sentinel |
| Host | CORP-WS-001 |






---

