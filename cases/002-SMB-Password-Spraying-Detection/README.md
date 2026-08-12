# Case 002: SMB Password Spray Detection - NTLM Failed Logons
---

## Scenario
This case demonstrates the investigation of a Microsoft Sentinel alert triggered by an automated SMB Password Spraying attack executed during an authorized internal security infrastructure validation. 

The objective was to generate realistic network authentication telemetry using a custom user list, create  Microsoft Sentinel Analytics Rule and inspect raw Windows security event fields (specifically Event ID 4625, Logon Type 3, and SubStatus codes).

## Executive Summary

Microsoft Sentinel generated a Medium-severity alert after detecting an automated SMB Password Spraying pattern targeting a Windows endpoint (`CORP-WS-001`). The investigation reconstructed the attack timeline using Windows Security Event telemetry (`EventID 4625`, `LogonType 3`) and confirmed that the primary high-velocity activity originated from an authorized internal laboratory machine (`10.0.0.5`). 

The same time during investigation was detected two attempts acces from a public Bulgarian IP address (`37.63.19.164`) . The Sentinel Analytics Rule successfully aggregated the telemetry, mapped the necessary entities, and validated that no successful credential access or lateral movement occurred during the simulation.

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

| Time (UTC) | Event | Source |
|------------|-------|--------|
| Aug 11, 2026 4:32:18 PM | First activity:Detects SMB password spraying | Microsoft Sentinel |
| Aug 11, 2026 4:47:18 PM | Last activity| Microsoft Sentinel |
| Aug 11, 2026 4:53:12 PM | Incident created | Microsoft Sentinel |

---

## Objectives

- Trigger Controlled Password Spray
- Create Microsoft Sentinel Scheduled Analytics Rule for Network Logons
- Check Microsoft Defender Incident Entities
- Analyze Windows Security Event ID 4625 (Failed Logon)
- Inspect low-level authentication failure codes (`Status: 0xc000006d`, `SubStatus: 0xc0000064` / `0xc000006a`)
- Perform Source IP Analysis & Blast Radius Evaluation
- Classify the incident






---

