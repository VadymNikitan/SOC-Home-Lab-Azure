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
- Event ID 4625 (Failed Logon)
- LogonType 3 (Network Logon, representing remote connections like SMB)
- AuthenticationPackageName: NTLM 
- High-velocity failure attempts from a single static source IP address across multiple distinct user accounts .


![17-analytics-rule.png](./screenshots/17-analytics-rule.png)

### KQL Query


[01-Detection-Rule.kql](./queries/01-Detection-Rule.kql)


---

## Attack Simulation


| Item| Value |
|---|---|
| Target Service | SMB (Server Message Block) |
| Execution Tool | NetExec / CrackMapExec |
| Attack Type | Password Spraying |
| Test Strategy | Testing a single popular password against multiple accounts |
|Account and passwords list | one password → many accounts pattern |

### Controlled SMB Password Spray:
**bash**

crackmapexec smb 10.0.0.4 -u /tmp/users.txt -p 'Summer2026!'



![06-account-and-passwords-list.png](./screenshots/06-account-and-passwords-list.png)
![08-password-spray.png](./screenshots/08-password-spray.png)

---

## Alert Details

| Field | Value |
|-|-|
| Alert |SMB Password Spray Detection - NTLM Failed Logons |
| Severity | Medium |
| Source | Microsoft Sentinel |
| Host | CORP-WS-001 |

---


## Investigation
### Step 1 - Verify Raw 4625 Events
After the final attack, ensure logs arrived at the SIEM repository

[02-Verify-Raw-4625-Events.kql](./queries/02-Verify Raw-4625-Events.kql)

![09-verify-raw-4625-events.png](./screenshots/09-verify-raw-4625-events.png)


### Step 2 — Incident Validation 

Microsoft Sentinel generated a incident SMB Password Spray Detection - NTLM Failed Logons.

![10-microsoft-defender-incident.png](./screenshots/10-microsoft-defender-incident.png)
![11-microsoft-defender-incident-02.png](./screenshots/11-microsoft-defender-incident-02.png)
![12-microsoft-defender-incident-03.png](./screenshots/12-microsoft-defender-incident-03.png)

### Findings
IP: 10.0.0.5
Host: CORP-WS-001


### Step 2 — Process Analysis 
### SOC Analyst Triage:General overview of logs for one day (where EventID == 4625 and AuthenticationPackageName has "NTLM")

Purpose: Before focusing exclusively on the current Password Spray incident, Ireview the broader NTLM authentication-failure activity observed on the affected host during the previous 24 hours. The goal is to distinguish the current laboratory attack from unrelated historical authentication activity.

[03-General-overview-of-logs-for-one-day.kql](./queries/03-General-overview-of-logs-for-one-day.kql)
![13-global-infrastructure-context.png](./screenshots/13-global-infrastructure-context.png)

#### Result:

Computer: CORP-WS-001

FailedAttempts: 59 

UniqueIPs: 2 

**FailureReasons:** ["0xc000006d"] (Windows sign-in failure caused by a bad username, incorrect password, or corrupted Windows Hello PIN data)

**FailureReasons:** ["0x80090308"] (SEC_E_UNTRUSTED_ROOT: Authentication failed during the TLS/network handshake phase due to untrusted certificate chain; connection dropped before credentials could be processed)

 
The value 59 represents all matching NTLM authentication failures observed on CORP-WS-001 during the one-day investigation window. Bigger part of faild aatmpt occured before incident becouse I created a lot of attempt attack for create a correct detection rule.










---

