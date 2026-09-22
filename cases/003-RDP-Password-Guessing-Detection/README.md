# Case 004: RDP Password Guessing Detection — Failed Logons Followed by Successful Authentication
---

## Scenario

This case demonstrates the investigation of a controlled RDP password-guessing attack performed against an authorized Windows endpoint in a Microsoft Azure security laboratory.

The objective was to simulate repeated RDP authentication failures from a Kali Linux attacker host, generate Windows Security authentication telemetry, detect the sequence using a Microsoft Sentinel Analytics Rule, and investigate the resulting authentication timeline.

The investigation focused on correlating:

Windows Security Event ID 4625 — failed authentication
Windows Security Event ID 4624 — successful authentication
Logon Type 3 — network authentication
Logon Type 10 — interactive Remote Desktop logon
Event ID 4634 — logoff
Source IP and target account correlation
Microsoft Sentinel incident generation

The case also included post-authentication investigation for process execution, account/group modification, and persistence indicators within the available telemetry.

## Executive Summary

Microsoft Sentinel generated a High-severity incident after detecting multiple failed Windows authentication attempts followed by a successful authentication from the same source IP and user within a 15-minute correlation window.

The controlled attack originated from the authorized Kali Linux laboratory host:

10.0.1.11

The target was:

CORP-WS-001

The targeted account was:

Ragnar

Five failed authentication attempts were observed as Windows Security Event ID 4625, Logon Type 3, using NTLM authentication.

The subsequent successful authentication generated Event ID 4624, Logon Type 3. Approximately one second later, Event ID 4624, Logon Type 10 confirmed the interactive RDP logon.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1110.001 — Brute Force: Password Guessing |
| Credential Access / Remote Services | T1021.001 — Remote Services: Remote Desktop Protocol |

## Lab Environment

| Component | Value |
|---|---|
| SIEM | Microsoft Sentinel |
| Telemetry | Windows Security Events (`EventID 4625`) |
| Log Collection | Azure Monitor Agent (AMA) / Log Analytics Workspace |
| Target Host | CORP-WS-001 |
| Attacking Host | Kali Linux (Aktep-02) |
| Simulation | Controlled RDP Password Guessing |
| Detection | Microsoft Sentinel Scheduled Analytics Rule |

---

## Timeline

| Time (UTC)               | Event                                                                     | Source                 |
| ------------------------ | ------------------------------------------------------------------------- | ---------------------- |
| 17 Sep 2026 18:33:11.257 | First failed RDP authentication attempt — Event ID `4625`, Logon Type `3` | Windows Security Event |
| 17 Sep 2026 18:33:13.319 | Second failed authentication — Event ID `4625`, Logon Type `3`            | Windows Security Event |
| 17 Sep 2026 18:33:15.381 | Third failed authentication — Event ID `4625`, Logon Type `3`             | Windows Security Event |
| 17 Sep 2026 18:33:17.444 | Fourth failed authentication — Event ID `4625`, Logon Type `3`            | Windows Security Event |
| 17 Sep 2026 18:33:19.510 | Fifth failed authentication — Event ID `4625`, Logon Type `3`             | Windows Security Event |
| 17 Sep 2026 18:33:57.569 | Successful network authentication — Event ID `4624`, Logon Type `3`       | Windows Security Event |
| 17 Sep 2026 18:33:58.536 | Successful interactive RDP logon — Event ID `4624`, Logon Type `10`       | Windows Security Event |
| 17 Sep 2026 18:33:59.396 | RDP session terminated — Event ID `4634`, Logon Type `10`                 | Windows Security Event |
| 17 Sep 2026 21:44:35     | Microsoft Sentinel incident created/updated                               | Microsoft Sentinel     |

> **Important:** The raw Windows Security Event timestamps used for the authentication timeline are represented in UTC. Microsoft Sentinel displays incident timestamps according to the portal/workspace time-zone context. Therefore, the Sentinel incident timestamp should not be directly compared with the raw UTC event timestamps without accounting for the time-zone difference.

### Actual Authentication Sequence

The raw Windows Security Events establish the following sequence:

`4625 × 5 → 4624 Type 3 → 4624 Type 10 → 4634 Type 10`

The five failed authentication attempts occurred between:

`18:33:11.257` and `18:33:19.510` UTC.

The successful network authentication occurred at:

`18:33:57.569` UTC.

The interactive RDP logon occurred at:

`18:33:58.536` UTC.

The RDP session ended at:

`18:33:59.396` UTC.

The interactive RDP session therefore lasted approximately **0.86 seconds**.

### Sentinel Correlation Window

The Sentinel Analytics Rule recorded:

* **FirstSeen:** `2026-09-17T18:33:11.2572998Z`
* **LastSeen:** `2026-09-17T18:33:57.5693917Z`
* **FailedAttempts:** `5`
* **SuccessfulLogons:** `1`

The `LastSeen` value corresponds to the successful `4624 Type 3` event used by the analytics rule. The subsequent `4624 Type 10` RDP logon occurred approximately **0.97 seconds later**.

Therefore, the Sentinel incident's correlation timestamps should not be interpreted as the complete duration of the RDP session.

---

## Objectives

- Simulate controlled RDP password guessing from an authorized Kali Linux host
- Generate Windows Security Event ID 4625
- Confirm successful authentication with Event ID 4624
- Confirm interactive RDP logon using Logon Type 10
- Create and validate a Microsoft Sentinel Analytics Rule
- Correlate failed and successful authentication attempts
- Investigate the resulting Sentinel incident
- Verify the source IP and target account
- Investigate post-authentication process execution
- Check for account/group modification
- Check for service and scheduled-task persistence
- Document telemetry limitations and investigation findings


