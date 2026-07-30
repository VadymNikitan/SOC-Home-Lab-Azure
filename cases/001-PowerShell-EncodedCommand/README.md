# Case 001: PowerShell Encoded Command Execution (MITRE ATT&CK T1059.001)
---

# Scenario
This case demonstrates the investigation of a Microsoft Sentinel alert triggered by an encoded PowerShell command executed during an authorized Atomic Red Team simulation.
The objective was to validate the detection, analyze Sysmon telemetry, and determine whether the activity represented malicious behavior or legitimate security testing.

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Execution | T1059.001 — PowerShell |

---

# Lab Environment

| Component | Value |
|---|---|
| SIEM | Microsoft Sentinel |
| Telemetry | Sysmon v15 |
| Log Collection | Azure Monitor Agent |
| Host | CORP-WS-001 |
| Simulation | Atomic Red Team |
| Detection | Scheduled Analytics Rule |

---

# Objectives

- Trigger Sentinel Analytics Rule
- Analyze Sysmon Event ID 1
- Decode Base64 PowerShell command
- Review Sysmon Event ID 3
- Review Sysmon Event ID 11
- Classify incident

---

# Detection Rule

## Objective

Detect encoded PowerShell execution.

## Detection Logic

The rule monitors:

- Sysmon Event ID 1
- PowerShell execution
- Encoded command parameters

Detected parameters:
-e
-enc
-EncodedCommand

Screenshot:

![03-analytics-rule.png](./screenshots/03-analytics-rule.png)

## KQL Query

File:

[01-Detection-Rule.kql](./queries/01-Detection-Rule.kql)

---

# Attack Simulation

| Item | Value |
|-|-|
| Framework | Atomic Red Team |
| Technique | T1059.001 |
| Test | Atomic Test #17 |
| Description | PowerShell Command Execution |

![Atomic test](./screenshots/04-atomic-test-17.png)

---

# Alert Details

| Field | Value |
|-|-|
| Alert | PowerShell Encoded Command Execution |
| Severity | Medium |
| Source | Microsoft Sentinel |
| Host | CORP-WS-001 |



---

# Investigation

## Step 1 — Alert Validation

Microsoft Sentinel generated an alert after execution of an encoded PowerShell command.

Evidence:

![Incident Alert](./screenshots/01-incident-alert.png)


![Incident Details](./screenshots/02-incident-details.png)


---

## Step 2 — Process Analysis

Reviewed Sysmon Event ID 1.

Query:

[02-Process-Creation.kql](./queries/02-Process-Creation.kql)


Findings:

✅ PowerShell executed  
✅ Encoded command identified  
✅ Parent process identified  
✅ User identified  
✅ Elevated execution confirmed  


Screenshot:


![Process Creation](./screenshots/05-process-creation-event-id-1.png)


---

## Step 3 — PowerShell Decoding

The Base64 encoded command was decoded.

Decoded output:

File:

[decoded-command.txt](./artifacts/decoded-command.txt)


Result:

The command executed a simple `Write-Host` statement.

No malicious functionality was identified.


Screenshot:

![Decoded Command](./screenshots/04-decoded-command.png)


---

## Step 4 — Network Analysis

Reviewed Sysmon Event ID 3.

Query:

[03-Network-Analysis.kql](./queries/03-Network-Analysis.kql)


Result:

No outbound network connections related to the PowerShell process were identified.


Screenshot:

![Network Analysis](./screenshots/06-network-analysis-event-id-3.png)


---

## Step 5 — File Analysis

Reviewed Sysmon Event ID 11.

Query:

[04-File-Analysis.kql](./queries/04-File-Analysis.kql)




Analysis:

Temporary PowerShell execution policy test file.

No suspicious payloads created.


Screenshot:


![File Creation](./screenshots/07-file-analysis-event-id-11.png)



---

# Evidence Summary

| Evidence | Result |
|-|-|
| PowerShell execution | ✅ |
| Encoded command | ✅ |
| Base64 decoded | ✅ |
| Parent process identified | ✅ |
| User identified | ✅ |
| Elevated privileges | ✅ |
| Network communication | ❌ None |
| Malicious file creation | ❌ None |

---

# Incident Classification

| Field | Result |
|-|-|
| Severity | Low |
| Confidence | High |
| Classification | Benign True Positive |
| Root Cause | Authorized Atomic Red Team Testing |

---

# Lessons Learned

- Sysmon Event ID 1 provides process execution visibility.
- Encoded PowerShell commands must always be decoded before classification.
- Sysmon Event ID 3 helps identify possible external communication.
- Sysmon Event ID 11 helps identify dropped files or payloads.
- Microsoft Sentinel successfully detected the simulated behavior.



The decoded payload performed no malicious activity.
