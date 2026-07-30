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

---

# Alert Details

| Field | Value |
|-|-|
| Alert | PowerShell Encoded Command Execution |
| Severity | Medium |
| Source | Microsoft Sentinel |
| Host | CORP-WS-001 |

Screenshot:

![Alert](./screenshots/01-sentinel-alert.png)

---

# Investigation

## Step 1 — Alert Validation

Microsoft Sentinel generated an alert after execution of an encoded PowerShell command.

Evidence:

![Alert](./screenshots/01-sentinel-alert.png)


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

![Process Creation](./screenshots/03-sysmon-event-id-1.png)


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

![Network Analysis](./screenshots/05-sysmon-event-id-3.png)


---

## Step 5 — File Analysis

Reviewed Sysmon Event ID 11.

Query:

[04-File-Analysis.kql](./queries/04-File-Analysis.kql)


Observed file:

 
### Objectives
Trigger a Microsoft Sentinel analytics rule
Investigate Sysmon Event ID 1
Decode the PowerShell command
Validate network activity (Sysmon Event ID 3)
Validate file creation (Sysmon Event ID 11)
Document the investigation and incident closure

### Lab Environment
Component	Value
SIEM	Microsoft Sentinel
Log Source	Sysmon
Agent	Azure Monitor Agent
Detection	Scheduled Analytics Rule
Host	CORP-WS-001
Attack Simulation	Atomic Red Team

### Attack Simulation
Technique
MITRE ATT&CK
T1059.001 - PowerShell
Atomic Test
Atomic Test #17
PowerShell Command Execution

### Alert Triggered

Several minutes after executing the Atomic Test, Microsoft Sentinel generated an alert.

Alert Details
Field	Value
Alert	PowerShell Encoded Command Execution
Severity	Medium
Source	Microsoft Sentinel
MITRE	T1059.001

### Investigation
Step 1 — Review Alert Evidence

The incident contained a Sysmon Process Creation event.

Findings
Field	Value
Image	powershell.exe
Parent Image	cmd.exe
User	CORP-WS-001\azureuser
Integrity Level	High

### Step 2 — Analyze Command Line

The PowerShell process used the following parameter:

powershell.exe -e

The Base64 string was decoded.

Decoded command:

Write-Host "Hello, from PowerShell!"
Analyst Notes

The decoded payload performed no malicious activity.
