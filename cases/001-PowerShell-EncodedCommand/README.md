# Case 001: PowerShell Encoded Command Execution
---

## Scenario
This case demonstrates the investigation of a Microsoft Sentinel alert triggered by an encoded PowerShell command executed during an authorized Atomic Red Team simulation.
The objective was to validate the detection, analyze Sysmon telemetry, and determine whether the activity represented malicious behavior or legitimate security testing.

## Executive Summary

Microsoft Sentinel generated an alert after detecting an encoded PowerShell command executed on a Windows endpoint. The investigation reconstructed the execution chain using Sysmon telemetry and confirmed that the activity originated from an authorized Atomic Red Team simulation. No evidence of persistence, credential access, lateral movement, or malicious outbound network communication was identified.

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Execution | T1059.001 — PowerShell |

## Lab Environment

| Component | Value |
|---|---|
| SIEM | Microsoft Sentinel |
| Telemetry | Sysmon v15 |
| Log Collection | Azure Monitor Agent |
| Host | CORP-WS-001 |
| Simulation | Atomic Red Team |
| Detection | Scheduled Analytics Rule |

---


## Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| Jul 30, 2026 13:09:18 | Encoded PowerShell execution detected | Sysmon Event ID 1 |
| Jul 30, 2026 13:16:44 | Alert generated | Microsoft Sentinel |
| Jul 30, 2026 13:16:44 | Incident created | Microsoft Sentinel |

---


## Objectives

- Trigger Sentinel Analytics Rule
- Analyze Sysmon Event ID 1
- Decode Base64 PowerShell command
- Review Sysmon Event ID 3
- Review Sysmon Event ID 11
- Classify incident

---

## Detection Rule

### Objective

Detect encoded PowerShell execution.

### Detection Logic

The analytics rule monitors:

- Sysmon Event ID 1
- PowerShell execution
- Encoded command parameters

Detected command-line parameters:

- `-e`
- `-enc`
- `-EncodedCommand`


![03-analytics-rule.png](./screenshots/03-analytics-rule.png)

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

## Investigation

### Step 1 — Alert Validation

Microsoft Sentinel generated an alert following the execution of an encoded PowerShell command.


![Incident Alert](./screenshots/01-incident-alert.png)


![Incident Details](./screenshots/02-incident-details.png)


---

### Step 2 — Process Analysis

Reviewed Sysmon Event ID 1.

Query:

[02-Process-Creation.kql](./queries/02-Process-Creation.kql)


### Findings

- Encoded PowerShell execution confirmed.
- Parent process identified (`cmd.exe`).
- User successfully identified.
- Process executed with High Integrity.



![Process Creation](./screenshots/05-process-creation-event-id-1.png)


---

### Step 3 — PowerShell Decoding

Decoded command:

```powershell
Write-Host "Hello, from PowerShell!"
```


Result:

The command executed a simple `Write-Host` statement.

No malicious functionality was identified.

---

### Step 4 — Network Analysis

Reviewed Sysmon Event ID 3.

Query:

[03-Network-Analysis.kql](./queries/03-Network-Analysis.kql)


Result:

No outbound network connections related to the PowerShell process were identified.



![Network Analysis](./screenshots/06-network-analysis-event-id-3.png)


---

### Step 5 — File Analysis

Reviewed Sysmon Event ID 11.

Query:

[04-File-Analysis.kql](./queries/04-File-Analysis.kql)




Analysis:

A temporary file associated with PowerShell execution policy testing was created.

No suspicious payloads created.


![File Creation](./screenshots/07-file-analysis-event-id-11.png)



---

## Evidence Summary

| Evidence | Status |
|----------|--------|
| PowerShell execution | Confirmed |
| Encoded command | Confirmed |
| Base64 command decoded | Completed |
| Parent process identified | Confirmed |
| User identified | Confirmed |
| Elevated execution | Confirmed |
| Outbound network activity | Not Observed |
| Malicious file creation | Not Observed |

## Attack Flow

```text
Atomic Red Team
        │
        ▼
PowerShell (EncodedCommand)
        │
        ▼
Sysmon Event ID 1
        │
        ▼
Azure Monitor Agent
        │
        ▼
Log Analytics Workspace
        │
        ▼
Microsoft Sentinel
        │
        ▼
Analytics Rule
        │
        ▼
Alert
        │
        ▼
Incident
```

---

## Incident Classification

| Field | Result |
|-|-|
| Severity | Low |
| Confidence | High |
| Classification | Benign True Positive |
| Root Cause | Authorized Atomic Red Team Simulation |

---

## Remediation and Response Steps

Although this incident was ultimately classified as a **Benign True Positive** due to the authorized Atomic Red Team simulation, a standardized response workflow has been documented to support analysts investigating similar alerts in production environments.

### 1. Immediate Containment

If the encoded PowerShell execution is determined to be unauthorized or malicious, the following containment actions should be performed immediately:

- Isolate the endpoint using Microsoft Defender for Endpoint (MDE) or network access controls to prevent lateral movement.
- Disable or reset the affected user account if compromise is suspected.
- Terminate the malicious PowerShell process along with any associated child processes identified through Sysmon Event ID 1.

---

### 2. Investigation and Eradication

After containment, perform additional investigation and remove any identified threats.

- Identify and remove malicious payloads or temporary files discovered during Sysmon Event ID 11 analysis.
- Inspect persistence mechanisms, including:
  - Scheduled Tasks
  - Registry Run Keys
  - WMI Event Subscriptions
  - Startup Folders
- Review additional endpoint telemetry for evidence of privilege escalation, credential access, or lateral movement.
- Reset privileged credentials if credential theft or dumping is suspected.

---

### 3. Recovery and Hardening

Implement security improvements to reduce the likelihood of similar attacks.

- Enable PowerShell Script Block Logging (Event ID 4104).
- Enable PowerShell Module Logging (Event ID 4103).
- Enforce PowerShell Constrained Language Mode where appropriate.
- Implement Windows Defender Application Control (WDAC) or AppLocker to restrict unauthorized PowerShell execution.
- Enforce PowerShell Execution Policies through Group Policy.
- Review and tune Microsoft Sentinel analytics rules to reduce false positives while maintaining detection coverage.

---

## Conclusion

The investigation confirmed that an encoded PowerShell command was successfully executed.
Although the activity matched the detection logic for MITRE ATT&CK technique T1059.001 (PowerShell), further analysis determined that it originated from an authorized Atomic Red Team simulation.
Review of Sysmon telemetry found no evidence of malicious payload execution, persistence, credential access, lateral movement, or malicious outbound network communication.
Based on the collected evidence, the incident was classified as a **Benign True Positive** and no additional response actions were required.

---

## Lessons Learned

- Sysmon Event ID 1 provides process execution visibility.
- Encoded PowerShell commands should always be decoded before classification.
- Sysmon Event ID 3 helps identify outbound network communication.
- Sysmon Event ID 11 helps identify dropped files and payloads.
- Microsoft Sentinel successfully detected the simulated activity.




