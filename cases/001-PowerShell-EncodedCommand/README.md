### Case 001: PowerShell Encoded Command Execution (MITRE ATT&CK T1059.001)
### Scenario

This case demonstrates the investigation of a Microsoft Sentinel alert triggered by an encoded PowerShell command executed during an authorized Atomic Red Team simulation.

The objective was to validate the detection, analyze Sysmon telemetry, and determine whether the activity represented malicious behavior or legitimate security testing.
 
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
