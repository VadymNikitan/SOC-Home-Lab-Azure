# FTP Brute Force Detection & Investigation with Microsoft Sentinel

> **SOC Detection Engineering / Incident Response Lab**
>
> Detection, investigation, and response to a controlled FTP password-guessing attack using **Microsoft Sentinel, Azure Monitor Agent, Syslog, rsyslog, KQL, and Linux endpoint telemetry**.

---

## Overview

This project demonstrates an end-to-end SOC workflow for detecting and investigating a controlled FTP password-guessing attack in an Azure-hosted Linux environment.

The scenario simulates:

**Reconnaissance → Service Enumeration → Password Guessing → Successful Authentication → Detection → Investigation → Response**

The primary objective was to validate the **SOC detection and investigation workflow**, rather than demonstrate a complete host-compromise chain.

### Final verdict

**Confirmed FTP password-guessing activity followed by successful authentication.**

No subsequent FTP file operations or file modifications were observed during the investigation window.

---

## Architecture

```text
                         Azure SOC Laboratory

        ┌──────────────────────────────┐
        │         ATTACKER-01          │
        │          Kali Linux          │
        │          10.0.1.4            │
        └──────────────┬───────────────┘
                       │
                       │ FTP / TCP 21
                       ▼
        ┌──────────────────────────────┐
        │           FILE-01            │
        │         Ubuntu Linux         │
        │          10.0.1.9            │
        │                              │
        │          vsftpd 3.0.5        │
        └──────────────┬───────────────┘
                       │
                       │ Syslog
                       ▼
                    rsyslog
                       │
                       ▼
                Azure Monitor Agent
                       │
                       ▼
                Data Collection Rule
                       │
                       ▼
                Log Analytics
                       │
                       ▼
             Microsoft Sentinel
                       │
                       ▼
        Analytics Rule: FTP Brute Force-
             Successful Login
                       │
                       ▼
                SOC Investigation
                       │
                       ▼
                    Response
```

---

## Environment

| Component   | Role                              | Address       |
| ----------- | --------------------------------- | ------------- |
| ATTACKER-01 | Kali Linux attack simulation host | `10.0.1.4`    |
| FILE-01     | Ubuntu Linux FTP server           | `10.0.1.9`    |
| Gateway     | Azure lab network gateway         | `10.0.1.1`    |
| Network     | Azure VNet                        | `10.0.1.0/24` |

### FILE-01 exposed services

```text
21/tcp  open  ftp  vsftpd 3.0.5
22/tcp  open  ssh  OpenSSH 9.6p1 Ubuntu
```

The FTP service was the target of the detection scenario.

---

## Telemetry Pipeline

The endpoint telemetry pipeline was configured as:

```text
vsftpd
   │
   ├── PAM authentication events
   │
   └── FTP service events
          │
          ▼
       rsyslog
          │
          ▼
Azure Monitor Agent (AMA)
          │
          ▼
Data Collection Rule (DCR)
          │
          ▼
Log Analytics Workspace
          │
          ▼
Microsoft Sentinel
```

Two relevant telemetry paths were observed:

### Authentication failures

PAM authentication failures were written to:

```text
/var/log/auth.log
```

Example:

```text
pam_unix(vsftpd:auth): authentication failure
ruser=bubaleh
rhost=10.0.1.4
user=bubaleh
```

### Successful FTP authentication

`vsftpd` successful login events used the `ftp` facility and were observed in:

```text
/var/log/syslog
```

Example:

```text
[bubaleh] OK LOGIN: Client "10.0.1.4"
```

Both telemetry streams were successfully ingested into Microsoft Sentinel.

---

# Attack Scenario

## 1. Reconnaissance

The attacker performed network discovery from `ATTACKER-01`.

### Host discovery

```bash
nmap -sn 10.0.1.0/24
```

Discovered hosts included:

```text
10.0.1.1  gateway
10.0.1.4  ATTACKER-01
10.0.1.9  FILE-01
```

### Port discovery

```bash
nmap -p- 10.0.1.9
```

The scan identified:

```text
21/tcp  FTP
22/tcp  SSH
```

### Service enumeration

```bash
nmap -sV -sC -p 21,22 10.0.1.9
```

FTP was identified as:

```text
vsftpd 3.0.5
```

---

## 2. FTP Authentication Assessment

Anonymous FTP access was tested first.

The server returned:

```text
530 Login incorrect.
```

This confirmed that anonymous FTP authentication was disabled.

The scenario then proceeded to authenticated login attempts against the designated laboratory test account.

> The test account was part of the controlled laboratory setup. It was not obtained through the modeled reconnaissance phase.

---

## 3. Controlled Password Guessing

A deliberately bounded password-guessing test was performed against the FTP service.

The test used five invalid passwords:

```text
wrongA
wrongB
wrongC
wrongD
wrongE
```

Attack command:

```bash
hydra -l bubaleh -P bad_passwords.txt ftp://10.0.1.9
```

The test was intentionally limited to five password attempts.

The resulting attack sequence produced:

```text
5 failed authentication attempts
        ↓
1 successful authentication
```

---

# Detection Engineering

## Microsoft Sentinel Analytics Rule

**Rule name:**

`FTP Brute Force-Successful Login`

**Severity:**

`High`

**MITRE ATT&CK:**

* `T1110` — Brute Force
* `T1110.001` — Password Guessing
* `T1078` — Valid Accounts

The rule correlates multiple failed FTP authentication attempts with a subsequent successful authentication from the same source IP against the same account.

### Detection logic

```kusto
Syslog
| where TimeGenerated > ago(15m)
| where ProcessName == "vsftpd"
| where SyslogMessage has_any ("authentication failure", "OK LOGIN")
| extend SourceIP = coalesce(
    extract(@"rhost=([0-9.]+)", 1, SyslogMessage),
    extract(@"Client ""([0-9.]+)""", 1, SyslogMessage)
)
| extend User = coalesce(
    extract(@"user=([^\s]+)", 1, SyslogMessage),
    extract(@"\[([^\]]+)\]", 1, SyslogMessage)
)
| summarize
    Failures = countif(SyslogMessage has "authentication failure"),
    Successes = countif(SyslogMessage has "OK LOGIN"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, User
| where Failures >= 4 and Successes >= 1
```

### Detection result

```text
Source IP:  10.0.1.4
Account:    bubaleh
Failures:   5
Successes:  1
```

---

# Incident Investigation

Microsoft Sentinel generated a **High-severity incident**:

```text
FTP Brute Force-Successful Login
```

The incident identified two primary entities:

```text
IP Address
10.0.1.4

Account
bubaleh
```

Target host:

```text
FILE-01
```

This provided a clear investigation pivot:

```text
Source IP
    ↓
Affected account
    ↓
Target host
    ↓
FTP authentication activity
```

---

# Attack Timeline

The exact event sequence was validated directly against the Syslog telemetry.

```text
11:36:22 UTC
5 × authentication failure
        │
        ▼
11:36:25 UTC
5 × FTP FAIL LOGIN
        │
        ▼
11:37:04 UTC
1 × FTP OK LOGIN
```

The correlation window was approximately:

```text
11:36:22 → 11:37:04 UTC
```

The successful authentication occurred approximately **42 seconds after the first recorded failure**.

---

# Post-Authentication Investigation

Successful authentication does not by itself demonstrate full host compromise.

Additional endpoint validation was therefore performed.

## FTP activity

The relevant successful login event was:

```text
2026-09-09T11:37:04.779978+00:00
FILE-01 vsftpd[8454]:
[bubaleh] OK LOGIN: Client "10.0.1.4"
```

No subsequent FTP file-operation events were observed in the investigated period.

No evidence of the following operations was identified:

```text
STOR
RETR
DELE
MKD
RMD
LIST
CWD
```

## File-system validation

The FTP user's home directory was checked:

```bash
sudo ls -la /home/bubaleh
```

Existing files were:

```text
.bash_logout
.bashrc
.profile
```

All existing files had timestamps from September 8, before the attack.

A targeted search for files created or modified after the successful authentication returned no results:

```bash
sudo find /home/bubaleh \
  -type f \
  -newermt '2026-09-09 11:37:00' \
  -ls
```

Result:

```text
No files found.
```

---

# Investigation Findings

## Confirmed

* Network reconnaissance occurred from `ATTACKER-01`.
* `FILE-01` exposed FTP on TCP/21.
* The FTP service was identified as `vsftpd 3.0.5`.
* Anonymous FTP access was denied.
* Five failed authentication attempts were recorded.
* All failures originated from `10.0.1.4`.
* All failures targeted `bubaleh`.
* A subsequent successful FTP authentication was recorded.
* Microsoft Sentinel correlated the activity.
* A High-severity incident was generated.
* The incident identified the source IP and affected account.

## Not observed

* No subsequent FTP file operations were observed.
* No new files were created in `/home/bubaleh`.
* No existing files in `/home/bubaleh` were modified after the successful login.
* No evidence was collected demonstrating command execution.
* No persistence was observed.
* No lateral movement was observed.
* No evidence was collected demonstrating broader host compromise.

---

# SOC Verdict

> **Confirmed FTP password-guessing activity followed by successful authentication. No subsequent FTP file activity or file modifications were observed during the investigation window.**

The successful `OK LOGIN` event confirms authenticated access to the FTP service.

However, the available telemetry does **not** demonstrate further compromise of the Linux host.

This distinction is important in incident analysis: an authenticated session is evidence of successful access, but not sufficient evidence by itself to claim complete host compromise.

---

# Response

Recommended SOC response:

1. Validate the source IP.
2. Identify the affected account.
3. Confirm the successful authentication.
4. Review post-authentication activity.
5. Preserve relevant endpoint and Sentinel telemetry.
6. Reset or disable the affected account in a production environment.
7. Restrict FTP access from the identified source where appropriate.
8. Review the host for additional suspicious activity.
9. Close the incident after confirming containment and absence of further malicious activity.

For this laboratory, the attacker host was intentionally left operational because `ATTACKER-01` is the controlled attack-simulation system.

---

# MITRE ATT&CK Mapping

| Technique         | ID          | Evidence                                        |
| ----------------- | ----------- | ----------------------------------------------- |
| Brute Force       | `T1110`     | Multiple failed FTP authentication attempts     |
| Password Guessing | `T1110.001` | Five password attempts against the same account |
| Valid Accounts    | `T1078`     | Successful authentication using `bubaleh`       |

`T1078` represents the observed use of a valid account. It does not imply that broader host compromise was established.

---

# Skills Demonstrated

### Detection Engineering

* Microsoft Sentinel Analytics Rules
* KQL
* Event correlation
* Threshold-based detection
* Entity extraction
* MITRE ATT&CK mapping
* Detection tuning

### Security Monitoring

* Linux Syslog
* rsyslog
* PAM authentication telemetry
* vsftpd logging
* Azure Monitor Agent
* Data Collection Rules
* Log Analytics

### Incident Response

* Alert triage
* Entity-based investigation
* Timeline reconstruction
* Endpoint validation
* Post-authentication analysis
* Evidence preservation
* Containment planning
* Incident classification

### Offensive Security / Adversary Simulation

* Nmap reconnaissance
* Service enumeration
* FTP authentication testing
* Controlled password guessing
* Atomic Red Team / adversary-simulation methodology

---

# Evidence

Selected screenshots document the complete investigation chain:

```text
01-reconnaissance.png
02-nmap-reconnaissance.png
03-nmap-ports.png
04-service-enumeration.png
05-ftp-enumeration.png
06-ftp-connectivity.png
07-anonymous-access-denied.png
08-authentication-failure.png
09-file01-ftp-logs.png
10-sentinel-logs.png
11-ama-dcr-syslog-validation.png
12-attack-test.png
13-successful-login.png
14-sentinel-attack-logs.png
15-incident-entities.png
16-correlation-query.png
17-post-auth-check.png
18-response.png
```

The key evidence chain is:

```text
Attack
  ↓
Endpoint telemetry
  ↓
AMA / DCR
  ↓
Microsoft Sentinel
  ↓
Analytics Rule
  ↓
Incident
  ↓
Entity correlation
  ↓
Endpoint investigation
  ↓
SOC verdict
```

---

# Project Outcome

This project successfully validated an end-to-end SOC detection and investigation workflow for FTP password-guessing activity.

The detection identified a correlated pattern of:

**5 failed authentication attempts → 1 successful authentication**

The investigation then validated the alert against endpoint telemetry and filesystem evidence.

The final investigation determined that:

**FTP authentication was successfully obtained, but no subsequent FTP file activity or file modifications were observed during the investigation window.**

---

## Disclaimer

This project was conducted in an isolated Azure laboratory environment using designated test systems and accounts.

All attack activity was intentionally bounded and performed for defensive security monitoring, detection engineering, and incident-response training.

