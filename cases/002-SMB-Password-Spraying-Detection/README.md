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

 
The value 59 represents all matching NTLM authentication failures observed on CORP-WS-001 during the one-day investigation window.As seen in incident page only 10 failed attempts linked to this case.The remaining majority of the failed attempts occurred before the incident was triggered, due to multiple simulated attack attempts executed for tuning a correct detection rule.

### Step 3 - More detailed analysis to detect unique IPs 2:

[04-More-detailed-analysis.kql](./queries/04-More-detailed-analysis.kql)

![14-more-detailed-analysis.png](./screenshots/14-more-detailed-analysis.png)

Detailed analysis: Identify distinct two source IPs 

####  Review Detailed analysis 

**Source 1**

Source IP: 10.0.0.5

Target Host: CORP-WS-001

Activity: Event ID 4625

Status: 0xc000006d (STATUS_LOGON_FAILURE)

Target Accounts & Automation Timeline [UTC]

Ten accounts were targeted in less than one second, demonstrating a high-velocity automated authentication pattern. 

13:43:40.334 — Administrator

13:43:40.361 — guest

13:43:40.386 — backup_admin

13:43:40.412 — j.doe

13:43:40.432 — m.smith

13:43:40.458 — a.ivanov

13:43:40.483 — security_test

13:43:40.508 — user1

13:43:40.532 — user2

13:43:40.560 — operator

This pattern is consistent with the controlled Password Spray:

One source IP → multiple accounts → rapid 4625 failures → NTLM network authentication.

SubStatus context:

0xc0000064 — the specified account does not exist.

0xc000006a — the account exists, but the supplied password is incorrect.





**Source 2** — Additional Authentication Noise

The second source, 00.00.00.000, generated two failed authentication attempts against the same azureuser account:

Source IP:       00.00.00.000

Target Host:     CORP-WS-001

Target Account:  azureuser

13:45:03.694 — 4625
13:45:09.065 — 4625

Status:          0xc000006d

SubStatus:       0xc000006a

These events were intentionally generated as benign authentication noise, simulating a user entering an incorrect password twice.
The activity does not satisfy the Password Spray detection condition because both failures target the same account:
One source IP → one account →  2 failed 4625  → TargetedUsersCount = 1→ threshold ≥ 3 not reached

Analyst interpretation: The two azureuser failures represent authentication noise rather than Password Spray. This demonstrates why the detection relies on distinct targeted accounts, rather than simply counting 4625 events.

### Step 4 - Attack Source IP Analysis & Blast Radius Evaluation

**Purpose:** Pivot directly to the malicious source IP address to verify the exact pattern of the horizontal password-spraying blast radius and list targeted accounts.

[05-Attack-Source-IP-Analysis-&-Blast-Radius-Evaluation.kql](./queries/05-Attack-Source-IP-Analysis-&-Blast-Radius-Evaluation.kql)

![15-source-ip-analysis-blast-radius-evaluation.png](./screenshots/15-source-ip-analysis-blast-radius-evaluation.png)

The >=10 threshold is used for this laboratory investigation to reduce unrelated historical NTLM failures. Production thresholds should be calibrated against the organization's normal baseline.

**My Idea:** The ultimate goal of any credential harvesting or guessing campaign is to compromise at least one account to establish initial access. If we detect even a single successful logon event (EventID == 4624) matching the same logon type (LogonType == 3) from the identified malicious IP address amidst hundreds of 4625 errors, the compromise hypothesis is validated, confirming that the attacker has successfully authenticated to the environment.
Possible Outcomes & Next Steps:

**- Outcome A** (No results / Empty Table): No successful authentication was observed from 10.0.0.5 during the investigation window. The observed password spray did not result in an observed successful network logon from the identified source.

**Actions:** Continue monitoring the affected accounts and source IP, document the incident as a True Positive with no observed successful authentication, and close the incident according to the organization's response procedure.

**- Outcome B** — Successful Authentication Observed (e.g., Row populated for account j.doe): A successful authentication was observed from the spray source. This strongly supports the compromise hypothesis and requires immediate investigation.

  **- Actions:** Escalate for immediate incident response. Review the full 4624 context, determine the affected account's privileges and scope of access, initiate account containment and credential reset/revocation according to organizational procedures, isolate the affected host if compromise is suspected, and proceed to Live Forensic Collection where required.

  ### Step 5 - Successful Authentication Check

Run the critical query to establish whether Outcome A or Outcome B occurred

[06-Successful-Authentication-Check.kql](./queries/06-Successful-Authentication-Check.kql)

![16-successful-authentication-check.png](./screenshots/16-successful-authentication-check.png)






### Step 3 — Detailed Multi-IP Isolation Analysis

[04-More-detailed-analysis.kql](./queries/04-More-detailed-analysis.kql)

![14-more-detailed-analysis.png](./screenshots/14-more-detailed-analysis.png)

**Analysis Objective:** Identify and analyze the distinct behavioral signatures of the two isolated source IP addresses.

#### Telemetry Review

**Source 1 (Simulated Attack)**
- **Source IP:** `10.0.0.5`
- **Target Host:** `CORP-WS-001`
- **Activity:** Event ID `4625` (Failed Logon)
- **Status:** `0xc000006d` (`STATUS_LOGON_FAILURE`)

*Target Accounts & Automation Timeline [UTC]:*
Ten distinct corporate accounts were sequentially targeted in less than one second, demonstrating a high-velocity automated authentication pattern:
- **13:43:40.334** — `Administrator`
- **13:43:40.361** — `guest`
- **13:43:40.386** — `backup_admin`
- **13:43:40.412** — `j.doe`
- **13:43:40.432** — `m.smith`
- **13:43:40.458** — `a.ivanov`
- **13:43:40.483** — `security_test`
- **13:43:40.508** — `user1`
- **13:43:40.532** — `user2`
- **13:43:40.560** — `operator`

*Analyst Note:* This behavior perfectly matches the horizontal Password Spraying signature: 
`One source IP` ➔ `Multiple distinct accounts` ➔ `High-velocity 4625 entries` ➔ `NTLM Network Authentication (LogonType 3)`.

*SubStatus Subsystem Context:*
- `0xc0000064` (`STATUS_NO_SUCH_USER`): The specified account does not exist on the target system (blind dictionary spray).
- `0xc000006a` (`STATUS_WRONG_PASSWORD`): The account exists, but the provided credential token was incorrect (`guest` account).

**Source 2 (Additional Authentication Noise)**
The second source, masked as `37.63.00.000`, generated two failed authentication events against the exact same local cloud management account:
- **Source IP:** `37.63.00.000`
- **Target Host:** `CORP-WS-001`
- **Target Account:** `azureuser`
- **Timeline:** `13:45:03.694` & `13:45:09.065` (Event ID `4625`)
- **Status / SubStatus:** `0xc000006d` / `0xc000006a`

*Analyst Note:* These events represent standard, automated external brute-force noise (simulating a basic user typo or generic bot traffic). This specific activity **does not** satisfy the analytical conditions of a Password Spraying alert because it focuses vertically on a single account name:
`One source IP` ➔ `One single account` ➔ `Low-velocity 4625 failures` ➔ `TargetedUsersCount = 1` (Threshold of `≥ 3` unique users is not met).

*Triage Conclusion:* The `azureuser` failures are classified as baseline internet scanning noise rather than an active multi-vector password spray. This highlights why robust analytics rules must aggregate by *distinct targeted accounts* (`dcount(TargetUserName)`) rather than just raw volume tracking.

---

### Step 4 — Attack Source IP Analysis & Blast Radius Evaluation

**Purpose:** Pivot investigation resources directly to the malicious source IP address (`10.0.0.5`) to analyze the precise boundaries of the horizontal password-spraying blast radius and correlate targeted accounts.

[05-Attack-Source-IP-Analysis-and-Blast-Radius-Evaluation.kql](./queries/05-Attack-Source-IP-Analysis-and-Blast-Radius-Evaluation.kql)

![15-source-ip-analysis-blast-radius-evaluation.png](./screenshots/15-source-ip-analysis-blast-radius-evaluation.png)

*Deployment Note:* A threshold of `≥ 10` is applied during this laboratory evaluation to suppress historical NTLM noise. Production rule thresholds should be continuously calibrated against the organization's normal historical baseline.

**Core Analytical Hypothesis:** The ultimate objective of any credential-harvesting or password-guessing campaign is to compromise at least one corporate account to establish an initial foothold. If a single successful logon event (Event ID `4624`) matching the same authentication parameters (`LogonType 3`) is detected originating from the same suspicious source IP amidst a surge of `4625` events, the compromise hypothesis is validated, confirming active environment intrusion.

#### Evaluated Outcomes & Triage Next Steps

- **Outcome A (No Results / Empty Matrix):** 
  No successful authentication events (`4624`) were recorded from `10.0.0.5` during the active investigation window. The active password spray failed to secure initial access.
  - **Remediation Actions:** Continue standard network monitoring on the targeted accounts and the source IP. Document the event as a **True Positive (No Compromise)**, log the investigative artifacts, and close the incident within the SIEM queue according to normal operating procedures.

- **Outcome B (Successful Authentication Observed):** 
  A successful network authentication is observed from the spray source (e.g., active row populated for a user like `j.doe`). This confirms a critical breach of credentials.
  - **Remediation Actions:** Escalate immediately to Tier-3 / Incident Response (IR) team. Extrapolate the full context of the `4624` event to identify the compromised account's network privileges. Initiate immediate credential revocation, force an Active Directory reset, isolate the affected endpoint (`CORP-WS-001`) from the local network segment, and pivot to active Live Forensic Collection.

---

### Step 5 — Successful Authentication Check

Run the critical pivot query to confirm whether **Outcome A** or **Outcome B** occurred in the SIEM infrastructure:

[06-Successful-Authentication-Check.kql](./queries/06-Successful-Authentication-Check.kql)

![16-successful-authentication-check.png](./screenshots/16-successful-authentication-check.png)
























---

