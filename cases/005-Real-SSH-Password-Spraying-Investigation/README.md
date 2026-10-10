# Case 005: Real SSH Brute-Force Detection — Failed Authentication Attempts from Multiple External Sources
---

## Scenario

This case documents a real-world SSH brute-force detection and investigation involving an Ubuntu virtual machine hosted in Microsoft Azure. On October 3, 2026, Microsoft Sentinel recorded repeated failed SSH authentication attempts originating from multiple external IP addresses while SSH was exposed to the internet through an Azure Network Security Group (NSG) rule allowing inbound TCP/22 traffic from any source.

The investigation focused on identifying the external sources, analyzing targeted usernames and authentication patterns, checking for evidence of successful SSH access, and examining selected host artifacts for indicators of compromise. The activity was investigated using available Sentinel telemetry and host-level evidence. This was not a controlled attack simulation; conclusions are limited to the evidence collected and reviewed.


The investigation correlated:

* OpenSSH (`sshd`) Syslog entries and failed password-authentication events
* Invalid-user messages and authentication failure records
* Source IP addresses and targeted usernames
* Authentication event counts and timestamps
* Microsoft Sentinel / Log Analytics query results
* VirusTotal IP reputation results
* Local SSH authentication logs and failed-login records
* SSH runtime configuration and selected host persistence locations
* Azure NSG exposure and subsequent containment

The case title uses *Password Spraying* as the working incident label. However, the exact password strategy could not be established from the available telemetry. The observed behavior is more conservatively classified as automated SSH password-guessing activity targeting multiple usernames.

## Executive Summary

On October 3, 2026, an Azure-hosted Ubuntu virtual machine recorded **212 failed SSH password-authentication events from five external IP addresses** in the reviewed Microsoft Sentinel / Log Analytics data.

The activity targeted multiple usernames, including common system and application account names such as `root`, `ubuntu`, `admin`, `debian`, `postgres`, `mysql`, `jenkins`, and `deploy`. The pattern was consistent with automated SSH password guessing or opportunistic credential scanning against commonly used usernames.

The available evidence established that multiple usernames were targeted but did not establish how many distinct passwords were attempted, whether the same password was reused across multiple accounts, or whether previously compromised credentials were used. Therefore, the exact password strategy could not be confirmed as password spraying or credential stuffing.

At the time of the activity, inbound TCP/22 was permitted from `Any` in the Azure NSG as part of an FTP laboratory exercise. The effective SSH configuration also had password authentication enabled through `PasswordAuthentication yes`.

After noticing the activity, the investigator restricted inbound SSH access in the NSG to their own public IP address. The exact time of this change was not recorded. SSH password authentication remained enabled after the network-layer containment action.

The investigation included a review of Sentinel authentication events, local SSH authentication logs, failed-login records, SSH runtime configuration, account-modification logs, temporary directories, cron jobs, systemd units, and selected recently modified files.

No successful SSH authentication was identified in the reviewed records for October 3, 2026. The scoped host investigation did not identify suspicious artifacts or persistence mechanisms in the reviewed locations.

However, `auditd` was inactive, and `auditctl` was unavailable. The investigation did not include a complete forensic acquisition of the VM, and the available evidence cannot conclusively exclude every possible form of compromise.

**Conclusion:** The evidence supports an incident involving repeated, likely automated SSH password-guessing attempts against an Azure Ubuntu VM exposed to broad inbound SSH access. No successful SSH authentication or persistence was identified in the reviewed evidence. A successful compromise was not established.

## MITRE ATT&CK Mapping

| Tactic | Technique | Relevance to This Case |
|---|---|---|
| Credential Access | T1110 — Brute Force | Primary classification for repeated failed SSH password-authentication attempts |
| Credential Access | T1110.001 — Password Guessing | Consistent with attempts to authenticate using candidate passwords; the exact password strategy was not established |
| Discovery | T1087 — Account Discovery | Potentially relevant because multiple common usernames were targeted; successful enumeration of valid accounts was not established |

### Technique Assessment

The observed activity involved repeated failed SSH password-authentication attempts from five external IP addresses, targeting numerous usernames. The pattern is consistent with automated SSH credential guessing against common Linux and application account names.

The available logs establish that multiple candidate usernames were used in authentication attempts. They do not establish the number of distinct passwords attempted, whether the same passwords were reused across accounts, or whether previously exposed credentials were used.

For this reason, **T1110 — Brute Force** is the most defensible primary classification. `T1110.001 — Password Guessing` is a plausible sub-technique based on the observed authentication behavior.

`T1087 — Account Discovery` is a potential secondary mapping because the sources attempted authentication with numerous usernames. However, targeting multiple usernames does not, by itself, prove that the attacker successfully identified valid accounts or that account discovery was the primary objective.

`T1110.003 — Password Spraying` and `T1110.004 — Credential Stuffing` are not assigned as confirmed techniques because the available evidence does not establish the defining password strategy or the use of previously exposed credentials.

## Lab Environment

| Component | Value |
|---|---|
| Cloud Provider | Microsoft Azure |
| SIEM / Log Analytics | Microsoft Sentinel / Log Analytics Workspace |
| Telemetry | Linux Syslog / OpenSSH authentication logs |
| Log Collection | Azure Monitor Agent (AMA), as configured in the environment |
| Target Host | `FILE01` |
| Operating System | Ubuntu |
| Relevant User Account | `Neo` |
| Target Service | OpenSSH (`sshd`) |
| Target Port | TCP/22 |
| Initial Network Exposure | Inbound TCP/22 allowed from `Any` in the Azure NSG |
| Authentication Method | SSH password authentication enabled |
| Incident Date | October 3, 2026 |
| Investigation Type | External SSH authentication activity investigation |
| Containment | SSH network access restricted to the investigator's public IP |

## Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| Before detection | Inbound TCP/22 was permitted from `Any` in the Azure NSG during the FTP laboratory exercise. | Investigator-provided configuration context |
| 03 Oct 2026 11:04:24.716–11:04:26.189 | Seven failed password events from `77.239.124.202` and one event from `2.57.122.238` were recorded within the observed interval. | Sentinel query results |
| 03 Oct 2026 12:11:28.569–12:16:51.903 | 81 failed password events were observed from `178.128.57.150`. | Sentinel query results |
| 03 Oct 2026 12:34:19.280–12:42:08.324 | 41 failed password events were observed from `103.174.114.111`. | Sentinel query results |
| 03 Oct 2026 12:42:52.378–12:50:49.751 | 82 failed password events were observed from `162.14.107.96`. | Sentinel query results |
| After detection; exact time unavailable | The investigator restricted inbound SSH access in the Azure NSG to their own public IP address. | Investigator statement |
| After detection; exact date unavailable | The five source IP addresses were checked using VirusTotal. | Investigator-provided results |
| During subsequent investigation | SSH authentication logs, failed-login records, SSH runtime configuration, account changes, temporary directories, cron, systemd, and selected recently modified files were reviewed. | Investigator-provided investigation results |

> **Important:** The Sentinel timestamps listed above are in UTC. The exact timestamp of the NSG change was not recorded in the supplied evidence.

### Authentication Activity Summary

The incident-day Sentinel query returned the following distribution:

| Source IP | Failed Password Events | Distinct Usernames | First Observed (UTC) | Last Observed (UTC) |
|---|---:|---:|---|---|
| `162.14.107.96` | 82 | 43 | 12:42:52.378 | 12:50:49.751 |
| `178.128.57.150` | 81 | 42 | 12:11:28.569 | 12:16:51.903 |
| `103.174.114.111` | 41 | 28 | 12:34:19.280 | 12:42:08.324 |
| `77.239.124.202` | 7 | 5 | 11:04:24.716 | 11:04:26.189 |
| `2.57.122.238` | 1 | 1 | 11:04:26.189 | 11:04:26.189 |
| **Total** | **212** | — | — | — |

The two highest-volume sources generated 163 of the 212 failed password events, approximately 76.9% of the total. The three highest-volume sources generated 204 events.

The targeting of numerous usernames is consistent with automated credential guessing. However, the event counts do not reveal the number of distinct passwords attempted, so they cannot independently distinguish password spraying from other password-guessing strategies.

## Objectives

* Identify repeated failed SSH password-authentication attempts in Microsoft Sentinel
* Determine the number of events associated with each external source IP
* Identify usernames targeted by each source
* Reconstruct the observed authentication timeline
* Search for successful SSH authentication in Sentinel and local logs
* Review historical failed-login records without mixing them with the incident-day event count
* Examine the effective SSH runtime configuration
* Review selected host locations for suspicious artifacts and persistence
* Enrich observed source IP addresses with VirusTotal reputation data
* Document the initial network exposure and subsequent containment
* Map the observed behavior to MITRE ATT&CK without overstating the evidence
* Document telemetry limitations and provide evidence-based remediation recommendations

  ## Investigation

### Identify External SSH Sources

#### KQL Query

`[01-authentication-evidence.kql](./queries/01-authentication-evidence.kql)`

![SSH authentication failures](./screenshots/01-authentication-fail.png)

### Determine Targeted User Accounts

#### KQL Query

`[03-determine-how-many-accounts-each-source-targeted.kql](./queries/03-determine-how-many-accounts-each-source-targeted.kql)`

![Targeted accounts by source IP](./screenshots/03-targeted-accounts-by-source.png)

### Review Individual Source Activity

#### KQL Query

`[12-individual-attack-timeline.kql](./queries/12-individual-attack-timeline.kql)`

![Individual SSH attack timeline](./screenshots/12-individual-attack-timeline.png)

### Verify Successful SSH Authentication

#### KQL Query

`[13-successful-authentication.kql](./queries/13-successful-authentication.kql)`

![Successful SSH authentication review](./screenshots/13-successful-authentication.png)

### Review SSH Sessions and Login History

#### KQL Queries and Host-Level Checks

`[14-ssh-sessions.pdf](./evidence/screenshots/14-ssh-sessions.pdf)`

`[17-successful-login-history.pdf](./evidence/screenshots/17-successful-login-history.pdf)`

### Host-Based Investigation

#### SSH Configuration

`[21-ssh-configuration.pdf](./evidence/screenshots/21-ssh-configuration.pdf)`

#### Temporary Directories

`[18-temporary-directories.pdf](./evidence/screenshots/18-temporary-directories.pdf)`

#### Cron and Scheduled Tasks

`[19-cron.pdf](./evidence/screenshots/19-cron.pdf)`

#### Systemd Persistence

`[20-systemd-persistence.pdf](./evidence/screenshots/20-systemd-persistence.pdf)`

### Investigation Summary

The investigation identified 212 failed SSH password-authentication events from five external source IP addresses on October 3, 2026. The attempts targeted multiple usernames, including common administrative and service account names.

The reviewed Microsoft Sentinel results and host-level authentication records did not reveal successful SSH authentication. The examined SSH configuration, temporary directories, scheduled tasks, systemd services, and selected filesystem locations did not identify clear evidence of post-exploitation activity.

These findings do not establish that the host was compromised. However, the absence of successful authentication events in the reviewed telemetry does not conclusively prove that access was never obtained. The assessment is limited to the available logs and the host artifacts examined during the investigation.


