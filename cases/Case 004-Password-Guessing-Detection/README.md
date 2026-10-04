# Case 004: FTP Brute Force Detection — Failed Logons Followed by Successful Authentication

---

## Scenario

This case demonstrates the investigation of a controlled FTP password-guessing attack performed against an authorized Ubuntu endpoint in a Microsoft Azure security laboratory.

The objective was to simulate repeated FTP authentication failures from a Kali Linux attacker host, generate FTP/vsftpd authentication telemetry, detect the sequence using a Microsoft Sentinel Analytics Rule, and investigate the resulting authentication timeline.

The investigation focused on correlating:

* vsftpd log entries — `FAIL LOGIN` events
* vsftpd log entries — `OK LOGIN` events
* Source IP and target account correlation
* Authentication timestamps and event sequence
* Azure Monitor Agent (AMA) log collection
* Microsoft Sentinel incident generation

The case also included post-authentication investigation for subsequent FTP-related activity within the available Syslog telemetry.

## Executive Summary

Microsoft Sentinel generated a **High-severity incident** after detecting multiple failed FTP authentication attempts followed by a successful authentication from the same source IP and user within a five-minute correlation window.

The successful FTP authentication was performed manually by the lab operator as part of the authorized detection validation procedure. The purpose was to verify that Microsoft Sentinel could correlate repeated failed authentication attempts with a subsequent successful login and generate an incident.

The controlled attack originated from the authorized Kali Linux laboratory host:

```text
10.0.0.4
```

The target was:

```text
FILE01
```

The targeted account was:

```text
Neo
```

Five failed authentication attempts were observed as vsftpd `FAIL LOGIN` events.

The subsequent successful authentication generated a vsftpd `OK LOGIN` event. The successful login was recorded at `2026-10-03 11:06:59.988967 UTC`.

The investigation confirmed that the source IP belonged to the authorized Kali Linux laboratory host. Subsequent Syslog analysis did not identify additional FTP-related activity from that source after the successful login. However, the available telemetry did not provide a complete record of FTP commands or file modifications, so the absence of post-authentication activity in Syslog does not establish that no FTP operations occurred.

## MITRE ATT&CK Mapping

| Tactic            | Technique           |
| ----------------- | ------------------- |
| Credential Access | T1110 — Brute Force |

## Lab Environment

| Component      | Value                                               |
| -------------- | --------------------------------------------------- |
| SIEM           | Microsoft Sentinel                                  |
| Telemetry      | Linux Syslog / vsftpd authentication logs           |
| Log Collection | Azure Monitor Agent (AMA) / Log Analytics Workspace |
| Target Host    | `FILE01`                                            |
| Attacking Host | Kali Linux (`10.0.0.4`)                             |
| Target Account | `Neo`                                               |
| FTP Service    | `vsftpd`                                            |
| Simulation     | Controlled FTP Password Guessing                    |
| Detection      | Microsoft Sentinel Scheduled Analytics Rule         |

## Timeline

| Time (UTC)                          | Event                                                                                         | Source             |
| ----------------------------------- | --------------------------------------------------------------------------------------------- | ------------------ |
| 03 Oct 2026 11:06:32.632            | FTP connection activity from `10.0.0.4`                                                       | vsftpd Syslog      |
| 03 Oct 2026 11:06:33.000            | PAM authentication failure events observed during the failed-login sequence                   | Linux Syslog       |
| 03 Oct 2026 11:06:36                | Five failed FTP authentication attempts — `FAIL LOGIN`                                        | vsftpd Syslog      |
| 03 Oct 2026 11:06:49                | Subsequent FTP connection activity from `10.0.0.4`                                            | vsftpd Syslog      |
| 03 Oct 2026 11:06:59.988            | Successful FTP authentication — `OK LOGIN` for `Neo`, performed manually by the lab operator  | vsftpd Syslog      |
| 03 Oct 2026 11:06:59–11:20:00       | Follow-up Syslog investigation; no additional FTP-related activity from `10.0.0.4` identified | Linux Syslog       |
| 03 Oct 2026 14:06–14:11 (UTC+03:00) | Microsoft Sentinel incident time range                                                        | Microsoft Sentinel |
| 03 Oct 2026 14:17 (UTC+03:00)       | Last update time displayed for the Sentinel incident                                          | Microsoft Sentinel |

> **Important:** Raw Syslog timestamps are recorded in UTC. Microsoft Sentinel incident timestamps shown above are in local time (UTC+03:00). The successful FTP authentication was deliberately performed by the lab operator to validate the detection rule; it was not an unauthorized login. 


### Actual Authentication Sequence

The raw vsftpd logs establish the following sequence:

`FAIL LOGIN × 5 → OK LOGIN × 1`

The failed FTP authentication events were recorded at approximately:

`11:06:36 UTC`

The successful FTP authentication was recorded at:

`11:06:59.988967 UTC`

The source IP for both the failed and successful authentication events was:

`10.0.0.4`

The targeted account was:

`Neo`


### Sentinel Correlation Window

Microsoft Sentinel generated an incident using the scheduled Analytics Rule `FTP Brute Force Followed by Successful Login`.

The incident included two entities:

* **IP Address:** `10.0.0.4` — the authorized Kali Linux laboratory host
* **Account:** `Neo` — the targeted FTP account


The Sentinel incident displayed the following timestamps in local time (UTC+03:00):

* **Start Time:** `2026-10-03 14:06`
* **End Time:** `2026-10-03 14:11`
* **Last Update Time:** `2026-10-03 14:17`

The raw FTP authentication logs use UTC timestamps. The successful login was recorded at `2026-10-03T11:06:59.988967Z`, corresponding to `2026-10-03 14:06:59.988967` local time (UTC+03:00).


The incident demonstrates that the Analytics Rule detected the intended authentication sequence and associated the alert with the expected IP and account entities.


---

## Objectives

* Simulate controlled FTP password guessing from an authorized Kali Linux host
* Generate vsftpd `FAIL LOGIN` events
* Confirm successful authentication using the `OK LOGIN` event
* Configure and validate a Microsoft Sentinel Analytics Rule
* Correlate failed and successful authentication attempts
* Create and investigate the resulting Sentinel incident
* Reconstruct the FTP authentication timeline from raw Syslog records
* Investigate subsequent FTP-related activity within the available telemetry
* Document telemetry limitations and investigation findings
