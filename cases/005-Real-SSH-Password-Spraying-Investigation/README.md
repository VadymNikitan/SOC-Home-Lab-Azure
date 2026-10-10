# DFIR Incident Report: SSH  Activity on an Azure Ubuntu VM

> **Incident date:** October 3, 2026
> **Report type:** Digital Forensics and Incident Response (DFIR)
> **Environment:** Microsoft Azure — Ubuntu virtual machine
> **Hostname:** `FILE01`
> **Relevant user account:** `Neo`
> **Primary telemetry:** Azure Sentinel / Log Analytics (`Syslog`), local SSH authentication logs, failed-login records, host configuration and persistence checks
> **Incident classification:** External SSH password-spraying activity
> **Investigation status:** Review completed based on the available evidence
> **Compromise status:** No successful SSH authentication or persistence was identified in the reviewed evidence. A compromise cannot be categorically excluded.

---

## 1. Executive Summary

On October 3, 2026, an Ubuntu virtual machine hosted in Microsoft Azure recorded repeated failed SSH password-authentication attempts from five external IP addresses.

At the time of the activity, inbound TCP port 22 was allowed from `Any` in the Azure Network Security Group (NSG) as part of an FTP lab. The effective SSH configuration also had password authentication enabled through `PasswordAuthentication yes`.

An Azure Sentinel / Log Analytics investigation identified **212 failed SSH password-authentication events from five source IP addresses** during the UTC day of October 3, 2026. The three highest-volume sources accounted for 204 events. The attempts targeted numerous common usernames, a pattern consistent with automated SSH credential guessing.

After noticing the activity, the investigator restricted inbound SSH access in the Azure NSG to their own public IP address. SSH password authentication remained enabled after this network-layer containment action.

The five source IP addresses were subsequently checked using VirusTotal. All five had at least one security-vendor detection at the time of the later check, with reported detection counts ranging from 1/92 to 15/92. These reputation results provide additional context but do not independently establish attribution, common ownership, or malicious intent for every connection from those addresses.

The investigation included reviews of SSH authentication logs, failed-login records, SSH runtime configuration, account-modification logs, temporary directories, cron jobs, systemd units, and selected recently modified files. No successful SSH authentication was identified in the reviewed records for the incident date. No suspicious artifacts or persistence mechanisms were identified in the reviewed locations.

However, `auditd` was inactive, and `auditctl` was unavailable. The investigation was based on selected logs, queries, and host paths rather than a complete forensic acquisition.

**Conclusion:** The evidence supports an incident involving repeated, likely automated SSH password-guessing attempts against an Azure-hosted Ubuntu VM exposed to broad inbound SSH access. No successful SSH access or persistence was identified in the reviewed evidence. The available findings do not establish that the host was compromised, but they also do not prove that compromise was impossible.

### Key Findings

- **212** failed SSH password-authentication events were identified in Azure Sentinel for October 3, 2026.
- **5** source IP addresses were identified in the incident-day query results.
- Inbound TCP/22 was allowed from `Any` in the Azure NSG during the FTP lab.
- Effective SSH settings included `PasswordAuthentication yes`, `PermitRootLogin without-password`, `MaxAuthTries 6`, and `LoginGraceTime 120`.
- No successful SSH authentication was identified in the reviewed Sentinel and local authentication records for October 3, 2026.
- SSH access was restricted to the investigator's public IP after the activity was noticed.
- No suspicious artifacts were identified in the reviewed temporary directories, account-modification logs, cron configuration, systemd persistence locations, or selected recently modified files.
- `auditd` was inactive, and `auditctl` was not available.
- VirusTotal later reported security-vendor detections for all five source IP addresses.

---

## 2. Incident Overview

### 2.1 Environment

| Attribute                   | Value                             |
| --------------------------- | --------------------------------- |
| Cloud provider              | Microsoft Azure                   |
| Operating system            | Ubuntu                            |
| Hostname                    | `FILE01`                          |
| Relevant user account       | `Neo`                             |
| Service under investigation | OpenSSH server (`sshd`)           |
| Relevant network port       | TCP/22                            |
| Initial network exposure    | Inbound TCP/22 allowed from `Any` |
| Log analytics platform      | Azure Sentinel / Log Analytics    |
| Relevant table              | `Syslog`                          |
| Incident date               | October 3, 2026                   |

### 2.2 Context

The SSH activity was discovered while the investigator was conducting an FTP lab. The Azure NSG permitted inbound TCP/22 from `Any` during the lab.

This configuration allowed sources beyond the investigator's own IP to attempt to reach the SSH service, subject to the remaining network path, public IP configuration, routing, and host firewall rules.

The investigator reports that the NSG rule was changed immediately after the attempts were noticed, restricting SSH access to their own public IP.

### 2.3 Scope

The primary incident window covered:

`2026-10-03 00:00:00 UTC` through `2026-10-03 23:59:59 UTC`

The investigation also reviewed historical failed-login records and host configuration after the incident.

The following data sets are kept separate throughout this report:

1. Azure Sentinel failed-password events for October 3, 2026.
2. Historical failed-login activity found in `btmp`, including activity from other dates.
3. VirusTotal reputation results collected after the incident was noticed.

Historical `btmp` entries are not included in the count of 212 Sentinel events.

---

## 3. Incident Timeline

| Time / Period                                       | Event                                                                                                                                      | Evidence                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| Before detection                                    | Inbound TCP/22 was allowed from `Any` in the Azure NSG during the FTP lab.                                                                 | Investigator-provided configuration context |
| October 3, 2026, 11:04 UTC                          | Failed SSH attempts were observed from `77.239.124.202` and `2.57.122.238`.                                                                | Sentinel query results                      |
| October 3, 2026, 12:11–12:16 UTC                    | 81 failed password events were observed from `178.128.57.150`.                                                                             | Sentinel query results                      |
| October 3, 2026, 12:34–12:42 UTC                    | 41 failed password events were observed from `103.174.114.111`.                                                                            | Sentinel query results                      |
| October 3, 2026, 12:42–12:50 UTC                    | 82 failed password events were observed from `162.14.107.96`.                                                                              | Sentinel query results                      |
| Immediately after detection; exact time unavailable | The investigator changed the NSG rule to restrict SSH access to their own public IP.                                                       | Investigator statement                      |
| After detection; exact date unavailable             | The five source IP addresses were checked in VirusTotal.                                                                                   | Investigator-provided results               |
| During subsequent investigation                     | SSH logs, failed-login records, account changes, temporary directories, cron, systemd, and selected recently modified files were reviewed. | Investigator-provided investigation results |

**Time-zone note:** The Sentinel results were displayed in UTC+00:00. The exact timestamp of the NSG change was not recorded in the supplied evidence.

---

## 4. SSH Authentication Analysis

### 4.1 Failed Password Events by Source IP

The following results were returned by the Azure Sentinel query for October 3, 2026.

| Source IP         | Failed Password Events | First Observed (UTC) | Last Observed (UTC) |
| ----------------- | ---------------------: | -------------------- | ------------------- |
| `162.14.107.96`   |                     82 | 12:42:52.378         | 12:50:49.751        |
| `178.128.57.150`  |                     81 | 12:11:28.569         | 12:16:51.903        |
| `103.174.114.111` |                     41 | 12:34:19.280         | 12:42:08.324        |
| `77.239.124.202`  |                      7 | 11:04:24.716         | 11:04:26.189        |
| `2.57.122.238`    |                      1 | 11:04:26.189         | 11:04:26.189        |
| **Total**         |                **212** |                      |                     |

The two highest-volume sources generated 163 of 212 events, approximately **76.9%** of the incident-day total. The three highest-volume sources generated 204 of 212 events.

Repeated failed authentication attempts against multiple usernames over short time intervals are consistent with automated SSH password guessing or opportunistic credential scanning.

The available logs do not identify a specific tool, operator, botnet, or relationship between the source IP addresses.

### 4.2 Username Targeting

The latest supplied username aggregation query reported the following counts:

| Source IP         | Failed Events | Distinct Usernames |
| ----------------- | ------------: | -----------------: |
| `162.14.107.96`   |            82 |                 43 |
| `178.128.57.150`  |            81 |                 42 |
| `103.174.114.111` |            41 |                 28 |
| `77.239.124.202`  |             7 |                  5 |
| `2.57.122.238`    |             1 |                  1 |

Observed usernames included common system and application accounts such as:

- `root`
- `ubuntu`
- `admin`
- `debian`
- `pi`
- `postgres`
- `mysql`
- `jenkins`
- `git`
- `ftp`
- `dev`
- `deploy`
- `test`

The wide range of candidate usernames is consistent with automated username enumeration or credential guessing.

The counts above use the latest supplied query output. Earlier informal counts differed slightly, so this report does not combine results from different query versions.

### 4.3 Representative Log Messages

The investigator supplied SSH log excerpts containing messages such as:

- `Invalid user ...`
- `Failed password for invalid user ...`
- `authentication failure`
- `Connection closed by invalid user ... [preauth]`
- `Failed password for root`
- `Connection closed by authenticating user root ... [preauth]`

These messages indicate failed authentication attempts and connection closure before authentication completed.

The supplied excerpts did not show a successful login.

### 4.4 KQL: Failed Password Events by Source IP

```kusto
Syslog
| where TimeGenerated between (
    datetime(2026-10-03 00:00:00) ..
    datetime(2026-10-03 23:59:59)
)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| extend SourceIP = extract(
    @"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
    1,
    SyslogMessage
)
| where isnotempty(SourceIP)
| summarize
    FailedPasswords = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP
| order by FailedPasswords desc
```

### 4.5 KQL: Username Aggregation by Source IP

```kusto
Syslog
| where TimeGenerated between (
    datetime(2026-10-03 00:00:00) ..
    datetime(2026-10-03 23:59:59)
)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| extend SourceIP = extract(
    @"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
    1,
    SyslogMessage
)
| extend User = extract(
    @"Failed password for (?:invalid user )?([A-Za-z0-9._-]+)",
    1,
    SyslogMessage
)
| where isnotempty(SourceIP)
| where isnotempty(User)
| summarize
    FailedPasswords = count(),
    UniqueUsers = dcount(User),
    TargetedUsers = make_set(User, 100),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP
| order by FailedPasswords desc
```

### 4.6 Successful SSH Authentication Check

The following query was used to search for successful SSH authentication messages:

```kusto
Syslog
| where TimeGenerated between (
    datetime(2026-10-03 00:00:00) ..
    datetime(2026-10-03 23:59:59)
)
| where ProcessName == "sshd"
| where SyslogMessage has_any (
    "Accepted password",
    "Accepted publickey",
    "Accepted keyboard-interactive"
)
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated asc
```

The investigator reported no successful SSH login in the reviewed Sentinel results.

Local checks of `/var/log/auth.log` and the SSH journal also returned no successful authentication entries for the reviewed date.

**Assessment:** No successful SSH authentication was identified in the reviewed sources for October 3, 2026. This finding is limited to the logs, time window, and search criteria reviewed. It does not rule out every possible access method or compromise at another time.

---

## 5. SSH Configuration and Root Cause Analysis

### 5.1 Effective SSH Runtime Settings

The investigator reported the following effective settings from `sshd -T`:

| Parameter                    | Value                           | Security Interpretation                                                                                       |
| ---------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `port`                       | `22`                            | SSH used the default port. A default port is not inherently vulnerable; exposure depends on network controls. |
| `passwordauthentication`     | `yes`                           | Password-based SSH authentication was enabled.                                                                |
| `permitrootlogin`            | `without-password`              | Root password authentication was disabled, while key-based root authentication could remain permitted.        |
| `maxauthtries`               | `6`                             | Limits authentication attempts per connection but does not prevent repeated attempts across many connections. |
| `logingracetime`             | `120`                           | Sets the authentication grace period in seconds.                                                              |
| `allowusers` / `allowgroups` | No restrictive value documented | The supplied evidence does not establish that an SSH account allowlist was configured.                        |

The reported effective configuration should be retained alongside the original command output if the report is used as a formal evidence package.

### 5.2 Primary Contributing Conditions

The primary contributing conditions were:

1. Inbound TCP/22 was permitted from `Any` in the Azure NSG during the FTP lab.
2. SSH password authentication was enabled.
3. SSH was therefore available for password-authentication attempts from sources allowed through the network path.

The evidence supports identifying broad network exposure and password authentication as the principal enabling conditions for the observed attempts.

### 5.3 Root Account Protection

`PermitRootLogin without-password` prevented direct root authentication using a password, but did not necessarily prohibit root authentication using a public key.

Therefore, it would be inaccurate to state that every possible root login attempt was guaranteed to fail regardless of authentication method.

The supplied incident-day events specifically show failed password attempts, and no successful SSH authentication was identified in the reviewed logs.

### 5.4 Containment and Residual Risk

After detecting the activity, the investigator changed the NSG rule to restrict SSH access to their own public IP.

The investigator reported no other broad TCP/22 allow rule, but did not independently review every effective NSG rule for overlapping or higher-priority permissions.

The SSH setting `PasswordAuthentication yes` remained enabled after the network restriction.

**Residual risk:** If the network rule is later broadened, password authentication remains available and can again be targeted by automated guessing.

---

## 6. Threat Intelligence and Indicators of Compromise (IOCs)

The five observed IP addresses were checked in VirusTotal after the incident was detected. The values below are the detection counts supplied by the investigator.

| IP Address        | VirusTotal Detections | Reported Network / ASN                                                        |
| ----------------- | --------------------: | ----------------------------------------------------------------------------- |
| `162.14.107.96`   |                  2/92 | `162.14.64.0/18`; AS45090 — Shenzhen Tencent Computer Systems Company Limited |
| `178.128.57.150`  |                  5/92 | `178.128.0.0/16`; AS14061 — DigitalOcean, LLC                                 |
| `103.174.114.111` |                  1/92 | `103.174.114.0/23`; AS136052 — PT Cloud Hosting Indonesia                     |
| `77.239.124.202`  |                  9/92 | `77.239.124.0/24`; AS198364 — Banatsync Srl                                   |
| `2.57.122.238`    |                 15/92 | `2.57.122.0/24`; AS47890 — Unmanaged Ltd                                      |

### 6.1 Interpretation

All five IP addresses had at least one VirusTotal security-vendor detection at the time of the later check.

The highest supplied detection count was **15/92 for `2.57.122.238`**, although this address was associated with only one failed password event in the Sentinel results for October 3, 2026.

VirusTotal reputation results are supporting threat-intelligence context. They can change over time and may differ between vendors. They do not independently prove that every connection from an IP address is malicious, identify the responsible actor, or establish that the IP addresses share a common operator.

The exact VirusTotal check date and direct report URLs were not supplied.

### 6.2 Historical Failed-Login Activity

The investigator also reviewed `lastb -ai` output, which contained failed-login activity from dates other than October 3, 2026. Historical entries included previous attempts associated with `77.239.124.202` and `2.57.122.238`, as well as other addresses.

Some historical output contained hundreds of failures from other IPs, including addresses within `77.239.124.0/24`.

These historical entries are **not included in the 212-event Sentinel total for October 3**.

IP addresses sharing a subnet do not, by themselves, establish common ownership, a botnet, or a common operator. A subnet-wide block should be based on operational requirements and additional evidence, not IP similarity alone.

---

## 7. Host-Based Investigation

The investigator performed a scoped review of SSH keys, temporary directories, account changes, cron configuration, systemd services, and recently modified files.

### 7.1 SSH Authorized Keys

Reviewed files:

- `/home/Neo/.ssh/authorized_keys`
- `/root/.ssh/authorized_keys`

Both files were reported as **0 bytes** and created on September 30, 2026, before the incident date.

No unauthorized key entry was identified in these two files.

This finding is limited to the files reviewed and does not establish that no other account or SSH key location existed.

### 7.2 Temporary and Staging Directories

Reviewed locations:

- `/tmp`
- `/var/tmp`
- `/dev/shm`

No suspicious payloads, scripts, or shell artifacts were identified in the reviewed directory listings.

The observed entries were reported as standard systemd-private directories, system IPC sockets, `snap-private-tmp`, cloud-init-related entries, and `PipelineAgentDebugOutput`.

`/dev/shm` was reported empty.

**Assessment:** No suspicious artifacts were identified in the reviewed temporary directories.

### 7.3 Account and Privilege Changes

The investigator searched local authentication logs for account and group administration events, including:

- `useradd`
- `usermod`
- `userdel`
- `passwd`
- `groupadd`
- `gpasswd`

No unexpected account or group modifications were reported in the reviewed logs.

This conclusion is limited to the available logs and the search terms used.

### 7.4 Cron Persistence

The investigator reviewed the user crontab and standard system cron directories, including:

- `/etc/cron.d`
- `/etc/cron.daily`
- `/etc/cron.hourly`
- `/etc/cron.weekly`
- `/etc/cron.monthly`

The observed entries were reported as standard Ubuntu maintenance tasks, including `e2scrub_all`, `sysstat`, `apport`, `apt-compat`, `dpkg`, `logrotate`, and `man-db`.

A search for suspicious command patterns, including `curl`, `wget`, `nc`, `bash -i`, `/dev/tcp`, `base64`, `python`, and `perl`, did not identify suspicious cron activity in the reviewed results.

### 7.5 systemd Persistence

The investigator reviewed enabled unit files, failed units, and files under `/etc/systemd/system`.

The following custom units were reported as Azure monitoring or metrics services:

- `azuremonitor-coreagent.service`
- `azuremonitoragent.service`
- `metrics-extension.service`

The Azure Monitor-related files were reported as created around September 30, 2026, during agent deployment. `metrics-extension.service` was reported as created on October 10, 2026.

No suspicious systemd persistence was identified in the reviewed results. A non-critical `fwupd-refresh.service` failure was considered a benign OS or firmware-metadata issue by the investigator.

The service names and timestamps alone do not independently establish provenance. In particular, the origin of `metrics-extension.service` was not independently validated against an Azure VM extension inventory in the supplied evidence.

### 7.6 Recently Modified Files

The investigator reviewed recently modified files in selected paths:

- `/etc`
- `/usr/local/bin`
- `/usr/local/sbin`
- `/opt`
- `/var/www`
- `/home`
- `/root`

The observed changes were categorized as follows.

**Azure Monitor Agent files**

Files and configuration under `/opt/microsoft/azuremonitoragent` and `/etc/opt/microsoft` were attributed to Azure Monitor Agent deployment. Binaries included `amacoreagent`, `MetricsExtension`, `AstExtension`, and `agentlauncher`, reported as created around September 30, 2026. Some monitoring files were refreshed on October 10.

**System package updates**

Changes around October 3, 2026, 11:43–11:45 UTC included `/etc/xml` files and `/etc/ld.so.cache`, attributed by the investigator to system package updates involving `polkit` and XML-related packages.

**User history and SSH files**

Files under `/home/Neo` and `/root` included the empty `authorized_keys` files and `.bash_history` / `.lesshst` files updated during administrative work.

**Cloud-init configuration**

`/etc/fstab` and `/etc/netplan/50-cloud-init.yaml` were reported as updated on October 10, 2026, as part of standard cloud-init networking or mount configuration.

No unauthorized binary drop, web shell, or suspicious configuration change was identified in the selected paths.

This was a scoped review and not a complete forensic examination of the entire filesystem.

### 7.7 Processes and Network Listeners

The investigation notes list checks of active processes (`ps auxf` or `ps -ef --forest`) and listening sockets (`ss -lntup`).

The investigator's summary described listeners for SSH (TCP/22), FTP (`vsftpd`, TCP/21), and Azure Monitor Agent-related services as legitimate. No specific suspicious process finding was provided in the final evidence summary.

Because raw command output was not supplied, these are recorded as investigator-reported observations rather than independently validated output.

The presence of `vsftpd` on TCP/21 is relevant to the FTP lab's attack surface and should be assessed separately for external exposure and necessity.

### 7.8 Audit Subsystem

The following commands were executed:

```bash
systemctl is-active auditd
# inactive

sudo auditctl -s
# sudo: auditctl: command not found
```

`auditd` was inactive, and `auditctl` was unavailable.

Consequently, Linux Audit status, rules, and records could not be used as a source of corroborating evidence in the supplied investigation.

This is a visibility limitation and is not, by itself, evidence of compromise.

---

## 8. Containment and Response

### 8.1 Completed Action

After noticing the failed SSH attempts, the investigator reports changing the Azure NSG rule so that inbound SSH access was restricted to their own public IP address.

### 8.2 Actions Not Reported as Completed

- SSH password authentication remained enabled (`PasswordAuthentication yes`).
- A complete independent review of all effective NSG rules was not provided.
- No installation or activation of `auditd` was reported.
- The exact timestamp of the NSG change was not recorded.

### 8.3 Containment Assessment

Restricting TCP/22 at the NSG to a known administrative IP is a meaningful network-layer containment measure.

However, because the exact change time and a full effective-rule review were not available, this report does not claim a measured containment interval or independently verified exclusivity of SSH access.

The report also does not claim that password authentication was disabled, because it remained enabled after containment.

---

## 9. Findings and Assessment

| Finding                                                                  | Assessment                                             |
| ------------------------------------------------------------------------ | ------------------------------------------------------ |
| Repeated SSH password failures from five external IPs on October 3, 2026 | Confirmed in reviewed Sentinel query results           |
| Broad username targeting                                                 | Confirmed in username aggregation results              |
| SSH password authentication enabled                                      | Reported from `sshd -T` output                         |
| Inbound TCP/22 allowed from `Any` before detection                       | Reported by investigator for the lab configuration     |
| Successful SSH authentication on the incident date                       | Not identified in the reviewed logs                    |
| Suspicious artifacts in reviewed temporary directories                   | Not identified                                         |
| Unexpected account modifications in reviewed log search                  | Not identified                                         |
| Suspicious cron/systemd persistence in reviewed locations                | Not identified; scope and provenance limitations apply |
| VirusTotal detections for all five source IPs                            | Reported by investigator; checked after the incident   |
| `auditd` active and providing audit evidence                             | No — reported inactive; `auditctl` unavailable         |
| Confirmed host compromise                                                | Not established by the evidence reviewed               |
| Absolute absence of compromise                                           | Cannot be established from the supplied evidence       |

### Overall Conclusion

The evidence supports an incident involving repeated, likely automated SSH password-guessing attempts against an Azure-hosted Ubuntu VM that was reachable on TCP/22 from broad sources during an FTP lab.

The investigator subsequently restricted SSH access to their own public IP address.

No successful SSH authentication was identified in the reviewed logs for October 3, 2026. The scoped host checks did not identify suspicious artifacts or persistence mechanisms.

Accordingly, **no compromise was demonstrated by the reviewed evidence**.

Because `auditd` was unavailable, the checks were scoped, and not all possible access paths or forensic artifacts were exhaustively examined, the appropriate conclusion is not “confirmed clean” or “no compromise possible.” It is:

> **No evidence of successful SSH access or persistence was identified in the sources reviewed. The available evidence does not establish a successful compromise, but cannot conclusively exclude all forms of compromise.**

---

## 10. Recommendations

### Priority 1 — Maintain Least-Privilege Network Access

- Keep inbound SSH restricted to a trusted administrative IP, approved VPN, or jump-host range.
- Review all effective Azure NSG rules for TCP/22, including priorities and overlapping permissions.
- Avoid `Any` / `0.0.0.0/0` for administrative SSH access unless there is a documented, temporary requirement.
- Remove temporary lab rules when the exercise is complete.
- Confirm whether the VM's public IP and routing expose SSH beyond the intended administrative sources.

### Priority 2 — Harden SSH Authentication

- Prefer public-key authentication, with passphrases and a managed key lifecycle where appropriate.
- After confirming that key-based access works, consider setting `PasswordAuthentication no`.
- Keep root password login disabled.
- Consider `PermitRootLogin no` if direct root SSH access is not operationally required.
- Consider `AllowUsers` or `AllowGroups` to limit the permitted account set, where compatible with the environment.
- Keep OpenSSH and the operating system patched.
- Consider rate-limiting or an appropriate intrusion-prevention control where suitable. These controls should supplement, not replace, network restrictions and strong authentication.

### Priority 3 — Improve Audit Coverage

- Evaluate enabling and configuring `auditd` if appropriate for the VM's operational requirements.
- Ensure SSH authentication logs and relevant system logs are retained centrally with an appropriate retention period.
- Create alerts for repeated SSH failures, bursts across multiple usernames, and successful authentication following repeated failures.
- Record timestamps for containment actions and preserve relevant Azure NSG configuration history where possible.

### Priority 4 — Review Exposed Services

- Confirm whether `vsftpd` on TCP/21 was required for the lab.
- Verify that FTP exposure was restricted to intended sources.
- Disable services and close ports when the lab no longer requires them.
- Review Azure monitoring and extension services against the expected Azure VM extension inventory when service provenance is uncertain.

### Priority 5 — Preserve Evidence and Document IOC Context

- Preserve relevant Sentinel query results, raw SSH log excerpts, NSG rule details, and timestamps.
- If VirusTotal results are included in a public report, add the report URLs and the date/time of the check.
- Record that reputation results can change over time.
- Do not attribute the activity to a particular botnet or operator based only on IP reputation, ASN, or subnet membership.

---

## Appendix A — Investigation Commands

### A.1 SSH Runtime Configuration

```bash
sudo sshd -T | egrep \
'port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|logingracetime|allowusers|allowgroups'
```

### A.2 Successful SSH Authentication in Local Logs

```bash
sudo grep -a '2026-10-03' /var/log/auth.log \
  | grep -E 'Accepted password|Accepted publickey'

sudo journalctl -u ssh \
  --since '2026-10-03 00:00:00' \
  --until '2026-10-03 23:59:59' \
  --no-pager | grep -i 'accepted'
```

### A.3 SSH Failures in Local Authentication Logs

```bash
sudo grep -a '2026-10-03' /var/log/auth.log \
  | grep -E 'sshd|Failed password|Invalid user|authentication failure'
```

### A.4 Failed Login History

```bash
lastb -ai | head -1000
```

`lastb` reads the failed-login database and may include activity from dates other than the incident date. Filter and corroborate timestamps before attributing historical entries to a specific incident.

### A.5 Account and Group Modification Search

```bash
sudo grep -a -E \
'useradd|usermod|userdel|passwd|groupadd|gpasswd' \
/var/log/auth.log
```

### A.6 Cron Review

```bash
sudo crontab -l

sudo ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly \
  /etc/cron.weekly /etc/cron.monthly

sudo grep -R -nE \
'curl|wget|bash -c|sh -c|nc |python|perl|base64' \
/etc/cron* 2>/dev/null
```

### A.7 systemd Review

```bash
systemctl list-unit-files --state=enabled
systemctl --failed
sudo find /etc/systemd/system -maxdepth 3 -type f -ls
```

### A.8 Recent File Review

```bash
sudo find /etc /usr/local/bin /usr/local/sbin /opt /var/www \
  /home /root -xdev -type f -mtime -14 -ls 2>/dev/null
```

### A.9 Audit Subsystem Status

```bash
systemctl is-active auditd
sudo auditctl -s
```

---

## Appendix B — Evidence Handling Notes

- The count of **212** refers to failed password events matching the supplied Sentinel query for **October 3, 2026, UTC**.
- Historical `lastb` results include failed-login records from other dates and are not included in the 212-event total.
- VirusTotal detection counts are investigator-provided results from a later check. The check date and direct report URLs were not supplied.
- Some checks were described by the investigator without raw command output. Those findings are explicitly presented as investigator-reported observations.
- No disk image, memory image, complete filesystem acquisition, or complete independent Azure network configuration export was supplied for this report.
- The report does not establish attribution to a specific actor, botnet, or organization.

---

## Appendix C — Suggested GitHub Repository Placement

**Suggested filename:** `DFIR-Incident-Report.md`

Suggested repository structure:

```text
repository/
├── README.md
└── DFIR-Incident-Report.md
```

The repository `README.md` can provide a short project overview and link to the full report.

This report retains the hostname, username, and public IP addresses supplied by the investigator. Before public publication, review whether raw logs, cloud configuration details, IP addresses, usernames, or other environment identifiers should remain visible.
