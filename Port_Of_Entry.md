
<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/09b44f4a-1670-4804-8009-5287751e7e8d" />

# 🕵️‍♀️ Threat Hunt Report: **Port of Entry**
INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社 
<br>
SITUATION: Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.
<br>
COMPANY: Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia
<br>
EVIDENCE AVAILABLE: Microsoft Defender for Endpoint logs
<br>
Analyst: Fe Esguerra
<br>
Environment Investigated: 
Azure Logs via Microsoft Defender
<br>
Timeframe: 11/20/2025
<br>
## 🧠 Scenario Overview

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

---


## Chronological Timeline of Compromise

All events occurred on host **azuki-sl** on **November 20, 2025** (timestamps approximate in UTC/local as shown in logs; primary activity between ~01:37 AM and ~02:11 AM).

| **Time (approx.)**       | **Flag** | **Action Observed**                          | **Key Evidence**                                                                 |
|--------------------------|----------|----------------------------------------------|----------------------------------------------------------------------------------|
| 2025-11-20 01:37 AM      | Flag 18  | Execution - Malicious Script                 | PowerShell script wupdate.ps1 executed to initiate attack chain                  |
| 2025-11-20 01:37 AM      | Flag 10  | Command & Control - Initial Beacon           | Outbound connection from malicious process (svchost.exe) to C2 IP 78.141.196.6 on port 443 |
| 2025-11-20 ~02:05 AM     | Flag 4   | Defense Evasion - Malware Staging Directory  | Creation of hidden directory C:\ProgramData\WindowsCache                         |
| 2025-11-20 02:06 AM      | Flag 7   | Defense Evasion - Download Utility Abuse     | certutil.exe used to download malicious payload                                  |
| 2025-11-20 02:07 AM      | Flag 12  | Credential Access - Credential Theft Tool    | Download and staging of renamed Mimikatz executable mm.exe                       |
| 2025-11-20 02:07 AM      | Flag 8   | Persistence - Scheduled Task Creation        | Scheduled task "Windows Update Check" created                                    |
| 2025-11-20 02:07 AM      | Flag 9   | Persistence - Scheduled Task Target          | Task configured to execute C:\ProgramData\WindowsCache\svchost.exe               |
| 2025-11-20 02:08 AM      | Flag 13  | Credential Access - Memory Extraction        | mm.exe executed with "privilege::debug sekurlsa::logonpasswords exit"            |
| 2025-11-20 ~02:08 AM     | Flag 14  | Collection - Data Staging Archive            | Creation of export-data.zip (and other .zip files like VMAgentLogs.zip) in staging directory |
| 2025-11-20 02:09 AM      | Flag 15  | Exfiltration - Exfiltration Channel          | curl.exe used to upload export-data.zip via HTTPS to Discord                     |
| 2025-11-20 02:10 AM      | Flag 19  | Lateral Movement - Secondary Target          | RDP connection attempted to internal IP 10.1.0.188                               |
| 2025-11-20 02:10 AM      | Flag 20  | Lateral Movement - Remote Access Tool        | mstsc.exe launched for remote desktop to 10.1.0.188                              |
| 2025-11-20 02:11 AM      | Flag 16  | Anti-Forensics - Log Tampering               | wevtutil.exe used to clear Security log (and possibly others)                    |
| 2025-11-20 (post-activity)| Flag 17 | Impact - Persistence Account                 | Hidden local administrator account "support" created and added to Administrators group |
| 2025-11-18 to 2025-11-21 | Flag 1   | Initial Access - Remote Access Source        | RDP connection from external IP 88.97.178.12                                     |
| 2025-11-18 to 2025-11-21 | Flag 2   | Initial Access - Compromised User Account    | Successful logon using account kenji.sato                                        |
| 2025-11-19 to 2025-11-21 | Flag 3   | Discovery - Network Reconnaissance           | arp -a executed to enumerate local network                                       |
| 2025-11-19 to 2025-11-21 | Flag 5   | Defense Evasion - File Extension Exclusions  | 3 file extensions added to Windows Defender exclusions                           |
| 2025-11-19 to 2025-11-21 | Flag 6   | Defense Evasion - Temporary Folder Exclusion | Exclusion added for Temp folder                                                  |
| 2025-11-19 to 2025-11-21 | Flag 11  | Command & Control - C2 Communication Port     | Persistent C2 traffic over port 443                                              |

**Notes:**
- One of my first threat hunts, and I didn't record the timestamps correctly.

### Starting Point – 
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
```

<img  alt="image" src="https://github.com/user-attachments/assets/32891371-965d-46a6-9699-eea4a0c0a5ed" />


**Identified System:**
azuki-sl 




### 🪪 Flag 1 – INITIAL ACCESS - Remote Access Source

**Objective:**
Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**What to Hunt:**
Query logon events for interactive sessions from external sources during the incident timeframe.

**Identified Activity:**
88.97.178.12 is the source IP address of the Remote Desktop Protocol Connection

**Why It Matters:**
The IP 88.97.178.12 is the external address the attacker used to connect via Remote Desktop Protocol (RDP). Pinpointing this source gives defenders a clear starting point: they can block the IP at the firewall, check threat intel to see if it’s linked to known actors or proxy services, and correlate it with other incidents. Knowing the exact entry vector speeds up containment and helps answer “who might be behind this?” (MITRE ATT&CK T1133 – External Remote Services).

**KQL Query Used:**
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
| where RemoteIP contains "."
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, AccountName,  RemoteIP, RemoteIPType, RemoteDeviceName
| order by Timestamp asc
```

<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/b006a8b5-c003-41a4-a9ee-db66e5c470e1" />



### 🛰️ Flag 2 – INITIAL ACCESS - Compromised User Account

**Objective:**
Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts, including password resets and privilege reviews.

**What to Hunt:**
Focus on the account that authenticated during the suspicious remote access session. Cross-reference the logon event timestamp with the external IP connection.

**Identified User Account:**
kenji.sato

**Why It Matters:**
The account kenji.sato was the valid credential the attacker used to log in successfully. This reveals the initial foothold: defenders can immediately disable or reset the account, investigate how the password was obtained (phishing, reuse from a breach, etc.), and check for similar compromises across the organization. Using legitimate accounts lets attackers blend in, making this a critical indicator of credential compromise (MITRE ATT&CK T1078 – Valid Accounts).

**KQL Query Used**
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-18) .. datetime(2025-11-21))
| where RemoteIP contains "."
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, AccountName,  RemoteIP, RemoteIPType, RemoteDeviceName
| order by Timestamp asc
```
<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/b006a8b5-c003-41a4-a9ee-db66e5c470e1" />



### 📄 Flag 3 – DISCOVERY - Network Reconnaissance

**Objective:**
Look for commands that reveal local network devices and their hardware addresses.

**What to Hunt:**
Look for file access involving keywords like board, financial, or crypto — especially in user folders. Check DeviceProcessEvents for network enumeration utilities executed after initial access.

**Identified Command:**
"ARP.EXE" -a

**Why It Matters:**
Running arp -a maps out nearby devices on the local network, giving the attacker a picture of potential next targets. Spotting this early reconnaissance shows the attacker is actively exploring the environment and planning lateral movement, allowing defenders to anticipate and monitor those systems before deeper access occurs (MITRE ATT&CK T1018 – Remote System Discovery).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| project Timestamp, DeviceName, ProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1709" height="488" alt="image" src="https://github.com/user-attachments/assets/4e45bc92-671c-4907-a5ee-983ccb5d7a1e" />



### ⏱️ Flag 4 – DEFENCE EVASION - Malware Staging Directory

**Objective:**
Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**What to Hunt:**
Search for newly created directories in system folders that were subsequently hidden from normal view. Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.

**PRIMARY Staging Directory Found:**
C:\ProgramData\WindowsCache
Nov 20, 2025 2:05:30 AM

**Why It Matters:**
Creating C:\ProgramData\WindowsCache as a hidden staging folder lets the attacker store tools in a location that looks semi-legitimate and isn’t routinely checked. Identifying these non-standard directories reveals where payloads are hidden and helps build detection rules for unusual folder creation in system paths (MITRE ATT&CK T1564 – Hide Artifacts).


**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName contains "powershell"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath
```
<img width="1679" height="432" alt="image" src="https://github.com/user-attachments/assets/e837177c-b26f-438b-8964-ec650d543705" />




### ⚙️ Flag 5 – DEFENCE EVASION - File Extension Exclusions

**Objective:**
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**What to Hunt:**
Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extension. Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

**Identified File Extension Excluded:**
3
powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command "& {$OutputEncoding = [Console]::OutputEncoding =[System.Text.Encoding]::UTF8;$scriptFileStream = [System.IO.File]::Open('C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\8809.14144035.0.14144035-462fc402c4ea5c03148fd915012f3d7aee74f9d4\05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read);$calculatedHash = Microsoft.PowerShell.Utility\Get-FileHash 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\8809.14144035.0.14144035-462fc402c4ea5c03148fd915012f3d7aee74f9d4\05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1' -Algorithm SHA256;if (!($calculatedHash.Hash -eq '25fda4c27044455e664e8c26cdd2911117493a9122c002cd9462a9ce9c677f22')) { exit 323;}; . 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\8809.14144035.0.14144035-462fc402c4ea5c03148fd915012f3d7aee74f9d4\05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1' }"

**Why It Matters:**
Adding specific extensions to Windows Defender exclusions disables scanning for those file types, giving downloaded malware a safe landing zone. This change directly weakens endpoint protection and highlights why monitoring Defender configuration modifications is essential for catching evasion in progress (MITRE ATT&CK T1562.001 – Impair Defenses: Disable or Modify Tools).

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessParentFileName contains "sense"
```

<img width="1678" height="435" alt="image" src="https://github.com/user-attachments/assets/96a4dc36-c292-4b2b-a368-fbe8c7360c0e" />



### 💾 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion

**Objective:**
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**What to Hunt:**
Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field. Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field. The registry key contains "Exclusions\Paths" under Windows Defender configuration.

**Identified Temporary Folder:**

C:\Users\KENJI~1.SAT\AppData\Local\Temp

**Why It Matters:**
Excluding the Temp folder from scans allows temporary malicious files to execute without interference. This common tactic reduces detection risk for short-lived payloads and shows the need for alerts on exclusion changes, especially to high-write locations (MITRE ATT&CK T1562.001 – Impair Defenses).

**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where RegistryValueName contains "temp"
```

<img width="1677" height="402" alt="image" src="https://github.com/user-attachments/assets/b3839619-dc2a-40bd-9ea5-38632ba9fe5e" />




### 📎 Flag 7 – DEFENCE EVASION - Download Utility Abuse

**Objective:**
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**What to Hunt:**
Look for built-in Windows tools with network download capabilities being used during the attack. Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

**Identified Command**
certutil.exe
Nov 20, 2025 2:06:58 AM

**Why It Matters:**
Using certutil.exe—a built-in Windows tool—to download payloads avoids triggering alerts that third-party downloaders would cause. This living-off-the-land approach makes the activity look administrative, emphasizing why behavioral monitoring of native utilities is key (MITRE ATT&CK T1105 – Ingress Tool Transfer).

KQL Query Used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "//"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```

<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/1f681024-5ad3-4160-a844-addec2abee0b" />




### 🗂️ Flag 8 – Scheduled Task Name

**Objective:**
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**What to Hunt:**
Search for scheduled task creation commands executed during the attack timeline. Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

**Identified Scheduled Task:**
Windows Update Check
Nov 19, 2025 7:07:46 PM

**Why It Matters:**
The fake task “Windows Update Check” ensures the malware runs again after reboot or logon. Naming it to mimic legitimate updates helps it evade review; detecting these masquerading tasks lets defenders remove persistence quickly and improve monitoring of new scheduled tasks (MITRE ATT&CK T1053.005 – Scheduled Task).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "schtasks"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/c33f9a24-0087-42f4-b372-063cbd43736a" />




### 🗝️ Flag 9 – PERSISTENCE - Scheduled Task Target

**Objective:**
The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

**What to Hunt:**
Extract the task action from the scheduled task creation command line. Look for the /tr parameter value in the schtasks command.

**Identified Executable Path within Scheduled Task:**
C:\ProgramData\WindowsCache\svchost.exe
Nov 19, 2025 7:07:46 PM

**Why It Matters:**
This reveals the exact malicious executable (svchost.exe in a non-standard path) the task launches. Knowing the payload location enables precise cleanup and hunting for similar anomalous binaries across the environment (MITRE ATT&CK T1053.005 – Scheduled Task).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "schtasks"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```

<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/8b414d25-9d67-4eaa-89cc-ad828e0d2e49" />




### ⏰ Flag 10 – COMMAND & CONTROL - C2 Server Address

**Objective:**
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**What to Hunt:**
Analyse network connections initiated by the suspicious executable shortly after it was downloaded. Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.


**Why It Matters:**
The outbound connection to 78.141.196.6 on port 443 is the malware checking in with the attacker’s server. Blocking this IP/domain disrupts command flow and prevents further instructions or data theft, making it a high-priority indicator for network-level containment (MITRE ATT&CK T1071 – Application Layer Protocol).

**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where ActionType == "ConnectionSuccess"
| summarize NumberOfPorts = count() by RemotePort, ActionType, DeviceName
| order by NumberOfPorts 
```

<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/ae0a5944-674b-4e0c-ba47-f9683a1fa79f" />



### 🧭 Flag 11 – COMMAND & CONTROL - C2 Communication Port

**Objective:**
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**What to Hunt:**
Examine the destination port for outbound connections from the malicious executable. Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.

**Identified Destination Port:**
443

**Why It Matters:**
Traffic over port 443 blends malicious C2 with normal HTTPS, bypassing port-based blocks. Recognizing this pattern pushes defenses toward TLS inspection and behavioral anomaly detection rather than relying solely on firewalls (MITRE ATT&CK T1571 – Non-Standard Port / HTTPS blending).

**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where ActionType == "ConnectionSuccess"
| summarize NumberOfPorts = count() by RemotePort, ActionType, DeviceName
| order by NumberOfPorts 
```

<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/ae0a5944-674b-4e0c-ba47-f9683a1fa79f" />



### ⏱️ Flag 12 – CREDENTIAL ACCESS - Credential Theft Tool

**Objective:**
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**What to Hunt:**
Look for executables downloaded to the staging directory with very short filenames. Search for files created shortly before LSASS memory access events.

**Identified Executable:**
mm.exe
Nov 19, 2025 7:07:22 PM

**Why It Matters:**
Downloading a renamed Mimikatz (mm.exe) signals intent to dump credentials from memory. Catching the transfer early limits the window for password theft and prompts proactive credential rotation (MITRE ATT&CK T1003 – OS Credential Dumping).

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FolderPath contains "cache"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath
```
<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/08376383-17c7-447b-9568-3ab36e038ef8" />




### 📂 Flag 13 – CREDENTIAL ACCESS - Memory Extraction Module

**Objective:**
Reveal which specific document the attacker targeted on the second host.

**What to Hunt:**
Examine the command line arguments passed to the credential dumping tool. Look for module::command syntax in the process command line or output redirection.

**Identified Permissions:**

"mm.exe" privilege::debug sekurlsa::logonpasswords exit

Nov 19, 2025 7:08:26 PM

**Why It Matters:**
The specific Mimikatz arguments (sekurlsa::logonpasswords) confirm successful extraction of clear-text credentials from LSASS. This evidence drives immediate enterprise-wide password resets and evaluation of protections like Credential Guard (MITRE ATT&CK T1003.001 – LSASS Memory).

**KQL Queries Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where FileName contains "mm.exe"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession

```
<img width="1739" height="382" alt="image" src="https://github.com/user-attachments/assets/ecbe602a-4201-4419-8adf-00db6b07590c" />





### ☁️ Flag 14 – COLLECTION - Data Staging Archive

**Objective:**
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**What to Hunt:**
Search for ZIP file creation in the staging directory during the collection phase. Look for Compress-Archive commands or examine files created before exfiltration activity.

**Compressed archives for Data Exfiltration:**
export-data.zip

**Why It Matters:**

Creating zip archives (e.g., export-data.zip) organizes stolen files for efficient exfiltration. Identifying these staging files reveals exactly what data was targeted and helps assess business impact or regulatory exposure (MITRE ATT&CK T1560 – Archive Collected Data).

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FileName contains ".zip"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath
| order by FileName
```

<img width="1096" height="161" alt="image" src="https://github.com/user-attachments/assets/3762cf08-5831-494d-9626-a9024ab7051f" />



### 🌐 Flag 15 – EXFILTRATION - Exfiltration Channel

**Objective:**
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**What to Hunt:**
Analyse outbound HTTPS connections and file upload operations during the exfiltration phase. Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

**Cloud Service:**
discord
Nov 19, 2025 7:09:21 PM

**Why It Matters:**
Uploading data via Discord abuses a trusted consumer service to move stolen files out undetected. This highlights the growing challenge of detecting exfiltration over allowed platforms and the value of DLP controls on cloud collaboration tools (MITRE ATT&CK T1567 – Exfiltration Over Web Service).

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where FileName contains ".zip"
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath
| order by FileName
```

<img width="1096" height="161" alt="image" src="https://github.com/user-attachments/assets/3762cf08-5831-494d-9626-a9024ab7051f" />

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contatins "curl"
```

<img width="1096" height="161" alt="image" src="https://github.com/user-attachments/assets/4e758e57-34bc-4dd2-accc-f2c32f8af6ef" />




### 🧬 Flag 16 – ANTI-FORENSICS - Log Tampering

**Objective:**
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**What to Hunt:**
Search for event log clearing commands near the end of the attack timeline. Look for wevtutil.exe executions and identify which log was cleared first.

**Cleared Windows Event Log:**
Security
Nov 19, 2025 7:11:46 PM

**Why It Matters:**
Clearing the Security log first removes evidence of authentication and privilege use. This sophisticated cover-up tactic underscores the need to forward logs to a central protected SIEM in real time (MITRE ATT&CK T1070.001 – Clear Windows Event Logs).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "wev"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1641" height="358" alt="image" src="https://github.com/user-attachments/assets/d1247291-df42-4050-b84e-5aa368da7088" />



### 🧹 Flag 17 – IMPACT - Persistence Account

**Objective:**
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**What to Hunt:**
Search for account creation commands executed during the impact phase. Look for commands with the /add parameter followed by administrator group additions.

**Hidden Username:**
support

**Why It Matters:**
Adding a hidden local admin account (“support”) creates a long-term backdoor. Discovering these planted accounts allows immediate removal and strengthens controls around local account creation and monitoring (MITRE ATT&CK T1098 – Account Manipulation).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "add"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1678" height="358" alt="image" src="https://github.com/user-attachments/assets/628c302d-3d98-4158-9df1-655026b34832" />




---

### 🧹 Flag 18 – EXECUTION - Malicious Script

**Objective:**
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**What to Hunt:**
Search DeviceFileEvents for script files created in temporary directories during the initial compromise phase. Look for PowerShell or batch script files downloaded from external sources shortly after initial access.

**Found PowerShell Script to Start Attack Chain:**
Nov 19, 2025 7:09:48 PM
wupdate.ps1

**Why It Matters:**
The PowerShell script wupdate.ps1 automated most of the attack chain from the start. Analyzing it reveals the attacker’s full playbook and tooling, aiding threat intelligence and future detection signatures (MITRE ATT&CK T1059.001 – PowerShell).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "add"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1678" height="358" alt="image" src="https://github.com/user-attachments/assets/190fffcd-d666-423e-9505-eba6c1d07ebe" />


---

### 🧹 Flag 19 – LATERAL MOVEMENT - Secondary Target

**Objective:**
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**What to Hunt:**
Examine the target system specified in remote access commands during lateral movement.Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.
**IP Address Target:**
10.1.0.188

Nov 19, 2025 7:10:41 PM

**Why It Matters:**
Targeting IP 10.1.0.188 shows the attacker’s next objective—likely a system with higher privileges or sensitive data. Mapping intended movement paths helps defenders prioritize protection and isolation of critical assets (MITRE ATT&CK T1021 – Remote Services).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "mstsc"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1670" height="384" alt="image" src="https://github.com/user-attachments/assets/287d224c-49e8-419a-952b-9b8835205f0e" />


---

### 🧹 Flag 20 – LATERAL MOVEMENT - Remote Access Tool

**Objective:**
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.
**What to Hunt:**
Search for remote desktop connection utilities executed near the end of the attack timeline. Look for processes launched with remote system names or IP addresses as arguments.
**Remote Access Tool:**
mstsc.exe
Nov 19, 2025 7:10:41 PM

**Why It Matters:**
Using native mstsc.exe for RDP to the next target makes the activity look like legitimate administration. This blending is why restricting and logging internal RDP use, plus network segmentation, are key defenses (MITRE ATT&CK T1021.001 – Remote Desktop Protocol).

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (startofday(datetime(2025-11-19)) .. endofday(datetime(2025-11-21)))
| where ProcessCommandLine contains "mstsc"
| project Timestamp, FileName, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, AccountName, IsProcessRemoteSession
```
<img width="1699" height="388" alt="image" src="https://github.com/user-attachments/assets/6d493c7b-b1c3-46ff-a7dd-ae073f0dedaa" />



---

### Intrusion Narrative Chain

0 ➝ 1 🚩: Initial access often starts with remote services exposed to the internet. **Was RDP used from an external source to gain entry?**  
*(Yes – successful RDP connection originated from external IP 88.97.178.12, establishing the initial foothold.)*

1 ➝ 2 🚩: Once connected remotely, attackers rely on valid credentials to authenticate. **Was a legitimate user account compromised to complete the logon?**  
*(Yes – the account kenji.sato was used for authentication, allowing the attacker to operate as a legitimate user.)*

2 ➝ 3 🚩: With access secured, early discovery focuses on mapping the local network. **Did the attacker enumerate nearby systems to identify potential targets?**  
*(Yes – arp -a was executed to discover devices on the local segment, revealing the network layout.)*

3 ➝ 4 🚩: To avoid detection, attackers create non-obvious locations for their tools. **Was a hidden staging directory established for malware and payloads?**  
*(Yes – C:\ProgramData\WindowsCache was created as a concealed directory for storing malicious files.)*

4 ➝ 5 🚝: Weakening endpoint protection improves survival odds. **Were specific file extensions excluded from Windows Defender scanning?**  
*(Yes – three extensions were added to Defender exclusions, preventing scans of attacker-chosen file types.)*

5 ➝ 6 🚩: Further evasion involves protecting high-activity folders. **Was the temporary folder excluded from real-time protection?**  
*(Yes – the Temp folder path was added to exclusions, creating a safe space for transient payloads.)*

6 ➝ 7 🚩: Attackers frequently abuse built-in utilities to pull down additional tools. **Was certutil used to download malicious payloads?**  
*(Yes – certutil.exe was leveraged to fetch external files while appearing administrative.)*

7 ➝ 8 🚩: Persistence ensures access survives reboots. **Was a scheduled task created under a deceptive name?**  
*(Yes – a task named “Windows Update Check” was registered to maintain access.)*

8 ➝ 9 🚩: The task needs a target to execute. **Did the scheduled task point to a malicious binary in the staging directory?**  
*(Yes – the task was configured to run svchost.exe from the hidden WindowsCache folder.)*

9 ➝ 10 🚩: After landing, implants typically reach out to attacker infrastructure. **Did the malware send an initial beacon to a command-and-control server?**  
*(Yes – outbound connection established to 78.141.196.6 on port 443, confirming C2 communication.)*

10 ➝ 11 🚩: Blending C2 traffic with legitimate protocols evades network filters. **Was port 443 used to mask command-and-control activity?**  
*(Yes – all C2 traffic flowed over HTTPS on port 443, indistinguishable from normal web traffic at the port level.)*

11 ➝ 12 🚩: With a foothold and C2, attackers move to credential theft. **Was a known credential-dumping tool transferred to the host?**  
*(Yes – a renamed Mimikatz binary mm.exe was downloaded and staged.)*

12 ➝ 13 🚩: The tool is only useful when executed with specific modules. **Were LSASS memory extraction commands run to harvest credentials?**  
*(Yes – mm.exe executed privilege::debug and sekurlsa::logonpasswords, successfully dumping credentials.)*

13 ➝ 14 🚩: Stolen data must be organized before exfiltration. **Was collected information compressed into an archive for easier transfer?**  
*(Yes – export-data.zip and similar archives were created in the staging directory containing recon output.)*

14 ➝ 15 🚩: Attackers increasingly abuse trusted platforms for data theft. **Was a consumer cloud service used as the exfiltration channel?**  
*(Yes – curl.exe uploaded the archive to Discord, leveraging a legitimate service to move data out.)*

15 ➝ 16 🚩: Covering tracks is a priority before departure. **Were critical event logs cleared to remove forensic evidence?**  
*(Yes – wevtutil.exe cleared the Security log first, erasing records of authentication and privilege use.)*

16 ➝ 17 🚩: Long-term access requires fallback options. **Was a hidden local administrator account created for future use?**  
*(Yes – a new account named “support” was added to the local Administrators group as a persistent backdoor.)*

17 ➝ 18 🚩: Automation drives efficiency in post-compromise activity. **Was a PowerShell script used to orchestrate the attack chain?**  
*(Yes – wupdate.ps1 served as the primary execution payload that automated most observed actions.)*

18 ➝ 19 🚩: With credentials and data in hand, attackers pivot deeper. **Did the attacker target a specific internal system for lateral movement?**  
*(Yes – RDP connection initiated toward internal IP 10.1.0.188, indicating the next high-value target.)*

19 ➝ 20 🚩: Native tools help lateral movement blend with admin activity. **Was the built-in Remote Desktop client used to attempt the pivot?**  
*(Yes – mstsc.exe was launched with arguments pointing to the secondary target, using legitimate RDP for movement.)*
