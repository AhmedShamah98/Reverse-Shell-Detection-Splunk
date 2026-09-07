# 🛡️ Reverse Shell & Privilege Escalation Detection Lab

## 📌 Overview
This repository documents an end-to-end Blue Team homelab scenario demonstrating the detection, log correlation, and manual containment of a **Reverse Shell** attack and **Process Injection / Privilege Escalation** activity. 

The lab simulates a malicious DLL execution (`Project.dll` / `Project[1].dll`) via Windows utilities, tracking outbound connections on port **4444**, and verifying manual network containment.

---

## 🏗️ Environment & Architecture
- **Attacker Infrastructure:** Kali Linux (Metasploit Framework)
- **Target Host:** Windows 10 (`DESKTOP-IL0EOKR`) with Sysmon & Splunk Universal Forwarder
- **SIEM Platform:** Splunk Enterprise (`v10.4.1`)
- **Monitored Telemetry:** Windows Security Events & Sysmon Operational Logs

---

## 📌 Sysmon Event Codes Summary
| EventCode | Event Name | Detection Purpose |
| :--- | :--- | :--- |
| **EventCode 3** | Network Connection | Detects outbound reverse shell over port 4444 |
| **EventCode 8** | CreateRemoteThread | Detects process injection from PowerShell |
| **EventCode 11** | File Create | Detects dropping of `.dll` payloads via `certutil.exe` |

---

## 🔍 Key Detection Queries (SPL)

### 1. Network Connection Detection (Reverse Shell Port 4444)
Monitors outbound network connections initiated by system processes (e.g., `rundll32.exe`) to suspicious ports.
```spl
index=* EventCode=3 
| table _time Computer SourceIp SourcePort DestinationIp DestinationPort Image
