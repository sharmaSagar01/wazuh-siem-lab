# 🛡️ Wazuh SIEM Lab — Security Monitoring on Windows Server 2025

> A fully operational SIEM environment built on **Wazuh** — deployed on Ubuntu 25,
> monitoring two Windows Server 2025 Domain Controllers in real time.
> Extends the [AD & Windows Server Labs](https://github.com/your-username/ad-windows-server-labs) project
> with live threat detection, custom alert rules, and documented incident cases.

<div align="center">

![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue?style=flat-square)
![Ubuntu](https://img.shields.io/badge/Ubuntu-25-E95420?style=flat-square&logo=ubuntu)
![Windows Server](https://img.shields.io/badge/Windows%20Server-2025-blue?style=flat-square&logo=windows)
![Active Directory](https://img.shields.io/badge/Domain-InfoTech.com-darkblue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)

</div>

---

## 📌 Overview

Monitoring an IT environment is just as critical as building it. This project deploys a full SIEM stack that ingests Windows Security Event logs from both Domain Controllers, applies custom detection rules for Active Directory threats, and documents real incident detection cases.

**What this project demonstrates:**

- Deploying and configuring a production-grade SIEM from scratch
- Forwarding and parsing Windows Security Event logs in real time
- Writing custom XML alert rules mapped to MITRE ATT&CK
- Detecting, investigating, and documenting real security incidents
- Monitoring infrastructure proactively — not just reacting to complaints

---

## 🖥️ Environment

<table>
<tr>
<td width="50%" valign="top">

**Infrastructure**
| Component | Details |
|-----------|---------|
| **SIEM Manager** | Wazuh on Ubuntu 25 |
| **Dashboard** | `https://192.168.1.xx` |
| **Primary DC** | `VM-WINSERV-01` — `192.168.1.10` |
| **Secondary DC** | `VM-WINSERV-02` — `192.168.1.12` |
| **Domain** | `InfoTech.com` |
| **Network** | Bridged — all on `192.168.1.0/24` |

</td>
<td width="50%" valign="top">

**Stack**
| Component | Tool |
|-----------|------|
| **SIEM Platform** | Wazuh Manager |
| **Search & Index** | Wazuh Indexer (OpenSearch) |
| **Dashboard** | Wazuh Dashboard (port 443) |
| **Agent OS** | Windows Server 2025 |
| **Host OS** | Ubuntu 25 Desktop |
| **Virtualisation** | VMware Workstation Pro |

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────┐
│         Ubuntu 25 Host (192.168.1.xx)    │
│                                          │
│   Wazuh Manager  +  Indexer  +  Dashboard│
│   Port 1514 ← agent events              │
│   Port 1515 ← agent registration        │
│   Port  443 → dashboard (HTTPS)         │
└───────────────┬──────────────────────────┘
                │ encrypted traffic
       ┌────────┴────────┐
       ↓                 ↓
┌─────────────────┐ ┌─────────────────┐
│  VM-WINSERV-01  │ │  VM-WINSERV-02  │
│  192.168.1.10   │ │  192.168.1.12   │
│  Wazuh Agent    │ │  Wazuh Agent    │
│  Security logs  │ │  Security logs  │
│  AD events      │ │  AD events      │
└─────────────────┘ └─────────────────┘
```

---

## 📁 Repository Structure

```
wazuh-siem-lab/
├── config/
│   ├── ossec.conf                   # Wazuh manager config
│   ├── agent-winserv-01.conf        # Agent config — Server 01
│   └── agent-winserv-02.conf        # Agent config — Server 02
├── rules/
│   ├── custom-ad-rules.xml          # Custom AD detection rules
│   └── custom-windows-rules.xml     # Custom Windows detection rules
├── alerts/
│   ├── account-lockout.md           # Detection case — account lockout
│   ├── failed-logins.md             # Detection case — brute force
│   └── privilege-escalation.md      # Detection case — group change
├── dashboards/
│   └── screenshots/                 # Dashboard screenshots per phase
├── docs/
│   └── runbook.md                   # Operational runbook
└── README.md
```

---

## 🧩 Build Progress

| #   | Phase                                           | Status |
| --- | ----------------------------------------------- | ------ |
| 1   | Install Wazuh Manager on Ubuntu                 | ✅     |
| 2   | Access Wazuh Dashboard in browser               | ✅     |
| 3   | Install Wazuh Agent on VM-WINSERV-01            | ✅     |
| 4   | Install Wazuh Agent on VM-WINSERV-02            | ✅     |
| 5   | Configure Windows Security Event log forwarding | ✅     |
| 6   | Verify events appearing in dashboard            | ✅     |
| 7   | Write custom AD alert rules                     | ✅     |
| 8   | Test rules — trigger real events from lab       | ✅     |
| 9   | Document 3 detection cases                      | ✅     |
| 10  | Runbook + final documentation                   | ✅     |

---

## 🎯 Detection Coverage

| Event ID       | Description                      | Rule   | Severity |
| -------------- | -------------------------------- | ------ | -------- |
| `4625`         | Failed logon                     | 100101 | Medium   |
| `4625` x5/2min | Brute force pattern              | 100102 | High     |
| `4740`         | Account locked out               | 100001 | High     |
| `4767`         | Account unlocked by admin        | 100002 | Medium   |
| `4720`         | New user account created         | 100003 | Medium   |
| `4725`         | User account disabled            | 100004 | Medium   |
| `4728`         | User added to security group     | 100005 | High     |
| `4729`         | User removed from security group | 100006 | Medium   |
| `5136`         | GPO modified                     | 100007 | Critical |
| `4726`         | User account deleted             | 100008 | High     |
| `4624` Type 3  | Network logon                    | 100103 | Low      |
| `4624` Type 10 | RDP session started              | 100104 | Medium   |

---

---

# ✅ Phase 1 — Install Wazuh Manager on Ubuntu

Wazuh is a three-component stack — **Manager**, **Indexer** (OpenSearch), and **Dashboard** — all installed together using the official installation assistant.

## Installation

```bash
# Download the installer and config file
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.11/config.yml

# Edit config.yml — set all three node IPs to your Ubuntu host IP
nano config.yml
```

```yaml
nodes:
  indexer:
    - name: node-1
      ip: "192.168.1.xx"
  server:
    - name: wazuh-1
      ip: "192.168.1.xx"
  dashboard:
    - name: dashboard
      ip: "192.168.1.xx"
```

```bash
# Install in order
bash wazuh-install.sh --generate-config-files
bash wazuh-install.sh --wazuh-indexer node-1
bash wazuh-install.sh --start-cluster
bash wazuh-install.sh --wazuh-server wazuh-1
bash wazuh-install.sh --wazuh-dashboard dashboard
```

> ⚠️ Save the `admin` password printed at the end — it is needed to log into the dashboard.

## Verify

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo ss -tlnp | grep -E "1514|1515|443|9200"
```

## Outcome

- All three Wazuh services running on Ubuntu ✅
- Ports `1514`, `1515`, `443`, `9200` confirmed listening ✅
- All three services enabled for auto-start on boot ✅

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase1-image-1.png" width="70%" />
</p>

---

# ✅ Phase 2 — Access the Wazuh Dashboard

Open a browser on any machine on the `192.168.1.0/24` network:

```
https://192.168.1.xx
```

Accept the SSL certificate warning — self-signed certificates are expected in a lab environment. Log in with `admin` and the password saved during Phase 1.

## Verify

Navigate to **☰ → Server Management → Status** — all components should show green. The dashboard will show **0 agents** at this point — agents are added in Phases 3 and 4.

## ⚠️ Troubleshooting — "Dashboard server is not ready yet"

If the dashboard shows this message, the `opensearch_dashboards.yml` config had `localhost` instead of the actual host IP:

```bash
sudo grep "opensearch.hosts" /etc/wazuh-dashboard/opensearch_dashboards.yml
# Must show 192.168.1.xx — not localhost or 127.0.0.1

# Fix if needed
sudo sed -i 's/localhost/192.168.1.xx/g' /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo systemctl restart wazuh-dashboard
```

## Outcome

- Dashboard accessible at `https://192.168.1.xx` ✅
- All manager components confirmed running ✅
- Auto-start enabled on all three services ✅

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase2-image-1.png" width="45%" />
  <img src="dashboards/Screenshots/phase2-image-2.png" width="45%" />
</p>

---

# ✅ Phase 3 — Install Wazuh Agent on VM-WINSERV-01

## Part A — Open Ports on Ubuntu

```bash
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw allow in proto icmp
sudo ufw enable && sudo ufw status
```

## Part B — Install Agent on VM-WINSERV-01

Run on **VM-WINSERV-01** as Administrator:

```powershell
# Download the installer
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile "C:\wazuh-agent.msi"

# Install — all on one line
msiexec.exe /i "C:\wazuh-agent.msi" /q WAZUH_MANAGER="192.168.1.xx" WAZUH_AGENT_NAME="VM-WINSERV-01" WAZUH_REGISTRATION_SERVER="192.168.1.xx"

# Start the service
NET START WazuhSvc
Get-Service -Name WazuhSvc
```

## Part C — Configure Security Log Collection

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Confirm these entries exist — `eventchannel` is required:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```powershell
NET STOP WazuhSvc && NET START WazuhSvc
```

## Outcome

- Agent registered with Wazuh Manager ✅
- `WazuhSvc` running and connected ✅
- VM-WINSERV-01 visible as **Active** in dashboard ✅

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase3-image-1.png" width="45%" />
  <img src="dashboards/Screenshots/phase3-image-2.png" width="45%" />
</p>

---

# ✅ Phase 4 — Install Wazuh Agent on VM-WINSERV-02

Identical process to Phase 3 — run on **VM-WINSERV-02** (`192.168.1.12`):

```powershell
# Download and install — note the different agent name
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile "C:\wazuh-agent.msi"

msiexec.exe /i "C:\wazuh-agent.msi" /q WAZUH_MANAGER="192.168.1.xx" WAZUH_AGENT_NAME="VM-WINSERV-02" WAZUH_REGISTRATION_SERVER="192.168.1.xx"

NET START WazuhSvc
```

Apply the same `ossec.conf` event log collection config as Phase 3.

## Verify Both Agents

```bash
# On Ubuntu — both should show Active
sudo /var/ossec/bin/agent_control -l
```

Expected:

```
ID: 001  Name: VM-WINSERV-01  IP: 192.168.1.10  Status: Active
ID: 002  Name: VM-WINSERV-02  IP: 192.168.1.12  Status: Active
```

## Outcome

- Both agents registered and Active in dashboard ✅
- Full domain coverage — both DCs monitored ✅

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase4-image-1.png" width="45%" />
  <img src="dashboards/Screenshots/phase4-image-2.png" width="45%" />
</p>

---

# ✅ Phase 5 & 6 — Security Event Forwarding & Verification

## How Windows Security Logging Works

```
User action → Windows checks audit policy
  ├── Policy OFF → event silently dropped (Wazuh sees nothing)
  └── Policy ON  → event written to Security log
                      → Wazuh Agent reads it
                        → forwarded to Manager
                          → indexed and displayed
```

## Enable Audit Policy on Both Servers

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
gpupdate /force
```

## Issues Encountered & Fixed

| Issue                         | Root Cause                                                                                        | Fix                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Events not appearing in Wazuh | `Account Lockout` and `Credential Validation` only had **Success** — missing **Failure** auditing | Enabled Failure on all subcategories via `auditpol`                                     |
| Agent couldn't reach manager  | UFW was blocking all traffic after being enabled                                                  | Added explicit UFW rules for ports `1514`, `1515`, and ICMP                             |
| Administrator account locked  | Used Administrator account for lockout testing                                                    | Recovered via Utilman.exe technique — created dedicated `wazuhtest` account for testing |

## Outcome

- Audit policy confirmed **Success and Failure** on all subcategories ✅
- Agent config using `eventchannel` format ✅
- `4625` events confirmed in local Security log and in Wazuh dashboard ✅
- `1,661` low + `204` medium severity events confirmed in dashboard ✅

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase5-6-image-1.png" width="45%" />
  <img src="dashboards/Screenshots/phase5-6-image-2.png" width="45%" />
</p>

---

# ✅ Phase 7 & 8 — Custom AD Alert Rules & Testing

## Rule Files

| File                             | Rules   | Coverage                                              |
| -------------------------------- | ------- | ----------------------------------------------------- |
| `rules/custom-ad-rules.xml`      | 8 rules | Lockout, group changes, new users, GPO edits          |
| `rules/custom-windows-rules.xml` | 6 rules | Brute force, RDP, failed logins, privilege assignment |

## How Rules Are Structured

```xml
<rule id="100001" level="10">
  <if_sid>60115</if_sid>                               <!-- Parent Wazuh rule SID -->
  <field name="win.system.eventID">^4740$</field>       <!-- Event ID to match -->
  <description>AD Account Lockout — $(win.eventdata.targetUserName)</description>
  <mitre><id>T1110</id></mitre>                        <!-- MITRE ATT&CK mapping -->
  <group>account_lockout,authentication_failed,</group>
</rule>
```

> **Important:** The `<if_sid>` value must match the correct **parent rule ID** from the Wazuh ruleset — not the Windows Event ID. Find it with:
>
> ```bash
> grep -B5 "eventID.*4740" /var/ossec/ruleset/rules/0580-win-security_rules.xml | grep "rule id"
> ```

## Deploy & Validate

```bash
# Validate syntax — filter out harmless IOC warnings
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -v "7616\|7617"

# Restart to apply
sudo systemctl restart wazuh-manager
```

## Rule Summary

| Rule ID  | Event ID       | Level | Detection               | MITRE     |
| -------- | -------------- | ----- | ----------------------- | --------- |
| `100001` | `4740`         | 10    | Account locked out      | T1110     |
| `100002` | `4767`         | 7     | Account unlocked        | T1098     |
| `100003` | `4720`         | 8     | New user created        | T1136.001 |
| `100004` | `4725`         | 7     | User disabled           | T1531     |
| `100005` | `4728`         | 10    | User added to group     | T1098     |
| `100006` | `4729`         | 8     | User removed from group | T1098     |
| `100007` | `5136`         | 14    | GPO modified            | T1484.001 |
| `100008` | `4726`         | 10    | User account deleted    | T1531     |
| `100101` | `4625`         | 7     | Failed login            | T1110     |
| `100102` | `4625` x5      | 12    | Brute force detected    | T1110.001 |
| `100103` | `4624` Type 3  | 3     | Network logon           | T1078     |
| `100104` | `4624` Type 10 | 8     | RDP session             | T1021.001 |

## Outcome

- 14 custom rules deployed and validated ✅
- All rules mapped to MITRE ATT&CK ✅
- All 5 test scenarios confirmed firing in dashboard ✅

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase7-8-image-1.png" width="45%" />
  <img src="dashboards/Screenshots/phase7-8-image-2.png" width="45%" />
</p>
<p align="center">
  <img src="dashboards/Screenshots/phase7-8-image-3.png" width="45%" />
</p>

---

# ✅ Phase 9 — Detection Case Documentation

Three real detection cases documented in SOC incident report format. Full details in the `alerts/` folder.

## Case 1 — Brute Force → Account Lockout

| Field        | Details                                     |
| ------------ | ------------------------------------------- |
| **Rules**    | 100101 → 100102 → 100001                    |
| **Severity** | High (Level 12)                             |
| **MITRE**    | T1110, T1110.001                            |
| **Events**   | 5x `4625` within 2 minutes → `4740` lockout |

Five failed logins within 120 seconds triggered the brute force correlation rule — followed by the account lockout alert. The brute force rule fires **before** lockout, giving analysts time to act before an attacker succeeds.

📄 Full case: [`alerts/failed-logins.md`](alerts/failed-logins.md) + [`alerts/account-lockout.md`](alerts/account-lockout.md)

---

## Case 2 — Privilege Escalation via Group Change

| Field        | Details                                  |
| ------------ | ---------------------------------------- |
| **Rule**     | 100005                                   |
| **Severity** | High (Level 10)                          |
| **MITRE**    | T1098                                    |
| **Event**    | `4728` — `wazuhtest` added to `IT_Staff` |

`wazuhtest` was added to the `IT_Staff` security group by `Administrator`. Any group membership change grants access to all resources that group controls — this must be verified against an approved change record.

📄 Full case: [`alerts/privilege-escalation.md`](alerts/privilege-escalation.md)

---

## Case 3 — RDP Session Detection

| Field        | Details                                        |
| ------------ | ---------------------------------------------- |
| **Rule**     | 100104                                         |
| **Severity** | Medium (Level 8)                               |
| **MITRE**    | T1021.001                                      |
| **Event**    | `4624` Logon Type 10 — `sue` connected via RDP |

Every RDP session is logged — who connected, from which IP, and when. RDP is one of the most common lateral movement and ransomware delivery vectors. Any unexpected source IP or off-hours connection warrants immediate investigation.

## 📸 Screenshots

<p align="center">
  <img src="dashboards/Screenshots/phase9-image-1.png" width="45%" />
  <img src="dashboards/Screenshots/phase9-image-2.png" width="45%" />
</p>
<p align="center">
  <img src="dashboards/Screenshots/phase9-image-3.png" width="45%" />
</p>

---

# ✅ Phase 10 — Final Documentation

## Real Troubleshooting Documented

| Issue                     | Root Cause                             | Resolution                               |
| ------------------------- | -------------------------------------- | ---------------------------------------- |
| Dashboard "not ready yet" | Config had `localhost` not actual IP   | Updated `opensearch_dashboards.yml`      |
| Agent couldn't connect    | UFW blocking ports after enable        | Added explicit UFW rules                 |
| Events not appearing      | Audit policy missing Failure logging   | Enabled via `auditpol`                   |
| Custom rules not firing   | Wrong `<if_sid>` parent rule IDs       | Mapped correct SIDs from ruleset files   |
| Duplicate rule ID warning | Rule defined in two locations          | Removed duplicate from `local_rules.xml` |
| AD replication error 8524 | DNS ordering + IPv6 interference       | Fixed DNS config, disabled IPv6 binding  |
| Administrator lockout     | Used admin account for lockout testing | Recovered via Utilman technique          |

---

## Project Complete

```
wazuh-siem-lab
──────────────────────────────────────────────────
Ubuntu 25 host running a full Wazuh SIEM stack
Two Windows Server 2025 Domain Controllers monitored
14 custom detection rules mapped to MITRE ATT&CK
3 documented detection cases in SOC incident format
Real troubleshooting documented end to end
```

---

<div align="center">

![Complete](https://img.shields.io/badge/Project-Complete-brightgreen?style=flat-square)

**🛡️ Built for learning • ⭐ Star if you find this useful**

_Part of a series:_
_[AD & Windows Server Labs](https://github.com/sharmaSagar01/Active-Directory-Lab.git) |_
_[AD Automation Toolkit](https://github.com/sharmaSagar01/ad-automation-toolkit) |_
_[Wazuh SIEM Lab](https://github.com/sharmaSagar01/wazuh-siem-lab)_

</div>
