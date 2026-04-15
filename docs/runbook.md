# 📖 Wazuh SIEM Lab — Operational Runbook

> Operational guide for the `wazuh-siem-lab` project.
> Covers daily checks, incident response, rule management, and troubleshooting.

---

## 📑 Table of Contents

| # | Section |
|---|---------|
| 1 | [Environment Reference](#environment-reference) |
| 2 | [Daily Operations Checklist](#daily-operations-checklist) |
| 3 | [Starting & Stopping Services](#starting--stopping-services) |
| 4 | [Responding to Alerts](#responding-to-alerts) |
| 5 | [Managing Detection Rules](#managing-detection-rules) |
| 6 | [Agent Management](#agent-management) |
| 7 | [Troubleshooting](#troubleshooting) |
| 8 | [Quick Reference Commands](#quick-reference-commands) |

---

## Environment Reference

| Component | Details |
|-----------|---------|
| **Wazuh Manager** | Ubuntu 25 — `192.168.1.xx` |
| **Dashboard URL** | `https://192.168.1.xx` |
| **Agent 1** | `VM-WINSERV-01` — `192.168.1.10` |
| **Agent 2** | `VM-WINSERV-02` — `192.168.1.12` |
| **Domain** | `InfoTech.com` |
| **Rules directory** | `/var/ossec/etc/rules/` |
| **Alert logs** | `/var/ossec/logs/alerts/alerts.log` |
| **Manager config** | `/var/ossec/etc/ossec.conf` |
| **Agent config** | `C:\Program Files (x86)\ossec-agent\ossec.conf` |

---

## Daily Operations Checklist

Run these every morning on **Ubuntu**:

```bash
# 1 — Confirm all three services are healthy
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager

# 2 — Confirm both agents are active
sudo /var/ossec/bin/agent_control -l

# 3 — Check for overnight high-severity alerts
sudo tail -100 /var/ossec/logs/alerts/alerts.log | grep "level.*1[0-9]\|level.*[2-9]"
```

**Then in the dashboard** (`https://192.168.1.xx → Overview`):

| Check | Expected |
|-------|---------|
| Critical alerts | 0 |
| High alerts | Reviewed and explained |
| Agent: VM-WINSERV-01 | 🟢 Active |
| Agent: VM-WINSERV-02 | 🟢 Active |

---

## Starting & Stopping Services

### ⚠️ Always start in this exact order

```bash
# Start — indexer must be fully up before manager, manager before dashboard
sudo systemctl start wazuh-indexer
sleep 30
sudo systemctl start wazuh-manager
sleep 15
sudo systemctl start wazuh-dashboard
sleep 120    # Dashboard takes ~2 minutes to fully initialise
```

### Stop

```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
```

### Restart all (e.g. after config change)

```bash
sudo systemctl restart wazuh-manager    # Rules and config changes
sudo systemctl restart wazuh-indexer    # Index issues
sudo systemctl restart wazuh-dashboard  # UI issues
```

### Enable auto-start on boot

```bash
sudo systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard
```

---

## Responding to Alerts

### General Response Workflow

```
1. Open the alert in the dashboard — note Rule ID, agent, timestamp, affected user
2. Click the alert row → expand → view full event JSON
3. Determine if the event is legitimate or suspicious
4. If legitimate   → add a comment and dismiss
5. If suspicious   → follow the detection-specific runbook below
6. If confirmed IR → escalate per your organisation's process
7. Document the outcome in the alert or linked ticket
```

### Alert Severity Reference

| Level | Severity | Action Required |
|-------|---------|----------------|
| 0–6 | Low | Review during daily check |
| 7–11 | Medium | Investigate within the shift |
| 12–14 | High / Critical | Investigate immediately |
| 15 | Critical | Immediate escalation |

### Detection-Specific Response

| Alert | Rule | See |
|-------|------|-----|
| Brute force / account lockout | 100101, 100102, 100001 | `alerts/failed-logins.md` + `alerts/account-lockout.md` |
| User added to security group | 100005 | `alerts/privilege-escalation.md` |
| RDP session detected | 100104 | Investigate source IP — verify with user |
| GPO modified | 100007 | Verify with AD admin — check change record |
| New user created | 100003 | Verify against approved HR new starter list |

---

## Managing Detection Rules

### Add a New Rule

```bash
# Step 1 — Find the correct parent SID for the target event
grep -B5 "eventID.*<EVENT_ID>" /var/ossec/ruleset/rules/0580-win-security_rules.xml | grep "rule id"

# Step 2 — Edit the appropriate custom rule file
sudo nano /var/ossec/etc/rules/custom-ad-rules.xml
# or
sudo nano /var/ossec/etc/rules/custom-windows-rules.xml

# Step 3 — Validate syntax BEFORE restarting
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -v "7616\|7617"

# Step 4 — If clean — restart the manager
sudo systemctl restart wazuh-manager

# Step 5 — Trigger a test event and confirm the rule fires in the dashboard
```

### Rule ID Ranges

| Range | Purpose |
|-------|---------|
| `100001–100099` | AD-specific rules (`custom-ad-rules.xml`) |
| `100100–100199` | Windows platform rules (`custom-windows-rules.xml`) |
| `100200+` | Reserved for future rule sets |

### Validate Rules Without Restarting

```bash
# Filter out the harmless IOC list warnings (7616, 7617)
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -v "7616\|7617"
```

**Expected clean output:**
```
wazuh-analysisd: INFO: No errors found. Ready to start.
```

---

## Agent Management

### Check Agent Status

```bash
# List all agents and their connection status
sudo /var/ossec/bin/agent_control -l

# Get detailed info on a specific agent
sudo /var/ossec/bin/agent_control -i 001
```

### Restart an Agent (on the Windows Server)

```powershell
NET STOP WazuhSvc
NET START WazuhSvc

# Verify
Get-Service -Name WazuhSvc
```

### View Agent Logs (on the Windows Server)

```powershell
# Last 20 lines — look for Connected / ERROR
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20

# Search for connection-related entries
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" |
    Select-String "Connected|ERROR|Unable|refused"
```

### Re-register an Agent

```powershell
# If agent loses its key and can't connect
NET STOP WazuhSvc
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 192.168.1.xx
NET START WazuhSvc
```

---

## Troubleshooting

### Dashboard shows "Wazuh dashboard server is not ready yet"

```bash
# Check if indexer is fully up first
sudo systemctl status wazuh-indexer

# Restart in correct order
sudo systemctl restart wazuh-indexer
sleep 30
sudo systemctl restart wazuh-dashboard
sleep 120
```

If still failing — check the config file:
```bash
sudo grep "opensearch.hosts" /etc/wazuh-dashboard/opensearch_dashboards.yml
# Must show your actual IP, not 'localhost' or '127.0.0.1'
```

---

### Agent shows Disconnected in dashboard

```bash
# On Ubuntu — check which agent is disconnected
sudo /var/ossec/bin/agent_control -l
```

```powershell
# On the affected Windows Server — restart the agent service
NET STOP WazuhSvc
NET START WazuhSvc
```

Also verify connectivity:
```powershell
Test-NetConnection -ComputerName 192.168.1.xx -Port 1514
Test-NetConnection -ComputerName 192.168.1.xx -Port 1515
```

---

### Events not appearing in dashboard

**Step 1 — Check audit policy on the Windows Server:**
```powershell
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Account Lockout"
# All must show "Success and Failure"
```

**Step 2 — Check agent config uses eventchannel:**
```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "eventchannel"
```

**Step 3 — Confirm events exist locally on Windows:**
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 5
```

---

### Custom rules not firing

```bash
# Find the correct parent SID — common mistake is using wrong <if_sid>
grep -B5 "eventID.*4625" /var/ossec/ruleset/rules/0580-win-security_rules.xml | grep "rule id"

# Watch alerts in real time to see which rule is actually firing
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -A3 "4625"
```

---

### UFW blocking agent after enabling firewall

```bash
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw allow in proto icmp
sudo ufw reload
sudo ufw status
```

---

## Quick Reference Commands

```bash
# ── Ubuntu / Wazuh Manager ──────────────────────────────────────
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager
sudo /var/ossec/bin/agent_control -l                    # List all agents
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -v "7616\|7617"  # Validate rules
sudo tail -f /var/ossec/logs/alerts/alerts.log          # Live alert stream
sudo systemctl restart wazuh-manager                    # Apply rule changes
```

```powershell
# ── Windows Server (run as Administrator) ──────────────────────
NET STOP WazuhSvc; NET START WazuhSvc                   # Restart agent
Get-Service -Name WazuhSvc                              # Check agent status
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20  # Agent log
auditpol /get /subcategory:"Account Lockout"            # Check audit policy
gpupdate /force                                         # Apply GP changes
Unlock-ADAccount -Identity "username"                   # Unlock locked account
```

---

<div align="center">
<sub>📖 Wazuh SIEM Lab — Operational Runbook | InfoTech.com | Windows Server 2025 + Ubuntu 25</sub>
</div>