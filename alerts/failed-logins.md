# 🟠 Detection Case — Failed Logins & Brute Force

| Field | Details |
|-------|---------|
| **Detection Name** | Repeated Failed Login Attempts — Brute Force Pattern |
| **Rule IDs** | `100101` (single failure), `100102` (brute force correlation) |
| **Severity** | Medium → High (Level 7 → 12) |
| **MITRE Technique** | T1110 — Brute Force, T1110.001 — Password Guessing |
| **Affected Account** | `wazuhtest` |
| **Source Agent** | `VM-WINSERV-01` (`192.168.1.10`) |
| **Event ID** | `4625` — An account failed to log on |

---

## What Happened

Each failed login attempt generates a Windows Security **Event ID 4625**. Wazuh's custom rule `100101` fires on every individual failure (Level 7 — Medium).

When **5 or more failures for the same username occur within 120 seconds**, the correlation rule `100102` fires a higher-severity alert (Level 12 — High), indicating an automated or persistent brute force attempt.

```
Single failure  → Rule 100101 fires  (Level 7  — Medium)
5 failures/2min → Rule 100102 fires  (Level 12 — High)
Account locked  → Rule 100001 fires  (Level 10 — High)
```

---

## Wazuh Alert — Single Failed Login

```json
{
  "rule": {
    "id": "100101",
    "level": 7,
    "description": "Windows Failed Login — wazuhtest failed on VM-WINSERV-01"
  },
  "agent": { "name": "VM-WINSERV-01", "ip": "192.168.1.10" },
  "data": {
    "win": {
      "system": { "eventID": "4625" },
      "eventdata": {
        "targetUserName": "wazuhtest",
        "targetDomainName": "INFOTECH",
        "workstationName": "CLIENT-WIN11",
        "ipAddress": "192.168.1.105",
        "logonType": "3",
        "failureReason": "%%2313"
      }
    }
  },
  "mitre": { "technique": ["Brute Force"], "id": ["T1110"] }
}
```

## Wazuh Alert — Brute Force Correlation

```json
{
  "rule": {
    "id": "100102",
    "level": 12,
    "description": "Brute Force Detected — 5+ failed logins for wazuhtest in 2 minutes"
  },
  "agent": { "name": "VM-WINSERV-01", "ip": "192.168.1.10" },
  "data": {
    "win": {
      "system": { "eventID": "4625" },
      "eventdata": {
        "targetUserName": "wazuhtest",
        "targetDomainName": "INFOTECH",
        "ipAddress": "192.168.1.105"
      }
    }
  },
  "mitre": { "technique": ["Brute Force"], "id": ["T1110.001"] }
}
```

---

## Common Failure Reason Codes

| Code | Meaning |
|------|---------|
| `%%2313` | Unknown username or bad password |
| `%%2304` | Account expired |
| `%%2305` | Password expired |
| `%%2310` | Account locked out |
| `%%2311` | Account disabled |

---

## Response Actions

```powershell
# 1 — Identify the source IP and targeted accounts
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 20 |
    Select TimeCreated,
    @{N="TargetUser"; E={$_.Properties[5].Value}},
    @{N="SourceIP";   E={$_.Properties[19].Value}},
    @{N="Workstation";E={$_.Properties[13].Value}}

# 2 — Check how many accounts were targeted from the same IP
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 100 |
    Group-Object { $_.Properties[19].Value } |
    Sort-Object Count -Descending | Select Name, Count

# 3 — If account is now locked — unlock it
Unlock-ADAccount -Identity "wazuhtest"

# 4 — Block the source IP at the firewall if external
# Windows Defender Firewall:
New-NetFirewallRule -DisplayName "Block Brute Force Source" `
    -Direction Inbound -Action Block `
    -RemoteAddress "ATTACKER_IP"
```

---

## How to Test This Rule

```powershell
# Generate 6 rapid failed logins on VM-WINSERV-01
# This fires Rule 100101 six times and triggers Rule 100102 (brute force)
1..6 | ForEach-Object {
    try {
        $null = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://192.168.1.10",
            "INFOTECH\wazuhtest",
            "WRONGPASSWORD$_"
        )
    } catch {}
    Start-Sleep -Seconds 3
}
```

Then search in Wazuh dashboard:
```
rule.id: 100101 OR rule.id: 100102
```

---

## Prevention

- Set Account Lockout Threshold to 5 in Default Domain Policy
- Enable audit policy: `auditpol /set /subcategory:"Credential Validation" /failure:enable`
- Restrict domain account logon to specific workstations via **Log On To** in ADUC
- Use **Multi-Factor Authentication** for privileged accounts