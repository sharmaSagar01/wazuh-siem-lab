# 🔴 Detection Case — Account Lockout

| Field | Details |
|-------|---------|
| **Detection Name** | Account Lockout following Brute Force Pattern |
| **Rule IDs** | `100101` (failed login) → `100102` (brute force) → `100001` (lockout) |
| **Severity** | High — Level 12 |
| **MITRE Technique** | T1110 — Brute Force / T1110.001 — Password Guessing |
| **Affected Account** | `wazuhtest` |
| **Source Agent** | `VM-WINSERV-01` (`192.168.1.10`) |
| **Event IDs** | `4625` (failed logon), `4740` (account locked out) |

---

## What Happened

```
Timeline:
──────────────────────────────────────────────────────────
T+00s  INFOTECH\wazuhtest — failed login attempt (4625) #1
T+15s  INFOTECH\wazuhtest — failed login attempt (4625) #2
T+28s  INFOTECH\wazuhtest — failed login attempt (4625) #3
T+41s  INFOTECH\wazuhtest — failed login attempt (4625) #4
T+55s  INFOTECH\wazuhtest — failed login attempt (4625) #5
         └── Rule 100102 fires: BRUTE FORCE DETECTED (Level 12)
T+68s  INFOTECH\wazuhtest — account locked out (4740)
         └── Rule 100001 fires: ACCOUNT LOCKOUT (Level 10)
──────────────────────────────────────────────────────────
```

---

## Why This Matters

An attacker with a valid username — sourced from LinkedIn, a data breach, or directory enumeration — may attempt repeated password guesses. The brute force rule fires **before** the account locks out, giving the security team time to investigate and block the source before the attacker succeeds.

Account lockout itself confirms the attack reached its threshold. Both alerts together paint the full picture.

---

## Wazuh Alert — Brute Force

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
        "failureReason": "%%2313"
      }
    }
  },
  "mitre": { "technique": ["Brute Force"], "id": ["T1110"] }
}
```

## Wazuh Alert — Account Lockout

```json
{
  "rule": {
    "id": "100001",
    "level": 10,
    "description": "AD Account Lockout — wazuhtest locked out on INFOTECH"
  },
  "agent": { "name": "VM-WINSERV-01", "ip": "192.168.1.10" },
  "data": {
    "win": {
      "system": { "eventID": "4740" },
      "eventdata": {
        "targetUserName": "wazuhtest",
        "targetDomainName": "INFOTECH"
      }
    }
  },
  "mitre": { "technique": ["Brute Force"], "id": ["T1110"] }
}
```

---

## Response Actions

```powershell
# 1 — Unlock the account
Unlock-ADAccount -Identity "wazuhtest"

# 2 — Identify the source IP from the 4625 events
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 10 |
    Select TimeCreated,
    @{N="TargetUser"; E={$_.Properties[5].Value}},
    @{N="SourceIP";   E={$_.Properties[19].Value}}

# 3 — Check if other accounts were targeted from the same IP
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 50 |
    Group-Object { $_.Properties[19].Value } |
    Sort-Object Count -Descending

# 4 — If source IP is external — block at the firewall level
# 5 — Notify the account owner and force a password reset
Set-ADAccountPassword -Identity "wazuhtest" -Reset `
    -NewPassword (ConvertTo-SecureString "NewSecure@Pass1!" -AsPlainText -Force)

# 6 — Review for other accounts targeted from the same source
```

---

## Prevention

- Use a dedicated low-privilege test account for lockout testing — never `Administrator`
- Restrict RDP access to known IP ranges via GPO or Windows Firewall
- Consider enabling **Microsoft Entra ID Smart Lockout** for cloud-joined environments
- Review lockout threshold in **Default Domain Policy** — 5 attempts is the lab setting; production should align to your security policy