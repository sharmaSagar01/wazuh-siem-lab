# 🟡 Detection Case — Privilege Escalation via Group Membership Change

| Field | Details |
|-------|---------|
| **Detection Name** | Unauthorised User Added to Privileged Security Group |
| **Rule ID** | `100005` |
| **Severity** | High — Level 10 |
| **MITRE Technique** | T1098 — Account Manipulation |
| **Affected Account** | `wazuhtest` added to `IT_Staff` |
| **Performed By** | `Administrator` |
| **Source Agent** | `VM-WINSERV-01` (`192.168.1.10`) |
| **Event ID** | `4728` — A member was added to a security-enabled global group |

---

## What Happened

```
Timeline:
──────────────────────────────────────────────────────────
T+00s  Administrator runs: Add-ADGroupMember IT_Staff wazuhtest
T+01s  Windows writes Event ID 4728 to Security log
T+02s  Wazuh Agent collects the event and forwards to manager
T+03s  Rule 100005 fires: USER ADDED TO SECURITY GROUP (Level 10)
──────────────────────────────────────────────────────────
```

---

## Why This Matters

Adding a user to a privileged security group immediately grants them access to all resources that group can reach — shared folders, systems, administrative tools, and network drives. This is a primary indicator of:

- **Privilege escalation** — attacker elevating their own access after initial compromise
- **Insider threat** — employee granting themselves unauthorised access
- **Admin error** — accidental group assignment that violates least privilege

Every security group membership change should be verified against an approved change record. Unverified changes must be investigated immediately.

---

## Wazuh Alert

```json
{
  "rule": {
    "id": "100005",
    "level": 10,
    "description": "AD User Added to Security Group — wazuhtest added to IT_Staff"
  },
  "agent": { "name": "VM-WINSERV-01", "ip": "192.168.1.10" },
  "data": {
    "win": {
      "system": { "eventID": "4728" },
      "eventdata": {
        "memberName": "CN=Wazuh Test,OU=All_Staff,DC=InfoTech,DC=com",
        "targetUserName": "IT_Staff",
        "subjectUserName": "Administrator",
        "subjectDomainName": "INFOTECH"
      }
    }
  },
  "mitre": { "technique": ["Account Manipulation"], "id": ["T1098"] }
}
```

---

## Response Actions

```powershell
# 1 — Verify the change was authorised
#     Check against approved change records or contact the admin who made the change

# 2 — Review exactly who made the change and when
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4728 } -MaxEvents 10 |
    Select TimeCreated,
    @{N="MemberAdded";  E={$_.Properties[0].Value}},
    @{N="GroupName";    E={$_.Properties[2].Value}},
    @{N="PerformedBy";  E={$_.Properties[4].Value}}

# 3 — If unauthorised — remove the user from the group immediately
Remove-ADGroupMember -Identity "IT_Staff" -Members "wazuhtest" -Confirm:$false

# 4 — Check for other suspicious changes made by the same admin account
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4728, 4729, 4720, 4726, 4732, 4756
} -MaxEvents 30 | Select TimeCreated, Id,
    @{N="Details"; E={$_.Properties[4].Value}}

# 5 — If the admin account appears compromised — disable it immediately
Disable-ADAccount -Identity "Administrator"

# 6 — Review all group memberships the affected user now has
Get-ADUser "wazuhtest" -Properties MemberOf |
    Select -ExpandProperty MemberOf |
    ForEach-Object { (Get-ADGroup $_).Name }
```

---

## Related Event IDs to Monitor

| Event ID | Description |
|----------|-------------|
| `4728` | User added to global security group |
| `4729` | User removed from global security group |
| `4732` | User added to local security group |
| `4756` | User added to universal security group |
| `4720` | New user account created |
| `4672` | Special privileges assigned at logon |

---

## How to Test This Rule

```powershell
# On VM-WINSERV-01 — add the test account to a security group
Add-ADGroupMember -Identity "IT_Staff" -Members "wazuhtest"
```

Then search in Wazuh dashboard:
```
rule.id: 100005
```

Clean up after testing:
```powershell
Remove-ADGroupMember -Identity "IT_Staff" -Members "wazuhtest" -Confirm:$false
```

---

## Prevention

- Implement **Privileged Access Workstations (PAW)** for admin tasks
- Enforce **Delegation of Control** — limit who can modify group memberships
- Require a **change ticket** for any security group modification
- Run `Get-UserAuditReport.ps1` from the AD Automation Toolkit weekly to audit all group memberships
- Set up a scheduled Wazuh report on Rule `100005` alerts for weekly review