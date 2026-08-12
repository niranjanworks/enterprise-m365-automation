# 007 — Microsoft Entra Privileged Role Audit

## What this tool does

Shows who has high-impact Entra directory roles. It includes both active assignments—people who can administer now—and eligible Privileged Identity Management (PIM) assignments—people who can activate a role when needed.

It answers the CEO-level question: **Who can control the tenant, and is that access intentional?** The script is strictly read-only.

## Run it

```powershell
Set-Location .\scripts\PowerShell\007-EntraID-Privileged-Role-Audit
.\Get-EntraPrivilegedRoleAudit.ps1 -OutputFolder "C:\Reports\PrivilegedRoles"
```

## Access required

Microsoft Graph delegated permissions: `RoleManagement.Read.Directory` and `Directory.Read.All`.

## Outputs

- `Entra-Privileged-Role-Active.csv` — current role assignments;
- `Entra-Privileged-Role-Eligible.csv` — PIM-eligible assignments;
- `Entra-Privileged-Role-Summary.csv` — combined role-access overview.

Review unknown users, guest users, disabled users, service principals, and permanent active assignments in powerful roles. Role membership is security-sensitive information and must be handled accordingly.
