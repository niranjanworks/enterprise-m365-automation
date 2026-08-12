# 004 — Microsoft Entra User Audit

## What this tool does

Creates a richer user-account inventory. It answers: **Which accounts exist, are they enabled, are they members or guests, and what business information is recorded for them?**

The script is read-only in Microsoft Entra ID. It exports the findings to a local CSV and does not enable, disable, create, or delete accounts.

## Run it

```powershell
Set-Location .\scripts\PowerShell\004-EntraID-User-Audit
.\Get-EntraUserAudit.ps1
```

## Access required

Microsoft Graph delegated permission: `User.Read.All`.

## Output

`Entra-User-Audit.csv` includes account identity, email, enabled status, `UserType` (such as Member or Guest), creation date, job title, and department.

Useful reviews include disabled accounts with unexpected business details, guest accounts that need ownership review, and accounts missing department/job information. Report data is confidential identity information.
