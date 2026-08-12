# 003 — Microsoft 365 User License Assignment Audit

## What this tool does

Lists every Entra user and whether they currently have a Microsoft 365 license. It answers: **Who is licensed, who is unlicensed, and how many licenses does each account hold?**

It is an audit only. It reads user and license-assignment data and writes a local report; it does not modify licensing.

## Run it

```powershell
Set-Location .\scripts\PowerShell\003-M365-License-Assignment-Audit
.\Get-M365UserLicenseAudit.ps1
```

## Access required

Microsoft Graph delegated permission: `User.Read.All`.

## Output

`M365-User-License-Audit.csv` contains:

- `DisplayName` and `UserPrincipalName` — the account owner and sign-in;
- `LicenseStatus` — `Licensed` or `Unlicensed`;
- `LicenseCount` — number of assigned product SKUs;
- `LicenseIds` — the technical SKU IDs assigned to the user.

Use it to identify unlicensed accounts that may need service access, or licensed accounts that should be reviewed during offboarding. SKU IDs are technical identifiers; combine this report with Project 002 to interpret the product names.
