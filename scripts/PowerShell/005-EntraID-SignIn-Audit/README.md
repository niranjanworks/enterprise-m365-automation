# 005 — Microsoft Entra Sign-In Audit

## What this tool does

Retrieves Entra sign-in events for a chosen recent period. It answers: **Who signed in, to which app, from where, on what device/browser, and did the sign-in succeed?**

This is a monitoring and investigation tool. It reads sign-in logs and writes a local report; it does not block sign-ins or change Conditional Access policies.

## Run it

```powershell
Set-Location .\scripts\PowerShell\005-EntraID-SignIn-Audit
.\Get-EntraSignInAudit.ps1 -Days 7
```

## Access required

Microsoft Graph delegated permission: `AuditLog.Read.All`. The available retention period depends on your Entra licensing and log-retention configuration.

## Output

`Entra-SignIn-Audit.csv` records time, user, application, IP address, location, device operating system, browser, Conditional Access result, risk level, and success/failure reason.

Look for unexpected countries, repeated failures, unusual applications, or risky sign-ins. This report is especially sensitive: restrict access and do not upload it to public repositories.
