# 008 — Microsoft Entra Application Audit

## What this tool does

Audits application registrations and enterprise applications (service principals) in Microsoft Entra ID. In plain English, it answers: **Which apps can interact with our tenant, who owns them, do their credentials expire soon, and which items deserve review?**

The script only reads application and directory data, then writes local CSV reports. It does not grant permissions, disable apps, rotate secrets, or change ownership.

## Run it

```powershell
Set-Location .\scripts\PowerShell\008-EntraID-Application-Audit
.\Get-EntraApplicationAudit.ps1 -OutputFolder "C:\Reports\ApplicationAudit"
```

## Access required

Microsoft Graph delegated permissions: `Application.Read.All` and `Directory.Read.All`.

## Outputs

- `Entra-Application-Registration-Audit.csv` — apps registered by the tenant, their sign-in audience, and credential/API-permission counts;
- `Entra-Enterprise-Application-Audit.csv` — installed enterprise apps, ownership, grants, role assignments, credentials, classification, and findings;
- `Entra-Application-Credential-Audit.csv` — every discovered password/certificate credential with expiry status.

## How to interpret findings

- `High` — an expired credential was found. Investigate and rotate/remove it through the approved change process.
- `Medium` — a credential expires within 30 days, or an app without Microsoft first-party classification has no returned owner. Review the app and its business owner.
- `Informational` — context for review; it is not automatically a security problem. Microsoft first-party applications can legitimately have no returned owner.

The tool recognizes verified Microsoft first-party identifiers, including Microsoft Graph Command Line Tools, to avoid known false positives. Do not add application IDs to that trusted list unless their ownership has been verified.
