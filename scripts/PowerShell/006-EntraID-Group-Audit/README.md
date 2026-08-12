# 006 — Microsoft Entra Group, Membership, and Owner Audit

## What this tool does

Builds a complete picture of Entra groups: what groups exist, what type they are, who belongs to them, and who owns them. It answers: **Are access groups understood and owned, and can we trace membership?**

The tool reads group data only. It does not add or remove members, modify owners, or alter group settings.

## Run it

```powershell
Set-Location .\scripts\PowerShell\006-EntraID-Group-Audit
.\Get-EntraGroupAudit.ps1 -OutputFolder "C:\Reports\GroupAudit"
```

## Access required

Microsoft Graph delegated permissions: `Group.Read.All` and `User.Read.All`.

## Outputs

- `Entra-Group-Audit.csv` — group type, mail/security status, dynamic rule, member count, and owner count;
- `Entra-Group-Members.csv` — group-to-member relationship details;
- `Entra-Group-Owners.csv` — group-to-owner relationship details.

Prioritize groups with no owner, unexpectedly high membership, or unclear descriptions. Dynamic groups should be reviewed through their membership rule rather than by manually changing members.
