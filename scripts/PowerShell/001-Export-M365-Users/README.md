# 001 — Export Microsoft 365 Users

## What this tool does

Creates a simple inventory of the people and accounts in Microsoft Entra ID. Think of it as the starting address book for an administrator: it tells you **who has an account**, their sign-in name, and their directory ID.

It reads user data from Microsoft Graph and creates a local CSV file. It does **not** change user accounts, licenses, groups, or mailboxes.

## Run it

```powershell
Set-Location .\scripts\PowerShell\001-Export-M365-Users
.\Export-M365Users.ps1
```

To save reports elsewhere:

```powershell
.\Export-M365Users.ps1 -OutputPath "C:\Reports\Users.csv"
```

## Access required

Microsoft Graph delegated permission: `User.Read.All`. A tenant administrator may need to grant consent.

## Output

`Users.csv` contains:

- `DisplayName` — the name shown in Microsoft 365;
- `UserPrincipalName` — the user’s normal sign-in address;
- `Id` — the unique Entra directory identifier.

Use this as a source list for account reviews, HR reconciliation, or future audits. It is confidential because it identifies people and accounts.
