# 010 — Microsoft Entra MFA & Authentication Methods Audit

## What this tool does

This tool shows which authentication methods users have registered in Microsoft Entra. It helps answer: **Which enabled employee accounts have a method beyond a password, and which accounts need an MFA-registration review?**

It is read-only. It does not view passwords, reset MFA, register devices, change a user, or enable/disable an MFA policy.

## Important distinction

**Registered authentication method** and **MFA enforcement** are different things.

- This tool reports methods registered on a user account—such as Microsoft Authenticator, phone, FIDO2 security key, or Windows Hello for Business.
- It does not prove that the user will be prompted for MFA at every sign-in. That depends on Conditional Access, Security Defaults, authentication-strength policies, and the app being used.

## Run it

```powershell
Set-Location .\scripts\PowerShell\010-EntraID-MFA-Authentication-Methods-Audit
.\Get-EntraMfaAuthenticationMethodAudit.ps1 -OutputFolder "C:\Reports\MfaAudit"
```

## Access required

Microsoft Graph delegated permissions: `User.Read.All` and `UserAuthenticationMethod.Read.All`.

`UserAuthenticationMethod.Read.All` requires admin consent. The signed-in account also needs a suitable role, such as **Global Reader**, **Authentication Administrator**, or **Privileged Authentication Administrator**. The Authentication Administrator role sees masked phone numbers. [Microsoft Graph documentation](https://learn.microsoft.com/en-us/graph/api/authentication-list-methods?view=graph-rest-1.0)

## Outputs

- `Entra-MFA-Authentication-Method-Audit.csv` — one row per user with registered-method counts, readable method names, and review status;
- `Entra-Authentication-Method-Detail.csv` — one row per discovered method, for deeper analysis;
- `Entra-MFA-Authentication-Method-Summary.csv` — counts of audited users and accounts requiring review.

## How to interpret findings

- `Medium` — an enabled member account has no discovered non-password method, or its methods could not be read. Confirm whether an MFA method is required and registered before taking action.
- `Informational` — disabled accounts and guest accounts are deliberately not judged as missing MFA. Guests can authenticate through their home tenant.

The reports contain sensitive identity and authentication-registration data. Keep them confidential and out of source control.
