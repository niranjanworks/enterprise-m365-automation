# 009 — Microsoft Entra Conditional Access Policy Audit

## What this tool does

Conditional Access is the rule engine that decides whether a sign-in should be allowed, blocked, or required to meet controls such as MFA or a compliant device. This tool creates a readable inventory of those rules.

It answers: **Which Conditional Access policies protect the organization, who and what do they apply to, are they enabled, and do they contain a clear configuration issue worth reviewing?**

The script is read-only. It does not create, edit, enable, disable, or delete Conditional Access policies.

## Run it

```powershell
Set-Location .\scripts\PowerShell\009-EntraID-Conditional-Access-Audit
.\Get-EntraConditionalAccessAudit.ps1 -OutputFolder "C:\Reports\ConditionalAccess"
```

## Access required

Microsoft Graph delegated permission: `Policy.Read.All`.

The signed-in account also needs a suitable Entra role, such as **Security Reader**, **Global Reader**, **Conditional Access Administrator**, or **Security Administrator**. Microsoft documents `Policy.Read.All` as the least-privileged permission for listing Conditional Access policies. [Microsoft Graph documentation](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0)

## Outputs

- `Entra-Conditional-Access-Policy-Audit.csv` — one readable row per policy, including state, users/groups/apps in scope, location and device conditions, grant controls, session controls, and findings.
- `Entra-Conditional-Access-Policy-Summary.csv` — total, enabled, report-only, disabled, and Medium-finding counts.

## How to interpret findings

- `Medium` — an enabled policy has no grant control (for example, no MFA, block, compliant-device, custom-authentication-factor, or terms-of-use control). Review it before assuming it protects anything.
- `Informational` — operational context, not an automatic security failure. Disabled and report-only policies are deliberately shown so a reviewer can confirm they are intentional.

When a policy targets **All** users, the report reminds you to verify exclusions and emergency-access account coverage. It does not judge the policy as insecure; that decision depends on your organization’s approved security design.

## Data handling

Policy reports can reveal security architecture, protected groups, application IDs, trusted locations, and access-control choices. Treat them as confidential and keep the generated CSV files out of source control.
