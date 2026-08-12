# Enterprise M365 Automation

Practical, read-only PowerShell tools for understanding and improving a Microsoft 365 / Microsoft Entra environment.

## What this repository is

This is an administrator's toolkit. Each project answers one operational or security question—such as *who has a license?*, *who has privileged access?*, or *which applications have expiring credentials?*—and exports an evidence-based CSV report.

The tools are built with Microsoft Graph PowerShell and are designed to be safe to run: they **read tenant data and write local report files only**. They do not create, change, or delete Microsoft 365 objects.

## Before you run a tool

1. Install PowerShell 7 and the Microsoft Graph PowerShell module.
2. Run the tool in a folder where you are comfortable storing the generated CSV reports.
3. Sign in with an account that can consent to, or has already been granted, the stated Microsoft Graph permissions.
4. Treat reports as confidential: they can contain names, email addresses, sign-in information, role assignments, and application details. Generated reports are excluded from Git.

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Tool catalogue

| Project | Plain-English question it answers | Main report |
| --- | --- | --- |
| [001 — User export](scripts/PowerShell/001-Export-M365-Users/README.md) | Who exists in our Microsoft 365 directory? | `Users.csv` |
| [002 — License inventory](scripts/PowerShell/002-M365-License-Report/README.md) | What licenses do we own, use, and have left? | `M365-License-Report.csv` |
| [003 — User license audit](scripts/PowerShell/003-M365-License-Assignment-Audit/README.md) | Which users have licenses, and how many? | `M365-User-License-Audit.csv` |
| [004 — Entra user audit](scripts/PowerShell/004-EntraID-User-Audit/README.md) | What kinds of user accounts exist and are they enabled? | `Entra-User-Audit.csv` |
| [005 — Sign-in audit](scripts/PowerShell/005-EntraID-SignIn-Audit/README.md) | What sign-ins occurred recently, from where, and did they succeed? | `Entra-SignIn-Audit.csv` |
| [006 — Group audit](scripts/PowerShell/006-EntraID-Group-Audit/README.md) | Which groups exist, who belongs to them, and who owns them? | Three group, member, and owner reports |
| [007 — Privileged role audit](scripts/PowerShell/007-EntraID-Privileged-Role-Audit/README.md) | Who can administer the tenant now or through PIM eligibility? | Active, eligible, and summary role reports |
| [008 — Application audit](scripts/PowerShell/008-EntraID-Application-Audit/README.md) | Which apps exist, what access/credentials do they have, and what needs review? | Registration, enterprise-app, and credential reports |
| [009 — Conditional Access audit](scripts/PowerShell/009-EntraID-Conditional-Access-Audit/README.md) | Which sign-in protection policies exist, what do they target, and are they enforced? | Policy and summary reports |

## Operating model

Every new tool must ship with:

- a plain-language `README.md` in its project folder;
- a read-only/safety statement;
- exact Microsoft Graph permissions and a runnable command;
- clear explanation of exported fields and the decisions they support;
- tenant-generated output excluded from Git;
- validation before commit and push.

This turns a collection of scripts into a maintainable product portfolio.
