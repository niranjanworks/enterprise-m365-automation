# 002 — Microsoft 365 License Inventory

## What this tool does

Shows the tenant’s purchased Microsoft 365 license products and the number that are total, already assigned, and still available. It answers: **Do we have enough licenses, and are we paying for unused capacity?**

The script reads subscription information from Microsoft Graph and writes one local CSV. It never assigns or removes a license.

## Run it

```powershell
Set-Location .\scripts\PowerShell\002-M365-License-Report
.\Get-M365LicenseReport.ps1
```

## Access required

Microsoft Graph delegated permission: `Organization.Read.All`.

## Output and how to read it

`M365-License-Report.csv` contains one row per subscribed product.

- `SkuPartNumber` — the product’s technical name;
- `TotalLicenses` — usable purchased licenses;
- `UsedLicenses` — currently assigned licenses;
- `AvailableLicenses` — `TotalLicenses` minus `UsedLicenses`;
- `CapabilityStatus` — subscription availability/status.

Low availability signals a purchasing or allocation decision. A high availability count is a prompt to investigate whether licenses can be reclaimed.
