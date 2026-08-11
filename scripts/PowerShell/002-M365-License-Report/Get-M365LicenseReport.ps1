<#
.SYNOPSIS
Reports Microsoft 365 license information.

.AUTHOR
Niranjan Babu

.VERSION
1.3.0
#>

param(
    [string]$OutputPath = ".\M365-License-Report.csv"
)

try {
    $OutputFolder = Split-Path -Path $OutputPath -Parent

    if ($OutputFolder -and -not (Test-Path -Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-Host "Created folder: $OutputFolder"
    }

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph -Scopes "Organization.Read.All" -NoWelcome

    Write-Host "Retrieving license information..."

    $Licenses = Get-MgSubscribedSku -ErrorAction Stop

    $Report = $Licenses | Select-Object `
        SkuPartNumber,
        @{Name="TotalLicenses"; Expression={$_.PrepaidUnits.Enabled}},
        @{Name="UsedLicenses"; Expression={$_.ConsumedUnits}},
        @{Name="AvailableLicenses"; Expression={
            $_.PrepaidUnits.Enabled - $_.ConsumedUnits
        }}

    $Report | Export-Csv -Path $OutputPath -NoTypeInformation -ErrorAction Stop

    Write-Host "License report exported: $OutputPath"
    Write-Host "Licenses found: $($Licenses.Count)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}