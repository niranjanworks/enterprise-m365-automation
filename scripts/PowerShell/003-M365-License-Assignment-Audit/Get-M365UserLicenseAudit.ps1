<#
.SYNOPSIS
Audits Microsoft 365 license assignments for users.

.AUTHOR
Niranjan Babu

.VERSION
1.2.0
#>

param(
    [string]$OutputPath = ".\M365-User-License-Audit.csv"
)

try {
    $OutputFolder = Split-Path -Path $OutputPath -Parent

    if ($OutputFolder -and -not (Test-Path -Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-Host "Created folder: $OutputFolder"
    }

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph -Scopes "User.Read.All" -NoWelcome

    Write-Host "Retrieving users..."

    $Users = Get-MgUser -All `
        -Property DisplayName,UserPrincipalName,AssignedLicenses `
        -ErrorAction Stop

    $Report = foreach ($User in $Users) {

        $LicenseCount = $User.AssignedLicenses.Count

        [PSCustomObject]@{
            DisplayName       = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            LicenseStatus     = if ($LicenseCount -gt 0) { "Licensed" } else { "Unlicensed" }
            LicenseCount      = $LicenseCount
            LicenseIds        = ($User.AssignedLicenses.SkuId -join "; ")
        }
    }

    $Report | Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -ErrorAction Stop

    Write-Host "License audit exported: $OutputPath"
    Write-Host "Users audited: $($Users.Count)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}