<#
.SYNOPSIS
Audits Microsoft Entra ID user accounts.

.AUTHOR
Niranjan Babu

.VERSION
1.1.0
#>

param(
    [string]$OutputPath = ".\Entra-User-Audit.csv"
)

try {
    $OutputFolder = Split-Path -Path $OutputPath -Parent

    if ($OutputFolder -and -not (Test-Path -Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-Host "Created folder: $OutputFolder"
    }

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph -Scopes "User.Read.All" -NoWelcome

    Write-Host "Retrieving Entra ID users..."

    $Users = Get-MgUser -All `
        -Property DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,CreatedDateTime,JobTitle,Department `
        -ErrorAction Stop

    $Report = $Users | Select-Object `
        DisplayName,
        UserPrincipalName,
        Mail,
        AccountEnabled,
        UserType,
        CreatedDateTime,
        JobTitle,
        Department

    $Report | Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -ErrorAction Stop

    Write-Host "Entra ID audit exported: $OutputPath"
    Write-Host "Users audited: $($Users.Count)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}