<#
.SYNOPSIS
Exports Microsoft 365 users to a CSV file.

.AUTHOR
Niranjan Babu

.VERSION
1.3.0
#>

param(
    [string]$OutputPath = ".\Users.csv"
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

    $Users = Get-MgUser -All -ErrorAction Stop |
        Select-Object DisplayName, UserPrincipalName, Id

    $Users | Export-Csv -Path $OutputPath -NoTypeInformation -ErrorAction Stop

    Write-Host "Export completed: $OutputPath"
    Write-Host "Users exported: $($Users.Count)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}