<#
.SYNOPSIS
Exports Microsoft 365 users to a CSV file.

.AUTHOR
Niranjan Babu

.VERSION
1.2.0
#>

param(
    [string]$OutputPath = ".\Users.csv"
)

$OutputFolder = Split-Path -Path $OutputPath -Parent

if ($OutputFolder -and -not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    Write-Host "Created folder: $OutputFolder"
}

Connect-MgGraph -Scopes "User.Read.All" -NoWelcome

$Users = Get-MgUser -All |
    Select-Object DisplayName, UserPrincipalName, Id

$Users | Export-Csv -Path $OutputPath -NoTypeInformation

Write-Host "Export completed: $OutputPath"