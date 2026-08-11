<#
.SYNOPSIS
Audits Microsoft Entra ID sign-in activity.

.AUTHOR
Niranjan Babu

.VERSION
1.4.0
#>

param(
    [string]$OutputPath = ".\Entra-SignIn-Audit.csv",
    [int]$Days = 7
)

try {
    $OutputFolder = Split-Path -Path $OutputPath -Parent

    if ($OutputFolder -and -not (Test-Path -Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-Host "Created folder: $OutputFolder"
    }

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome

    $StartDate = (Get-Date).ToUniversalTime().AddDays(-$Days)
    $StartDateFormatted = $StartDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "Retrieving all sign-ins from the last $Days days..."

    $SignIns = Get-MgAuditLogSignIn `
        -Filter "createdDateTime ge $StartDateFormatted" `
        -All `
        -ErrorAction Stop

    $Report = $SignIns | Select-Object `
        CreatedDateTime,
        UserDisplayName,
        UserPrincipalName,
        AppDisplayName,
        ResourceDisplayName,
        IpAddress,
        IsInteractive,
        ClientAppUsed,
        ConditionalAccessStatus,
        @{Name="Country"; Expression={$_.Location.CountryOrRegion}},
        @{Name="State"; Expression={$_.Location.State}},
        @{Name="City"; Expression={$_.Location.City}},
        @{Name="OperatingSystem"; Expression={$_.DeviceDetail.OperatingSystem}},
        @{Name="Browser"; Expression={$_.DeviceDetail.Browser}},
        @{Name="RiskLevel"; Expression={$_.RiskLevelDuringSignIn}},
        @{Name="Result"; Expression={$_.Status.ErrorCode}},
        @{Name="SignInResult"; Expression={
            if ($_.Status.ErrorCode -eq 0) {
                "Success"
            }
            else {
                "Failure"
            }
        }},
        @{Name="FailureReason"; Expression={$_.Status.FailureReason}}

    $Report | Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -ErrorAction Stop

    Write-Host "Sign-in audit exported: $OutputPath"
    Write-Host "Sign-ins retrieved: $($SignIns.Count)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}