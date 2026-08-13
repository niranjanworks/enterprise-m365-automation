<#
.SYNOPSIS
    Audits Microsoft Entra user authentication-method registrations.

.DESCRIPTION
    Retrieves the authentication methods registered for Entra users and
    produces user, method-detail, and summary reports. This script is
    read-only: it never adds, resets, deletes, or changes authentication
    methods or MFA policy.

.AUTHOR
    Niranjan Babu

.VERSION
    1.0.0
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "."
)

$ErrorActionPreference = "Stop"

function ConvertTo-AuthenticationMethodName {
    param(
        [string]$OdataType
    )

    $MethodNames = @{
        "#microsoft.graph.passwordAuthenticationMethod"                 = "Password"
        "#microsoft.graph.phoneAuthenticationMethod"                    = "Phone"
        "#microsoft.graph.emailAuthenticationMethod"                    = "Email"
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"   = "Microsoft Authenticator"
        "#microsoft.graph.fido2AuthenticationMethod"                    = "FIDO2 security key"
        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"  = "Windows Hello for Business"
        "#microsoft.graph.softwareOathAuthenticationMethod"             = "Software OATH token"
        "#microsoft.graph.temporaryAccessPassAuthenticationMethod"      = "Temporary Access Pass"
        "#microsoft.graph.passkeyAuthenticationMethod"                  = "Passkey"
        "#microsoft.graph.platformCredentialAuthenticationMethod"       = "Platform credential"
        "#microsoft.graph.externalAuthenticationMethod"                 = "External authentication method"
    }

    if ($MethodNames.ContainsKey($OdataType)) {
        return $MethodNames[$OdataType]
    }

    if ([string]::IsNullOrWhiteSpace($OdataType)) {
        return "Unknown method type"
    }

    return ($OdataType -replace "^#microsoft\.graph\.", "")
}

function New-HeaderOnlyCsv {
    param(
        [string]$Path,
        [string[]]$Columns
    )

    Set-Content `
        -Path $Path `
        -Value ('"' + ($Columns -join '","') + '"') `
        -Encoding utf8 `
        -ErrorAction Stop
}

try {

    # ============================================================
    # CONFIGURATION
    # ============================================================

    $RequiredScopes = @(
        "User.Read.All"
        "UserAuthenticationMethod.Read.All"
    )

    # ============================================================
    # OUTPUT DIRECTORY AND CONNECTION
    # ============================================================

    if (-not (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force |
            Out-Null

        Write-Host "Created output folder: $OutputFolder"
    }

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph `
        -Scopes $RequiredScopes `
        -NoWelcome

    Write-Host "Retrieving Entra users..."

    $Users = @(
        Get-MgUser `
            -All `
            -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType `
            -ErrorAction Stop
    )

    Write-Host "Users found: $($Users.Count)"

    # ============================================================
    # USER AND METHOD REPORTS
    # ============================================================

    $UserReport = [System.Collections.Generic.List[object]]::new()
    $MethodReport = [System.Collections.Generic.List[object]]::new()

    foreach ($User in $Users) {

        Write-Host "Checking authentication methods: $($User.UserPrincipalName)"

        $Methods = @()
        $ReadError = $null

        try {
            $Methods = @(
                Get-MgUserAuthenticationMethod `
                    -UserId $User.Id `
                    -All `
                    -ErrorAction Stop
            )
        }
        catch {
            $ReadError = $_.Exception.Message
        }

        $MethodNames = [System.Collections.Generic.List[string]]::new()
        $NonPasswordMethodCount = 0

        foreach ($Method in $Methods) {
            $OdataType = $Method.AdditionalProperties['@odata.type']
            $MethodName = ConvertTo-AuthenticationMethodName -OdataType $OdataType

            $MethodNames.Add($MethodName)

            if ($MethodName -ne "Password") {
                $NonPasswordMethodCount++
            }

            $MethodReport.Add(
                [PSCustomObject]@{
                    UserId            = $User.Id
                    DisplayName       = $User.DisplayName
                    UserPrincipalName = $User.UserPrincipalName
                    AccountEnabled    = $User.AccountEnabled
                    UserType          = $User.UserType
                    MethodType        = $MethodName
                    OdataType         = $OdataType
                    MethodId          = $Method.Id
                }
            )
        }

        $FindingStatus = "Informational"
        $Findings = [System.Collections.Generic.List[string]]::new()
        $AuthenticationMethodStatus = "Registered"

        if ($ReadError) {
            $AuthenticationMethodStatus = "Unable to read"
            $FindingStatus = "Medium"
            $Findings.Add("Authentication methods could not be read: $ReadError")
        }
        elseif (-not $User.AccountEnabled) {
            $AuthenticationMethodStatus = "Not evaluated - disabled account"
            $Findings.Add("Disabled account; authentication-method registration was not evaluated")
        }
        elseif ($User.UserType -eq "Guest") {
            $AuthenticationMethodStatus = "Not evaluated - guest account"
            $Findings.Add("Guest account; authentication methods may be managed by the guest's home tenant")
        }
        elseif ($NonPasswordMethodCount -eq 0) {
            $AuthenticationMethodStatus = "No non-password method registered"
            $FindingStatus = "Medium"
            $Findings.Add("Enabled member account has no non-password authentication method registered")
        }

        $UserReport.Add(
            [PSCustomObject]@{
                UserId                       = $User.Id
                DisplayName                  = $User.DisplayName
                UserPrincipalName            = $User.UserPrincipalName
                AccountEnabled               = $User.AccountEnabled
                UserType                     = $User.UserType
                RegisteredMethodCount        = $Methods.Count
                NonPasswordMethodCount       = $NonPasswordMethodCount
                RegisteredMethods            = (($MethodNames | Sort-Object -Unique) -join "; ")
                AuthenticationMethodStatus   = $AuthenticationMethodStatus
                FindingStatus                = $FindingStatus
                Findings                     = ($Findings -join "; ")
            }
        )
    }

    # ============================================================
    # SUMMARY REPORT
    # ============================================================

    $SummaryReport = @(
        [PSCustomObject]@{ Metric = "Users audited"; Count = $UserReport.Count }
        [PSCustomObject]@{ Metric = "Enabled member users"; Count = @($UserReport | Where-Object {
            $_.AccountEnabled -and $_.UserType -ne "Guest"
        }).Count }
        [PSCustomObject]@{ Metric = "Enabled members with non-password methods"; Count = @($UserReport | Where-Object {
            $_.AccountEnabled -and
            $_.UserType -ne "Guest" -and
            $_.NonPasswordMethodCount -gt 0
        }).Count }
        [PSCustomObject]@{ Metric = "Enabled members requiring review"; Count = @($UserReport | Where-Object {
            $_.AuthenticationMethodStatus -eq "No non-password method registered"
        }).Count }
        [PSCustomObject]@{ Metric = "Method-read errors"; Count = @($UserReport | Where-Object {
            $_.AuthenticationMethodStatus -eq "Unable to read"
        }).Count }
    )

    # ============================================================
    # EXPORT REPORTS
    # ============================================================

    $UserPath = Join-Path $OutputFolder "Entra-MFA-Authentication-Method-Audit.csv"
    $MethodPath = Join-Path $OutputFolder "Entra-Authentication-Method-Detail.csv"
    $SummaryPath = Join-Path $OutputFolder "Entra-MFA-Authentication-Method-Summary.csv"

    $UserReport |
        Export-Csv -Path $UserPath -NoTypeInformation -ErrorAction Stop

    if ($MethodReport.Count -gt 0) {
        $MethodReport |
            Export-Csv -Path $MethodPath -NoTypeInformation -ErrorAction Stop
    }
    else {
        New-HeaderOnlyCsv `
            -Path $MethodPath `
            -Columns @(
                "UserId", "DisplayName", "UserPrincipalName", "AccountEnabled",
                "UserType", "MethodType", "OdataType", "MethodId"
            )
    }

    $SummaryReport |
        Export-Csv -Path $SummaryPath -NoTypeInformation -ErrorAction Stop

    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    Write-Host ""
    Write-Host "============================================"
    Write-Host "MFA and Authentication Method Audit Complete"
    Write-Host "============================================"
    Write-Host "Users audited             : $($UserReport.Count)"
    Write-Host "Users requiring review    : $(@($UserReport | Where-Object { $_.FindingStatus -eq 'Medium' }).Count)"
    Write-Host ""
    Write-Host "User report               : $UserPath"
    Write-Host "Method detail report      : $MethodPath"
    Write-Host "Summary report            : $SummaryPath"
    Write-Host "============================================"
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
