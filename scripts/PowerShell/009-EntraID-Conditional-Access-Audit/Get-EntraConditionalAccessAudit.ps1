<#
.SYNOPSIS
    Audits Microsoft Entra Conditional Access policies.

.DESCRIPTION
    Retrieves Conditional Access policies and creates a readable report of
    policy state, targeting conditions, grant controls, session controls, and
    review findings. The script is read-only: it does not create, update,
    enable, disable, or delete any Conditional Access policy.

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

function ConvertTo-AuditValue {
    param(
        [object]$Value,
        [string]$EmptyValue = "None"
    )

    if ($null -eq $Value) {
        return $EmptyValue
    }

    $Values = @(
        $Value |
        Where-Object {
            $null -ne $_ -and
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } |
        ForEach-Object {
            if ($_ -is [string]) {
                $_
            }
            elseif ($_.Id) {
                $_.Id
            }
            else {
                [string]$_
            }
        }
    )

    if ($Values.Count -eq 0) {
        return $EmptyValue
    }

    return ($Values -join "; ")
}

function Get-ConfiguredSessionControls {
    param(
        [object]$SessionControls
    )

    if ($null -eq $SessionControls) {
        return "None"
    }

    $ConfiguredControls = @(
        $SessionControls.PSObject.Properties |
        Where-Object {
            $_.Name -ne "AdditionalProperties" -and
            $null -ne $_.Value -and
            (
                $_.Value -isnot [bool] -or
                $_.Value
            )
        } |
        Select-Object -ExpandProperty Name
    )

    if ($ConfiguredControls.Count -eq 0) {
        return "None"
    }

    return ($ConfiguredControls -join "; ")
}

try {

    # ============================================================
    # CONFIGURATION
    # ============================================================

    $RequiredScopes = @(
        "Policy.Read.All"
    )

    # ============================================================
    # OUTPUT DIRECTORY
    # ============================================================

    if (-not (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force |
            Out-Null

        Write-Host "Created output folder: $OutputFolder"
    }

    # ============================================================
    # CONNECT AND RETRIEVE
    # ============================================================

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph `
        -Scopes $RequiredScopes `
        -NoWelcome

    Write-Host "Retrieving Conditional Access policies..."

    $Policies = @(
        Get-MgIdentityConditionalAccessPolicy `
            -All `
            -ErrorAction Stop
    )

    Write-Host "Conditional Access policies found: $($Policies.Count)"

    # ============================================================
    # POLICY REPORT
    # ============================================================

    $PolicyReport = foreach ($Policy in $Policies) {

        Write-Host "Processing policy: $($Policy.DisplayName)"

        $Conditions = $Policy.Conditions
        $Users = $Conditions.Users
        $Applications = $Conditions.Applications
        $Platforms = $Conditions.Platforms
        $Locations = $Conditions.Locations
        $Devices = $Conditions.Devices
        $GrantControls = $Policy.GrantControls

        $IncludeUsers = ConvertTo-AuditValue -Value $Users.IncludeUsers
        $ExcludeUsers = ConvertTo-AuditValue -Value $Users.ExcludeUsers
        $IncludeGroups = ConvertTo-AuditValue -Value $Users.IncludeGroups
        $ExcludeGroups = ConvertTo-AuditValue -Value $Users.ExcludeGroups
        $IncludeRoles = ConvertTo-AuditValue -Value $Users.IncludeRoles
        $ExcludeRoles = ConvertTo-AuditValue -Value $Users.ExcludeRoles
        $IncludeApplications = ConvertTo-AuditValue -Value $Applications.IncludeApplications
        $ExcludeApplications = ConvertTo-AuditValue -Value $Applications.ExcludeApplications
        $BuiltInControls = ConvertTo-AuditValue -Value $GrantControls.BuiltInControls
        $CustomAuthenticationFactors = ConvertTo-AuditValue -Value $GrantControls.CustomAuthenticationFactors
        $TermsOfUse = ConvertTo-AuditValue -Value $GrantControls.TermsOfUse

        $Findings = [System.Collections.Generic.List[string]]::new()
        $FindingStatus = "Informational"

        if ($Policy.State -eq "enabled") {

            if (
                $BuiltInControls -eq "None" -and
                $CustomAuthenticationFactors -eq "None" -and
                $TermsOfUse -eq "None"
            ) {
                $Findings.Add("Enabled policy has no grant control configured")
                $FindingStatus = "Medium"
            }

            if ($IncludeUsers -match "(^|; )All(;|$)") {
                $Findings.Add("Targets all users; review exclusions and emergency-access account coverage")
            }
        }
        elseif ($Policy.State -eq "enabledForReportingButNotEnforced") {
            $Findings.Add("Report-only policy; sign-ins are evaluated but controls are not enforced")
        }
        elseif ($Policy.State -eq "disabled") {
            $Findings.Add("Policy is disabled and is not enforced")
        }
        else {
            $Findings.Add("Policy state was not recognized by this audit")
        }

        [PSCustomObject]@{
            PolicyId                           = $Policy.Id
            DisplayName                        = $Policy.DisplayName
            State                              = $Policy.State
            CreatedDateTime                    = $Policy.CreatedDateTime
            ModifiedDateTime                   = $Policy.ModifiedDateTime
            IncludeUsers                       = $IncludeUsers
            ExcludeUsers                       = $ExcludeUsers
            IncludeGroups                      = $IncludeGroups
            ExcludeGroups                      = $ExcludeGroups
            IncludeRoles                       = $IncludeRoles
            ExcludeRoles                       = $ExcludeRoles
            IncludeApplications                = $IncludeApplications
            ExcludeApplications                = $ExcludeApplications
            IncludePlatforms                   = ConvertTo-AuditValue -Value $Platforms.IncludePlatforms
            ExcludePlatforms                   = ConvertTo-AuditValue -Value $Platforms.ExcludePlatforms
            IncludeLocations                   = ConvertTo-AuditValue -Value $Locations.IncludeLocations
            ExcludeLocations                   = ConvertTo-AuditValue -Value $Locations.ExcludeLocations
            ClientAppTypes                     = ConvertTo-AuditValue -Value $Conditions.ClientAppTypes
            SignInRiskLevels                   = ConvertTo-AuditValue -Value $Conditions.SignInRiskLevels
            UserRiskLevels                     = ConvertTo-AuditValue -Value $Conditions.UserRiskLevels
            ServicePrincipalRiskLevels         = ConvertTo-AuditValue -Value $Conditions.ServicePrincipalRiskLevels
            DeviceFilterMode                   = $Devices.DeviceFilter.Mode
            DeviceFilterRule                   = $Devices.DeviceFilter.Rule
            GrantControlOperator               = $GrantControls.Operator
            BuiltInGrantControls               = $BuiltInControls
            CustomAuthenticationFactors        = $CustomAuthenticationFactors
            TermsOfUse                         = $TermsOfUse
            SessionControlsConfigured          = Get-ConfiguredSessionControls -SessionControls $Policy.SessionControls
            FindingStatus                      = $FindingStatus
            Findings                           = ($Findings -join "; ")
        }
    }

    # ============================================================
    # SUMMARY REPORT
    # ============================================================

    $SummaryReport = @(
        [PSCustomObject]@{
            Metric = "Total policies"
            Count  = $PolicyReport.Count
        }
        [PSCustomObject]@{
            Metric = "Enabled policies"
            Count  = @($PolicyReport | Where-Object { $_.State -eq "enabled" }).Count
        }
        [PSCustomObject]@{
            Metric = "Report-only policies"
            Count  = @($PolicyReport | Where-Object {
                $_.State -eq "enabledForReportingButNotEnforced"
            }).Count
        }
        [PSCustomObject]@{
            Metric = "Disabled policies"
            Count  = @($PolicyReport | Where-Object { $_.State -eq "disabled" }).Count
        }
        [PSCustomObject]@{
            Metric = "Medium findings"
            Count  = @($PolicyReport | Where-Object {
                $_.FindingStatus -eq "Medium"
            }).Count
        }
    )

    # ============================================================
    # EXPORT REPORTS
    # ============================================================

    $PolicyPath = Join-Path `
        $OutputFolder `
        "Entra-Conditional-Access-Policy-Audit.csv"

    $SummaryPath = Join-Path `
        $OutputFolder `
        "Entra-Conditional-Access-Policy-Summary.csv"

    if ($PolicyReport.Count -gt 0) {

        $PolicyReport |
            Export-Csv `
                -Path $PolicyPath `
                -NoTypeInformation `
                -ErrorAction Stop
    }
    else {

        # Keep a stable, header-only CSV schema for a new tenant with
        # no Conditional Access policies. This makes the output safe for
        # Excel, Power BI, scheduled reporting, and later comparisons.
        $PolicyColumns = @(
            "PolicyId"
            "DisplayName"
            "State"
            "CreatedDateTime"
            "ModifiedDateTime"
            "IncludeUsers"
            "ExcludeUsers"
            "IncludeGroups"
            "ExcludeGroups"
            "IncludeRoles"
            "ExcludeRoles"
            "IncludeApplications"
            "ExcludeApplications"
            "IncludePlatforms"
            "ExcludePlatforms"
            "IncludeLocations"
            "ExcludeLocations"
            "ClientAppTypes"
            "SignInRiskLevels"
            "UserRiskLevels"
            "ServicePrincipalRiskLevels"
            "DeviceFilterMode"
            "DeviceFilterRule"
            "GrantControlOperator"
            "BuiltInGrantControls"
            "CustomAuthenticationFactors"
            "TermsOfUse"
            "SessionControlsConfigured"
            "FindingStatus"
            "Findings"
        )

        Set-Content `
            -Path $PolicyPath `
            -Value ('"' + ($PolicyColumns -join '","') + '"') `
            -Encoding utf8 `
            -ErrorAction Stop
    }

    $SummaryReport |
        Export-Csv `
            -Path $SummaryPath `
            -NoTypeInformation `
            -ErrorAction Stop

    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    Write-Host ""
    Write-Host "============================================"
    Write-Host "Conditional Access Policy Audit Complete"
    Write-Host "============================================"
    Write-Host "Policies audited : $($PolicyReport.Count)"
    Write-Host "Enabled policies : $(@($PolicyReport | Where-Object { $_.State -eq 'enabled' }).Count)"
    Write-Host "Medium findings  : $(@($PolicyReport | Where-Object { $_.FindingStatus -eq 'Medium' }).Count)"
    Write-Host ""
    Write-Host "Policy report    : $PolicyPath"
    Write-Host "Summary report   : $SummaryPath"
    Write-Host "============================================"
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
