<#
.SYNOPSIS
Audits Microsoft Entra ID privileged role assignments.

.DESCRIPTION
Retrieves active directory role assignments and eligible/PIM role
assignments from Microsoft Graph. Resolves role definitions and
principal details dynamically and exports detailed and summary reports.

.AUTHOR
Niranjan Babu

.VERSION
2.1.0
#>

param(
    [string]$OutputFolder = "."
)

try {

    if (-not (Test-Path -Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        Write-Host "Created output folder: $OutputFolder"
    }

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph `
        -Scopes "RoleManagement.Read.Directory","Directory.Read.All" `
        -NoWelcome

    function Get-PrincipalDetails {
        param(
            [string]$PrincipalId
        )

        try {
            $Principal = Get-MgDirectoryObject `
                -DirectoryObjectId $PrincipalId `
                -ErrorAction Stop

            $PrincipalType = $Principal.AdditionalProperties['@odata.type']
            $PrincipalName = $Principal.AdditionalProperties['displayName']

            $UserPrincipalName = $null
            $AccountEnabled = $null
            $UserType = $null

            if ($PrincipalType -eq "#microsoft.graph.user") {
                try {
                    $User = Get-MgUser `
                        -UserId $PrincipalId `
                        -Property DisplayName,UserPrincipalName,AccountEnabled,UserType `
                        -ErrorAction Stop

                    $PrincipalName = $User.DisplayName
                    $UserPrincipalName = $User.UserPrincipalName
                    $AccountEnabled = $User.AccountEnabled
                    $UserType = $User.UserType
                }
                catch {
                }
            }

            return [PSCustomObject]@{
                PrincipalType     = $PrincipalType
                PrincipalName     = $PrincipalName
                UserPrincipalName = $UserPrincipalName
                AccountEnabled    = $AccountEnabled
                UserType          = $UserType
            }
        }
        catch {
            return [PSCustomObject]@{
                PrincipalType     = $null
                PrincipalName     = $null
                UserPrincipalName = $null
                AccountEnabled    = $null
                UserType          = $null
            }
        }
    }

    # ------------------------------------------------------------
    # ACTIVE ROLE ASSIGNMENTS
    # ------------------------------------------------------------

    Write-Host "Retrieving active role assignments..."

    $ActiveAssignments = Get-MgRoleManagementDirectoryRoleAssignment `
        -All `
        -ErrorAction Stop

    $ActiveReport = foreach ($Assignment in $ActiveAssignments) {

        Write-Host "Processing active assignment: $($Assignment.Id)"

        $Role = Get-MgRoleManagementDirectoryRoleDefinition `
            -UnifiedRoleDefinitionId $Assignment.RoleDefinitionId `
            -ErrorAction SilentlyContinue

        $Principal = Get-PrincipalDetails `
            -PrincipalId $Assignment.PrincipalId

        [PSCustomObject]@{
            AssignmentType    = "Active"
            AccessStatus      = "Active"
            AssignmentId      = $Assignment.Id
            PrincipalId       = $Assignment.PrincipalId
            PrincipalType     = $Principal.PrincipalType
            PrincipalName     = $Principal.PrincipalName
            UserPrincipalName = $Principal.UserPrincipalName
            AccountEnabled    = $Principal.AccountEnabled
            UserType          = $Principal.UserType
            RoleDefinitionId  = $Assignment.RoleDefinitionId
            RoleName          = $Role.DisplayName
            RoleDescription   = $Role.Description
            IsBuiltInRole     = $Role.IsBuiltIn
            IsRoleEnabled     = $Role.IsEnabled
            DirectoryScopeId  = $Assignment.DirectoryScopeId
            StartDateTime     = $null
            EndDateTime       = $null
        }
    }

    # ------------------------------------------------------------
    # ELIGIBLE / PIM ROLE ASSIGNMENTS
    # ------------------------------------------------------------

    Write-Host "Retrieving eligible/PIM role assignments..."

    $EligibleAssignments = @()

    try {

        $EligibleAssignments =
            Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance `
            -All `
            -ErrorAction Stop

        Write-Host "Eligible assignments found: $($EligibleAssignments.Count)"
    }
    catch {

        if ($_.Exception.Message -match "PremiumLicenseRequired|AadPremiumLicenseRequired|P2|Governance") {

            Write-Host `
                "PIM eligible assignments unavailable because the required Entra licensing is not available." `
                -ForegroundColor Yellow
        }
        else {

            Write-Host `
                "Unable to retrieve eligible assignments: $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }
    }

    $EligibleReport = foreach ($Assignment in $EligibleAssignments) {

        Write-Host "Processing eligible assignment: $($Assignment.Id)"

        $Role = $null

        try {
            $Role = Get-MgRoleManagementDirectoryRoleDefinition `
                -UnifiedRoleDefinitionId $Assignment.RoleDefinitionId `
                -ErrorAction Stop
        }
        catch {
        }

        $Principal = Get-PrincipalDetails `
            -PrincipalId $Assignment.PrincipalId

        [PSCustomObject]@{
            AssignmentType            = "Eligible"
            AccessStatus              = "Eligible"
            EligibilityInstanceId    = $Assignment.Id
            PrincipalId               = $Assignment.PrincipalId
            PrincipalType             = $Principal.PrincipalType
            PrincipalName             = $Principal.PrincipalName
            UserPrincipalName         = $Principal.UserPrincipalName
            AccountEnabled            = $Principal.AccountEnabled
            UserType                  = $Principal.UserType
            RoleDefinitionId          = $Assignment.RoleDefinitionId
            RoleName                  = $Role.DisplayName
            RoleDescription           = $Role.Description
            IsBuiltInRole             = $Role.IsBuiltIn
            IsRoleEnabled             = $Role.IsEnabled
            MemberType                = $Assignment.MemberType
            DirectoryScopeId          = $Assignment.DirectoryScopeId
            RoleEligibilityScheduleId = $Assignment.RoleEligibilityScheduleId
            StartDateTime             = $Assignment.StartDateTime
            EndDateTime               = $Assignment.EndDateTime
        }
    }

    # ------------------------------------------------------------
    # COMBINED SUMMARY
    # ------------------------------------------------------------

    $SummaryReport = @()

    foreach ($Item in $ActiveReport) {
        $SummaryReport += [PSCustomObject]@{
            AccessStatus      = $Item.AccessStatus
            PrincipalId       = $Item.PrincipalId
            PrincipalType     = $Item.PrincipalType
            PrincipalName     = $Item.PrincipalName
            UserPrincipalName = $Item.UserPrincipalName
            RoleDefinitionId  = $Item.RoleDefinitionId
            RoleName          = $Item.RoleName
            DirectoryScopeId  = $Item.DirectoryScopeId
            StartDateTime     = $Item.StartDateTime
            EndDateTime       = $Item.EndDateTime
        }
    }

    foreach ($Item in $EligibleReport) {
        $SummaryReport += [PSCustomObject]@{
            AccessStatus      = $Item.AccessStatus
            PrincipalId       = $Item.PrincipalId
            PrincipalType     = $Item.PrincipalType
            PrincipalName     = $Item.PrincipalName
            UserPrincipalName = $Item.UserPrincipalName
            RoleDefinitionId  = $Item.RoleDefinitionId
            RoleName          = $Item.RoleName
            DirectoryScopeId  = $Item.DirectoryScopeId
            StartDateTime     = $Item.StartDateTime
            EndDateTime       = $Item.EndDateTime
        }
    }

    # ------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------

    $ActivePath = Join-Path `
        $OutputFolder `
        "Entra-Privileged-Role-Active.csv"

    $EligiblePath = Join-Path `
        $OutputFolder `
        "Entra-Privileged-Role-Eligible.csv"

    $SummaryPath = Join-Path `
        $OutputFolder `
        "Entra-Privileged-Role-Summary.csv"

    $ActiveReport | Export-Csv `
        -Path $ActivePath `
        -NoTypeInformation `
        -ErrorAction Stop

    $EligibleReport | Export-Csv `
        -Path $EligiblePath `
        -NoTypeInformation `
        -ErrorAction Stop

    $SummaryReport | Export-Csv `
        -Path $SummaryPath `
        -NoTypeInformation `
        -ErrorAction Stop

    # ------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------

    Write-Host ""
    Write-Host "============================================"
    Write-Host "Entra Privileged Role Audit Complete"
    Write-Host "============================================"
    Write-Host "Active assignments   : $($ActiveReport.Count)"
    Write-Host "Eligible assignments : $($EligibleReport.Count)"
    Write-Host "Total privileged     : $($SummaryReport.Count)"
    Write-Host ""
    Write-Host "Active report        : $ActivePath"
    Write-Host "Eligible report      : $EligiblePath"
    Write-Host "Summary report       : $SummaryPath"
    Write-Host "============================================"
}
catch {

    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}