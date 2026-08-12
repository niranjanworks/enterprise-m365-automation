<#
.SYNOPSIS
Audits Microsoft Entra ID groups, memberships, and owners.

.AUTHOR
Niranjan Babu

.VERSION
2.0.0
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

    Connect-MgGraph -Scopes "Group.Read.All","User.Read.All" -NoWelcome

    Write-Host "Retrieving Entra ID groups..."

    $Groups = Get-MgGroup -All `
        -Property Id,DisplayName,Description,GroupTypes,SecurityEnabled,MailEnabled,Mail,MembershipRule,MembershipRuleProcessingState `
        -ErrorAction Stop

    $GroupReport = @()
    $MemberReport = @()
    $OwnerReport = @()

    foreach ($Group in $Groups) {

        Write-Host "Processing group: $($Group.DisplayName)"

        # Get group members
        $Members = Get-MgGroupMember `
            -GroupId $Group.Id `
            -All `
            -ErrorAction SilentlyContinue

        # Get group owners
        $Owners = Get-MgGroupOwner `
            -GroupId $Group.Id `
            -All `
            -ErrorAction SilentlyContinue

        # Determine group type
        $GroupType = if ($Group.GroupTypes -contains "Unified") {
            "Microsoft 365"
        }
        elseif ($Group.MailEnabled -and -not $Group.SecurityEnabled) {
            "Distribution"
        }
        elseif ($Group.SecurityEnabled) {
            "Security"
        }
        else {
            "Other"
        }

        # Group-level report
        $GroupReport += [PSCustomObject]@{
            GroupId                       = $Group.Id
            DisplayName                   = $Group.DisplayName
            GroupType                     = $GroupType
            IsDynamic                     = [bool]$Group.MembershipRule
            MemberCount                   = @($Members).Count
            OwnerCount                    = @($Owners).Count
            SecurityEnabled               = $Group.SecurityEnabled
            MailEnabled                   = $Group.MailEnabled
            Mail                          = $Group.Mail
            Description                   = $Group.Description
            MembershipRule               = $Group.MembershipRule
            MembershipRuleProcessingState = $Group.MembershipRuleProcessingState
        }

        # Member-level report
        foreach ($Member in $Members) {

            $MemberDetails = $null

            if ($Member.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user') {
                try {
                    $MemberDetails = Get-MgUser `
                        -UserId $Member.Id `
                        -Property DisplayName,UserPrincipalName,AccountEnabled,UserType,JobTitle,Department `
                        -ErrorAction Stop
                }
                catch {
                    $MemberDetails = $null
                }
            }

            $MemberReport += [PSCustomObject]@{
                GroupId           = $Group.Id
                GroupName         = $Group.DisplayName
                MemberId          = $Member.Id
                MemberType        = $Member.AdditionalProperties['@odata.type']
                MemberDisplayName = if ($MemberDetails) { $MemberDetails.DisplayName } else { $Member.AdditionalProperties['displayName'] }
                UserPrincipalName  = if ($MemberDetails) { $MemberDetails.UserPrincipalName } else { $null }
                AccountEnabled    = if ($MemberDetails) { $MemberDetails.AccountEnabled } else { $null }
                UserType          = if ($MemberDetails) { $MemberDetails.UserType } else { $null }
                JobTitle          = if ($MemberDetails) { $MemberDetails.JobTitle } else { $null }
                Department        = if ($MemberDetails) { $MemberDetails.Department } else { $null }
            }
        }

        # Owner-level report
        foreach ($Owner in $Owners) {

            $OwnerDetails = $null

            if ($Owner.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user') {
                try {
                    $OwnerDetails = Get-MgUser `
                        -UserId $Owner.Id `
                        -Property DisplayName,UserPrincipalName,AccountEnabled,UserType,JobTitle,Department `
                        -ErrorAction Stop
                }
                catch {
                    $OwnerDetails = $null
                }
            }

            $OwnerReport += [PSCustomObject]@{
                GroupId           = $Group.Id
                GroupName         = $Group.DisplayName
                OwnerId           = $Owner.Id
                OwnerType         = $Owner.AdditionalProperties['@odata.type']
                OwnerDisplayName  = if ($OwnerDetails) { $OwnerDetails.DisplayName } else { $Owner.AdditionalProperties['displayName'] }
                UserPrincipalName = if ($OwnerDetails) { $OwnerDetails.UserPrincipalName } else { $null }
                AccountEnabled    = if ($OwnerDetails) { $OwnerDetails.AccountEnabled } else { $null }
                UserType          = if ($OwnerDetails) { $OwnerDetails.UserType } else { $null }
                JobTitle          = if ($OwnerDetails) { $OwnerDetails.JobTitle } else { $null }
                Department        = if ($OwnerDetails) { $OwnerDetails.Department } else { $null }
            }
        }
    }

    # Export reports
    $GroupReport | Export-Csv `
        -Path (Join-Path $OutputFolder "Entra-Group-Audit.csv") `
        -NoTypeInformation `
        -ErrorAction Stop

    $MemberReport | Export-Csv `
        -Path (Join-Path $OutputFolder "Entra-Group-Members.csv") `
        -NoTypeInformation `
        -ErrorAction Stop

    $OwnerReport | Export-Csv `
        -Path (Join-Path $OutputFolder "Entra-Group-Owners.csv") `
        -NoTypeInformation `
        -ErrorAction Stop

    Write-Host ""
    Write-Host "Group audit exported: $OutputFolder\Entra-Group-Audit.csv"
    Write-Host "Member audit exported: $OutputFolder\Entra-Group-Members.csv"
    Write-Host "Owner audit exported: $OutputFolder\Entra-Group-Owners.csv"
    Write-Host ""
    Write-Host "Groups audited: $($Groups.Count)"
    Write-Host "Membership records: $($MemberReport.Count)"
    Write-Host "Owner records: $($OwnerReport.Count)"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}