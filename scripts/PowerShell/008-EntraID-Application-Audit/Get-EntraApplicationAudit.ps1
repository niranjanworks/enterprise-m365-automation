<#
.SYNOPSIS
    Audits Microsoft Entra ID application registrations and
    enterprise applications / service principals.

.DESCRIPTION
    Collects and analyzes:

      Application Registrations
        - Application identity
        - Sign-in audience
        - Publisher information
        - API permission resource count
        - Password credentials
        - Certificate credentials
        - Credential expiration status

      Enterprise Applications / Service Principals
        - Service principal identity
        - Enabled/disabled state
        - Publisher
        - Microsoft first-party classification
        - Owners
        - OAuth2 delegated permission grants
        - Application role assignments
        - Password credentials
        - Certificate credentials
        - Credential expiration status
        - Security findings

    The script is designed for multi-tenant enterprise environments
    and gracefully handles tenants with:
        - Zero application registrations
        - Zero service principals
        - Zero owners
        - Zero permissions
        - Zero credentials
        - Unavailable relationships

.AUTHOR
    Niranjan Babu

.VERSION
    1.1.0
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "."
)

$ErrorActionPreference = "Stop"

try {

    # ============================================================
    # CONFIGURATION
    # ============================================================

    $RequiredScopes = @(
        "Application.Read.All",
        "Directory.Read.All"
    )

    # Microsoft first-party owner organization ID
    $MicrosoftOwnerOrganizationId =
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

    # Credential warning threshold
    $CredentialWarningDays = 30

    # Known Microsoft first-party application IDs. Keep this list
    # deliberately small and add values only when they are verified.
    $KnownMicrosoftFirstPartyAppIds = @(
        # Microsoft Graph Command Line Tools / PowerShell
        "14d82eec-204b-4c2f-b7e8-296a70dab67e"

        # Microsoft Graph
        "00000003-0000-0000-c000-000000000000"
    )

    # ============================================================
    # OUTPUT DIRECTORY
    # ============================================================

    if (-not (Test-Path -Path $OutputFolder)) {

        New-Item `
            -Path $OutputFolder `
            -ItemType Directory `
            -Force |
            Out-Null
    }

    # ============================================================
    # CONNECT TO MICROSOFT GRAPH
    # ============================================================

    Write-Host "Connecting to Microsoft Graph..."

    Connect-MgGraph `
        -Scopes $RequiredScopes `
        -NoWelcome

    # ============================================================
    # APPLICATION REGISTRATIONS
    # ============================================================

    Write-Host ""
    Write-Host "Retrieving application registrations..."

    $Applications = Get-MgApplication `
        -All `
        -Property `
        Id,
        AppId,
        DisplayName,
        Description,
        SignInAudience,
        PublisherDomain,
        IsFallbackPublicClient,
        PublicClient,
        Web,
        RequiredResourceAccess,
        PasswordCredentials,
        KeyCredentials `
        -ErrorAction Stop

    Write-Host "Application registrations found: $($Applications.Count)"

    # ============================================================
    # APPLICATION REGISTRATION REPORT
    # ============================================================

    $ApplicationReport = foreach ($App in $Applications) {

        Write-Host "Processing application: $($App.DisplayName)"

        $PasswordCredentials = @(
            $App.PasswordCredentials
        )

        $KeyCredentials = @(
            $App.KeyCredentials
        )

        $CredentialRecords = @()

        # --------------------------------------------------------
        # Password credentials
        # --------------------------------------------------------

        foreach ($Credential in $PasswordCredentials) {

            $DaysRemaining = $null
            $CredentialStatus = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $CredentialStatus = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $CredentialStatus = "Expiring Soon"
                }
                else {

                    $CredentialStatus = "Healthy"
                }
            }

            $CredentialRecords += [PSCustomObject]@{
                Type          = "Password"
                KeyId         = $Credential.KeyId
                DisplayName   = $Credential.DisplayName
                StartDateTime = $Credential.StartDateTime
                EndDateTime   = $Credential.EndDateTime
                DaysRemaining = $DaysRemaining
                Status        = $CredentialStatus
            }
        }

        # --------------------------------------------------------
        # Certificate credentials
        # --------------------------------------------------------

        foreach ($Credential in $KeyCredentials) {

            $DaysRemaining = $null
            $CredentialStatus = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $CredentialStatus = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $CredentialStatus = "Expiring Soon"
                }
                else {

                    $CredentialStatus = "Healthy"
                }
            }

            $CredentialRecords += [PSCustomObject]@{
                Type          = "Certificate"
                KeyId         = $Credential.KeyId
                DisplayName   = $Credential.DisplayName
                StartDateTime = $Credential.StartDateTime
                EndDateTime   = $Credential.EndDateTime
                DaysRemaining = $DaysRemaining
                Status        = $CredentialStatus
            }
        }

        $ExpiredCredentialCount = @(
            $CredentialRecords |
            Where-Object {
                $_.Status -eq "Expired"
            }
        ).Count

        $ExpiringCredentialCount = @(
            $CredentialRecords |
            Where-Object {
                $_.Status -eq "Expiring Soon"
            }
        ).Count

        [PSCustomObject]@{

            ObjectType =
                "ApplicationRegistration"

            ObjectId =
                $App.Id

            AppId =
                $App.AppId

            DisplayName =
                $App.DisplayName

            Description =
                $App.Description

            SignInAudience =
                $App.SignInAudience

            PublisherDomain =
                $App.PublisherDomain

            PasswordCredentialCount =
                $PasswordCredentials.Count

            CertificateCredentialCount =
                $KeyCredentials.Count

            ApiPermissionResourceCount =
                @(
                    $App.RequiredResourceAccess
                ).Count

            ExpiredCredentialCount =
                $ExpiredCredentialCount

            ExpiringCredentialCount =
                $ExpiringCredentialCount

            ApplicationStatus =
                "Enabled"
        }
    }

    # ============================================================
    # ENTERPRISE APPLICATIONS / SERVICE PRINCIPALS
    # ============================================================

    Write-Host ""
    Write-Host "Retrieving enterprise applications / service principals..."

    $ServicePrincipals = Get-MgServicePrincipal `
        -All `
        -Property `
        Id,
        AppId,
        DisplayName,
        AccountEnabled,
        ServicePrincipalType,
        AppOwnerOrganizationId,
        PublisherName,
        Homepage,
        LoginUrl,
        Tags,
        PasswordCredentials,
        KeyCredentials `
        -ErrorAction Stop

    Write-Host "Enterprise applications found: $($ServicePrincipals.Count)"

    # ============================================================
    # SERVICE PRINCIPAL REPORT
    # ============================================================

    $ServicePrincipalReport = foreach ($SP in $ServicePrincipals) {

        Write-Host "Processing enterprise application: $($SP.DisplayName)"

        # --------------------------------------------------------
        # Owners
        # --------------------------------------------------------

        $Owners = @()

        try {

            $Owners = @(
                Get-MgServicePrincipalOwner `
                    -ServicePrincipalId $SP.Id `
                    -All `
                    -ErrorAction Stop
            )
        }
        catch {

            $Owners = @()
        }

        # --------------------------------------------------------
        # OAuth2 delegated permission grants
        # --------------------------------------------------------

        $OAuth2Grants = @()

        try {

            $OAuth2Grants = @(
                Get-MgServicePrincipalOauth2PermissionGrant `
                    -ServicePrincipalId $SP.Id `
                    -All `
                    -ErrorAction Stop
            )
        }
        catch {

            $OAuth2Grants = @()
        }

        # --------------------------------------------------------
        # Application role assignments
        # --------------------------------------------------------

        $AppRoleAssignments = @()

        try {

            $AppRoleAssignments = @(
                Get-MgServicePrincipalAppRoleAssignedTo `
                    -ServicePrincipalId $SP.Id `
                    -All `
                    -ErrorAction Stop
            )
        }
        catch {

            $AppRoleAssignments = @()
        }

        # --------------------------------------------------------
        # Credentials
        # --------------------------------------------------------

        $PasswordCredentials = @(
            $SP.PasswordCredentials
        )

        $KeyCredentials = @(
            $SP.KeyCredentials
        )

        $CredentialRecords = @()

        # Password credentials
        foreach ($Credential in $PasswordCredentials) {

            $DaysRemaining = $null
            $CredentialStatus = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $CredentialStatus = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $CredentialStatus = "Expiring Soon"
                }
                else {

                    $CredentialStatus = "Healthy"
                }
            }

            $CredentialRecords += [PSCustomObject]@{
                Type          = "Password"
                KeyId         = $Credential.KeyId
                DisplayName   = $Credential.DisplayName
                StartDateTime = $Credential.StartDateTime
                EndDateTime   = $Credential.EndDateTime
                DaysRemaining = $DaysRemaining
                Status        = $CredentialStatus
            }
        }

        # Certificate credentials
        foreach ($Credential in $KeyCredentials) {

            $DaysRemaining = $null
            $CredentialStatus = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $CredentialStatus = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $CredentialStatus = "Expiring Soon"
                }
                else {

                    $CredentialStatus = "Healthy"
                }
            }

            $CredentialRecords += [PSCustomObject]@{
                Type          = "Certificate"
                KeyId         = $Credential.KeyId
                DisplayName   = $Credential.DisplayName
                StartDateTime = $Credential.StartDateTime
                EndDateTime   = $Credential.EndDateTime
                DaysRemaining = $DaysRemaining
                Status        = $CredentialStatus
            }
        }

        $ExpiredCredentialCount = @(
            $CredentialRecords |
            Where-Object {
                $_.Status -eq "Expired"
            }
        ).Count

        $ExpiringCredentialCount = @(
            $CredentialRecords |
            Where-Object {
                $_.Status -eq "Expiring Soon"
            }
        ).Count

        # ========================================================
        # APPLICATION CLASSIFICATION
        # ========================================================

        $ApplicationClassification = "Unknown"

        # Strong Microsoft ownership signal
        if (
            $SP.AppOwnerOrganizationId -eq
            $MicrosoftOwnerOrganizationId
        ) {

            $ApplicationClassification =
                "MicrosoftFirstParty"
        }

        # Verified Microsoft first-party application ID
        elseif (
            $SP.AppId -and
            $KnownMicrosoftFirstPartyAppIds -contains $SP.AppId
        ) {

            $ApplicationClassification =
                "MicrosoftFirstParty"
        }

        # Publisher-provided Microsoft signal
        elseif (
            $SP.PublisherName -and
            $SP.PublisherName -match "(?i)^Microsoft"
        ) {

            $ApplicationClassification =
                "MicrosoftFirstParty"
        }

        # Secondary service-name heuristic for Microsoft services
        elseif (
            $SP.DisplayName -and
            (
                $SP.DisplayName -match "(?i)^Microsoft(?: |$)" -or
                $SP.DisplayName -match "(?i)^Office 365" -or
                $SP.DisplayName -match "(?i)^Windows " -or
                $SP.DisplayName -match "(?i)^Azure "
            )
        ) {

            $ApplicationClassification =
                "MicrosoftFirstParty"
        }

        # Do not classify an application as third-party when the
        # directory has not returned publisher or owner metadata.
        elseif (
            -not $SP.PublisherName -and
            -not $SP.AppOwnerOrganizationId
        ) {

            $ApplicationClassification =
                "Unknown"
        }

        else {

            $ApplicationClassification =
                "ThirdPartyOrCustomer"
        }

        $IsMicrosoftOwned = (
            $ApplicationClassification -eq "MicrosoftFirstParty"
        )

        # ========================================================
        # SECURITY FINDINGS
        # ========================================================

        $Findings =
            [System.Collections.Generic.List[string]]::new()

        # Disabled application
        if (-not $SP.AccountEnabled) {

            $Findings.Add(
                "Enterprise application is disabled"
            )
        }

        # Expired credentials
        if (
            $ExpiredCredentialCount -gt 0
        ) {

            $Findings.Add(
                "Contains expired credentials"
            )
        }

        # Expiring credentials
        if (
            $ExpiringCredentialCount -gt 0
        ) {

            $Findings.Add(
                "Credential expires within 30 days"
            )
        }

        # Ownerless application
        if (
            $Owners.Count -eq 0 -and
            -not $IsMicrosoftOwned
        ) {

            $Findings.Add(
                "No owners returned"
            )
        }

        # Microsoft first-party ownerless application
        if (
            $Owners.Count -eq 0 -and
            $IsMicrosoftOwned
        ) {

            $Findings.Add(
                "No owners returned; Microsoft first-party application"
            )
        }

        # No permissions
        if (
            $OAuth2Grants.Count -eq 0 -and
            $AppRoleAssignments.Count -eq 0
        ) {

            $Findings.Add(
                "No delegated or application permissions detected"
            )
        }

        # ========================================================
        # FINDING SEVERITY
        # ========================================================

        $FindingStatus = "Informational"

        if (
            $ExpiredCredentialCount -gt 0
        ) {

            $FindingStatus = "High"
        }
        elseif (
            $ExpiringCredentialCount -gt 0
        ) {

            $FindingStatus = "Medium"
        }
        elseif (
            $Owners.Count -eq 0 -and
            -not $IsMicrosoftOwned
        ) {

            $FindingStatus = "Medium"
        }
        elseif (
            $Owners.Count -eq 0 -and
            $IsMicrosoftOwned
        ) {

            $FindingStatus = "Informational"
        }

        # ========================================================
        # REPORT OBJECT
        # ========================================================

        [PSCustomObject]@{

            ObjectType =
                "EnterpriseApplication"

            ObjectId =
                $SP.Id

            AppId =
                $SP.AppId

            DisplayName =
                $SP.DisplayName

            AccountEnabled =
                $SP.AccountEnabled

            ServicePrincipalType =
                $SP.ServicePrincipalType

            PublisherName =
                $SP.PublisherName

            AppOwnerOrganizationId =
                $SP.AppOwnerOrganizationId

            ApplicationClassification =
                $ApplicationClassification

            IsMicrosoftOwned =
                $IsMicrosoftOwned

            OwnerCount =
                $Owners.Count

            OAuth2GrantCount =
                $OAuth2Grants.Count

            AppRoleAssignmentCount =
                $AppRoleAssignments.Count

            PasswordCredentialCount =
                $PasswordCredentials.Count

            CertificateCredentialCount =
                $KeyCredentials.Count

            ExpiredCredentialCount =
                $ExpiredCredentialCount

            ExpiringCredentialCount =
                $ExpiringCredentialCount

            Homepage =
                $SP.Homepage

            LoginUrl =
                $SP.LoginUrl

            Tags =
                ($SP.Tags -join ";")

            FindingStatus =
                $FindingStatus

            Findings =
                ($Findings -join "; ")
        }
    }

    # ============================================================
    # CREDENTIAL DETAIL REPORT
    # ============================================================

    Write-Host ""
    Write-Host "Building credential audit..."

    $CredentialReport =
        [System.Collections.Generic.List[object]]::new()

    # ------------------------------------------------------------
    # Application registration credentials
    # ------------------------------------------------------------

    foreach ($App in $Applications) {

        foreach (
            $Credential in
            @($App.PasswordCredentials)
        ) {

            $DaysRemaining = $null
            $Status = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $Status = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $Status = "Expiring Soon"
                }
                else {

                    $Status = "Healthy"
                }
            }

            $CredentialReport.Add(
                [PSCustomObject]@{

                    ObjectType =
                        "ApplicationRegistration"

                    ObjectId =
                        $App.Id

                    AppId =
                        $App.AppId

                    DisplayName =
                        $App.DisplayName

                    CredentialType =
                        "Password"

                    CredentialId =
                        $Credential.KeyId

                    CredentialName =
                        $Credential.DisplayName

                    StartDateTime =
                        $Credential.StartDateTime

                    EndDateTime =
                        $Credential.EndDateTime

                    DaysRemaining =
                        $DaysRemaining

                    CredentialStatus =
                        $Status
                }
            )
        }

        foreach (
            $Credential in
            @($App.KeyCredentials)
        ) {

            $DaysRemaining = $null
            $Status = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $Status = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $Status = "Expiring Soon"
                }
                else {

                    $Status = "Healthy"
                }
            }

            $CredentialReport.Add(
                [PSCustomObject]@{

                    ObjectType =
                        "ApplicationRegistration"

                    ObjectId =
                        $App.Id

                    AppId =
                        $App.AppId

                    DisplayName =
                        $App.DisplayName

                    CredentialType =
                        "Certificate"

                    CredentialId =
                        $Credential.KeyId

                    CredentialName =
                        $Credential.DisplayName

                    StartDateTime =
                        $Credential.StartDateTime

                    EndDateTime =
                        $Credential.EndDateTime

                    DaysRemaining =
                        $DaysRemaining

                    CredentialStatus =
                        $Status
                }
            )
        }
    }

    # ------------------------------------------------------------
    # Service principal credentials
    # ------------------------------------------------------------

    foreach ($SP in $ServicePrincipals) {

        foreach (
            $Credential in
            @($SP.PasswordCredentials)
        ) {

            $DaysRemaining = $null
            $Status = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $Status = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $Status = "Expiring Soon"
                }
                else {

                    $Status = "Healthy"
                }
            }

            $CredentialReport.Add(
                [PSCustomObject]@{

                    ObjectType =
                        "EnterpriseApplication"

                    ObjectId =
                        $SP.Id

                    AppId =
                        $SP.AppId

                    DisplayName =
                        $SP.DisplayName

                    CredentialType =
                        "Password"

                    CredentialId =
                        $Credential.KeyId

                    CredentialName =
                        $Credential.DisplayName

                    StartDateTime =
                        $Credential.StartDateTime

                    EndDateTime =
                        $Credential.EndDateTime

                    DaysRemaining =
                        $DaysRemaining

                    CredentialStatus =
                        $Status
                }
            )
        }

        foreach (
            $Credential in
            @($SP.KeyCredentials)
        ) {

            $DaysRemaining = $null
            $Status = "No Expiration"

            if ($Credential.EndDateTime) {

                $DaysRemaining = [math]::Floor(
                    (
                        $Credential.EndDateTime -
                        (Get-Date)
                    ).TotalDays
                )

                if ($DaysRemaining -lt 0) {

                    $Status = "Expired"
                }
                elseif (
                    $DaysRemaining -le
                    $CredentialWarningDays
                ) {

                    $Status = "Expiring Soon"
                }
                else {

                    $Status = "Healthy"
                }
            }

            $CredentialReport.Add(
                [PSCustomObject]@{

                    ObjectType =
                        "EnterpriseApplication"

                    ObjectId =
                        $SP.Id

                    AppId =
                        $SP.AppId

                    DisplayName =
                        $SP.DisplayName

                    CredentialType =
                        "Certificate"

                    CredentialId =
                        $Credential.KeyId

                    CredentialName =
                        $Credential.DisplayName

                    StartDateTime =
                        $Credential.StartDateTime

                    EndDateTime =
                        $Credential.EndDateTime

                    DaysRemaining =
                        $DaysRemaining

                    CredentialStatus =
                        $Status
                }
            )
        }
    }

    # ============================================================
    # EXPORT REPORTS
    # ============================================================

    $ApplicationPath =
        Join-Path `
            $OutputFolder `
            "Entra-Application-Registration-Audit.csv"

    $ServicePrincipalPath =
        Join-Path `
            $OutputFolder `
            "Entra-Enterprise-Application-Audit.csv"

    $CredentialPath =
        Join-Path `
            $OutputFolder `
            "Entra-Application-Credential-Audit.csv"

    $ApplicationReport |
        Export-Csv `
            -Path $ApplicationPath `
            -NoTypeInformation

    $ServicePrincipalReport |
        Export-Csv `
            -Path $ServicePrincipalPath `
            -NoTypeInformation

    $CredentialReport |
        Export-Csv `
            -Path $CredentialPath `
            -NoTypeInformation

    # ============================================================
    # SUMMARY
    # ============================================================

    $HighFindings = @(
        $ServicePrincipalReport |
        Where-Object {
            $_.FindingStatus -eq "High"
        }
    ).Count

    $MediumFindings = @(
        $ServicePrincipalReport |
        Where-Object {
            $_.FindingStatus -eq "Medium"
        }
    ).Count

    $ExpiredCredentials = @(
        $CredentialReport |
        Where-Object {
            $_.CredentialStatus -eq "Expired"
        }
    ).Count

    $ExpiringCredentials = @(
        $CredentialReport |
        Where-Object {
            $_.CredentialStatus -eq "Expiring Soon"
        }
    ).Count

    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    Write-Host ""
    Write-Host "============================================"
    Write-Host "Entra Application Audit Complete"
    Write-Host "============================================"

    Write-Host "Application registrations : $($Applications.Count)"
    Write-Host "Enterprise applications   : $($ServicePrincipals.Count)"
    Write-Host "Credential records        : $($CredentialReport.Count)"

    Write-Host ""

    Write-Host "High findings             : $HighFindings"
    Write-Host "Medium findings           : $MediumFindings"
    Write-Host "Expired credentials       : $ExpiredCredentials"
    Write-Host "Expiring credentials      : $ExpiringCredentials"

    Write-Host ""

    Write-Host "Application report        : $ApplicationPath"
    Write-Host "Enterprise app report     : $ServicePrincipalPath"
    Write-Host "Credential report         : $CredentialPath"

    Write-Host "============================================"
}
catch {

    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" `
        -ForegroundColor Red

    exit 1
}
