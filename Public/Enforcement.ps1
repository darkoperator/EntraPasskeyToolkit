#region Enforcement: authentication strengths and Conditional Access (Part 3) ---

# Built-in authentication strength IDs (identical in every tenant).
$script:EptBuiltInStrength = @{
    Mfa               = '00000000-0000-0000-0000-000000000002'
    Passwordless      = '00000000-0000-0000-0000-000000000003'
    PhishingResistant = '00000000-0000-0000-0000-000000000004'
}

# The 14 roles in Microsoft's "Require phishing-resistant MFA for administrators" template.
$script:EptAdminRoleName = @(
    'Global Administrator', 'Application Administrator', 'Authentication Administrator',
    'Billing Administrator', 'Cloud Application Administrator', 'Conditional Access Administrator',
    'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator',
    'Privileged Authentication Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'SharePoint Administrator', 'User Administrator'
)

function Get-EptAuthenticationStrength {
    <#
    .SYNOPSIS
        Lists built-in and custom authentication strengths with their allowed method combinations.
    .DESCRIPTION
        GET /policies/authenticationStrengthPolicies (v1.0). Output exposes StrengthId, which binds by
        property name to New-EptStrengthPolicy -AuthenticationStrengthId.
        Requires: Policy.Read.All (or Policy.Read.AuthenticationMethod).
    .EXAMPLE
        Get-EptAuthenticationStrength | Format-Table Name, PolicyType, AllowsPhishable
    .EXAMPLE
        Get-EptAuthenticationStrength -Name 'Admin*' | New-EptStrengthPolicy -DisplayName 'CA101 Admins - custom strength' -AdminRoles -ExcludeGroupId $bg
    #>
    [CmdletBinding()]
    [OutputType('Ept.AuthenticationStrength')]
    param(
        [SupportsWildcards()]
        [string] $Name = '*'
    )
    Assert-EptGraphConnection -RequiredScope 'Policy.Read.All'
    $phishable = 'sms|voice|softwareOath|hardwareOath|microsoftAuthenticatorPush|deviceBasedPush|temporaryAccessPass|email|federated|qrCodePin|password'

    Invoke-EptGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies' |
        Where-Object displayName -Like $Name |
        ForEach-Object {
            $aaguids = @($_.combinationConfigurations | Where-Object allowedAAGUIDs | ForEach-Object allowedAAGUIDs)
            [pscustomobject]@{
                PSTypeName          = 'Ept.AuthenticationStrength'
                StrengthId          = $_.id
                Name                = $_.displayName
                PolicyType          = $_.policyType
                AllowedCombinations = @($_.allowedCombinations)
                AllowsPhishable     = [bool](@($_.allowedCombinations) -match $phishable)
                RestrictedAaguids   = $aaguids
            }
        }
}

function New-EptAuthenticationStrength {
    <#
    .SYNOPSIS
        Creates a custom authentication strength, optionally pinning passkeys to approved AAGUIDs.
    .DESCRIPTION
        WRITE OPERATION. POST /policies/authenticationStrengthPolicies (v1.0).
        The typical use is a "privileged" strength that only accepts FIDO2 keys from an approved
        model list, plus Windows Hello for Business and multifactor certificates.
        Tenants can hold up to 15 custom strengths.
        AAGUID restriction is only a hard control when attestation is enforced on the matching
        passkey profile; otherwise an authenticator can claim any AAGUID.
        Requires: Policy.ReadWrite.ConditionalAccess + Conditional Access Administrator or Security Administrator.
    .EXAMPLE
        New-EptAuthenticationStrength -DisplayName 'Admins - approved security keys' `
            -AllowedCombination fido2, windowsHelloForBusiness -AllowedAaguid $approvedKeys -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType('Ept.AuthenticationStrength')]
    param(
        [Parameter(Mandatory)]
        [string] $DisplayName,

        [string] $Description = 'Created by EntraPasskeyToolkit',

        [ValidateSet('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor', 'deviceBasedPush',
                     'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse')]
        [string[]] $AllowedCombination = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor'),

        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string[]] $AllowedAaguid
    )
    Assert-EptGraphConnection -RequiredScope 'Policy.ReadWrite.ConditionalAccess'

    $body = [ordered]@{
        displayName           = $DisplayName
        description           = $Description
        requirementsSatisfied = 'mfa'
        allowedCombinations   = @($AllowedCombination)
    }
    if ($AllowedAaguid) {
        if ($AllowedCombination -notcontains 'fido2') { throw '-AllowedAaguid requires fido2 in -AllowedCombination.' }
        $body.combinationConfigurations = @(@{
            '@odata.type'         = '#microsoft.graph.fido2CombinationConfiguration'
            appliesToCombinations = @('fido2')
            allowedAAGUIDs        = @($AllowedAaguid | ForEach-Object ToLower)
        })
    }

    if ($PSCmdlet.ShouldProcess($DisplayName, "Create authentication strength ($($AllowedCombination -join ', '))")) {
        $created = Invoke-EptGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies' -Body $body
        Get-EptAuthenticationStrength | Where-Object StrengthId -eq $created.id
    }
}

function Get-EptConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Flattens Conditional Access policies into reviewable rows with MFA-relevant flags.
    .DESCRIPTION
        GET /identity/conditionalAccess/policies (v1.0). Resolves the authentication strength name and
        flags policies that require phishing-resistant MFA, generic MFA, or block device code flow.
        It does NOT compute effective access; group nesting, exclusions and multiple policies must still
        be evaluated with the What If tool or report-only results.
        Requires: Policy.Read.All + a role such as Security Reader or Global Reader.
    .EXAMPLE
        Get-EptConditionalAccessPolicy | Where-Object RequiresPhishResistant | Format-Table Name, State, IncludeUsers, IncludeRoles
    .EXAMPLE
        Get-EptConditionalAccessPolicy | Where-Object { $_.State -eq 'enabled' -and $_.RequiresMfa -and -not $_.StrengthName }
    #>
    [CmdletBinding()]
    [OutputType('Ept.ConditionalAccessPolicy')]
    param(
        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string[]] $State
    )
    Assert-EptGraphConnection -RequiredScope 'Policy.Read.All'

    $strengths = @{}
    Get-EptAuthenticationStrength | ForEach-Object { $strengths[$_.StrengthId] = $_ }

    Invoke-EptGraphRequest -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' |
        Where-Object { -not $State -or $_.state -in $State } |
        ForEach-Object {
            $c = $_.conditions
            $g = $_.grantControls
            $strengthId = $g.authenticationStrength.id
            $strength = if ($strengthId) { $strengths[$strengthId] }
            [pscustomobject]@{
                PSTypeName             = 'Ept.ConditionalAccessPolicy'
                PolicyId               = $_.id
                Name                   = $_.displayName
                State                  = $_.state
                IncludeUsers           = @($c.users.includeUsers)
                IncludeGroups          = @($c.users.includeGroups)
                IncludeRoles           = @($c.users.includeRoles)
                ExcludeUsers           = @($c.users.excludeUsers)
                ExcludeGroups          = @($c.users.excludeGroups)
                Applications           = @($c.applications.includeApplications)
                UserActions            = @($c.applications.includeUserActions)
                ClientAppTypes         = @($c.clientAppTypes)
                TransferMethods        = $c.authenticationFlows.transferMethods
                GrantOperator          = $g.operator
                BuiltInControls        = @($g.builtInControls)
                StrengthName           = $strength.Name
                RequiresMfa            = (@($g.builtInControls) -contains 'mfa') -or [bool]$strengthId
                RequiresPhishResistant = [bool]($strength -and -not $strength.AllowsPhishable)
                BlocksDeviceCode       = (@($g.builtInControls) -contains 'block') -and ([string]$c.authenticationFlows.transferMethods -match 'deviceCodeFlow')
                SessionControls        = @($_.sessionControls.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object Name)
            }
        }
}

function New-EptStrengthPolicy {
    <#
    .SYNOPSIS
        Creates a Conditional Access policy that requires an authentication strength (report-only by default).
    .DESCRIPTION
        WRITE OPERATION. POST /identity/conditionalAccess/policies (v1.0).
        Defaults follow Microsoft's deployment guidance: built-in Phishing-resistant MFA strength,
        All resources, report-only state. -ExcludeGroupId is mandatory so that break-glass
        accounts are never forgotten.

        Accepts StrengthId from Get-EptAuthenticationStrength over the pipeline.
        Only built-in directory roles are honoured by Conditional Access; administrative-unit-scoped
        and custom roles are not.

        Requires: Policy.Read.All + Policy.ReadWrite.ConditionalAccess (+ RoleManagement.Read.Directory
        for -AdminRoles) and Conditional Access Administrator.
    .EXAMPLE
        New-EptStrengthPolicy -DisplayName 'CA100 Admins - Phishing-resistant MFA' -AdminRoles -ExcludeGroupId $breakGlassGroupId -WhatIf
    .EXAMPLE
        New-EptStrengthPolicy -DisplayName 'CA110 Pilot - Phishing-resistant MFA' -IncludeGroupId $pilotGroupId -ExcludeGroupId $breakGlassGroupId
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = '-AdminRoles and -AllUsers select parameter sets.')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Groups')]
    [OutputType('Ept.ConditionalAccessPolicy')]
    param(
        [Parameter(Mandatory)]
        [string] $DisplayName,

        [Parameter(Mandatory, ParameterSetName = 'Groups')]
        [guid[]] $IncludeGroupId,

        [Parameter(Mandatory, ParameterSetName = 'Roles')]
        [switch] $AdminRoles,

        [Parameter(ParameterSetName = 'Roles')]
        [string[]] $RoleName = $script:EptAdminRoleName,

        [Parameter(Mandatory, ParameterSetName = 'AllUsers')]
        [switch] $AllUsers,

        [Parameter(Mandatory)]
        [guid[]] $ExcludeGroupId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('StrengthId')]
        [guid] $AuthenticationStrengthId = $script:EptBuiltInStrength.PhishingResistant,

        [string[]] $IncludeApplication = @('All'),

        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string] $State = 'enabledForReportingButNotEnforced'
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess'
    }
    process {
        $users = @{ excludeGroups = @($ExcludeGroupId.Guid) }
        switch ($PSCmdlet.ParameterSetName) {
            'Groups' { $users.includeGroups = @($IncludeGroupId.Guid) }
            'AllUsers' { $users.includeUsers = @('All') }
            'Roles' {
                Assert-EptGraphConnection -RequiredScope 'RoleManagement.Read.Directory'
                $users.includeRoles = @(foreach ($r in $RoleName) {
                    $def = Invoke-EptGraphRequest -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '{0}'&`$select=templateId" -f $r)
                    if (-not $def) { throw "Role '$r' not found." }
                    $def.templateId
                })
            }
        }

        $body = [ordered]@{
            displayName   = $DisplayName
            state         = $State
            conditions    = @{
                users          = $users
                applications   = @{ includeApplications = $IncludeApplication }
                clientAppTypes = @('all')
            }
            grantControls = @{
                operator               = 'OR'
                authenticationStrength = @{ id = $AuthenticationStrengthId.Guid }
            }
        }

        if ($State -eq 'enabled') {
            Write-Warning 'Creating an ENFORCED policy. Confirm every targeted user has a qualifying method registered, and that break-glass accounts are excluded.'
        }
        if ($PSCmdlet.ShouldProcess($DisplayName, "Create CA policy [$State] requiring strength $AuthenticationStrengthId")) {
            $created = Invoke-EptGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Body $body
            Get-EptConditionalAccessPolicy | Where-Object PolicyId -eq $created.id
        }
    }
}

function New-EptDeviceCodeBlockPolicy {
    <#
    .SYNOPSIS
        Creates a Conditional Access policy that blocks device code flow (and optionally authentication transfer).
    .DESCRIPTION
        WRITE OPERATION. Microsoft recommends blocking device code flow wherever possible, because an
        attacker can get a victim to approve a code on the genuine Microsoft sign-in page.
        Created in report-only state by default so you can find legitimate users first
        (Teams Rooms, shared-device provisioning, some CLI workflows).
        -ExcludeDeviceRegistrationService excludes the Device Registration Service app
        (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) for tenants that register devices with device code flow.
        Requires: Policy.Read.All + Policy.ReadWrite.ConditionalAccess + Conditional Access Administrator.
    .EXAMPLE
        New-EptDeviceCodeBlockPolicy -DisplayName 'CA010 All users - Block device code flow' -ExcludeGroupId $breakGlass, $teamsRoomsAccounts -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Ept.ConditionalAccessPolicy')]
    param(
        [Parameter(Mandatory)]
        [string] $DisplayName,

        [Parameter(Mandatory)]
        [guid[]] $ExcludeGroupId,

        [switch] $IncludeAuthenticationTransfer,

        [switch] $ExcludeDeviceRegistrationService,

        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string] $State = 'enabledForReportingButNotEnforced'
    )
    Assert-EptGraphConnection -RequiredScope 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess'

    $transfer = if ($IncludeAuthenticationTransfer) { 'deviceCodeFlow,authenticationTransfer' } else { 'deviceCodeFlow' }
    $apps = @{ includeApplications = @('All') }
    if ($ExcludeDeviceRegistrationService) { $apps.excludeApplications = @('01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9') }

    $body = [ordered]@{
        displayName   = $DisplayName
        state         = $State
        conditions    = @{
            users               = @{ includeUsers = @('All'); excludeGroups = @($ExcludeGroupId.Guid) }
            applications        = $apps
            clientAppTypes      = @('all')
            authenticationFlows = @{ transferMethods = $transfer }   # a flags string, not an array
        }
        grantControls = @{ operator = 'OR'; builtInControls = @('block') }
    }

    if ($PSCmdlet.ShouldProcess($DisplayName, "Create CA policy [$State] blocking $transfer")) {
        $created = Invoke-EptGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -Body $body
        Get-EptConditionalAccessPolicy | Where-Object PolicyId -eq $created.id
    }
}

function Test-EptPhishResistantCoverage {
    <#
    .SYNOPSIS
        For each user, answers: "Is an enforced phishing-resistant policy covering this user, and which
        phishable methods could still satisfy other policies?"
    .DESCRIPTION
        Combines three sources per user:
          1. Registered methods (Get-EptUserRegistration),
          2. Group and active directory-role membership (GET /users/{id}/transitiveMemberOf),
          3. ENABLED Conditional Access policies that require a strength with no phishable combinations
             and target All resources.
        A user is 'Covered' when at least one such policy includes them (All users, directly, by group or
        by role) and no exclusion removes them. Users who are not covered but have phishable methods
        registered are the "weak fallback" population described in Part 3.

        This is a triage aid, not an effective-access engine: it ignores conditions such as platforms,
        locations, client apps and PIM roles that are eligible but not active. Confirm edge cases with
        the Conditional Access What If tool.

        Requires: AuditLog.Read.All, Policy.Read.All, GroupMember.Read.All (or Directory.Read.All).
    .EXAMPLE
        Get-EptPrivilegedUser | Test-EptPhishResistantCoverage | Where-Object Verdict -ne 'Covered'
    .EXAMPLE
        Get-Content pilot-users.txt | Test-EptPhishResistantCoverage | Export-Csv coverage.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    [OutputType('Ept.CoverageResult')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'UserId', 'UPN')]
        [string] $UserPrincipalName
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'AuditLog.Read.All', 'Policy.Read.All', 'GroupMember.Read.All'
        $strongPolicies = @(Get-EptConditionalAccessPolicy -State enabled |
            Where-Object { $_.RequiresPhishResistant -and $_.Applications -contains 'All' })
        if (-not $strongPolicies) {
            Write-Warning 'No ENABLED policy requires a phishing-resistant strength for All resources. Every user will report NotCovered.'
        }
    }
    process {
        $reg = Get-EptUserRegistration -UserPrincipalName $UserPrincipalName | Select-Object -First 1
        $userId = if ($reg) { $reg.UserId } else { $UserPrincipalName }

        # No $select: groups and directoryRoles have different properties; discriminate on @odata.type.
        $memberOf = @(Invoke-EptGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$(Resolve-EptUserId $userId)/transitiveMemberOf")
        $groupIds = @($memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object id)
        $roleIds = @($memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object roleTemplateId)

        $covering = foreach ($p in $strongPolicies) {
            $included = $p.IncludeUsers -contains 'All' -or $p.IncludeUsers -contains $userId -or
                        ($p.IncludeGroups | Where-Object { $_ -in $groupIds }) -or
                        ($p.IncludeRoles | Where-Object { $_ -in $roleIds })
            $excluded = $p.ExcludeUsers -contains $userId -or ($p.ExcludeGroups | Where-Object { $_ -in $groupIds })
            if ($included -and -not $excluded) { $p.Name }
        }

        $hasStrong = [bool]$reg.HasPhishingResistant
        $verdict = if ($covering -and $hasStrong) { 'Covered' }
                   elseif ($covering) { 'CoveredButNoMethod' }      # will be blocked or prompted to register
                   elseif ($reg.PhishableMethods) { 'NotCovered-PhishableFallback' }
                   else { 'NotCovered' }

        [pscustomobject]@{
            PSTypeName           = 'Ept.CoverageResult'
            UserPrincipalName    = if ($reg) { $reg.UserPrincipalName } else { $UserPrincipalName }
            Verdict              = $verdict
            CoveringPolicies     = @($covering) -join '; '
            HasPhishingResistant = $hasStrong
            PhishableMethods     = @($reg.PhishableMethods) -join ';'
            ActiveRoleCount      = $roleIds.Count
        }
    }
}

#endregion
