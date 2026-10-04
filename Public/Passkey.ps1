#region Passkeys and the Authentication methods policy (Parts 2 and 7) ---------

# Well-known AAGUIDs published on Microsoft Learn. Extend with your own security-key models
# (vendors publish theirs, and the FIDO Alliance Metadata Service lists them).
$script:EptKnownAaguid = @{
    'de1e552d-db1d-4423-a619-566b625cdc84' = 'Microsoft Authenticator (Android)'
    '90a3ccdf-635c-4729-a248-9b709135078f' = 'Microsoft Authenticator (iOS)'
    '08987058-cadc-4b81-b6e1-30de50dcbe96' = 'Windows Hello (hardware)'
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9' = 'Windows Hello (VBS hardware)'
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2' = 'Windows Hello (software)'
}

function Get-EptUserPasskey {
    <#
    .SYNOPSIS
        Lists the passkeys (FIDO2 methods) registered to one or more users.
    .DESCRIPTION
        GET /users/{id}/authentication/fido2Methods (v1.0). Returns the passkey type (deviceBound or
        synced), attestation level, AAGUID with a friendly name where known, and creation date.

        Output binds by property name to Remove-EptUserPasskey (UserPrincipalName + MethodId).

        Remember: without attestation enforcement, Entra cannot guarantee any attribute of a
        passkey, including its AAGUID or whether it is device-bound. Treat unattested values as claims.

        Requires: UserAuthenticationMethod.Read.All (or UserAuthMethod-Passkey.Read.All) plus
        Global Reader, Authentication Administrator or Privileged Authentication Administrator.
    .PARAMETER AaguidMap
        Extra AAGUID-to-name mappings merged with the built-in list, e.g. your approved security keys.
    .EXAMPLE
        Get-EptPrivilegedUser | Get-EptUserPasskey | Where-Object PasskeyType -eq 'synced'
    .EXAMPLE
        Get-Content pilot.txt | Get-EptUserPasskey | Group-Object Authenticator | Sort-Object Count -Descending
    #>
    [CmdletBinding()]
    [OutputType('Ept.UserPasskey')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'UserId', 'UPN')]
        [string[]] $UserPrincipalName,

        [hashtable] $AaguidMap = @{}
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'UserAuthenticationMethod.Read.All'
        $names = $script:EptKnownAaguid.Clone()
        foreach ($k in $AaguidMap.Keys) { $names[$k.ToLower()] = $AaguidMap[$k] }
    }
    process {
        foreach ($user in $UserPrincipalName) {
            $uri = "https://graph.microsoft.com/v1.0/users/$(Resolve-EptUserId $user)/authentication/fido2Methods"
            try { $methods = @(Invoke-EptGraphRequest -Uri $uri) }
            catch { Write-Error "Could not read passkeys for '$user': $($_.Exception.Message)"; continue }

            foreach ($m in $methods) {
                $aaguid = ([string]$m.aaGuid).ToLower()
                [pscustomobject]@{
                    PSTypeName        = 'Ept.UserPasskey'
                    UserPrincipalName = $user
                    MethodId          = $m.id
                    DisplayName       = $m.displayName
                    Model             = $m.model
                    PasskeyType       = $m.passkeyType
                    AttestationLevel  = $m.attestationLevel
                    Aaguid            = $aaguid
                    Authenticator     = if ($names.ContainsKey($aaguid)) { $names[$aaguid] } elseif ($m.model) { $m.model } else { 'Unknown' }
                    Created           = if ($m.createdDateTime) { [datetime]$m.createdDateTime } else { $null }
                }
            }
        }
    }
}

function Get-EptPasskeyProfile {
    <#
    .SYNOPSIS
        Returns the Passkey (FIDO2) method configuration with its passkey profiles and targets.
    .DESCRIPTION
        GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2 (v1.0).
        Emits one object per passkey profile, with the groups that use it. Tenants that have not
        opted in to passkey profiles return the legacy tenant-wide settings as a single 'Legacy' profile.
        (The tenant-level isAttestationEnforced / keyRestrictions properties are deprecated and
        scheduled for removal in October 2027.)

        Requires: Policy.Read.All (or Policy.Read.AuthenticationMethod).
    .EXAMPLE
        Get-EptPasskeyProfile | Format-List
    #>
    [CmdletBinding()]
    [OutputType('Ept.PasskeyProfile')]
    param()

    Assert-EptGraphConnection -RequiredScope 'Policy.Read.All'
    $config = Invoke-EptGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'

    $profiles = @($config.passkeyProfiles)
    if (-not $profiles) {
        $profiles = @([pscustomobject]@{
            id                     = 'legacy'
            name                   = 'Legacy (tenant-wide settings)'
            passkeyTypes           = 'deviceBound,synced'
            attestationEnforcement = if ($config.isAttestationEnforced) { 'registrationOnly' } else { 'disabled' }
            keyRestrictions        = $config.keyRestrictions
        })
    }

    foreach ($p in $profiles) {
        $targets = @($config.includeTargets | Where-Object {
            $_.allowedPasskeyProfiles -contains $p.id -or $p.id -eq 'legacy' -or
            (-not $_.allowedPasskeyProfiles -and $p.id -eq $config.defaultPasskeyProfile)
        })
        [pscustomobject]@{
            PSTypeName           = 'Ept.PasskeyProfile'
            PolicyState          = $config.state
            SelfServiceSetup     = $config.isSelfServiceRegistrationAllowed
            ProfileId            = $p.id
            ProfileName          = $p.name
            IsDefault            = ($p.id -eq $config.defaultPasskeyProfile)
            PasskeyTypes         = $p.passkeyTypes
            Attestation          = $p.attestationEnforcement
            KeyRestriction       = if ($p.keyRestrictions.isEnforced) { $p.keyRestrictions.enforcementType } else { 'none' }
            Aaguids              = @($p.keyRestrictions.aaGuids)
            TargetIds            = @($targets.id)
            ExcludedIds          = @($config.excludeTargets.id)
        }
    }
}

function Get-EptAuthMethodPolicy {
    <#
    .SYNOPSIS
        Summarises every method in the Authentication methods policy: state, targets and exclusions.
    .DESCRIPTION
        GET /policies/authenticationMethodsPolicy (v1.0). One object per method configuration,
        plus the policy migration state and registration campaign settings on each object so that the
        output is self-contained when exported. Use it to answer "who is still enabled for SMS/voice?"
        and "is the legacy MFA/SSPR policy still in play?".

        Requires: Policy.Read.All (or Policy.Read.AuthenticationMethod).
    .EXAMPLE
        Get-EptAuthMethodPolicy | Where-Object State -eq 'enabled' | Format-Table Method, Targets, Excluded
    #>
    [CmdletBinding()]
    [OutputType('Ept.AuthMethodPolicy')]
    param()

    Assert-EptGraphConnection -RequiredScope 'Policy.Read.All'
    $policy = Invoke-EptGraphRequest -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    $campaign = $policy.registrationEnforcement.authenticationMethodsRegistrationCampaign

    foreach ($m in $policy.authenticationMethodConfigurations) {
        [pscustomobject]@{
            PSTypeName      = 'Ept.AuthMethodPolicy'
            Method          = $m.id
            State           = $m.state
            Targets         = @($m.includeTargets | ForEach-Object { if ($_.id -eq 'all_users') { 'All users' } else { $_.id } })
            Excluded        = @($m.excludeTargets.id)
            MigrationState  = $policy.policyMigrationState
            CampaignState   = $campaign.state
            CampaignMethod  = @($campaign.includeTargets.targetedAuthenticationMethod | Select-Object -Unique) -join ';'
            CampaignSnooze  = $campaign.snoozeDurationInDays
        }
    }
}

function Add-EptPasskeyProfile {
    <#
    .SYNOPSIS
        Adds a passkey profile to the Passkey (FIDO2) policy and, optionally, targets a group with it.
    .DESCRIPTION
        WRITE OPERATION. Read-modify-write against
        PATCH /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2 (v1.0):
        the current profiles and targets are read, the new profile is appended, and the complete
        collections are sent back so existing profiles are preserved.

        Prerequisites and limits (check Microsoft Learn for the current values):
          * The tenant must already have opted in to passkey profiles (a one-way change made in the portal).
          * The number of profiles per tenant is limited, and the whole policy must stay under 20 KB.
          * Attestation cannot be enforced on a profile that allows synced passkeys, and
            Entra passkeys on Windows need a profile without attestation enforcement.
          * Removing an AAGUID from an allow list later stops existing passkeys of that model from signing in.

        Validate in a test tenant first and run with -WhatIf to inspect the request body.
        Requires: Policy.ReadWrite.AuthenticationMethod + Authentication Policy Administrator.
    .EXAMPLE
        # Admin persona: hardware security keys only, attested
        Add-EptPasskeyProfile -Name 'Admins - attested security keys' -PasskeyType deviceBound `
            -EnforceAttestation -AllowedAaguid $approvedKeyAaguids -TargetGroupId $adminGroupId -WhatIf
    .EXAMPLE
        # Workforce: synced or device-bound, no attestation
        Add-EptPasskeyProfile -Name 'Workforce - synced allowed' -PasskeyType deviceBound, synced -TargetGroupId $pilotGroupId
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Ept.PasskeyProfile')]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 64)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('deviceBound', 'synced')]
        [string[]] $PasskeyType,

        [switch] $EnforceAttestation,

        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string[]] $AllowedAaguid,

        [guid] $TargetGroupId
    )

    Assert-EptGraphConnection -RequiredScope 'Policy.ReadWrite.AuthenticationMethod'
    if ($EnforceAttestation -and $PasskeyType -contains 'synced') {
        throw 'Synced passkeys do not support attestation. Use -PasskeyType deviceBound with -EnforceAttestation.'
    }

    $uri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2'
    $config = Invoke-EptGraphRequest -Uri $uri
    if (-not $config.passkeyProfiles) {
        throw 'Passkey profiles are not enabled in this tenant. Opt in from the Passkey (FIDO2) settings page first.'
    }
    if ($config.passkeyProfiles.name -contains $Name) { throw "A passkey profile named '$Name' already exists." }

    $newProfile = [ordered]@{
        id                     = [guid]::NewGuid().ToString()
        name                   = $Name
        passkeyTypes           = ($PasskeyType | Select-Object -Unique) -join ','
        attestationEnforcement = if ($EnforceAttestation) { 'registrationOnly' } else { 'disabled' }
        keyRestrictions        = @{
            isEnforced      = [bool]$AllowedAaguid
            enforcementType = 'allow'
            aaGuids         = @($AllowedAaguid | ForEach-Object ToLower)
        }
    }

    $body = [ordered]@{
        '@odata.type'   = '#microsoft.graph.fido2AuthenticationMethodConfiguration'
        passkeyProfiles = @($config.passkeyProfiles) + $newProfile
    }
    if ($TargetGroupId) {
        $targets = @($config.includeTargets | Where-Object id -ne $TargetGroupId.ToString())
        $targets += [ordered]@{
            targetType             = 'group'
            id                     = $TargetGroupId.ToString()
            isRegistrationRequired = $false
            allowedPasskeyProfiles = @($newProfile.id)
        }
        $body.includeTargets = $targets
    }

    Write-Verbose ($body | ConvertTo-Json -Depth 10)
    if ($PSCmdlet.ShouldProcess('Passkey (FIDO2) policy', "Add profile '$Name' ($($newProfile.passkeyTypes), attestation=$($newProfile.attestationEnforcement))")) {
        Invoke-EptGraphRequest -Method PATCH -Uri $uri -Body $body | Out-Null
        Get-EptPasskeyProfile | Where-Object ProfileName -eq $Name
    }
}

#endregion
