#region Credential lifecycle: registration, recovery, removal (Part 4) ----------

function Get-EptAuthMethodAuditEvent {
    <#
    .SYNOPSIS
        Returns audit events for authentication-method changes (registrations, deletions, TAP issuance).
    .DESCRIPTION
        Queries GET /auditLogs/directoryAudits filtered to loggedByService 'Authentication Methods'
        within a time window, and flattens initiator and target for easy filtering and correlation.
        Filtering on the service instead of a hard-coded list of activity names keeps the function
        working when Microsoft adds or renames activities. Use -Activity to narrow client-side.

        Requires: AuditLog.Read.All plus a role such as Reports Reader or Security Reader.
        Retention depends on licence (7 days free, 30 days P1/P2); stream to Log Analytics or Sentinel
        for anything longer.
    .PARAMETER UserPrincipalName
        Limit results to events targeting these users. Accepts pipeline input.
    .PARAMETER Activity
        Wildcard filter applied to activityDisplayName, e.g. '*registered*' or '*Temporary*'.
    .EXAMPLE
        Get-EptAuthMethodAuditEvent -Days 7 -Activity '*registered security info*'
    .EXAMPLE
        Get-EptPrivilegedUser | Get-EptAuthMethodAuditEvent -Days 30 | Sort-Object Time
    #>
    [CmdletBinding()]
    [OutputType('Ept.AuthMethodAuditEvent')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('UPN')]
        [string[]] $UserPrincipalName,

        [ValidateRange(1, 30)]
        [int] $Days = 7,

        [string] $Activity = '*'
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'AuditLog.Read.All'
        $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = "loggedByService eq 'Authentication Methods' and activityDateTime ge $since"
        $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + [uri]::EscapeDataString($filter)
        $targets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    process {
        foreach ($u in $UserPrincipalName) { if ($u) { [void]$targets.Add($u) } }
    }
    end {
        Invoke-EptGraphRequest -Uri $uri |
            Where-Object activityDisplayName -Like $Activity |
            ForEach-Object {
                $target = $_.targetResources | Select-Object -First 1
                $row = [pscustomobject]@{
                    PSTypeName    = 'Ept.AuthMethodAuditEvent'
                    Time          = [datetime]$_.activityDateTime
                    Activity      = $_.activityDisplayName
                    Result        = $_.result
                    ResultReason  = $_.resultReason
                    Initiator     = if ($_.initiatedBy.user) { $_.initiatedBy.user.userPrincipalName } else { $_.initiatedBy.app.displayName }
                    InitiatorIp   = $_.initiatedBy.user.ipAddress
                    TargetUpn     = $target.userPrincipalName
                    TargetId      = $target.id
                    SelfService   = ($_.initiatedBy.user.id -and $_.initiatedBy.user.id -eq $target.id)
                    Details       = ($_.additionalDetails | ForEach-Object { "$($_.key)=$($_.value)" }) -join '; '
                    CorrelationId = $_.correlationId
                }
                if ($targets.Count -eq 0 -or $targets.Contains([string]$row.TargetUpn) -or $targets.Contains([string]$row.TargetId)) { $row }
            }
    }
}

function New-EptTemporaryAccessPass {
    <#
    .SYNOPSIS
        Issues a Temporary Access Pass (TAP) for a verified onboarding or recovery case.
    .DESCRIPTION
        WRITE OPERATION. Creates a TAP via POST /users/{id}/authentication/temporaryAccessPassMethods.
        Creating a TAP replaces any existing TAP for the user. The pass value is only returned at
        creation time; this function returns it as a SecureString so it is not echoed to the console,
        transcripts or pipeline logs by accident.

        Guard rails:
          * -CaseId is mandatory and is written to the verbose stream and the returned object,
            so every TAP can be traced to a ticket.
          * SupportsShouldProcess with ConfirmImpact High: you are prompted unless you pass -Confirm:$false.
          * Lifetime and one-time use must also be allowed by the tenant's TAP policy, or Graph rejects the request.

        Requires: UserAuthenticationMethod.ReadWrite.All plus Authentication Administrator
        (Privileged Authentication Administrator for admin accounts).
    .EXAMPLE
        $tap = New-EptTemporaryAccessPass -UserPrincipalName jdoe@contoso.com -CaseId INC0012345 -LifetimeInMinutes 60 -OneTime
        $tap.Pass | ConvertFrom-SecureString -AsPlainText   # reveal once, deliver via the approved channel
    .EXAMPLE
        # Bulk onboarding: CSV columns UserPrincipalName, CaseId, LifetimeInMinutes
        Import-Csv ./new-hires.csv | New-EptTemporaryAccessPass -OneTime -Confirm:$false
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Graph returns the TAP in clear text once; it is wrapped in a SecureString immediately.')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Ept.TemporaryAccessPass')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'UserId', 'UPN')]
        [string] $UserPrincipalName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\S{3,}$')]
        [string] $CaseId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(10, 43200)]
        [int] $LifetimeInMinutes = 60,

        [switch] $OneTime,

        [datetime] $StartDateTime
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'UserAuthenticationMethod.ReadWrite.All'
    }
    process {
        $body = @{
            lifetimeInMinutes = $LifetimeInMinutes
            isUsableOnce      = [bool]$OneTime
        }
        if ($StartDateTime) { $body.startDateTime = $StartDateTime.ToUniversalTime().ToString('o') }

        $target = "$UserPrincipalName (case $CaseId, $LifetimeInMinutes min, one-time=$([bool]$OneTime))"
        if (-not $PSCmdlet.ShouldProcess($target, 'Create Temporary Access Pass (replaces any existing TAP)')) { return }

        Write-Verbose "Issuing TAP for $UserPrincipalName under case $CaseId"
        $uri = "https://graph.microsoft.com/v1.0/users/$(Resolve-EptUserId $UserPrincipalName)/authentication/temporaryAccessPassMethods"
        $result = Invoke-EptGraphRequest -Method POST -Uri $uri -Body $body

        $secure = ConvertTo-SecureString -String $result.temporaryAccessPass -AsPlainText -Force
        $result.temporaryAccessPass = $null

        [pscustomobject]@{
            PSTypeName        = 'Ept.TemporaryAccessPass'
            UserPrincipalName = $UserPrincipalName
            CaseId            = $CaseId
            MethodId          = $result.id
            StartDateTime     = $result.startDateTime
            LifetimeInMinutes = $result.lifetimeInMinutes
            IsUsableOnce      = $result.isUsableOnce
            Pass              = $secure
        }
    }
}

function Remove-EptUserPasskey {
    <#
    .SYNOPSIS
        Deletes a user's passkey (FIDO2) registration, for lost, stolen or unauthorized credentials.
    .DESCRIPTION
        WRITE OPERATION. DELETE /users/{id}/authentication/fido2Methods/{methodId}.
        Designed to take pipeline input from Get-EptUserPasskey so you can filter first and
        delete second, with -WhatIf to preview. Deleting a credential does not end sessions that
        were already issued: pair it with Revoke-EptUserSession during an incident.

        Requires: UserAuthenticationMethod.ReadWrite.All plus Authentication Administrator
        (Privileged Authentication Administrator for admin accounts).
    .EXAMPLE
        Get-EptUserPasskey -UserPrincipalName jdoe@contoso.com |
            Where-Object DisplayName -eq 'YubiKey lost 2026-09' |
            Remove-EptUserPasskey -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('UPN')]
        [string] $UserPrincipalName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string] $MethodId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $DisplayName
    )
    begin { Assert-EptGraphConnection -RequiredScope 'UserAuthenticationMethod.ReadWrite.All' }
    process {
        $label = if ($DisplayName) { "'$DisplayName' ($MethodId)" } else { $MethodId }
        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Delete passkey $label")) {
            $uri = "https://graph.microsoft.com/v1.0/users/$(Resolve-EptUserId $UserPrincipalName)/authentication/fido2Methods/$MethodId"
            Invoke-EptGraphRequest -Method DELETE -Uri $uri | Out-Null
        }
    }
}


# Resources that take part in credential registration. A Conditional Access policy that targets
# "All resources" also applies to these, which is how a registration flow gets blocked even though
# the user satisfied the policy targeting "Register security information".
$script:EptRegistrationResource = @{
    'ea890292-c8c8-4433-b5ea-b09d0668e1a6' = 'Azure Credential Configuration Endpoint Service'
    '00000002-0000-0000-c000-000000000000' = 'Windows Azure Active Directory'
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '0000000c-0000-0000-c000-000000000000' = 'My Sign-ins / My Apps'
}

function Get-EptRegistrationBlock {
    <#
    .SYNOPSIS
        Finds sign-ins where Conditional Access blocked or challenged a credential-registration resource.
    .DESCRIPTION
        Passkey registration does not happen entirely inside the "Register security information" user
        action. The flow also calls resources such as the Azure Credential Configuration Endpoint
        Service. A policy targeting All resources (for example "Require app protection policy" or
        "Require approved client app" on mobile) therefore blocks registration, usually with a
        confusing error in Microsoft Authenticator.

        This function reads the beta sign-in logs, keeps sign-ins against known registration resources
        (or any resource matched by -ResourceName), and reports which Conditional Access policies
        produced a failure or challenge, so you can see exactly which policy to adjust.

        Read-only. Requires AuditLog.Read.All plus Policy.Read.All to see appliedConditionalAccessPolicies,
        and a role such as Security Reader. Entra ID P1/P2.
    .PARAMETER ResourceName
        Additional resource display names to treat as registration-related (wildcards allowed).
    .EXAMPLE
        Get-EptRegistrationBlock -Days 7 | Format-Table Time, UserPrincipalName, Resource, Result, BlockingPolicies -Wrap
    .EXAMPLE
        # Which policies are responsible, across the whole window?
        Get-EptRegistrationBlock -Days 30 | Select-Object -ExpandProperty BlockingPolicies | Group-Object -NoElement | Sort-Object Count -Descending
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = '-ResourceName and -IncludeSuccess are read inside the nested query helpers.')]
    [CmdletBinding()]
    [OutputType('Ept.RegistrationBlock')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('UPN')]
        [string[]] $UserPrincipalName,

        [ValidateRange(1, 30)]
        [int] $Days = 7,

        [string[]] $ResourceName,

        # Include sign-ins that succeeded, to see the whole registration flow rather than only failures.
        [switch] $IncludeSuccess
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'AuditLog.Read.All', 'Policy.Read.All'
        $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $known = $script:EptRegistrationResource

        function Test-EptRegistrationResource($signIn) {
            if ($known.ContainsKey([string]$signIn.resourceId)) { return $true }
            foreach ($pattern in $ResourceName) {
                if ($signIn.resourceDisplayName -like $pattern) { return $true }
            }
            # The security-info user action itself, when the sign-in carries it.
            [string]$signIn.resourceDisplayName -like '*Credential Configuration*'
        }

        function Invoke-EptSignInQuery([string] $filter) {
            $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter=' + [uri]::EscapeDataString($filter)
            Invoke-EptGraphRequest -Uri $uri -Headers @{ Prefer = 'include-unknown-enum-members' } |
                Where-Object { Test-EptRegistrationResource $_ } |
                ForEach-Object {
                    $failed = ($_.status.errorCode -ne 0)
                    if (-not $failed -and -not $IncludeSuccess) { return }
                    [pscustomobject]@{
                        PSTypeName        = 'Ept.RegistrationBlock'
                        Time              = [datetime]$_.createdDateTime
                        UserPrincipalName = $_.userPrincipalName
                        Resource          = if ($known.ContainsKey([string]$_.resourceId)) { $known[[string]$_.resourceId] } else { $_.resourceDisplayName }
                        ResourceId        = $_.resourceId
                        ClientApp         = $_.appDisplayName
                        DevicePlatform    = $_.deviceDetail.operatingSystem
                        Result            = if ($failed) { 'Failure' } else { 'Success' }
                        ErrorCode         = $_.status.errorCode
                        FailureReason     = $_.status.failureReason
                        ConditionalAccess = $_.conditionalAccessStatus
                        BlockingPolicies  = @($_.appliedConditionalAccessPolicies | Where-Object result -eq 'failure' | ForEach-Object displayName)
                        CorrelationId     = $_.correlationId
                    }
                }
        }
        $anyUser = $false
    }
    process {
        foreach ($u in $UserPrincipalName) {
            if (-not $u) { continue }
            $anyUser = $true
            Invoke-EptSignInQuery ("createdDateTime ge $since and userPrincipalName eq '{0}'" -f ($u -replace "'", "''"))
        }
    }
    end {
        if (-not $anyUser) { Invoke-EptSignInQuery "createdDateTime ge $since" }
    }
}

#endregion
