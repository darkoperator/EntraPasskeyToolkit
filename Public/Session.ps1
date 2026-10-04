#region Session response (Part 5) --------------------------------------------

function Revoke-EptUserSession {
    <#
    .SYNOPSIS
        Revokes a user's refresh tokens and session cookies (POST /users/{id}/revokeSignInSessions).
    .DESCRIPTION
        WRITE OPERATION. Invalidates refresh tokens and browser session cookies issued to the user
        by resetting signInSessionsValidFromDateTime. Access tokens that are already issued stay valid
        until they expire, unless the resource supports Continuous Access Evaluation (CAE).

        Revocation is a containment step, not remediation. If the attacker still holds a working
        credential or a registered method, they can sign in again. Order matters in an incident:
        remove attacker-registered methods and reset credentials first, then revoke.

        Requires: User.RevokeSessions.All (or Directory.ReadWrite.All) plus a role such as
        User Administrator, Helpdesk Administrator (non-admin targets) or Privileged Authentication Administrator.
    .EXAMPLE
        'victim@contoso.com' | Revoke-EptUserSession -Reason 'INC0012345 AiTM phishing' -WhatIf
    .EXAMPLE
        Get-EptAuthMethodAuditEvent -Days 1 -Activity '*registered*' |
            Where-Object { -not $_.SelfService } |
            Select-Object @{ n = 'UserPrincipalName'; e = { $_.TargetUpn } } -Unique |
            Revoke-EptUserSession -Reason 'Unexpected admin-registered method'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Ept.SessionRevocation')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'UserId', 'UPN')]
        [string] $UserPrincipalName,

        [Parameter(Mandatory)]
        [string] $Reason
    )
    begin { Assert-EptGraphConnection -RequiredScope 'User.RevokeSessions.All' }
    process {
        if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke all sign-in sessions ($Reason)")) { return }
        $uri = "https://graph.microsoft.com/v1.0/users/$(Resolve-EptUserId $UserPrincipalName)/revokeSignInSessions"
        $ok = $false
        try {
            # The API returns { "value": true }; the helper unwraps 'value' for us.
            $ok = [bool](Invoke-EptGraphRequest -Method POST -Uri $uri)
        }
        catch { Write-Error "Revocation failed for ${UserPrincipalName}: $($_.Exception.Message)" }
        [pscustomobject]@{
            PSTypeName        = 'Ept.SessionRevocation'
            UserPrincipalName = $UserPrincipalName
            Revoked           = $ok
            Reason            = $Reason
            Time              = (Get-Date).ToUniversalTime()
        }
    }
}

function Get-EptSignInMethod {
    <#
    .SYNOPSIS
        Returns sign-ins with the authentication methods actually used, the protocol, and token-protection state.
    .DESCRIPTION
        Uses the BETA sign-in endpoint (GET /beta/auditLogs/signIns), because authenticationDetails,
        authenticationProtocol, originalTransferMethod and tokenProtectionStatusDetails are not
        exposed in v1.0. Beta APIs can change; pin a module version and re-test after upgrades.

        Each sign-in gets a MethodClass derived from the method names in authenticationDetails:
        PhishingResistant, Phishable, Telephony, SingleFactor or Unknown. Microsoft documents only a subset of
        these strings, so the classification is a heuristic. Spot-check new strings with -Verbose.

        By default only interactive user sign-ins are returned (the API default). Keep -Days small in
        large tenants, and use Log Analytics / Sentinel for anything beyond the API retention window.

        Requires: AuditLog.Read.All + Policy.Read.All (for Conditional Access details), Security Reader
        or Reports Reader, and Entra ID P1/P2.
    .EXAMPLE
        Get-EptSignInMethod -Days 7 | Measure-EptSignInMethod
    .EXAMPLE
        Get-EptSignInMethod -Days 30 -Protocol deviceCode | Group-Object UserPrincipalName, AppDisplayName | Sort-Object Count -Descending
    .EXAMPLE
        Get-EptPrivilegedUser | Get-EptSignInMethod -Days 14 | Where-Object MethodClass -ne 'PhishingResistant'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = '-Protocol and -SuccessOnly are read inside the nested Invoke-Query helper.')]
    [CmdletBinding()]
    [OutputType('Ept.SignInMethod')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('UPN')]
        [string[]] $UserPrincipalName,

        [ValidateRange(1, 30)]
        [int] $Days = 1,

        # Client-side filter on authenticationProtocol, e.g. deviceCode, ropc, saml20, wsFederation.
        [string] $Protocol,

        [switch] $SuccessOnly
    )
    begin {
        Assert-EptGraphConnection -RequiredScope 'AuditLog.Read.All'
        $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $headers = @{ Prefer = 'include-unknown-enum-members' }   # needed to see authenticationTransfer

        function Get-MethodClass([string[]] $methods) {
            $joined = $methods -join '|'
            if (-not $joined) { return 'Unknown' }
            if ($joined -match 'passkey|FIDO|Windows Hello|certificate|Platform Credential|Secure Enclave') { return 'PhishingResistant' }
            if ($joined -match 'SMS|Text message|Voice|phone call') { return 'Telephony' }
            if ($joined -match 'Authenticator|OATH|notification|verification code|Temporary Access Pass|QR code') { return 'Phishable' }
            if ($joined -match 'Previously satisfied|Satisfied by token') { return 'SatisfiedByToken' }
            if ($joined -match '^Password$') { return 'SingleFactor' }
            'Unknown'
        }

        function Invoke-Query([string] $filter) {
            $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter=' + [uri]::EscapeDataString($filter)
            Invoke-EptGraphRequest -Uri $uri -Headers $headers | ForEach-Object {
                $used = @($_.authenticationDetails | Where-Object succeeded | ForEach-Object authenticationMethod | Select-Object -Unique)
                Write-Verbose "$($_.userPrincipalName): methods '$($used -join ', ')'"
                $row = [pscustomobject]@{
                    PSTypeName             = 'Ept.SignInMethod'
                    Time                   = [datetime]$_.createdDateTime
                    UserPrincipalName      = $_.userPrincipalName
                    AppDisplayName         = $_.appDisplayName
                    ResourceDisplayName    = $_.resourceDisplayName
                    IPAddress              = $_.ipAddress
                    Country                = $_.location.countryOrRegion
                    Succeeded              = ($_.status.errorCode -eq 0)
                    ErrorCode              = $_.status.errorCode
                    AuthRequirement        = $_.authenticationRequirement
                    Protocol               = $_.authenticationProtocol
                    OriginalTransferMethod = $_.originalTransferMethod
                    MethodsUsed            = $used -join '; '
                    MethodClass            = Get-MethodClass $used
                    ConditionalAccess      = $_.conditionalAccessStatus
                    TokenProtection        = $_.tokenProtectionStatusDetails.signInSessionStatus
                    DeviceCompliant        = $_.deviceDetail.isCompliant
                    CorrelationId          = $_.correlationId
                }
                if ($Protocol -and $row.Protocol -ne $Protocol) { return }
                if ($SuccessOnly -and -not $row.Succeeded) { return }
                $row
            }
        }
        $anyUser = $false
    }
    process {
        foreach ($u in $UserPrincipalName) {
            if (-not $u) { continue }
            $anyUser = $true
            Invoke-Query ("createdDateTime ge $since and userPrincipalName eq '{0}'" -f ($u -replace "'", "''"))
        }
    }
    end {
        if (-not $anyUser) { Invoke-Query "createdDateTime ge $since" }
    }
}

function Measure-EptSignInMethod {
    <#
    .SYNOPSIS
        Aggregates Get-EptSignInMethod output: how many successful MFA sign-ins used each class of method.
    .DESCRIPTION
        This is the usage metric that registration reports cannot give you. "80% registered a passkey"
        means little if 60% of MFA sign-ins still use push or SMS.
    .EXAMPLE
        Get-EptSignInMethod -Days 7 | Measure-EptSignInMethod
    .EXAMPLE
        Get-EptSignInMethod -Days 7 | Measure-EptSignInMethod -GroupBy AppDisplayName | Sort-Object PhishingResistantPct
    #>
    [CmdletBinding()]
    [OutputType('Ept.SignInMethodSummary')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSTypeName('Ept.SignInMethod')] $InputObject,

        [string] $GroupBy
    )
    begin { $rows = [System.Collections.Generic.List[object]]::new() }
    process {
        if ($InputObject.Succeeded -and $InputObject.AuthRequirement -eq 'multiFactorAuthentication') { $rows.Add($InputObject) }
    }
    end {
        $groups = if ($GroupBy) { $rows | Group-Object -Property $GroupBy } else { , @{ Name = 'All'; Group = $rows } }
        foreach ($g in $groups) {
            $set = @($g.Group); $n = $set.Count
            if (-not $n) { continue }
            $count = { param($c) @($set | Where-Object MethodClass -eq $c).Count }
            [pscustomobject]@{
                PSTypeName           = 'Ept.SignInMethodSummary'
                Group                = $g.Name
                MfaSignIns           = $n
                PhishingResistantPct = [math]::Round(100 * (& $count 'PhishingResistant') / $n, 1)
                PhishablePct         = [math]::Round(100 * (& $count 'Phishable') / $n, 1)
                TelephonyPct         = [math]::Round(100 * (& $count 'Telephony') / $n, 1)
                SatisfiedByTokenPct  = [math]::Round(100 * (& $count 'SatisfiedByToken') / $n, 1)
                DistinctUsers        = @($set.UserPrincipalName | Select-Object -Unique).Count
                TelephonyUsers       = @($set | Where-Object MethodClass -eq 'Telephony' | ForEach-Object UserPrincipalName | Select-Object -Unique)
            }
        }
    }
}

#endregion
