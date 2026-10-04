#region Registration posture (Part 1) ----------------------------------------

# Method names returned in userRegistrationDetails.methodsRegistered, grouped by strength.
# Check the userRegistrationDetails reference periodically: Microsoft adds enum members
# (for example the passKey* values) as new methods ship. Anything unknown is reported as 'Unclassified'.
$script:EptMethodClass = @{
    PhishingResistant = @(
        'fido2SecurityKey', 'windowsHelloForBusiness', 'macOsSecureEnclaveKey',
        'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello',
        'passKeySynced', 'x509CertificateMultiFactor'
    )
    Phishable         = @(
        'microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless',
        'softwareOneTimePasscode', 'hardwareOneTimePasscode', 'externalAuthMethod'
    )
    Telephony         = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
    RecoveryOnly      = @('email', 'securityQuestion', 'temporaryAccessPass')
}

function Get-EptMethodStrength {
    <#
    .SYNOPSIS
        Classifies an authentication method name as PhishingResistant, Phishable, Telephony,
        RecoveryOnly or Unclassified.
    .EXAMPLE
        'mobilePhone','passKeyDeviceBound' | Get-EptMethodStrength
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]] $Method
    )
    process {
        foreach ($m in $Method) {
            $class = $script:EptMethodClass.GetEnumerator() |
                Where-Object { $_.Value -contains $m } |
                Select-Object -First 1 -ExpandProperty Key
            [pscustomobject]@{
                Method   = $m
                Strength = if ($class) { $class } else { 'Unclassified' }
            }
        }
    }
}

function Get-EptUserRegistration {
    <#
    .SYNOPSIS
        Returns authentication-method registration details for users, enriched with strength flags.
    .DESCRIPTION
        Reads the userRegistrationDetails report (GET /reports/authenticationMethods/userRegistrationDetails).
        With no input it streams every user in the report. With pipeline input (UPNs, user objects,
        or the output of Get-EptPrivilegedUser) it queries only those users.

        The report reflects *registration*, not usage and not enforcement. It is refreshed by the
        service and can lag recent changes; disabled users are not included.

        Requires: AuditLog.Read.All (delegated) plus a role such as Reports Reader,
        Security Reader or Global Reader. Entra ID P1/P2.
    .PARAMETER UserPrincipalName
        One or more UPNs or object IDs. Binds from pipeline strings or from a UserPrincipalName/Id property.
    .PARAMETER UserType
        Restrict the full-tenant report to 'member' or 'guest'.
    .EXAMPLE
        Get-EptUserRegistration | Where-Object { -not $_.HasPhishingResistant } | Export-Csv needs-passkey.csv
    .EXAMPLE
        Get-EptPrivilegedUser | Get-EptUserRegistration | Format-Table UserPrincipalName, StrongestMethod, HasTelephony
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType('Ept.UserRegistration')]
    param(
        [Parameter(ParameterSetName = 'ByUser', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id', 'UserId', 'UPN')]
        [string[]] $UserPrincipalName,

        [Parameter(ParameterSetName = 'All')]
        [ValidateSet('member', 'guest')]
        [string] $UserType
    )

    begin {
        Assert-EptGraphConnection -RequiredScope 'AuditLog.Read.All'
        $base = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'

        function ConvertTo-EptRegistration($r) {
            $methods = @($r.methodsRegistered)
            $classes = if ($methods) { $methods | Get-EptMethodStrength } else { @() }
            $strongest = foreach ($tier in 'PhishingResistant', 'Phishable', 'Telephony', 'RecoveryOnly') {
                if ($classes.Strength -contains $tier) { $tier; break }
            }
            [pscustomobject]@{
                PSTypeName            = 'Ept.UserRegistration'
                UserId                = $r.id
                UserPrincipalName     = $r.userPrincipalName
                DisplayName           = $r.userDisplayName
                UserType              = $r.userType
                IsAdmin               = $r.isAdmin
                IsMfaRegistered       = $r.isMfaRegistered
                IsMfaCapable          = $r.isMfaCapable
                IsPasswordlessCapable = $r.isPasswordlessCapable
                IsSsprRegistered      = $r.isSsprRegistered
                MethodsRegistered     = $methods
                StrongestMethod       = if ($strongest) { $strongest } else { 'None' }
                HasPhishingResistant  = $classes.Strength -contains 'PhishingResistant'
                HasTelephony          = $classes.Strength -contains 'Telephony'
                PhishableMethods      = @($classes | Where-Object Strength -in 'Phishable', 'Telephony' | ForEach-Object Method)
                SystemPreferredMethod = @($r.systemPreferredAuthenticationMethods) -join ';'
                UserPreferredMethod   = $r.userPreferredMethodForSecondaryAuthentication
                LastUpdated           = $r.lastUpdatedDateTime
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'All') { return }
        foreach ($user in $UserPrincipalName) {
            # The report is keyed by object ID; a UPN needs a filter instead of a path segment.
            $uri = if ($user -as [guid]) { "$base/$user" }
                   else { "$base`?`$filter=userPrincipalName eq '$($user -replace "'", "''")'" }
            try {
                Invoke-EptGraphRequest -Uri $uri | ForEach-Object { ConvertTo-EptRegistration $_ }
            }
            catch {
                Write-Error "Could not read registration details for '$user': $($_.Exception.Message)"
            }
        }
    }

    end {
        if ($PSCmdlet.ParameterSetName -ne 'All') { return }
        $uri = $base
        if ($UserType) { $uri += "?`$filter=userType eq '$UserType'" }
        Invoke-EptGraphRequest -Uri $uri | ForEach-Object { ConvertTo-EptRegistration $_ }
    }
}

function Measure-EptMfaPosture {
    <#
    .SYNOPSIS
        Aggregates Get-EptUserRegistration output into tenant-level (or group-level) posture metrics.
    .DESCRIPTION
        Pipeline-aggregating function: it collects input in process{} and emits one summary in end{}.
        Use -GroupBy to split the summary, for example by IsAdmin or UserType.
    .EXAMPLE
        Get-EptUserRegistration | Measure-EptMfaPosture
    .EXAMPLE
        Get-EptUserRegistration -UserType member | Measure-EptMfaPosture -GroupBy IsAdmin
    #>
    [CmdletBinding()]
    [OutputType('Ept.MfaPosture')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSTypeName('Ept.UserRegistration')] $InputObject,

        [string] $GroupBy
    )
    begin { $all = [System.Collections.Generic.List[object]]::new() }
    process { $all.Add($InputObject) }
    end {
        $groups = if ($GroupBy) { $all | Group-Object -Property $GroupBy } else { , @{ Name = 'All'; Group = $all } }
        foreach ($g in $groups) {
            $set = @($g.Group); $n = $set.Count
            if (-not $n) { continue }
            $pct = { param($count) [math]::Round(100 * $count / $n, 1) }
            [pscustomobject]@{
                PSTypeName                 = 'Ept.MfaPosture'
                Group                      = $g.Name
                Users                      = $n
                MfaRegisteredPct           = & $pct @($set | Where-Object IsMfaRegistered).Count
                PhishingResistantPct       = & $pct @($set | Where-Object HasPhishingResistant).Count
                TelephonyRegisteredPct     = & $pct @($set | Where-Object HasTelephony).Count
                TelephonyOnlyCount         = @($set | Where-Object StrongestMethod -eq 'Telephony').Count
                NoMfaCount                 = @($set | Where-Object StrongestMethod -in 'None', 'RecoveryOnly').Count
                AdminsWithoutPhishResistant = @($set | Where-Object { $_.IsAdmin -and -not $_.HasPhishingResistant }).Count
            }
        }
    }
}

#endregion
