#region Privileged access (Part 6) -------------------------------------------

function Get-EptPrivilegedUser {
    <#
    .SYNOPSIS
        Lists users who hold Entra directory roles, both active and PIM-eligible, one object per user.
    .DESCRIPTION
        Reads active assignments (GET /roleManagement/directory/roleAssignments) and, unless
        -ActiveOnly is used, PIM eligibility (GET /roleManagement/directory/roleEligibilityScheduleInstances).
        Role-assignable groups are expanded to their transitive user members so that group-based
        admins are not missed. Service principals holding roles are reported with -IncludeServicePrincipal.

        Output binds by property name (UserPrincipalName, Id) to the other Ept functions, which makes
        this the natural start of an admin posture pipeline.

        This covers Entra directory roles only. Azure RBAC, Intune, Defender, Purview and
        application ownership are separate control planes: review them separately.

        Requires: RoleManagement.Read.Directory (plus GroupMember.Read.All to expand groups) and
        a role such as Global Reader or Privileged Role Administrator. Eligibility needs Entra ID P2.
    .PARAMETER RoleName
        Only return holders of these roles (wildcards allowed), e.g. 'Global Administrator','*Authentication*'.
    .EXAMPLE
        Get-EptPrivilegedUser | Get-EptUserRegistration | Where-Object { -not $_.HasPhishingResistant }
    .EXAMPLE
        Get-EptPrivilegedUser -RoleName 'Global Administrator' | Format-Table UserPrincipalName, Roles, AssignmentTypes
    #>
    [CmdletBinding()]
    [OutputType('Ept.PrivilegedUser')]
    param(
        [string[]] $RoleName = '*',
        [switch] $ActiveOnly,
        [switch] $IncludeServicePrincipal
    )

    Assert-EptGraphConnection -RequiredScope 'RoleManagement.Read.Directory'
    $root = 'https://graph.microsoft.com/v1.0/roleManagement/directory'

    $sources = @(@{ Type = 'Active'; Uri = "$root/roleAssignments?`$expand=principal,roleDefinition" })
    if (-not $ActiveOnly) {
        $sources += @{ Type = 'Eligible'; Uri = "$root/roleEligibilityScheduleInstances?`$expand=principal,roleDefinition" }
    }

    $byPrincipal = @{}
    foreach ($source in $sources) {
        try {
            $assignments = @(Invoke-EptGraphRequest -Uri $source.Uri)
        }
        catch {
            if ($source.Type -eq 'Eligible') {
                Write-Warning "Could not read PIM eligibility (P2 licence or permission missing?): $($_.Exception.Message)"
                continue
            }
            throw
        }

        foreach ($a in $assignments) {
            $role = $a.roleDefinition.displayName
            if (-not ($RoleName | Where-Object { $role -like $_ })) { continue }

            $principal = $a.principal
            $kind = $principal.'@odata.type' -replace '#microsoft.graph.', ''
            $members = switch ($kind) {
                'user' { , $principal }
                'group' {
                    Invoke-EptGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($principal.id)/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,displayName,accountEnabled"
                }
                'servicePrincipal' { if ($IncludeServicePrincipal) { , $principal } }
            }

            foreach ($m in $members) {
                if (-not $byPrincipal.ContainsKey($m.id)) {
                    $byPrincipal[$m.id] = [pscustomobject]@{
                        PSTypeName        = 'Ept.PrivilegedUser'
                        Id                = $m.id
                        UserPrincipalName = if ($m.userPrincipalName) { $m.userPrincipalName } else { $m.appId }
                        DisplayName       = $m.displayName
                        PrincipalType     = $kind
                        AccountEnabled    = $m.accountEnabled
                        Roles             = [System.Collections.Generic.SortedSet[string]]::new()
                        AssignmentTypes   = [System.Collections.Generic.SortedSet[string]]::new()
                        ViaGroup          = [System.Collections.Generic.SortedSet[string]]::new()
                    }
                }
                $entry = $byPrincipal[$m.id]
                [void]$entry.Roles.Add($role)
                [void]$entry.AssignmentTypes.Add($source.Type)
                if ($kind -eq 'group') { [void]$entry.ViaGroup.Add($principal.displayName) }
            }
        }
    }

    $byPrincipal.Values | ForEach-Object {
        # Flatten sets to strings so the objects export cleanly to CSV.
        $_.Roles = @($_.Roles) -join '; '
        $_.AssignmentTypes = @($_.AssignmentTypes) -join '; '
        $_.ViaGroup = @($_.ViaGroup) -join '; '
        $_
    } | Sort-Object UserPrincipalName
}

function Get-EptAppCredentialOwner {
    <#
    .SYNOPSIS
        Inventories app registrations with their owners and credential metadata (never secret values).
    .DESCRIPTION
        An owner of an app registration can add credentials to it. If the app holds powerful
        application permissions, its owners are effectively privileged even without a directory role,
        and user MFA does not apply to the app-only tokens that credential can obtain.
        Pipe the Owners into Get-EptUserRegistration to check how those people authenticate.

        Requires: Application.Read.All.
    .EXAMPLE
        Get-EptAppCredentialOwner | Where-Object OwnerCount -eq 0
    .EXAMPLE
        Get-EptAppCredentialOwner | Select-Object -ExpandProperty Owners -Unique | Get-EptUserRegistration
    #>
    [CmdletBinding()]
    [OutputType('Ept.AppCredentialOwner')]
    param(
        [ValidateRange(0, 3650)]
        [int] $ExpiringWithinDays = 30
    )
    Assert-EptGraphConnection -RequiredScope 'Application.Read.All'
    $now = (Get-Date).ToUniversalTime()

    Invoke-EptGraphRequest -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$expand=owners($select=id,userPrincipalName)' |
        ForEach-Object {
            $creds = @($_.passwordCredentials) + @($_.keyCredentials) | Where-Object { $_ }
            $ends = $creds | ForEach-Object { [datetime]$_.endDateTime }
            [pscustomobject]@{
                PSTypeName         = 'Ept.AppCredentialOwner'
                AppId              = $_.appId
                DisplayName        = $_.displayName
                OwnerCount         = @($_.owners).Count
                Owners             = @($_.owners | Where-Object userPrincipalName | ForEach-Object userPrincipalName)
                SecretCount        = @($_.passwordCredentials).Count
                CertificateCount   = @($_.keyCredentials).Count
                ExpiredCredentials = @($ends | Where-Object { $_ -lt $now }).Count
                ExpiringSoon       = @($ends | Where-Object { $_ -ge $now -and $_ -lt $now.AddDays($ExpiringWithinDays) }).Count
            }
        }
}

#endregion
