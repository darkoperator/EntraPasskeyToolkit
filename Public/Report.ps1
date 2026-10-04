#region Programme reporting (Part 7) -----------------------------------------

function Export-EptReadinessReport {
    <#
    .SYNOPSIS
        Runs the read-only assessments from the series and writes a dated evidence folder plus a summary.
    .DESCRIPTION
        Orchestrates the other toolkit functions. It is read-only: nothing in the tenant is changed.
          * registration.csv          Get-EptUserRegistration (all users)
          * posture.csv               Measure-EptMfaPosture, overall and by IsAdmin
          * method-policy.csv         Get-EptAuthMethodPolicy
          * passkey-profiles.csv      Get-EptPasskeyProfile
          * conditional-access.csv    Get-EptConditionalAccessPolicy
          * admins.csv                Get-EptPrivilegedUser
          * admin-coverage.csv        Test-EptPhishResistantCoverage for every admin
          * signin-usage.csv          Measure-EptSignInMethod (unless -SkipSignIns)
          * summary.json              The headline numbers, for trending run over run

        Each section runs independently. If one fails (missing licence, scope or role), the error is
        recorded in summary.json and the remaining sections still run.

        Reports contain personal data (UPNs, IPs). Store them in approved locations only.

        Scopes: AuditLog.Read.All, Policy.Read.All, RoleManagement.Read.Directory, GroupMember.Read.All.
    .EXAMPLE
        Export-EptReadinessReport -Path ./reports -SignInDays 7
    .EXAMPLE
        # Trend the headline numbers across monthly runs
        Get-ChildItem ./reports -Filter summary.json -Recurse | Get-Content -Raw | ConvertFrom-Json |
            Sort-Object GeneratedUtc | Format-Table GeneratedUtc, PhishingResistantRegisteredPct, PhishingResistantSignInPct, AdminsNotCovered
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = '-SignInDays is used inside the Sign-in usage step scriptblock.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [ValidateRange(1, 30)]
        [int] $SignInDays = 7,

        [switch] $SkipSignIns
    )

    Assert-EptGraphConnection -RequiredScope 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All'
    $tenant = (Get-MgContext).TenantId
    $folder = Join-Path $Path ("{0}-{1}" -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'), $tenant.Substring(0, 8))
    New-Item -ItemType Directory -Path $folder -Force | Out-Null

    $summary = [ordered]@{ GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o'); TenantId = $tenant; Errors = @() }
    $csv = { param($data, $name) $data | Export-Csv -Path (Join-Path $folder $name) -NoTypeInformation -Encoding utf8 }

    # Run one section; record failures and keep going.
    $step = {
        param([string] $name, [scriptblock] $action)
        Write-Progress -Activity 'EntraPasskeyToolkit readiness report' -Status $name
        try { & $action }
        catch {
            Write-Warning "$name failed: $($_.Exception.Message)"
            $summary.Errors += "${name}: $($_.Exception.Message)"
        }
    }

    & $step 'Registration' {
        $reg = @(Get-EptUserRegistration)
        & $csv ($reg | Select-Object -Property *,
            @{ n = 'Methods'; e = { $_.MethodsRegistered -join ';' } },
            @{ n = 'Phishable'; e = { $_.PhishableMethods -join ';' } } -ExcludeProperty MethodsRegistered, PhishableMethods) 'registration.csv'
        $overall = $reg | Measure-EptMfaPosture
        & $csv (@($overall) + @($reg | Measure-EptMfaPosture -GroupBy IsAdmin)) 'posture.csv'
        $summary.Users = $overall.Users
        $summary.PhishingResistantRegisteredPct = $overall.PhishingResistantPct
        $summary.TelephonyOnlyUsers = $overall.TelephonyOnlyCount
        $summary.UsersWithoutMfa = $overall.NoMfaCount
    }

    & $step 'Method policy' {
        $policy = @(Get-EptAuthMethodPolicy)
        & $csv ($policy | Select-Object Method, State, MigrationState, CampaignState, CampaignMethod,
            @{ n = 'Targets'; e = { $_.Targets -join ';' } }, @{ n = 'Excluded'; e = { $_.Excluded -join ';' } }) 'method-policy.csv'
        $summary.MigrationState = ($policy | Select-Object -First 1).MigrationState
        $summary.SmsOrVoiceEnabled = [bool]($policy | Where-Object { $_.Method -in 'Sms', 'Voice' -and $_.State -eq 'enabled' })
    }

    & $step 'Passkey profiles' {
        & $csv (Get-EptPasskeyProfile | Select-Object ProfileName, PasskeyTypes, Attestation, KeyRestriction,
            @{ n = 'Aaguids'; e = { $_.Aaguids -join ';' } }, @{ n = 'TargetIds'; e = { $_.TargetIds -join ';' } }) 'passkey-profiles.csv'
    }

    & $step 'Conditional Access' {
        $ca = @(Get-EptConditionalAccessPolicy)
        & $csv ($ca | Select-Object Name, State, StrengthName, RequiresMfa, RequiresPhishResistant, BlocksDeviceCode,
            @{ n = 'IncludeUsers'; e = { $_.IncludeUsers -join ';' } }, @{ n = 'IncludeGroups'; e = { $_.IncludeGroups -join ';' } },
            @{ n = 'IncludeRoles'; e = { $_.IncludeRoles -join ';' } }, @{ n = 'ExcludeGroups'; e = { $_.ExcludeGroups -join ';' } }) 'conditional-access.csv'
        $summary.DeviceCodeBlockedEnforced = [bool]($ca | Where-Object { $_.BlocksDeviceCode -and $_.State -eq 'enabled' })
        $summary.PhishResistantPoliciesEnforced = @($ca | Where-Object { $_.RequiresPhishResistant -and $_.State -eq 'enabled' }).Count
    }

    & $step 'Privileged users' {
        $admins = @(Get-EptPrivilegedUser)
        & $csv $admins 'admins.csv'
        $coverage = @($admins | Where-Object PrincipalType -eq 'user' | Test-EptPhishResistantCoverage)
        & $csv $coverage 'admin-coverage.csv'
        $summary.Admins = $admins.Count
        $summary.AdminsNotCovered = @($coverage | Where-Object Verdict -ne 'Covered').Count
    }

    if (-not $SkipSignIns) {
        & $step 'Sign-in usage' {
            $usage = @(Get-EptSignInMethod -Days $SignInDays | Measure-EptSignInMethod)
            & $csv ($usage | Select-Object -Property *,
                @{ n = 'TelephonyUserList'; e = { $_.TelephonyUsers -join ';' } } -ExcludeProperty TelephonyUsers) 'signin-usage.csv'
            $summary.SignInDays = $SignInDays
            $summary.PhishingResistantSignInPct = ($usage | Select-Object -First 1).PhishingResistantPct
            $summary.TelephonySignInPct = ($usage | Select-Object -First 1).TelephonyPct
        }
    }

    Write-Progress -Activity 'EntraPasskeyToolkit readiness report' -Completed
    $summary.Folder = (Resolve-Path $folder).Path
    $summary | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $folder 'summary.json') -Encoding utf8
    [pscustomobject]$summary
}

#endregion
