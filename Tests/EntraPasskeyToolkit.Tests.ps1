# Offline unit tests: Microsoft Graph is mocked, so no tenant is contacted.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'EntraPasskeyToolkit.psd1') -Force
}

Describe 'EntraPasskeyToolkit' {
    BeforeEach {
        Mock -ModuleName EntraPasskeyToolkit Get-MgContext {
            [pscustomobject]@{ AuthType = 'Delegated'; Scopes = @(
                'AuditLog.Read.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'GroupMember.Read.All',
                'UserAuthenticationMethod.ReadWrite.All', 'RoleManagement.Read.Directory', 'User.RevokeSessions.All',
                'Policy.ReadWrite.AuthenticationMethod', 'Application.Read.All') }
        }
    }

    Context 'Connection guard' {
        It 'throws a readable error when a scope is missing' {
            Mock -ModuleName EntraPasskeyToolkit Get-MgContext { [pscustomobject]@{ AuthType = 'Delegated'; Scopes = @('User.Read') } }
            { Get-EptUserRegistration } | Should -Throw '*AuditLog.Read.All*'
        }
    }

    Context 'Paging' {
        It 'follows @odata.nextLink and streams every item' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest {
                if ($Uri -like '*page2*') { [pscustomobject]@{ value = @(@{ id = 'c' }) } }
                else { [pscustomobject]@{ value = @(@{ id = 'a' }, @{ id = 'b' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/x?page2' } }
            }
            InModuleScope EntraPasskeyToolkit { @(Invoke-EptGraphRequest -Uri 'https://graph.microsoft.com/v1.0/x').id } |
                Should -Be @('a', 'b', 'c')
        }
    }

    Context 'Registration posture' {
        BeforeEach {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest {
                [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = '1'; userPrincipalName = 'admin@contoso.com'; isAdmin = $true; isMfaRegistered = $true; methodsRegistered = @('mobilePhone', 'microsoftAuthenticatorPush') }
                    [pscustomobject]@{ id = '2'; userPrincipalName = 'user@contoso.com'; isAdmin = $false; isMfaRegistered = $true; methodsRegistered = @('passKeyDeviceBound', 'mobilePhone') }
                    [pscustomobject]@{ id = '3'; userPrincipalName = 'new@contoso.com'; isAdmin = $false; isMfaRegistered = $false; methodsRegistered = @() }
                ) }
            }
        }
        It 'classifies the strongest registered method' {
            $r = Get-EptUserRegistration
            ($r | Where-Object UserPrincipalName -eq 'admin@contoso.com').StrongestMethod | Should -Be 'Phishable'
            ($r | Where-Object UserPrincipalName -eq 'user@contoso.com').HasPhishingResistant | Should -BeTrue
            ($r | Where-Object UserPrincipalName -eq 'new@contoso.com').StrongestMethod | Should -Be 'None'
        }
        It 'aggregates posture through the pipeline' {
            $m = Get-EptUserRegistration | Measure-EptMfaPosture
            $m.Users | Should -Be 3
            $m.PhishingResistantPct | Should -Be 33.3
            $m.AdminsWithoutPhishResistant | Should -Be 1
            $m.NoMfaCount | Should -Be 1
        }
        It 'queries by UPN when piped strings' {
            'user@contoso.com' | Get-EptUserRegistration | Out-Null
            Should -Invoke -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest -ParameterFilter { $Uri -like "*userPrincipalName eq 'user@contoso.com'*" }
        }
    }

    Context 'Write operations honour -WhatIf' {
        It 'does not call Graph for New-EptTemporaryAccessPass -WhatIf' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest { throw 'should not be called' }
            New-EptTemporaryAccessPass -UserPrincipalName 'a@contoso.com' -CaseId 'INC1' -WhatIf
            Should -Invoke -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest -Times 0
        }
        It 'returns the TAP as a SecureString' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest { [pscustomobject]@{ id = 'm1'; temporaryAccessPass = 'Abc12345'; lifetimeInMinutes = 60; isUsableOnce = $true } }
            $tap = New-EptTemporaryAccessPass -UserPrincipalName 'a@contoso.com' -CaseId 'INC1' -OneTime -Confirm:$false
            $tap.Pass | Should -BeOfType [securestring]
            $tap.Pass | ConvertFrom-SecureString -AsPlainText | Should -Be 'Abc12345'
        }
        It 'builds a report-only device code block policy with a flags string' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest {
                if ($Method -eq 'POST') { $global:EptTestPosted = $Body | ConvertFrom-Json; return [pscustomobject]@{ id = 'p1' } }
                [pscustomobject]@{ value = @() }
            }
            New-EptDeviceCodeBlockPolicy -DisplayName 'CA010' -ExcludeGroupId ([guid]::NewGuid()) -IncludeAuthenticationTransfer -Confirm:$false | Out-Null
            $body = $global:EptTestPosted
            $body.state | Should -Be 'enabledForReportingButNotEnforced'
            $body.conditions.authenticationFlows.transferMethods | Should -Be 'deviceCodeFlow,authenticationTransfer'
            $body.grantControls.builtInControls | Should -Be 'block'
        }
    }

    Context 'Conditional Access flattening' {
        It 'flags phishing-resistant and device-code-block policies' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest {
                if ($Uri -like '*authenticationStrengthPolicies*') {
                    return [pscustomobject]@{ value = @(
                        [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA'; policyType = 'builtIn'; allowedCombinations = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor') }
                        [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000002'; displayName = 'Multifactor authentication'; policyType = 'builtIn'; allowedCombinations = @('fido2', 'password,sms') }) }
                }
                [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'a'; displayName = 'Admins PR'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeRoles = @('r1') }; applications = [pscustomobject]@{ includeApplications = @('All') } }; grantControls = [pscustomobject]@{ operator = 'OR'; authenticationStrength = [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000004' } } }
                    [pscustomobject]@{ id = 'b'; displayName = 'All MFA'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('All') } }; grantControls = [pscustomobject]@{ operator = 'OR'; authenticationStrength = [pscustomobject]@{ id = '00000000-0000-0000-0000-000000000002' } } }
                    [pscustomobject]@{ id = 'c'; displayName = 'Block DCF'; state = 'enabledForReportingButNotEnforced'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('All') }; authenticationFlows = [pscustomobject]@{ transferMethods = 'deviceCodeFlow' } }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('block') } }
                ) }
            }
            $p = Get-EptConditionalAccessPolicy
            ($p | Where-Object PolicyId -eq 'a').RequiresPhishResistant | Should -BeTrue
            ($p | Where-Object PolicyId -eq 'b').RequiresPhishResistant | Should -BeFalse
            ($p | Where-Object PolicyId -eq 'c').BlocksDeviceCode | Should -BeTrue
        }
    }

    Context 'Sign-in method classification' {
        It 'classifies and aggregates MFA sign-ins' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest {
                $mk = { param($m) [pscustomobject]@{ createdDateTime = '2026-09-18T10:00:00Z'; userPrincipalName = 'u@contoso.com'; status = @{ errorCode = 0 }; authenticationRequirement = 'multiFactorAuthentication'; authenticationDetails = @([pscustomobject]@{ authenticationMethod = $m; succeeded = $true }) } }
                [pscustomobject]@{ value = @((& $mk 'Passkey (device-bound)'), (& $mk 'Text message'), (& $mk 'Mobile app notification'), (& $mk 'FIDO2 security key')) }
            }
            $s = Get-EptSignInMethod -Days 1 | Measure-EptSignInMethod
            $s.MfaSignIns | Should -Be 4
            $s.PhishingResistantPct | Should -Be 50
            $s.TelephonyPct | Should -Be 25
            Should -Invoke -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest -ParameterFilter { $Uri -like 'https://graph.microsoft.com/beta/auditLogs/signIns*' }
        }
    }

    Context 'Readiness report orchestration' {
        It 'writes CSVs and a summary, and survives a failing section' {
            Mock -ModuleName EntraPasskeyToolkit Get-MgContext { [pscustomobject]@{ AuthType = 'Delegated'; TenantId = '11111111-2222-3333-4444-555555555555'; Scopes = @('AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All') } }
            Mock -ModuleName EntraPasskeyToolkit Get-EptUserRegistration {
                [pscustomobject]@{ PSTypeName = 'Ept.UserRegistration'; UserPrincipalName = 'a@c.com'; IsAdmin = $true; IsMfaRegistered = $true; MethodsRegistered = @('passKeyDeviceBound'); PhishableMethods = @(); StrongestMethod = 'PhishingResistant'; HasPhishingResistant = $true; HasTelephony = $false }
                [pscustomobject]@{ PSTypeName = 'Ept.UserRegistration'; UserPrincipalName = 'b@c.com'; IsAdmin = $false; IsMfaRegistered = $true; MethodsRegistered = @('mobilePhone'); PhishableMethods = @('mobilePhone'); StrongestMethod = 'Telephony'; HasPhishingResistant = $false; HasTelephony = $true }
            }
            Mock -ModuleName EntraPasskeyToolkit Get-EptAuthMethodPolicy { [pscustomobject]@{ Method = 'Sms'; State = 'enabled'; Targets = @('All users'); Excluded = @(); MigrationState = 'migrationComplete' } }
            Mock -ModuleName EntraPasskeyToolkit Get-EptPasskeyProfile { throw 'simulated 403' }
            Mock -ModuleName EntraPasskeyToolkit Get-EptConditionalAccessPolicy { [pscustomobject]@{ Name = 'CA010'; State = 'enabled'; BlocksDeviceCode = $true; RequiresPhishResistant = $false } }
            Mock -ModuleName EntraPasskeyToolkit Get-EptPrivilegedUser { [pscustomobject]@{ UserPrincipalName = 'a@c.com'; PrincipalType = 'user' } }
            Mock -ModuleName EntraPasskeyToolkit Test-EptPhishResistantCoverage { [pscustomobject]@{ UserPrincipalName = 'a@c.com'; Verdict = 'NotCovered' } }

            $r = Export-EptReadinessReport -Path $TestDrive -SkipSignIns -WarningAction SilentlyContinue
            $r.Users | Should -Be 2
            $r.PhishingResistantRegisteredPct | Should -Be 50
            $r.SmsOrVoiceEnabled | Should -BeTrue
            $r.DeviceCodeBlockedEnforced | Should -BeTrue
            $r.AdminsNotCovered | Should -Be 1
            $r.Errors | Should -HaveCount 1
            (Import-Csv (Join-Path $r.Folder 'registration.csv'))[1].Methods | Should -Be 'mobilePhone'
            Test-Path (Join-Path $r.Folder 'summary.json') | Should -BeTrue
        }
    }

    Context 'Registration blocks' {
        It 'reports failures against credential-registration resources with the blocking policy' {
            Mock -ModuleName EntraPasskeyToolkit Invoke-MgGraphRequest {
                [pscustomobject]@{ value = @(
                    [pscustomobject]@{ createdDateTime = '2026-09-22T09:00:00Z'; userPrincipalName = 'byod@c.com'
                        resourceId = 'ea890292-c8c8-4433-b5ea-b09d0668e1a6'; resourceDisplayName = 'Azure Credential Configuration Endpoint Service'
                        appDisplayName = 'Microsoft Authenticator'; status = @{ errorCode = 53003; failureReason = 'Blocked by Conditional Access' }
                        conditionalAccessStatus = 'failure'; deviceDetail = @{ operatingSystem = 'Ios' }
                        appliedConditionalAccessPolicies = @(
                            [pscustomobject]@{ displayName = 'CA200 Require app protection policy'; result = 'failure' }
                            [pscustomobject]@{ displayName = 'CA110 Pilot phishing-resistant'; result = 'notApplied' }) }
                    # Different resource, should be filtered out
                    [pscustomobject]@{ createdDateTime = '2026-09-22T09:05:00Z'; userPrincipalName = 'byod@c.com'
                        resourceId = '00000003-0000-0ff1-ce00-000000000000'; resourceDisplayName = 'Office 365 SharePoint Online'
                        status = @{ errorCode = 53003 }; appliedConditionalAccessPolicies = @() }
                    # Registration resource, but successful: only with -IncludeSuccess
                    [pscustomobject]@{ createdDateTime = '2026-09-22T09:10:00Z'; userPrincipalName = 'byod@c.com'
                        resourceId = '00000002-0000-0000-c000-000000000000'; resourceDisplayName = 'Windows Azure Active Directory'
                        status = @{ errorCode = 0 }; appliedConditionalAccessPolicies = @() }
                ) }
            }
            $blocks = @(Get-EptRegistrationBlock -Days 7)
            $blocks | Should -HaveCount 1
            $blocks[0].Resource | Should -Be 'Azure Credential Configuration Endpoint Service'
            $blocks[0].BlockingPolicies | Should -Be 'CA200 Require app protection policy'
            @(Get-EptRegistrationBlock -Days 7 -IncludeSuccess) | Should -HaveCount 2
        }
    }
}
