# EntraPasskeyToolkit

PowerShell advanced functions for assessing, rolling out and operating phishing-resistant MFA and passkeys in Microsoft Entra ID.

- **One dependency:** `Microsoft.Graph.Authentication` 2.x. All calls go through `Invoke-MgGraphRequest`.
- **Pipeline-first:** every user-oriented function accepts UPNs, object IDs, or any object with a `UserPrincipalName`/`Id` property. Output objects carry `PSTypeName`s (`Ept.*`) so aggregators can validate their input.
- **Safe by default:**
  - read functions never change the tenant;
  - write functions support `-WhatIf`/`-Confirm` at High impact;
  - Conditional Access policies are created in **report-only** unless you say otherwise;
  - break-glass exclusions are mandatory;
  - TAPs are returned as `SecureString`.
- **You own the connection:** the module never signs in for you. Use `Connect-MgGraph -TenantId … -Scopes …`.

## Quick start

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Import-Module ./EntraPasskeyToolkit/EntraPasskeyToolkit.psd1

Connect-MgGraph -TenantId '<tenant-guid>' -ContextScope Process -NoWelcome -Scopes `
    'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All'

Export-EptReadinessReport -Path ./reports -SignInDays 7
Get-EptPrivilegedUser | Test-EptPhishResistantCoverage | Where-Object Verdict -ne 'Covered'
```

## Commands

| Command | R/W | Graph | Purpose |
|---|---|---|---|
| `Get-EptMethodStrength` | – | – | Classify method names (PhishingResistant / Phishable / Telephony / RecoveryOnly) |
| `Get-EptUserRegistration` | R | v1.0 | Registration details plus strength flags |
| `Measure-EptMfaPosture` | – | – | Aggregate registration into posture metrics |
| `Get-EptAuthMethodPolicy` | R | v1.0 | Method states, targets, migration and campaign state |
| `Get-EptPasskeyProfile` | R | v1.0 | Passkey profiles and their targets |
| `Add-EptPasskeyProfile` | **W** | v1.0 | Add a passkey profile (read-modify-write) |
| `Get-EptUserPasskey` | R | v1.0 | Users' passkeys with type, attestation and AAGUID name |
| `Remove-EptUserPasskey` | **W** | v1.0 | Delete a passkey (pipe from `Get-EptUserPasskey`) |
| `Get-EptAuthenticationStrength` | R | v1.0 | Strengths and whether they allow phishable methods |
| `New-EptAuthenticationStrength` | **W** | v1.0 | Custom strength, optionally AAGUID-restricted |
| `Get-EptConditionalAccessPolicy` | R | v1.0 | Flattened CA policies with MFA flags |
| `New-EptStrengthPolicy` | **W** | v1.0 | CA policy requiring a strength (report-only default) |
| `New-EptDeviceCodeBlockPolicy` | **W** | v1.0 | CA policy blocking device code / authentication transfer |
| `Test-EptPhishResistantCoverage` | R | v1.0 | Per-user coverage verdict |
| `New-EptTemporaryAccessPass` | **W** | v1.0 | Case-bound TAP returned as SecureString |
| `Get-EptAuthMethodAuditEvent` | R | v1.0 | Authentication-method audit events |
| `Get-EptRegistrationBlock` | R | **beta** | Sign-ins where Conditional Access blocked a credential-registration resource |
| `Get-EptSignInMethod` | R | **beta** | Sign-ins with methods used, protocol and token protection |
| `Measure-EptSignInMethod` | – | – | Share of MFA sign-ins by method class |
| `Revoke-EptUserSession` | **W** | v1.0 | Revoke refresh tokens and session cookies |
| `Get-EptPrivilegedUser` | R | v1.0 | Active + PIM-eligible role holders, groups expanded |
| `Get-EptAppCredentialOwner` | R | v1.0 | App registrations, owners and credential metadata |
| `Export-EptReadinessReport` | R | both | Run every assessment into a dated evidence folder |

Run `Get-Help <command> -Full` for parameters, required scopes/roles and examples.

## Tests

```powershell
Invoke-Pester ./EntraPasskeyToolkit/Tests -Output Detailed
```

The tests mock `Get-MgContext` and `Invoke-MgGraphRequest`, so no tenant is contacted. They have not been run against a live tenant. Validate in a test tenant first.
