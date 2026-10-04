#region Private helpers ---------------------------------------------------------
# These helpers are not exported. Every public function uses them so that
# paging, throttling and permission checks behave the same way everywhere.

function Assert-EptGraphConnection {
    <#
    .SYNOPSIS
        Throws a readable error when there is no Graph session or a required scope is missing.
    .DESCRIPTION
        Checks the current Microsoft Graph PowerShell context. The function never signs in on
        your behalf: you choose the tenant, account and scopes with Connect-MgGraph.
        App-only (certificate) sessions have no delegated scopes, so the scope check is skipped
        for them and Graph itself will return 403 if an application permission is missing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $RequiredScope
    )

    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes '$($RequiredScope -join "','")'"
    }

    if ($context.AuthType -eq 'Delegated') {
        # A *.ReadWrite.* scope also satisfies the matching *.Read.* requirement.
        $missing = foreach ($scope in $RequiredScope) {
            $readWrite = $scope -replace '\.Read\.', '.ReadWrite.'
            if ($context.Scopes -notcontains $scope -and $context.Scopes -notcontains $readWrite) { $scope }
        }
        if ($missing) {
            throw "The current Graph session is missing scope(s): $($missing -join ', '). Reconnect with Connect-MgGraph -Scopes '$($RequiredScope -join "','")'"
        }
    }
}

function Invoke-EptGraphRequest {
    <#
    .SYNOPSIS
        Wraps Invoke-MgGraphRequest with paging (@odata.nextLink) and 429/503 retry handling.
    .DESCRIPTION
        For GET requests that return a collection, each item in 'value' is written to the
        pipeline as it arrives, so callers can stream results instead of buffering them.
        For single-object responses the object itself is returned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string] $Method = 'GET',

        [object] $Body,

        [hashtable] $Headers = @{},

        [ValidateRange(0, 10)]
        [int] $MaxRetry = 5
    )

    $next = $Uri
    while ($next) {
        $attempt = 0
        while ($true) {
            try {
                $params = @{
                    Method      = $Method
                    Uri         = $next
                    Headers     = $Headers
                    OutputType  = 'PSObject'
                    ErrorAction = 'Stop'
                }
                if ($PSBoundParameters.ContainsKey('Body')) {
                    $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
                    $params.ContentType = 'application/json'
                }
                $response = Invoke-MgGraphRequest @params
                break
            }
            catch {
                $status = $_.Exception.Response.StatusCode.value__
                if ($status -in 429, 503, 504 -and $attempt -lt $MaxRetry) {
                    $attempt++
                    $retryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                    if (-not $retryAfter) { $retryAfter = [math]::Pow(2, $attempt) }
                    Write-Verbose "Graph returned $status. Waiting $retryAfter s (attempt $attempt of $MaxRetry)."
                    Start-Sleep -Seconds $retryAfter
                    continue
                }
                throw
            }
        }

        if ($null -ne $response -and $response.PSObject.Properties.Name -contains 'value') {
            foreach ($item in $response.value) { $item }
            $next = $response.'@odata.nextLink'
        }
        else {
            $response
            $next = $null
        }
    }
}

function Resolve-EptUserId {
    <#
    .SYNOPSIS
        Accepts an object ID or UPN and returns a value safe to place in a /users/{id} URL.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Identity)
    [uri]::EscapeDataString($Identity)
}

#endregion
