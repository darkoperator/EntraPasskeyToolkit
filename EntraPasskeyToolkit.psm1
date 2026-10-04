# EntraPasskeyToolkit - companion module for the "MFA to passkeys in Microsoft Entra ID" blog series.
# Every function talks to Microsoft Graph through Invoke-MgGraphRequest, so the only dependency is
# Microsoft.Graph.Authentication. You choose the tenant, account and scopes with Connect-MgGraph.

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1')
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1')
foreach ($file in $private + $public) { . $file.FullName }

# Export only top-level functions defined in the Public folder.
$exports = foreach ($file in $public) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
    $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object Name
}
Export-ModuleMember -Function $exports
