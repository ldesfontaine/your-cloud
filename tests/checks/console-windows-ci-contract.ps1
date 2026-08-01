$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$proofScript = Resolve-Path (Join-Path $PSScriptRoot "console-windows-ci.ps1")
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $proofScript,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {
    throw ($errors.Message -join [Environment]::NewLine)
}

$cleanupFunctions = @($ast.FindAll(
    {
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Invoke-CleanupAction"
    },
    $true
))
if ($cleanupFunctions.Count -ne 1) {
    throw "expected exactly one Invoke-CleanupAction function"
}

$cleanupFunction = [scriptblock]::Create($cleanupFunctions[0].Extent.Text)
. $cleanupFunction

$failures = [Collections.Generic.List[string]]::new()
Invoke-CleanupAction -Failures $failures -Name "nominal cleanup" -Action {}
if ($failures.Count -ne 0) {
    throw "nominal cleanup unexpectedly produced a failure"
}

Invoke-CleanupAction -Failures $failures -Name "hostile cleanup" -Action {
    throw "synthetic failure"
}
if ($failures.Count -ne 1 -or
    $failures[0] -ne "hostile cleanup: synthetic failure") {
    throw "cleanup failure aggregation contract is broken"
}

Write-Host "PASS: Windows proof script parses and cleanup aggregation accepts an empty list"
