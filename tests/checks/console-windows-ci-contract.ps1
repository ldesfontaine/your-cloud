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

$requiredFunctions = @(
    "Invoke-CleanupAction",
    "Test-ProofProcessAttribution",
    "Test-ProcessInstanceIdentity",
    "Get-BoundedWaitMilliseconds",
    "Resolve-BoundedChildPath",
    "Get-AttributedProofProcesses"
)
$functionDefinitions = @($ast.FindAll(
    {
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    },
    $true
))
foreach ($requiredFunction in $requiredFunctions) {
    $matches = @($functionDefinitions | Where-Object { $_.Name -eq $requiredFunction })
    if ($matches.Count -ne 1) {
        throw "expected exactly one $requiredFunction function"
    }
    . ([scriptblock]::Create($matches[0].Extent.Text))
}

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

$automationSid = "S-1-5-21-1000"
$otherSid = "S-1-5-21-2000"
$consolePath = "C:\Program Files\Your Cloud\your-cloud-console.exe"
$driverPath = "C:\tools\tauri-driver.exe"
$webViewPath = "C:\Program Files\WebView2\msedgewebview2.exe"
$trackedPaths = @($consolePath, $driverPath)

if (-not (Test-ProofProcessAttribution `
    -CandidatePath $webViewPath `
    -CandidateOwnerSid $automationSid `
    -AutomationSid $automationSid `
    -TrackedExecutablePaths $trackedPaths)) {
    throw "the ephemeral SID must attribute its WebView2 process"
}
if (-not (Test-ProofProcessAttribution `
    -CandidatePath ($driverPath.ToUpperInvariant()) `
    -CandidateOwnerSid $otherSid `
    -AutomationSid $automationSid `
    -TrackedExecutablePaths $trackedPaths)) {
    throw "an exact tracked executable path must be attributed case-insensitively"
}
if (Test-ProofProcessAttribution `
    -CandidatePath $webViewPath `
    -CandidateOwnerSid $otherSid `
    -AutomationSid $automationSid `
    -TrackedExecutablePaths $trackedPaths) {
    throw "a foreign WebView2 process must not be attributed to the proof"
}
if (Test-ProofProcessAttribution `
    -CandidatePath $null `
    -CandidateOwnerSid $otherSid `
    -AutomationSid $automationSid `
    -TrackedExecutablePaths $trackedPaths) {
    throw "an unrelated process with no image path must not be attributed"
}

$script:contractProcessCandidates = @(
    [pscustomobject]@{ ProcessId = 1 }
)
function Get-CimInstance {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$ClassName)

    if ($ClassName -ne "Win32_Process") {
        throw "unexpected contract CIM class"
    }
    return $script:contractProcessCandidates
}
function Resolve-ProofProcessAttribution {
    param(
        [Parameter(Mandatory = $true)]$Candidate,
        [AllowNull()][string]$AutomationSid,
        [AllowEmptyCollection()][string[]]$TrackedExecutablePaths = @(),
        [AllowEmptyCollection()][string[]]$OwnerRequiredPaths = @()
    )

    if ($Candidate.ProcessId -eq 1) {
        return $null
    }
    return [pscustomobject]@{
        ProcessId = $Candidate.ProcessId
        CreationDate = [DateTime]::UtcNow
    }
}

$foreignOnlyProcesses = @(Get-AttributedProofProcesses)
if ($foreignOnlyProcesses.Count -ne 0) {
    throw "a non-attributed process must produce an empty process collection"
}
$script:contractProcessCandidates = @(
    [pscustomobject]@{ ProcessId = 1 },
    [pscustomobject]@{ ProcessId = 2 }
)
$mixedProcesses = @(Get-AttributedProofProcesses)
if ($mixedProcesses.Count -ne 1 -or $mixedProcesses[0].ProcessId -ne 2) {
    throw "null attribution results must not become process candidates"
}

$creationDate = [DateTime]::UtcNow.AddSeconds(-5)
if (-not (Test-ProcessInstanceIdentity `
    -ExpectedProcessId 42 `
    -ExpectedCreationDate $creationDate `
    -CurrentProcessId 42 `
    -CurrentCreationDate $creationDate)) {
    throw "the same PID and creation time must identify the same process instance"
}
if (Test-ProcessInstanceIdentity `
    -ExpectedProcessId 42 `
    -ExpectedCreationDate $creationDate `
    -CurrentProcessId 42 `
    -CurrentCreationDate ($creationDate.AddMilliseconds(1))) {
    throw "a reused PID with another creation time must not be terminated"
}
if (Test-ProcessInstanceIdentity `
    -ExpectedProcessId 42 `
    -ExpectedCreationDate $creationDate `
    -CurrentProcessId 42 `
    -CurrentCreationDate $null) {
    throw "a disappeared process instance must not be terminated"
}
if ((Get-BoundedWaitMilliseconds -RemainingMilliseconds 12000) -ne 5000 -or
    (Get-BoundedWaitMilliseconds -RemainingMilliseconds 1250) -ne 1250 -or
    (Get-BoundedWaitMilliseconds -RemainingMilliseconds -1) -ne 0) {
    throw "cleanup waits must remain capped by the global deadline"
}

$boundedRoot = Join-Path ([IO.Path]::GetTempPath()) "your-cloud-profile"
$boundedChild = Join-Path $boundedRoot "AppData/Roaming/fr.your-cloud.console"
$resolvedChild = Resolve-BoundedChildPath `
    -Root $boundedRoot `
    -Path $boundedChild `
    -Description "contract child"
if ($resolvedChild -ne [IO.Path]::GetFullPath($boundedChild)) {
    throw "bounded child path resolution drifted"
}
$siblingWasRejected = $false
try {
    [void](Resolve-BoundedChildPath `
        -Root $boundedRoot `
        -Path ($boundedRoot + "-sibling") `
        -Description "hostile sibling")
}
catch {
    $siblingWasRejected = $true
}
if (-not $siblingWasRejected) {
    throw "a sibling path sharing the profile prefix must be rejected"
}

$cleanupCommands = @($ast.FindAll(
    {
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq "Invoke-CleanupAction"
    },
    $true
))
$cleanupNames = @($cleanupCommands | ForEach-Object {
    if ($_.CommandElements.Count -lt 4 -or
        $_.CommandElements[2] -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        throw "cleanup actions must keep a literal positional name"
    }
    $_.CommandElements[2].Value
})
$requiredCleanupOrder = @(
    "attributed proof process drain",
    "product and driver process absence",
    "application data containment",
    "ephemeral profile removal",
    "ephemeral account removal",
    "ephemeral account and profile absence",
    "application data absence"
)
$previousPosition = -1
$cleanupPositions = @{}
foreach ($cleanupName in $requiredCleanupOrder) {
    $positions = @(for ($index = 0; $index -lt $cleanupNames.Count; $index++) {
        if ($cleanupNames[$index] -eq $cleanupName) {
            $index
        }
    })
    if ($positions.Count -ne 1) {
        throw "expected exactly one cleanup action named $cleanupName"
    }
    $position = $positions[0]
    if ($position -le $previousPosition) {
        throw "cleanup action order is missing or unsafe at $cleanupName"
    }
    $cleanupPositions[$cleanupName] = $position
    $previousPosition = $position
}
$applicationContainmentCommand = $cleanupCommands[
    $cleanupPositions["application data containment"]
]
if ($applicationContainmentCommand.Extent.Text -match '\bRemove-Item\b') {
    throw "the runner must not bypass the private vault DACL with direct deletion"
}
$processDrainCommand = $cleanupCommands[
    $cleanupPositions["attributed proof process drain"]
]
if ($processDrainCommand.Extent.Text -notmatch '\$drainDeadline\s*=\s*\[DateTime\]::UtcNow\.AddSeconds\(15\)' -or
    $processDrainCommand.Extent.Text -notmatch '\bGet-RevalidatedProofProcessHandle\b' -or
    $processDrainCommand.Extent.Text -notmatch '\bGet-BoundedWaitMilliseconds\b' -or
    $processDrainCommand.Extent.Text -notmatch '\bStop-BoundedProcessInstance\b') {
    throw "the process drain must keep one global deadline and revalidate each instance"
}
$treeStopFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Stop-BoundedProcessTree"
})
if ($treeStopFunctions.Count -ne 1 -or
    $treeStopFunctions[0].Extent.Text -match '\btaskkill(?:\.exe)?\b' -or
    $treeStopFunctions[0].Extent.Text -notmatch '\.Kill\(\$true\)') {
    throw "bounded process-tree termination must never use a bare PID"
}
$instanceStopFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Stop-BoundedProcessInstance"
})
if ($instanceStopFunctions.Count -ne 1 -or
    $instanceStopFunctions[0].Extent.Text -match '\btaskkill(?:\.exe)?\b' -or
    $instanceStopFunctions[0].Extent.Text -notmatch '\.Kill\(\)') {
    throw "the drain must terminate only the revalidated process instance"
}
$revalidationFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Get-RevalidatedProofProcessHandle"
})
if ($revalidationFunctions.Count -ne 1 -or
    $revalidationFunctions[0].Extent.Text -notmatch '\.SafeHandle\b' -or
    $revalidationFunctions[0].Extent.Text -notmatch '\bGet-CurrentProcessInstance\b' -or
    $revalidationFunctions[0].Extent.Text -notmatch '\bResolve-ProofProcessAttribution\b') {
    throw "the drain must pin and reattribute the exact process instance before termination"
}
$currentInstanceFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Get-CurrentProcessInstance"
})
if ($currentInstanceFunctions.Count -ne 1 -or
    $currentInstanceFunctions[0].Extent.Text -notmatch '\$null\s+-eq\s+\$current\.CreationDate' -or
    $currentInstanceFunctions[0].Extent.Text -notmatch 'creation time .* could not be verified' -or
    $currentInstanceFunctions[0].Extent.Text -notmatch '\bTest-ProcessInstanceIdentity\b') {
    throw "a present process with no creation time must fail closed"
}
$attributionResolutionFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Resolve-ProofProcessAttribution"
})
if ($attributionResolutionFunctions.Count -ne 1 -or
    $attributionResolutionFunctions[0].Extent.Text -match '\breturn\s+\$null\b') {
    throw "a non-attributed process must emit no pipeline object"
}

Write-Host "PASS: Windows proof cleanup is attributable, bounded and DACL-compatible"
