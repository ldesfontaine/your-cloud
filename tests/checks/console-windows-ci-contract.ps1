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
    "Get-AttributedProofProcesses",
    "Assert-NonReparseRegularFile",
    "Get-ExactExecutableArtifacts",
    "ConvertTo-SanitizedPeGateProof",
    "ConvertFrom-DevToolsActivePort",
    "Read-BoundedDevToolsActivePortContent",
    "Test-DebuggerListenerAttribution",
    "Get-AttributedDebuggerListeners"
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

$syntheticSha256 = [string]::new('a', 64)
$sanitizedPeProof = ConvertTo-SanitizedPeGateProof `
    -Document ([pscustomobject]@{
        target = "x86_64-pc-windows-msvc"
        size = [int64]42
        sha256 = $syntheticSha256
        cargo = [pscustomobject]@{
            packages = @(
                "your-cloud-bootstrap-protocol",
                "your-cloud-native-bootstrap-assistant"
            )
            sha256 = [string]::new('b', 64)
        }
        elf_direct_needed = $null
        pe_imports = [pscustomobject]@{
            format = "PE32+"
            machine = "AMD64"
            normal = @("kernel32.dll")
            delay = @("user32.dll")
            all = @("kernel32.dll", "user32.dll")
        }
    }) `
    -ExpectedSha256 $syntheticSha256
if ($sanitizedPeProof.sha256 -ne $syntheticSha256 -or
    $sanitizedPeProof.cargo.package_count -ne 2 -or
    $sanitizedPeProof.pe_imports.all.Count -ne 2) {
    throw "sanitized PE gate proof contract is broken"
}
$hostilePeProofWasRejected = $false
try {
    [void](ConvertTo-SanitizedPeGateProof `
        -Document ([pscustomobject]@{
            target = "x86_64-pc-windows-msvc"
            size = [int64]42
            sha256 = $syntheticSha256
            cargo = [pscustomobject]@{
                packages = @(
                    "your-cloud-bootstrap-protocol",
                    "your-cloud-native-bootstrap-assistant"
                )
                sha256 = [string]::new('b', 64)
            }
            elf_direct_needed = $null
            pe_imports = [pscustomobject]@{
                format = "PE32+"
                machine = "AMD64"
                normal = @("webkit.dll")
                delay = @()
                all = @("webkit.dll")
            }
        }) `
        -ExpectedSha256 $syntheticSha256)
}
catch {
    $hostilePeProofWasRejected = $true
}
if (-not $hostilePeProofWasRejected) {
    throw "an inconsistent PE import union must be rejected"
}

$devToolsEndpoint = ConvertFrom-DevToolsActivePort `
    -Content "55123`n/devtools/browser/01234567-89ab-cdef-0123-456789abcdef"
if ($devToolsEndpoint.Port -ne 55123 -or
    $devToolsEndpoint.BrowserPath -ne "/devtools/browser/01234567-89ab-cdef-0123-456789abcdef") {
    throw "nominal DevToolsActivePort parsing contract is broken"
}
foreach ($boundaryPort in @(1, 65535)) {
    $boundaryEndpoint = ConvertFrom-DevToolsActivePort `
        -Content "$boundaryPort`n/devtools/browser/boundary"
    if ($boundaryEndpoint.Port -ne $boundaryPort) {
        throw "DevToolsActivePort rejected a valid TCP boundary"
    }
}
foreach ($hostileDevToolsActivePort in @(
    "",
    "0`n/devtools/browser/01234567-89ab-cdef-0123-456789abcdef`n",
    "65536`n/devtools/browser/01234567-89ab-cdef-0123-456789abcdef`n",
    "not-a-port`n/devtools/browser/01234567-89ab-cdef-0123-456789abcdef`n",
    "55123`n",
    "55123`n/devtools/browser/valid`nextra`n",
    "55123`n/devtools/page/not-a-browser`n",
    "55123`n/devtools/browser/../traversal",
    "55123`r`n/devtools/browser/non-canonical-newline`r`n",
    [string]::new('a', 513)
)) {
    $hostileEndpointWasRejected = $false
    try {
        [void](ConvertFrom-DevToolsActivePort -Content $hostileDevToolsActivePort)
    }
    catch {
        $hostileEndpointWasRejected = $true
    }
    if (-not $hostileEndpointWasRejected) {
        throw "hostile DevToolsActivePort content was accepted"
    }
}

$devToolsContractPath = Join-Path `
    ([IO.Path]::GetTempPath()) `
    ("your-cloud-devtools-active-port-" + [Guid]::NewGuid().ToString("N"))
try {
    $nominalDevToolsContent = "55123`n/devtools/browser/contract"
    [IO.File]::WriteAllText(
        $devToolsContractPath,
        $nominalDevToolsContent,
        [Text.Encoding]::ASCII
    )
    if ((Read-BoundedDevToolsActivePortContent `
            -Path $devToolsContractPath `
            -ExpectedParent ([IO.Path]::GetDirectoryName($devToolsContractPath))) -ne
        $nominalDevToolsContent) {
        throw "bounded DevToolsActivePort handle read changed its content"
    }
    foreach ($hostileFileContent in @("", [string]::new('a', 513))) {
        [IO.File]::WriteAllText(
            $devToolsContractPath,
            $hostileFileContent,
            [Text.Encoding]::ASCII
        )
        $hostileFileWasRejected = $false
        try {
            [void](Read-BoundedDevToolsActivePortContent `
                -Path $devToolsContractPath `
                -ExpectedParent ([IO.Path]::GetDirectoryName($devToolsContractPath)))
        }
        catch {
            $hostileFileWasRejected = $true
        }
        if (-not $hostileFileWasRejected) {
            throw "empty or oversized DevToolsActivePort file was accepted"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $devToolsContractPath) {
        Remove-Item -LiteralPath $devToolsContractPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $devToolsContractPath) {
        throw "DevToolsActivePort contract scratch file remained after cleanup"
    }
}

$automationSid = "S-1-5-21-1000"
$otherSid = "S-1-5-21-2000"
$webViewPath = "C:\Program Files\WebView2\msedgewebview2.exe"
if (-not (Test-DebuggerListenerAttribution `
        -LocalAddress "127.0.0.1" `
        -CandidatePath ($webViewPath.ToUpperInvariant()) `
        -CandidateOwnerSid $automationSid `
        -ExpectedRuntimePath $webViewPath `
        -ExpectedOwnerSid $automationSid) -or
    -not (Test-DebuggerListenerAttribution `
        -LocalAddress "::1" `
        -CandidatePath $webViewPath `
        -CandidateOwnerSid $automationSid `
        -ExpectedRuntimePath $webViewPath `
        -ExpectedOwnerSid $automationSid)) {
    throw "exact loopback WebView2 listener attribution must be accepted"
}
foreach ($hostileListener in @(
    @{ Address = "0.0.0.0"; Path = $webViewPath; Sid = $automationSid },
    @{ Address = "127.0.0.2"; Path = $webViewPath; Sid = $automationSid },
    @{ Address = "127.0.0.1"; Path = "C:\foreign.exe"; Sid = $automationSid },
    @{ Address = "127.0.0.1"; Path = "$webViewPath.suffix"; Sid = $automationSid },
    @{ Address = "127.0.0.1"; Path = $webViewPath; Sid = $otherSid },
    @{ Address = "127.0.0.1"; Path = $null; Sid = $automationSid },
    @{ Address = "127.0.0.1"; Path = $webViewPath; Sid = $null }
)) {
    if (Test-DebuggerListenerAttribution `
        -LocalAddress $hostileListener.Address `
        -CandidatePath $hostileListener.Path `
        -CandidateOwnerSid $hostileListener.Sid `
        -ExpectedRuntimePath $webViewPath `
        -ExpectedOwnerSid $automationSid) {
        throw "foreign or unbounded debugger listener attribution was accepted"
    }
}
if (Test-DebuggerListenerAttribution `
    -LocalAddress "127.0.0.1" `
    -CandidatePath $webViewPath `
    -CandidateOwnerSid $automationSid `
    -ExpectedRuntimePath $webViewPath `
    -ExpectedOwnerSid $null) {
    throw "a missing expected debugger SID was accepted"
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

$consolePath = "C:\Program Files\Your Cloud\your-cloud-console.exe"
$driverPath = "C:\tools\tauri-driver.exe"
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
    "WebView2 debugger cleanup",
    "MSI uninstall",
    "MSI installation absence",
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
$debuggerCleanupCommand = $cleanupCommands[
    $cleanupPositions["WebView2 debugger cleanup"]
]
if ($debuggerCleanupCommand.Extent.Text -notmatch '\bGet-NetTCPConnection\b' -or
    $debuggerCleanupCommand.Extent.Text -notmatch '\$remoteDebuggingPort\b' -or
    $debuggerCleanupCommand.Extent.Text -notmatch '\$remainingDebuggerListeners\.Count\s+-ne\s+0') {
    throw "the debugger cleanup must prove the selected listener port absent"
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

$artifactSetFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Get-ExactExecutableArtifacts"
})
if ($artifactSetFunctions.Count -ne 1 -or
    $artifactSetFunctions[0].Extent.Text -notmatch '\*\.exe' -or
    $artifactSetFunctions[0].Extent.Text -notmatch '\bAssert-NonReparseRegularFile\b' -or
    $artifactSetFunctions[0].Extent.Text -notmatch '\$actualNames\.Count\s+-ne\s+\$expectedNames\.Count') {
    throw "the artifact proof must enforce one exact non-reparse executable file set"
}
$nonReparseFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Assert-NonReparseRegularFile"
})
if ($nonReparseFunctions.Count -ne 1 -or
    $nonReparseFunctions[0].Extent.Text -notmatch '\bReparsePoint\b' -or
    $nonReparseFunctions[0].Extent.Text -notmatch '\bGetDirectoryName\b' -or
    $nonReparseFunctions[0].Extent.Text -notmatch '\bLength\s+-le\s+0\b') {
    throw "packaged and installed executables must be direct non-empty non-reparse siblings"
}
$debuggerListenerFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Get-AttributedDebuggerListeners"
})
if ($debuggerListenerFunctions.Count -ne 1 -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bGet-NetTCPConnection\b' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bGetOwnerSid\b' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bCreationDate\b' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bCreationTime\b' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\[DateTime\]::MinValue' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bListenerCreationTime\b' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\$ownerProcessIds\.Count\s+-ne\s+1' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\$attributed\.LocalAddress\s+-notcontains\s+"127\.0\.0\.1"' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bProcessId\s*=' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bLocalAddress\s*=' -or
    $debuggerListenerFunctions[0].Extent.Text -notmatch '\bTest-DebuggerListenerAttribution\b') {
    throw "the debugger listener must be one exact loopback runtime process instance"
}
$devToolsReadFunctions = @($functionDefinitions | Where-Object {
    $_.Name -eq "Read-BoundedDevToolsActivePortContent"
})
if ($devToolsReadFunctions.Count -ne 1 -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\[IO\.File\]::Open' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\[IO\.FileMode\]::Open' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\[IO\.FileAccess\]::Read' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\[IO\.FileShare\]::Read' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\$handleLength\s+-gt\s+512' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\$stream\.Read\(' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\bAssert-NonReparseRegularFile\b' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\$stream\.Length\s+-ne\s+\$handleLength' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch '\$stableFile\.Length\s+-ne\s+\$handleLength' -or
    $devToolsReadFunctions[0].Extent.Text -notmatch 'non-ASCII byte') {
    throw "DevToolsActivePort must be read once through one bounded shared-read handle"
}
$tcpListenerTypeExpressions = @($ast.FindAll(
    {
        param($node)
        $node -is [System.Management.Automation.Language.TypeExpressionAst] -and
            $node.Extent.Text -match '(?i)TcpListener'
    },
    $true
))
if ($tcpListenerTypeExpressions.Count -ne 0) {
    throw "the proof must not reserve and release a debugger port before WebView2 binds it"
}

$proofSource = Get-Content -LiteralPath $proofScript -Raw
$artifactCommands = @($ast.FindAll(
    {
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq "Get-ExactExecutableArtifacts"
    },
    $true
))
$administrativeArtifactCall = @($artifactCommands | Where-Object {
    $_.Extent.Text.Contains('MSI administrative image installable payload')
})
$installedArtifactCall = @($artifactCommands | Where-Object {
    $_.Extent.Text.Contains('installed product directory')
})
if ($administrativeArtifactCall.Count -ne 1 -or
    $administrativeArtifactCall[0].Extent.Text -notmatch '(?m)-Recurse\b' -or
    $installedArtifactCall.Count -ne 1 -or
    $installedArtifactCall[0].Extent.Text -match '(?m)-Recurse\b') {
    throw "only the administrative image may be scanned recursively for executable artifacts"
}
foreach ($requiredProofFragment in @(
    '"your-cloud-console.exe"',
    '"your-cloud-native-bootstrap-assistant.exe"',
    '"x86_64-pc-windows-msvc"',
    '"--packaged"',
    '"tools\check-native-bootstrap-assistant.mjs"',
    '$installedHelperSha256 -ne $packagedHelperSha256',
    'Assert-AuthenticodeSignature $installedHelper $certificate.Thumbprint',
    '-Operation "direct native helper parent refusal"',
    '-AllowedExitCodes @(70)',
    'refused native helper invocation emitted public output',
    '"windows-native-personal-consent.png"',
    '$proofNameDifferences',
    'Compare-Object',
    'installed native helper remained at $installedHelper',
    '$shortcutTarget,',
    '$installedConsole.FullName,',
    'administrative_image_contains_exact_installable_executable_file_set',
    '"--remote-debugging-port=0"',
    '"DevToolsActivePort"',
    'ConvertFrom-DevToolsActivePort',
    'Test-DebuggerListenerAttribution',
    'Get-AttributedDebuggerListeners',
    '-Description "opened WebView2 DevToolsActivePort"',
    '[IO.FileShare]::Read',
    'DevToolsActivePort path changed after its bounded read',
    '-CandidatePath $candidate.ExecutablePath',
    '-CandidateOwnerSid $owner.Sid',
    '$debuggerSocket.AbsolutePath -eq $debuggerBrowserPath',
    'ListenerCreationTime.ToUniversalTime().Ticks',
    'WebView2 debugger listener instance changed during CDP verification'
)) {
    if (-not $proofSource.Contains($requiredProofFragment)) {
        throw "Windows artifact proof is incomplete at $requiredProofFragment"
    }
}
if ($proofSource.Contains('[Net.Sockets.TcpListener]') -or
    $proofSource.Contains('"--remote-debugging-port=$remoteDebuggingPort"') -or
    ([regex]::Matches($proofSource, [regex]::Escape('"--remote-debugging-port=0"'))).Count -ne 1) {
    throw "WebView2 must bind an OS-selected port atomically and publish DevToolsActivePort"
}
$orderedDebuggerFragments = @(
    '$devToolsActivePortPath = Join-Path $webViewUserData "DevToolsActivePort"',
    'WEBVIEW2_USER_DATA_FOLDER = $webViewUserData',
    'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=0"',
    '$automationProcess = Start-Process',
    '$devToolsEndpoint = $null',
    '$devToolsContent = Read-BoundedDevToolsActivePortContent',
    '$devToolsEndpoint = ConvertFrom-DevToolsActivePort',
    '$remoteDebuggingPort = $devToolsEndpoint.Port',
    '$debuggerBrowserPath = $devToolsEndpoint.BrowserPath',
    '$debuggerListeners = @(Get-AttributedDebuggerListeners',
    '$debuggerVersion = Invoke-RestMethod',
    '$revalidatedDebuggerListeners = @(Get-AttributedDebuggerListeners',
    '$listenerIdentities = @($debuggerListeners',
    '$revalidatedListenerIdentities = @(',
    'if ($listenerIdentities.Count -ne $revalidatedListenerIdentities.Count -or',
    '$remoteDebuggerReady = $true'
)
$debuggerFragmentSearchStart = 0
foreach ($orderedDebuggerFragment in $orderedDebuggerFragments) {
    $debuggerFragmentPosition = $proofSource.IndexOf(
        $orderedDebuggerFragment,
        $debuggerFragmentSearchStart,
        [StringComparison]::Ordinal
    )
    if ($debuggerFragmentPosition -lt 0) {
        throw "WebView2 debugger proof order is incomplete at $orderedDebuggerFragment"
    }
    $debuggerFragmentSearchStart = $debuggerFragmentPosition + $orderedDebuggerFragment.Length
}

$uiProofScript = Resolve-Path (Join-Path $PSScriptRoot "console-windows-ui-proof.py")
$uiProofSource = Get-Content -LiteralPath $uiProofScript -Raw
foreach ($requiredUiFragment in @(
    "window.__TAURI_INTERNALS__",
    "start_bootstrap",
    "bootstrap_status",
    "cancel_bootstrap",
    "bootstrap_busy",
    "phase: 'capture_ready'",
    "phase: 'finished'",
    "create_helper_running_after_native_capture",
    "replace_helper_running_after_millis",
    'driver.execute_async(BOOTSTRAP_IPC_PROOF_SCRIPT, ["start"])',
    '["finish", create_request_id]',
    "if create_request_id in serialized_proof",
    "bootstrap_request_refused",
    "sensitive-value-must-not-be-reflected",
    "frontend-consent-must-not-be-accepted",
    "authority_fields: authorityRejections",
    "active_target_mutation: targetMutationCode",
    "request_ids_included_in_proof_artifact",
    "target_included_in_public_error",
    "public_scope_machine_inspected",
    "SendMessageTimeoutW",
    "secret_control_machine_inspected",
    "synthetic_target_present",
    "secret_control_present",
    "sensitive_input_included_in_public_error_or_proof_artifact",
    "success_claimed: false",
    "MAX_SCREENSHOT_ATTEMPTS = 5",
    "MIN_SCREENSHOT_DISTINCT_RGB = 256",
    "MAX_SCREENSHOT_DOMINANT_RGB_RATIO = 0.995",
    "MAX_SCREENSHOT_EXACT_BLACK_RATIO = 0.10",
    "def inspect_png_raster(",
    "zlib.decompressobj()",
    "document.fonts?.ready",
    "requestAnimationFrame",
    "capture_attempts",
    "capture raster has too few distinct RGB colors",
    "capture raster is dominated by one RGB color",
    "capture raster contains too much exact black"
)) {
    if (-not $uiProofSource.Contains($requiredUiFragment)) {
        throw "live Windows Tauri bootstrap proof is incomplete at $requiredUiFragment"
    }
}
$startHandshakeIndex = $uiProofSource.IndexOf(
    'driver.execute_async(BOOTSTRAP_IPC_PROOF_SCRIPT, ["start"])'
)
$synchronousCaptureIndex = $uiProofSource.IndexOf("capture_facts = (")
$finishHandshakeIndex = $uiProofSource.IndexOf('["finish", create_request_id]')
if ($uiProofSource.Contains("threading.Thread") -or
    $startHandshakeIndex -lt 0 -or
    $synchronousCaptureIndex -le $startHandshakeIndex -or
    $finishHandshakeIndex -le $synchronousCaptureIndex) {
    throw "native capture must stay synchronous between the bootstrap start and finish handshakes"
}
$executeAsync = [regex]::Match(
    $uiProofSource,
    '(?ms)^    def execute_async\(.*?^    def wait\('
)
if (-not $executeAsync.Success -or
    $executeAsync.Value.Contains('self.safe_request(') -or
    -not $executeAsync.Value.Contains('return request(') -or
    -not $executeAsync.Value.Contains('self.base_url')) {
    throw "the mutating async WebDriver proof must use one non-retried request"
}
$resizeMethod = [regex]::Match(
    $uiProofSource,
    '(?ms)^    def resize\(.*?^    def wait_for_paint\('
)
$screenshotMethod = [regex]::Match(
    $uiProofSource,
    '(?ms)^    def screenshot\(.*?^    def press_tab\('
)
$screenshotOrder = @(
    "for attempt in range(",
    "self.wait_for_paint()",
    'f"/session/{self.session_id}/screenshot"',
    "base64.b64decode(encoded, validate=True)",
    "inspect_png_raster(payload, expected_width, expected_height)",
    "path.write_bytes(payload)",
    'return {**raster, "capture_attempts": attempt}'
)
$previousScreenshotPosition = -1
foreach ($fragment in $screenshotOrder) {
    $position = if ($screenshotMethod.Success) {
        $screenshotMethod.Value.IndexOf($fragment)
    }
    else {
        -1
    }
    if ($position -le $previousScreenshotPosition) {
        throw "WebDriver screenshot retry, validation and write order drifted at $fragment"
    }
    $previousScreenshotPosition = $position
}
if (-not $resizeMethod.Success -or
    -not $resizeMethod.Value.Contains("self.wait(") -or
    $resizeMethod.Value.Contains("time.sleep(0.25)")) {
    throw "WebDriver resize must wait for exact DOM dimensions without a blind sleep"
}

Write-Host "PASS: Windows artifact, live Tauri IPC and cleanup proof contracts are bounded"
