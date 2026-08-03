$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$console = Join-Path $root "console"
$temporaryRoot = Join-Path $env:RUNNER_TEMP ("your-cloud-windows-ci-" + [Guid]::NewGuid().ToString("N"))
$overridePath = Join-Path $temporaryRoot "tauri.windows-ci.conf.json"
$certificatePath = Join-Path $temporaryRoot "signer.cer"
$certificate = $null
$installationAttempted = $false
$process = $null
$driverProcess = $null
$automationProcess = $null
$automationUser = $null
$automationCredential = $null
$automationPassword = $null
$automationUserCreated = $false
$automationUserProfile = $null
$automationProfilePath = $null
$automationAccount = $null
$msi = $null
$packagedExecutable = $null
$packagedHelper = $null
$shortcut = $null
$installedExecutable = $null
$installedHelper = $null
$msiSha256 = $null
$packagedExecutableSha256 = $null
$installedExecutableSha256 = $null
$packagedHelperSha256 = $null
$installedHelperSha256 = $null
$peGateProof = $null
$packageLockSha256 = $null
$cargoLockSha256 = $null
$uiSmokeRoot = Join-Path $env:RUNNER_TEMP "your-cloud-windows-webview2-smoke"
$webViewDataRoot = $null
$webViewUserData = $null
$tauriDriverPath = $null
$edgeDriverPath = $null
$webViewRuntimePath = $null
$remoteDebuggingPort = $null
$devToolsActivePortPath = $null
$debuggerBrowserPath = $null
$sessionReadyMarker = Join-Path $temporaryRoot "webdriver-session-ready"
$applicationData = $null
$proofReportPath = Join-Path $uiSmokeRoot "windows-webview2-smoke.json"
$githubSha = $env:GITHUB_SHA
$githubRunId = $env:GITHUB_RUN_ID
$executionFailure = $null

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "native command failed with status ${LASTEXITCODE}: $FilePath"
    }
}

function Stop-BoundedProcessTree {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [ValidateRange(1, 60000)][int]$TimeoutMilliseconds = 10000
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        return
    }
    try {
        $Process.Kill($true)
    }
    catch {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            throw
        }
    }
    if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
        throw "process $($Process.Id) remained active after ${TimeoutMilliseconds}ms"
    }
}

function Stop-BoundedProcessInstance {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [ValidateRange(1, 60000)][int]$TimeoutMilliseconds = 10000
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        return
    }
    try {
        $Process.Kill()
    }
    catch {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            throw
        }
    }
    if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
        throw "process $($Process.Id) remained active after ${TimeoutMilliseconds}ms"
    }
}

function Wait-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][ValidateRange(1, 900)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Operation,
        [int[]]$AllowedExitCodes = @(0)
    )

    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-BoundedProcessTree -Process $Process
        throw "$Operation exceeded its ${TimeoutSeconds}-second limit"
    }
    if ($AllowedExitCodes -notcontains $Process.ExitCode) {
        throw "$Operation failed with status $($Process.ExitCode)"
    }
}

function Invoke-BoundedNative {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    $standardOutput = Join-Path $temporaryRoot ([Guid]::NewGuid().ToString("N") + ".stdout.log")
    $standardError = Join-Path $temporaryRoot ([Guid]::NewGuid().ToString("N") + ".stderr.log")
    $startArguments = @($Arguments | ForEach-Object {
        if ($_.Contains('"')) {
            throw "bounded native argument contains an unsupported quote"
        }
        if ($_ -match '\s') {
            return '"' + $_ + '"'
        }
        return $_
    })
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $startArguments `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $standardOutput `
        -RedirectStandardError $standardError
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            Stop-BoundedProcessTree -Process $process
            throw "$FilePath exceeded its ${TimeoutSeconds}-second limit"
        }
        $process.WaitForExit()
        Get-Content -LiteralPath $standardOutput
        Get-Content -LiteralPath $standardError
        if ($process.ExitCode -ne 0) {
            throw "$FilePath failed with status $($process.ExitCode)"
        }
    }
    finally {
        Remove-Item -LiteralPath $standardOutput, $standardError -Force -ErrorAction SilentlyContinue
    }
}

function Assert-AuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$SignTool
    )
    Invoke-Native $SignTool verify /pa /tw /v $Path
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid") {
        throw "invalid Authenticode status for ${Path}: $($signature.Status)"
    }
    if ($signature.SignerCertificate.Thumbprint -ne $Thumbprint) {
        throw "unexpected Authenticode signer for $Path"
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "missing RFC 3161 timestamp for $Path"
    }
}

function Assert-NonReparseRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullParent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($fullPath),
        $fullParent,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description is not an exact sibling in its expected directory"
    }

    $parentItem = Get-Item -LiteralPath $fullParent -Force -ErrorAction Stop
    $fileItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($fileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description or its direct parent is a reparse point"
    }
    if ($fileItem.PSIsContainer -or $fileItem.Length -le 0) {
        throw "$Description is not a non-empty regular file"
    }
    return $fileItem
}

function Assert-NonReparseDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $fullParent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($fullPath),
        $fullParent,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description is not a direct child of its expected directory"
    }

    $parentItem = Get-Item -LiteralPath $fullParent -Force -ErrorAction Stop
    $directoryItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $parentItem.PSIsContainer -or -not $directoryItem.PSIsContainer) {
        throw "$Description or its direct parent is not a directory"
    }
    if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description or its direct parent is a reparse point"
    }
    return $directoryItem
}

function Get-ExactExecutableArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$ExpectedFileNames,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$Recurse
    )

    if ($Recurse) {
        $executables = @(Get-ChildItem `
            -LiteralPath $Root `
            -Filter "*.exe" `
            -Recurse `
            -File `
            -Force `
            -ErrorAction Stop)
    }
    else {
        $executables = @(Get-ChildItem `
            -LiteralPath $Root `
            -Filter "*.exe" `
            -File `
            -Force `
            -ErrorAction Stop)
    }
    $actualNames = @($executables | ForEach-Object {
        $_.Name.ToLowerInvariant()
    } | Sort-Object)
    $expectedNames = @($ExpectedFileNames | ForEach-Object {
        $_.ToLowerInvariant()
    } | Sort-Object)
    if ($actualNames.Count -ne $expectedNames.Count -or
        ($actualNames -join "`n") -ne ($expectedNames -join "`n")) {
        throw "$Description must contain exactly $($expectedNames -join ', ')"
    }
    foreach ($executable in $executables) {
        [void](Assert-NonReparseRegularFile `
            -Path $executable.FullName `
            -ExpectedParent $executable.DirectoryName `
            -Description "$Description executable $($executable.Name)")
    }
    return $executables
}

function ConvertTo-SanitizedPeGateProof {
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if ($Document.target -ne "x86_64-pc-windows-msvc" -or
        $Document.size -isnot [ValueType] -or [int64]$Document.size -le 0 -or
        $Document.sha256 -notmatch '^[0-9a-f]{64}$' -or
        $Document.sha256 -ne $ExpectedSha256 -or
        $Document.cargo.sha256 -notmatch '^[0-9a-f]{64}$' -or
        $Document.elf_direct_needed -ne $null) {
        throw "native helper PE gate returned contradictory identity metadata"
    }
    $packages = @($Document.cargo.packages)
    if ($packages -notcontains "your-cloud-native-bootstrap-assistant" -or
        $packages -notcontains "your-cloud-bootstrap-protocol") {
        throw "native helper PE gate omitted its bounded Cargo roots"
    }
    $normalImports = @($Document.pe_imports.normal)
    $delayImports = @($Document.pe_imports.delay)
    $allImports = @($Document.pe_imports.all)
    if ($Document.pe_imports.format -ne "PE32+" -or
        $Document.pe_imports.machine -ne "AMD64") {
        throw "native helper PE gate returned an unexpected executable format"
    }
    foreach ($import in @($normalImports + $delayImports + $allImports)) {
        if ($import -isnot [string] -or $import -notmatch '^[A-Za-z0-9_.+-]+\.dll$') {
            throw "native helper PE gate returned a non-canonical import name"
        }
        if ($import -match '(?:webview|webkit|javascriptcore|wpe)') {
            throw "native helper PE gate returned a forbidden WebView-family import"
        }
    }
    if ($normalImports.Count -eq 0) {
        throw "native helper PE gate returned no direct import"
    }
    $expectedAllImports = @(($normalImports + $delayImports) |
        Sort-Object -Unique)
    $normalizedAllImports = (($allImports | Sort-Object) -join "`n")
    $normalizedExpectedImports = (($expectedAllImports | Sort-Object) -join "`n")
    if (($allImports | Sort-Object -Unique).Count -ne $allImports.Count -or
        $normalizedAllImports -ne $normalizedExpectedImports) {
        throw "native helper PE gate returned an inconsistent import union"
    }

    return [ordered]@{
        target = $Document.target
        size = [int64]$Document.size
        sha256 = $Document.sha256
        cargo = [ordered]@{
            package_count = $packages.Count
            graph_sha256 = $Document.cargo.sha256
        }
        pe_imports = [ordered]@{
            format = $Document.pe_imports.format
            machine = $Document.pe_imports.machine
            normal = $normalImports
            delay = $delayImports
            all = $allImports
        }
    }
}

function Get-ProcessOwnerIdentity {
    param([Parameter(Mandatory = $true)][uint32]$ProcessId)

    $processInstance = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId"
    if ($null -eq $processInstance) {
        throw "process $ProcessId disappeared before its owner was verified"
    }
    $owner = Invoke-CimMethod -InputObject $processInstance -MethodName GetOwner
    if ($owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($owner.User)) {
        throw "owner of process $ProcessId could not be resolved"
    }
    return "$($owner.Domain)\$($owner.User)"
}

function ConvertFrom-DevToolsActivePort {
    param([Parameter(Mandatory = $true)][string]$Content)

    if ($Content.Length -eq 0 -or $Content.Length -gt 512 -or $Content.Contains("`r")) {
        throw "DevToolsActivePort content is empty, oversized or non-canonical"
    }
    $body = if ($Content.EndsWith("`n")) {
        $Content.Substring(0, $Content.Length - 1)
    }
    else {
        $Content
    }
    $lines = @($body.Split([char]"`n"))
    if ($lines.Count -ne 2 -or
        $lines[0] -notmatch '^[1-9][0-9]{0,4}$' -or
        $lines[1] -notmatch '^/devtools/browser/[A-Za-z0-9._-]{1,128}$') {
        throw "DevToolsActivePort content is not the exact port and browser path pair"
    }
    $port = [int]$lines[0]
    if ($port -gt 65535) {
        throw "DevToolsActivePort port is outside the TCP range"
    }
    return [pscustomobject]@{
        Port = $port
        BrowserPath = $lines[1]
    }
}

function Read-BoundedDevToolsActivePortContent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent
    )

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $handleLength = $stream.Length
        if ($handleLength -le 0 -or $handleLength -gt 512) {
            throw [IO.InvalidDataException]::new(
                "DevToolsActivePort handle length is outside its public bound"
            )
        }
        $openedFile = Assert-NonReparseRegularFile `
            -Path $Path `
            -ExpectedParent $ExpectedParent `
            -Description "opened WebView2 DevToolsActivePort"
        if ($openedFile.Length -ne $handleLength) {
            throw [IO.InvalidDataException]::new(
                "DevToolsActivePort handle and direct path lengths differ"
            )
        }
        $bytes = [byte[]]::new([int]$handleLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw [IO.EndOfStreamException]::new(
                    "DevToolsActivePort ended before its declared handle length"
                )
            }
            $offset += $read
        }
        if ($stream.Length -ne $handleLength) {
            throw [IO.InvalidDataException]::new(
                "DevToolsActivePort handle length changed during its bounded read"
            )
        }
        $stableFile = Assert-NonReparseRegularFile `
            -Path $Path `
            -ExpectedParent $ExpectedParent `
            -Description "stable WebView2 DevToolsActivePort"
        if ($stableFile.Length -ne $handleLength) {
            throw [IO.InvalidDataException]::new(
                "DevToolsActivePort path changed after its bounded read"
            )
        }
        foreach ($value in $bytes) {
            if ($value -ne 0x0A -and ($value -lt 0x20 -or $value -gt 0x7E)) {
                throw [IO.InvalidDataException]::new(
                    "DevToolsActivePort contains a non-ASCII byte"
                )
            }
        }
        return [Text.Encoding]::ASCII.GetString($bytes)
    }
    finally {
        $stream.Dispose()
    }
}

function Test-DebuggerListenerAttribution {
    param(
        [AllowNull()][string]$LocalAddress,
        [AllowNull()][string]$CandidatePath,
        [AllowNull()][string]$CandidateOwnerSid,
        [AllowNull()][string]$ExpectedRuntimePath,
        [AllowNull()][string]$ExpectedOwnerSid
    )

    if ($LocalAddress -notin @("127.0.0.1", "::1") -or
        [string]::IsNullOrWhiteSpace($CandidatePath) -or
        [string]::IsNullOrWhiteSpace($CandidateOwnerSid) -or
        [string]::IsNullOrWhiteSpace($ExpectedRuntimePath) -or
        [string]::IsNullOrWhiteSpace($ExpectedOwnerSid)) {
        return $false
    }
    return [string]::Equals(
        $CandidatePath,
        $ExpectedRuntimePath,
        [StringComparison]::OrdinalIgnoreCase
    ) -and [string]::Equals(
        $CandidateOwnerSid,
        $ExpectedOwnerSid,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Get-AttributedDebuggerListeners {
    param(
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory = $true)][string]$ExpectedRuntimePath,
        [Parameter(Mandatory = $true)][string]$ExpectedOwnerSid
    )

    $listeners = @(Get-NetTCPConnection `
        -State Listen `
        -LocalPort $Port `
        -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) {
        return
    }
    $ownerProcessIds = [Collections.Generic.HashSet[uint32]]::new()
    $attributed = [Collections.Generic.List[object]]::new()
    foreach ($listener in $listeners) {
        $candidate = Get-CimInstance `
            Win32_Process `
            -Filter "ProcessId = $($listener.OwningProcess)" `
            -ErrorAction Stop
        if ($null -eq $candidate -or $null -eq $candidate.CreationDate) {
            throw "WebView2 debugger listener process disappeared or has no creation time"
        }
        if ($null -eq $listener.CreationTime) {
            throw "WebView2 debugger socket has no creation time"
        }
        $listenerCreationTime = [DateTime]$listener.CreationTime
        if ($listenerCreationTime -eq [DateTime]::MinValue) {
            throw "WebView2 debugger socket creation time is not attributable"
        }
        $owner = Invoke-CimMethod `
            -InputObject $candidate `
            -MethodName GetOwnerSid `
            -ErrorAction Stop
        if ($owner.ReturnValue -ne 0 -or
            $owner.Sid -notmatch '^S-[0-9]+(?:-[0-9]+)+$' -or
            -not (Test-DebuggerListenerAttribution `
                -LocalAddress $listener.LocalAddress `
                -CandidatePath $candidate.ExecutablePath `
                -CandidateOwnerSid $owner.Sid `
                -ExpectedRuntimePath $ExpectedRuntimePath `
                -ExpectedOwnerSid $ExpectedOwnerSid)) {
            throw "WebView2 debugger listener escaped its loopback runtime or account"
        }
        [void]$ownerProcessIds.Add([uint32]$candidate.ProcessId)
        [void]$attributed.Add([pscustomobject]@{
            ProcessId = [uint32]$candidate.ProcessId
            CreationDate = $candidate.CreationDate
            LocalAddress = [string]$listener.LocalAddress
            ListenerCreationTime = $listenerCreationTime
        })
    }
    if ($ownerProcessIds.Count -ne 1) {
        throw "WebView2 debugger listeners are not owned by one exact runtime process"
    }
    if ($attributed.LocalAddress -notcontains "127.0.0.1") {
        throw "WebView2 debugger did not expose the verified IPv4 loopback endpoint"
    }
    return $attributed.ToArray()
}

function Test-ProofProcessAttribution {
    param(
        [AllowNull()][string]$CandidatePath,
        [AllowNull()][string]$CandidateOwnerSid,
        [AllowNull()][string]$AutomationSid,
        [AllowEmptyCollection()][string[]]$TrackedExecutablePaths = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($AutomationSid) -and
        [string]::Equals(
            $CandidateOwnerSid,
            $AutomationSid,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        return $true
    }
    if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
        return $false
    }
    foreach ($trackedPath in $TrackedExecutablePaths) {
        if (-not [string]::IsNullOrWhiteSpace($trackedPath) -and
            [string]::Equals(
                $CandidatePath,
                $trackedPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return $true
        }
    }
    return $false
}

function Test-ProcessInstanceIdentity {
    param(
        [Parameter(Mandatory = $true)][uint32]$ExpectedProcessId,
        [AllowNull()]$ExpectedCreationDate,
        [Parameter(Mandatory = $true)][uint32]$CurrentProcessId,
        [AllowNull()]$CurrentCreationDate
    )

    return $ExpectedProcessId -eq $CurrentProcessId -and
        $null -ne $ExpectedCreationDate -and
        $null -ne $CurrentCreationDate -and
        $ExpectedCreationDate.ToUniversalTime().Ticks -eq
            $CurrentCreationDate.ToUniversalTime().Ticks
}

function Get-BoundedWaitMilliseconds {
    param(
        [Parameter(Mandatory = $true)][double]$RemainingMilliseconds,
        [ValidateRange(1, 60000)][int]$MaximumMilliseconds = 5000
    )

    if ($RemainingMilliseconds -le 0) {
        return 0
    }
    return [int][Math]::Min(
        $MaximumMilliseconds,
        [Math]::Max(1, [Math]::Floor($RemainingMilliseconds))
    )
}

function Get-CurrentProcessInstance {
    param([Parameter(Mandatory = $true)]$Candidate)

    $current = Get-CimInstance `
        Win32_Process `
        -Filter "ProcessId = $($Candidate.ProcessId)" `
        -ErrorAction Stop
    if ($null -eq $current) {
        return $null
    }
    if ($null -eq $Candidate.CreationDate -or
        $null -eq $current.CreationDate) {
        throw "creation time of process $($Candidate.ProcessId) could not be verified"
    }
    if (-not (Test-ProcessInstanceIdentity `
            -ExpectedProcessId $Candidate.ProcessId `
            -ExpectedCreationDate $Candidate.CreationDate `
            -CurrentProcessId $current.ProcessId `
            -CurrentCreationDate $current.CreationDate)) {
        return $null
    }
    return $current
}

function Resolve-ProofProcessAttribution {
    param(
        [Parameter(Mandatory = $true)]$Candidate,
        [AllowNull()][string]$AutomationSid,
        [AllowEmptyCollection()][string[]]$TrackedExecutablePaths = @(),
        [AllowEmptyCollection()][string[]]$OwnerRequiredPaths = @()
    )

    $pathAttributed = Test-ProofProcessAttribution `
        -CandidatePath $Candidate.ExecutablePath `
        -CandidateOwnerSid $null `
        -AutomationSid $null `
        -TrackedExecutablePaths $TrackedExecutablePaths
    $ownerRequired = Test-ProofProcessAttribution `
        -CandidatePath $Candidate.ExecutablePath `
        -CandidateOwnerSid $null `
        -AutomationSid $null `
        -TrackedExecutablePaths $OwnerRequiredPaths
    $ownerSid = $null
    $ownerFailure = $null
    try {
        $owner = Invoke-CimMethod `
            -InputObject $Candidate `
            -MethodName GetOwnerSid `
            -ErrorAction Stop
        if ($owner.ReturnValue -eq 0 -and
            $owner.Sid -match '^S-[0-9]+(?:-[0-9]+)+$') {
            $ownerSid = [string]$owner.Sid
        }
        elseif ($ownerRequired) {
            $ownerFailure = "owner SID lookup failed with status $($owner.ReturnValue)"
        }
    }
    catch {
        $ownerFailure = $_.Exception.Message
    }
    if ($ownerRequired -and $null -ne $ownerFailure) {
        $current = Get-CurrentProcessInstance -Candidate $Candidate
        if ($null -eq $current) {
            return
        }
        throw "owner SID of process $($Candidate.ProcessId) could not be resolved"
    }
    $attributed = $pathAttributed -or (Test-ProofProcessAttribution `
        -CandidatePath $Candidate.ExecutablePath `
        -CandidateOwnerSid $ownerSid `
        -AutomationSid $AutomationSid `
        -TrackedExecutablePaths @())
    if (-not $attributed) {
        return
    }
    if ($null -eq $Candidate.CreationDate) {
        throw "attributed process $($Candidate.ProcessId) has no creation time"
    }
    return [pscustomobject]@{
        ProcessId = [uint32]$Candidate.ProcessId
        ExecutablePath = [string]$Candidate.ExecutablePath
        CreationDate = $Candidate.CreationDate
        OwnerSid = $ownerSid
    }
}

function Get-AttributedProofProcesses {
    param(
        [AllowNull()][string]$AutomationSid,
        [AllowEmptyCollection()][string[]]$TrackedExecutablePaths = @(),
        [AllowEmptyCollection()][string[]]$OwnerRequiredPaths = @()
    )

    $attributedProcesses = [Collections.Generic.List[object]]::new()
    foreach ($candidate in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        if ($null -eq $candidate) {
            throw "process inventory returned an unverifiable entry"
        }
        $attribution = Resolve-ProofProcessAttribution `
            -Candidate $candidate `
            -AutomationSid $AutomationSid `
            -TrackedExecutablePaths $TrackedExecutablePaths `
            -OwnerRequiredPaths $OwnerRequiredPaths
        if ($null -ne $attribution) {
            [void]$attributedProcesses.Add($attribution)
        }
    }
    return $attributedProcesses.ToArray()
}

function Get-RevalidatedProofProcessHandle {
    param(
        [Parameter(Mandatory = $true)]$Candidate,
        [AllowNull()][string]$AutomationSid,
        [AllowEmptyCollection()][string[]]$TrackedExecutablePaths = @(),
        [AllowEmptyCollection()][string[]]$OwnerRequiredPaths = @()
    )

    $process = Get-Process -Id $Candidate.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $null
    }
    try {
        $boundHandle = $process.SafeHandle
        if ($boundHandle.IsInvalid -or $boundHandle.IsClosed) {
            throw "process handle could not be pinned"
        }
        $handleCreationDate = $process.StartTime.ToUniversalTime()
    }
    catch {
        $current = Get-CurrentProcessInstance -Candidate $Candidate
        $process.Dispose()
        if ($null -eq $current) {
            return $null
        }
        throw "process $($Candidate.ProcessId) could not be bound before termination"
    }
    try {
        $current = Get-CurrentProcessInstance -Candidate $Candidate
        if ($null -eq $current -or
            $boundHandle.IsInvalid -or
            $boundHandle.IsClosed) {
            $process.Dispose()
            return $null
        }
        if ([Math]::Abs(
            ($current.CreationDate.ToUniversalTime() - $handleCreationDate).TotalMilliseconds
        ) -gt 1) {
            $process.Dispose()
            return $null
        }
        $currentAttribution = Resolve-ProofProcessAttribution `
            -Candidate $current `
            -AutomationSid $AutomationSid `
            -TrackedExecutablePaths $TrackedExecutablePaths `
            -OwnerRequiredPaths $OwnerRequiredPaths
        if ($null -eq $currentAttribution) {
            $process.Dispose()
            return $null
        }
        return [pscustomobject]@{
            Process = $process
            BoundHandle = $boundHandle
        }
    }
    catch {
        $process.Dispose()
        throw
    }
}

function Resolve-BoundedChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $separatorCharacters = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $rootPath = [IO.Path]::GetFullPath(
        $Root.TrimEnd($separatorCharacters) + [IO.Path]::DirectorySeparatorChar
    )
    $candidatePath = [IO.Path]::GetFullPath($Path)
    if (-not $candidatePath.StartsWith(
        $rootPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description escaped its bounded root"
    }
    return $candidatePath
}

function Invoke-CleanupAction {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    try {
        & $Action
    }
    catch {
        $Failures.Add("${Name}: $($_.Exception.Message)")
    }
}

try {
    if ($githubSha -notmatch '^[0-9a-fA-F]{40}$') {
        throw "GITHUB_SHA is absent or non-canonical"
    }
    if ($githubRunId -notmatch '^[1-9][0-9]*$') {
        throw "GITHUB_RUN_ID is absent or non-canonical"
    }
    $githubSha = $githubSha.ToLowerInvariant()

    $checkoutSha = (& git -C $root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Git could not resolve the checked-out revision"
    }
    if ($checkoutSha -ne $githubSha) {
        throw "checked-out revision does not match GITHUB_SHA"
    }
    $gitStatus = @(& git -C $root status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) {
        throw "Git could not verify worktree cleanliness"
    }
    if ($gitStatus.Count -ne 0) {
        throw "Windows candidate worktree is not clean before build"
    }
    $packageLockSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $console "package-lock.json")
    ).Hash.ToLowerInvariant()
    $cargoLockSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $console "src-tauri\Cargo.lock")
    ).Hash.ToLowerInvariant()

    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    if (Test-Path -LiteralPath $uiSmokeRoot) {
        Remove-Item -LiteralPath $uiSmokeRoot -Recurse -Force
    }
    Write-Host "CI Windows: creating the synthetic code-signing certificate"
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=Your Cloud CI Synthetic" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(2)
    Write-Host "CI Windows: exporting the public certificate"
    Export-Certificate -Cert $certificate -FilePath $certificatePath | Out-Null
    Write-Host "CI Windows: trusting the synthetic certificate for this runner"
    Invoke-BoundedNative `
        -FilePath certutil.exe `
        -TimeoutSeconds 60 `
        -Arguments @("-f", "-addstore", "TrustedPeople", $certificatePath)
    Write-Host "CI Windows: synthetic certificate ready"

    $override = @{
        bundle = @{
            windows = @{
                certificateThumbprint = $certificate.Thumbprint
                digestAlgorithm = "sha256"
                timestampUrl = "http://timestamp.digicert.com"
                tsp = $true
            }
        }
    } | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($overridePath, $override, [Text.UTF8Encoding]::new($false))

    Push-Location $console
    try {
        Write-Host "CI Windows: building the signed MSI"
        $npmCommand = Get-Command npm.cmd -ErrorAction Stop
        $npmCli = Join-Path `
            (Split-Path -Parent $npmCommand.Source) `
            "node_modules\npm\bin\npm-cli.js"
        if (-not (Test-Path -LiteralPath $npmCli -PathType Leaf)) {
            throw "npm CLI entry point was not found"
        }
        Invoke-BoundedNative `
            -FilePath (Get-Command node.exe -ErrorAction Stop).Source `
            -TimeoutSeconds 1800 `
            -Arguments @($npmCli, "run", "tauri", "--", "build", "--bundles", "msi", "--config", $overridePath)
    }
    finally {
        Pop-Location
    }

    $buildOutputs = @(Get-ChildItem `
        -LiteralPath (Join-Path $console "src-tauri\target\release") `
        -Filter "your-cloud-console.exe" -File)
    $installers = @(Get-ChildItem `
        -LiteralPath (Join-Path $console "src-tauri\target\release\bundle\msi") `
        -Filter "*.msi" -File)
    if ($buildOutputs.Count -ne 1 -or $installers.Count -ne 1) {
        throw "expected exactly one Windows executable and one MSI"
    }
    $msi = $installers[0]

    $signTool = Get-ChildItem `
        -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" `
        -File | Sort-Object FullName -Descending | Select-Object -First 1
    if ($null -eq $signTool) {
        throw "signtool.exe was not found"
    }
    Assert-AuthenticodeSignature $msi.FullName $certificate.Thumbprint $signTool.FullName
    $msiSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi.FullName).Hash.ToLowerInvariant()
    Write-Host "CI Windows: verified MSI SHA-256 $msiSha256"

    # Tauri restaure volontairement la sortie Cargo non signee apres avoir cree
    # le MSI. Une image administrative permet de verifier l'executable reellement
    # embarque sans confondre ces deux artefacts.
    $administrativeImage = Join-Path $temporaryRoot "msi-administrative-image"
    $administrativeInstall = Start-Process -FilePath "msiexec.exe" `
        -ArgumentList "/a `"$($msi.FullName)`" /qn /norestart TARGETDIR=`"$administrativeImage`"" `
        -PassThru
    Wait-BoundedProcess `
        -Process $administrativeInstall `
        -TimeoutSeconds 300 `
        -Operation "MSI administrative extraction"
    $consoleFileName = "your-cloud-console.exe"
    $helperFileName = "your-cloud-native-bootstrap-assistant.exe"
    $packagedExecutables = @(Get-ExactExecutableArtifacts `
        -Root $administrativeImage `
        -ExpectedFileNames @($consoleFileName, $helperFileName) `
        -Description "MSI administrative image installable payload" `
        -Recurse)
    $packagedExecutable = $packagedExecutables |
        Where-Object { $_.Name -eq $consoleFileName } |
        Select-Object -First 1
    $packagedHelper = $packagedExecutables |
        Where-Object { $_.Name -eq $helperFileName } |
        Select-Object -First 1
    if ($null -eq $packagedExecutable -or $null -eq $packagedHelper -or
        -not [string]::Equals(
            $packagedExecutable.DirectoryName,
            $packagedHelper.DirectoryName,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "MSI must package the exact native helper beside the Console"
    }
    Assert-AuthenticodeSignature `
        $packagedExecutable.FullName `
        $certificate.Thumbprint `
        $signTool.FullName
    Assert-AuthenticodeSignature `
        $packagedHelper.FullName `
        $certificate.Thumbprint `
        $signTool.FullName
    $packagedExecutableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $packagedExecutable.FullName
    ).Hash.ToLowerInvariant()
    $packagedHelperSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $packagedHelper.FullName
    ).Hash.ToLowerInvariant()
    Write-Host "CI Windows: verified packaged executable SHA-256 $packagedExecutableSha256"
    Write-Host "CI Windows: verified packaged native helper SHA-256 $packagedHelperSha256"

    $nativeAssistantGate = Join-Path `
        $console `
        "tools\check-native-bootstrap-assistant.mjs"
    $peGateOutput = @(Invoke-BoundedNative `
        -FilePath (Get-Command node.exe -ErrorAction Stop).Source `
        -TimeoutSeconds 300 `
        -Arguments @(
            $nativeAssistantGate,
            "x86_64-pc-windows-msvc",
            $packagedHelper.FullName,
            "--packaged"
        ))
    try {
        $peGateDocument = ($peGateOutput -join [Environment]::NewLine) |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "native helper PE gate did not return one valid JSON document"
    }
    $peGateProof = ConvertTo-SanitizedPeGateProof `
        -Document $peGateDocument `
        -ExpectedSha256 $packagedHelperSha256

    $shortcutRoots = @(
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs")
    )
    $installationAttempted = $true
    $install = Start-Process -FilePath "msiexec.exe" `
        -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" `
        -PassThru
    Wait-BoundedProcess -Process $install -TimeoutSeconds 300 -Operation "MSI installation"
    $shortcut = Get-ChildItem -Path $shortcutRoots -Filter "*.lnk" -Recurse -File |
        Where-Object { $_.BaseName -eq "Your Cloud" } |
        Select-Object -First 1
    if ($null -eq $shortcut) {
        throw "installed Your Cloud shortcut was not found"
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcutTarget = [IO.Path]::GetFullPath(
        $shell.CreateShortcut($shortcut.FullName).TargetPath
    )
    if (-not (Test-Path -LiteralPath $shortcutTarget -PathType Leaf)) {
        throw "installed Your Cloud shortcut does not target a file"
    }
    $installedDirectory = [IO.Path]::GetDirectoryName(
        $shortcutTarget
    )
    $installedExecutables = @(Get-ExactExecutableArtifacts `
        -Root $installedDirectory `
        -ExpectedFileNames @($consoleFileName, $helperFileName) `
        -Description "installed product directory")
    $installedConsole = $installedExecutables |
        Where-Object { $_.Name -eq $consoleFileName } |
        Select-Object -First 1
    $installedNativeHelper = $installedExecutables |
        Where-Object { $_.Name -eq $helperFileName } |
        Select-Object -First 1
    if ($null -eq $installedConsole -or
        $null -eq $installedNativeHelper -or
        -not [string]::Equals(
            $shortcutTarget,
            $installedConsole.FullName,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            $installedConsole.DirectoryName,
            $installedNativeHelper.DirectoryName,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "shortcut target and installed native helper are not the exact Console siblings"
    }
    $installedExecutable = $installedConsole.FullName
    $installedHelper = $installedNativeHelper.FullName
    Assert-AuthenticodeSignature $installedExecutable $certificate.Thumbprint $signTool.FullName
    Assert-AuthenticodeSignature $installedHelper $certificate.Thumbprint $signTool.FullName
    $installedExecutableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $installedExecutable
    ).Hash.ToLowerInvariant()
    $installedHelperSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $installedHelper
    ).Hash.ToLowerInvariant()
    Write-Host "CI Windows: verified installed executable SHA-256 $installedExecutableSha256"
    Write-Host "CI Windows: verified installed native helper SHA-256 $installedHelperSha256"
    if ($installedExecutableSha256 -ne $packagedExecutableSha256) {
        throw "installed executable differs from the executable packaged in the MSI"
    }
    if ($installedHelperSha256 -ne $packagedHelperSha256) {
        throw "installed native helper differs from the helper packaged in the MSI"
    }

    $directHelperOutput = Join-Path $temporaryRoot "direct-helper.stdout.log"
    $directHelperError = Join-Path $temporaryRoot "direct-helper.stderr.log"
    $directHelper = Start-Process `
        -FilePath $installedHelper `
        -ArgumentList @("--native-bootstrap-assistant") `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $directHelperOutput `
        -RedirectStandardError $directHelperError
    Wait-BoundedProcess `
        -Process $directHelper `
        -TimeoutSeconds 30 `
        -Operation "direct native helper parent refusal" `
        -AllowedExitCodes @(70)
    if ((Get-Item -LiteralPath $directHelperOutput).Length -ne 0 -or
        (Get-Item -LiteralPath $directHelperError).Length -ne 0) {
        throw "refused native helper invocation emitted public output"
    }
    Write-Host "CI Windows: installed helper refused a direct non-Console parent"

    Write-Host "CI Windows: preparing the bounded WebView2 driver"
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw "the Windows proof requires the x64 WebView2 Runtime"
    }
    $webViewRuntimeClient = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    $webViewRuntimeCandidates = @(
        @{
            RegistryPath = "HKCU:\Software\Microsoft\EdgeUpdate\Clients\$webViewRuntimeClient"
            InstallRoot = Join-Path $env:LOCALAPPDATA "Microsoft\EdgeWebView\Application"
        },
        @{
            RegistryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$webViewRuntimeClient"
            InstallRoot = Join-Path ${env:ProgramFiles(x86)} "Microsoft\EdgeWebView\Application"
        }
    )
    $webViewRuntimes = @()
    foreach ($candidate in $webViewRuntimeCandidates) {
        $version = Get-ItemPropertyValue `
            -LiteralPath $candidate.RegistryPath `
            -Name "pv" `
            -ErrorAction SilentlyContinue
        if ($null -eq $version) {
            continue
        }
        if ($version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
            throw "WebView2 Runtime registry version is not canonical"
        }
        $executable = Join-Path $candidate.InstallRoot "$version\msedgewebview2.exe"
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
            throw "registered WebView2 Runtime executable was not found"
        }
        $runtimeItem = Get-Item -LiteralPath $executable
        if ($runtimeItem.VersionInfo.ProductVersion -ne $version) {
            throw "WebView2 Runtime registry and executable versions differ"
        }
        $runtimeSignature = Get-AuthenticodeSignature -LiteralPath $executable
        if ($runtimeSignature.Status -ne "Valid" -or
            $runtimeSignature.SignerCertificate.Subject -notmatch '(^|, )O=Microsoft Corporation(,|$)') {
            throw "WebView2 Runtime signature is invalid or has an unexpected publisher"
        }
        $webViewRuntimes += @{
            Version = $version
            Executable = $executable
            RegistryPath = $candidate.RegistryPath
        }
    }
    if ($webViewRuntimes.Count -ne 1) {
        throw "expected exactly one registered WebView2 Runtime on the Windows runner"
    }
    $webViewRuntime = $webViewRuntimes[0]
    $webViewRuntimePath = $webViewRuntime.Executable
    Write-Host "CI Windows: WebView2 Runtime $($webViewRuntime.Version) from $($webViewRuntime.RegistryPath)"

    $edgeDriverArchive = Join-Path $temporaryRoot "edgedriver_win64.zip"
    $edgeDriverDirectory = Join-Path $temporaryRoot "edgedriver"
    $edgeDriverUri = "https://msedgedriver.microsoft.com/$($webViewRuntime.Version)/edgedriver_win64.zip"
    Invoke-WebRequest -Uri $edgeDriverUri -OutFile $edgeDriverArchive -TimeoutSec 60
    $archiveLength = (Get-Item -LiteralPath $edgeDriverArchive).Length
    if ($archiveLength -lt 1024 -or $archiveLength -gt 50MB) {
        throw "Microsoft Edge Driver archive is outside its size bound"
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($edgeDriverArchive)
    try {
        $uncompressedLength = ($archive.Entries | Measure-Object -Property Length -Sum).Sum
        if ($archive.Entries.Count -gt 16 -or $uncompressedLength -gt 100MB) {
            throw "Microsoft Edge Driver archive is outside its extraction bound"
        }
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.Contains('..') -or [IO.Path]::IsPathRooted($entry.FullName)) {
                throw "Microsoft Edge Driver archive contains an unsafe path"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
    Expand-Archive -LiteralPath $edgeDriverArchive -DestinationPath $edgeDriverDirectory
    $edgeDrivers = @(Get-ChildItem -LiteralPath $edgeDriverDirectory -Filter "msedgedriver.exe" -Recurse -File)
    if ($edgeDrivers.Count -ne 1) {
        throw "expected exactly one Microsoft Edge Driver executable"
    }
    $edgeDriver = $edgeDrivers[0]
    $edgeDriverPath = $edgeDriver.FullName
    $edgeDriverSignature = Get-AuthenticodeSignature -LiteralPath $edgeDriver.FullName
    if ($edgeDriverSignature.Status -ne "Valid" -or
        $edgeDriverSignature.SignerCertificate.Subject -notmatch '(^|, )O=Microsoft Corporation(,|$)') {
        throw "Microsoft Edge Driver signature is invalid or has an unexpected publisher"
    }
    if ($edgeDriver.VersionInfo.ProductVersion -ne $webViewRuntime.Version) {
        throw "WebView2 Runtime and Microsoft Edge Driver versions differ"
    }

    $tauriDriver = Get-Command "tauri-driver.exe" -ErrorAction Stop
    $tauriDriverPath = $tauriDriver.Source
    $driverOutput = Join-Path $temporaryRoot "tauri-driver.stdout.log"
    $driverError = Join-Path $temporaryRoot "tauri-driver.stderr.log"
    $edgeDriverWrapper = Join-Path $temporaryRoot "msedgedriver-verbose.cmd"
    Set-Content `
        -LiteralPath $edgeDriverWrapper `
        -Encoding ascii `
        -Value @(
            '@echo off',
            '"%YOUR_CLOUD_EDGE_DRIVER%" %* --verbose 1>&2'
        )
    $previousNativeEdgeDriver = $env:YOUR_CLOUD_EDGE_DRIVER
    try {
        $env:YOUR_CLOUD_EDGE_DRIVER = $edgeDriver.FullName
        $driverProcess = Start-Process `
            -FilePath $tauriDriver.Source `
            -ArgumentList @("--native-driver", $edgeDriverWrapper) `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $driverOutput `
            -RedirectStandardError $driverError
    }
    finally {
        if ($null -eq $previousNativeEdgeDriver) {
            Remove-Item Env:\YOUR_CLOUD_EDGE_DRIVER -ErrorAction SilentlyContinue
        }
        else {
            $env:YOUR_CLOUD_EDGE_DRIVER = $previousNativeEdgeDriver
        }
    }
    $driverReady = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if ($driverProcess.HasExited) {
            Get-Content -LiteralPath $driverOutput, $driverError -ErrorAction SilentlyContinue
            throw "tauri-driver exited before accepting WebDriver sessions"
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connection = $client.ConnectAsync("127.0.0.1", 4444)
            if ($connection.Wait(250) -and $client.Connected) {
                $driverReady = $true
                break
            }
        }
        finally {
            $client.Dispose()
        }
        if (-not $driverReady) {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $driverReady) {
        throw "tauri-driver did not become ready within 30 seconds"
    }

    # GitHub-hosted Windows runners are administrators with UAC disabled. WebView2 150 can
    # suppress its DevTools endpoint from an elevated host, so exercise the installed app
    # under the standard-user context in which the product is meant to run.
    $automationUserName = "yc-ci-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $passwordText = "Yc!" + [Guid]::NewGuid().ToString("N") + "9z"
    try {
        $automationPassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
    }
    finally {
        $passwordText = $null
    }
    $automationUser = New-LocalUser `
        -Name $automationUserName `
        -Password $automationPassword `
        -AccountExpires (Get-Date).AddHours(2) `
        -UserMayNotChangePassword `
        -Description "Your Cloud ephemeral Windows UI proof"
    $automationUserCreated = $true
    $automationAccount = "$env:COMPUTERNAME\$automationUserName"
    $automationCredential = [PSCredential]::new($automationAccount, $automationPassword)

    $usersGroup = Get-LocalGroup -SID "S-1-5-32-545"
    $usersGroupMemberSids = @(
        Get-LocalGroupMember -Group $usersGroup.Name |
            ForEach-Object { $_.SID.Value }
    )
    if ($usersGroupMemberSids -notcontains $automationUser.SID.Value) {
        Add-LocalGroupMember -Group $usersGroup.Name -Member $automationUser
    }
    $administratorsGroup = Get-LocalGroup -SID "S-1-5-32-544"
    $administratorSids = @(
        Get-LocalGroupMember -Group $administratorsGroup.Name |
            ForEach-Object { $_.SID.Value }
    )
    if ($administratorSids -contains $automationUser.SID.Value) {
        throw "ephemeral Windows UI proof account unexpectedly belongs to Administrators"
    }

    $profileBootstrap = Start-Process `
        -FilePath $env:ComSpec `
        -ArgumentList @("/d", "/c", "exit", "/b", "0") `
        -Credential $automationCredential `
        -LoadUserProfile `
        -PassThru
    Wait-BoundedProcess `
        -Process $profileBootstrap `
        -TimeoutSeconds 60 `
        -Operation "ephemeral Windows UI proof profile bootstrap"
    $automationUserProfile = Get-CimInstance Win32_UserProfile |
        Where-Object { $_.SID -eq $automationUser.SID.Value } |
        Select-Object -First 1
    if ($null -eq $automationUserProfile -or
        [string]::IsNullOrWhiteSpace($automationUserProfile.LocalPath)) {
        throw "ephemeral Windows UI proof profile was not created"
    }
    $automationProfilePath = $automationUserProfile.LocalPath
    $automationLocalData = Join-Path $automationUserProfile.LocalPath "AppData\Local"
    $automationRoamingData = Join-Path $automationUserProfile.LocalPath "AppData\Roaming"
    $applicationData = Join-Path $automationRoamingData "fr.your-cloud.console"
    $automationTemp = Join-Path $automationLocalData "Temp"
    $webViewDataRoot = Join-Path `
        $automationLocalData `
        "your-cloud-windows-webview2-smoke"
    $webViewUserData = Join-Path $webViewDataRoot "EBWebView"
    $devToolsActivePortPath = Join-Path $webViewUserData "DevToolsActivePort"
    $unexpectedRootDevToolsActivePortPath = Join-Path `
        $webViewDataRoot `
        "DevToolsActivePort"
    $unexpectedNestedDevToolsActivePortPath = Join-Path `
        $webViewUserData `
        "EBWebView\DevToolsActivePort"
    New-Item `
        -ItemType Directory `
        -Path $automationTemp, $webViewDataRoot, $webViewUserData `
        -Force | Out-Null
    [void](Assert-NonReparseDirectory `
        -Path $webViewDataRoot `
        -ExpectedParent $automationLocalData `
        -Description "ephemeral WebView2 host data root")
    [void](Assert-NonReparseDirectory `
        -Path $webViewUserData `
        -ExpectedParent $webViewDataRoot `
        -Description "ephemeral WebView2 user data directory")
    foreach ($staleDevToolsActivePortPath in @(
        $devToolsActivePortPath,
        $unexpectedRootDevToolsActivePortPath,
        $unexpectedNestedDevToolsActivePortPath
    )) {
        if (Test-Path -LiteralPath $staleDevToolsActivePortPath) {
            throw "ephemeral WebView2 data contains a stale DevToolsActivePort file"
        }
    }
    Write-Host "CI Windows: installed Console will run as a bounded standard user"

    $automationHomeDrive = [IO.Path]::GetPathRoot(
        $automationUserProfile.LocalPath
    ).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $automationEnvironment = @{
        USERPROFILE = $automationUserProfile.LocalPath
        HOMEDRIVE = $automationHomeDrive
        HOMEPATH = $automationUserProfile.LocalPath.Substring($automationHomeDrive.Length)
        APPDATA = $automationRoamingData
        LOCALAPPDATA = $automationLocalData
        TEMP = $automationTemp
        TMP = $automationTemp
        # WebView2 appends the browser-owned EBWebView suffix to this host root.
        WEBVIEW2_USER_DATA_FOLDER = $webViewDataRoot
        WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=0"
    }
    $automationProcess = Start-Process `
        -FilePath $installedExecutable `
        -Credential $automationCredential `
        -LoadUserProfile `
        -Environment $automationEnvironment `
        -PassThru
    $automationOwner = Get-ProcessOwnerIdentity -ProcessId $automationProcess.Id
    if (-not [string]::Equals(
        $automationOwner,
        $automationAccount,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "installed Console did not start under the bounded standard-user account"
    }

    $devToolsEndpoint = $null
    $devToolsEndpointFailure = "file absent"
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $automationProcess.Refresh()
        if ($automationProcess.HasExited) {
            throw "installed Console exited before publishing DevToolsActivePort"
        }
        foreach ($unexpectedDevToolsActivePortPath in @(
            $unexpectedRootDevToolsActivePortPath,
            $unexpectedNestedDevToolsActivePortPath
        )) {
            if (Test-Path -LiteralPath $unexpectedDevToolsActivePortPath) {
                throw "WebView2 published DevToolsActivePort outside the exact EBWebView UDF"
            }
        }
        if (Test-Path -LiteralPath $devToolsActivePortPath) {
            try {
                [void](Assert-NonReparseDirectory `
                    -Path $webViewDataRoot `
                    -ExpectedParent $automationLocalData `
                    -Description "stable WebView2 host data root")
                [void](Assert-NonReparseDirectory `
                    -Path $webViewUserData `
                    -ExpectedParent $webViewDataRoot `
                    -Description "stable WebView2 user data directory")
                $devToolsContent = Read-BoundedDevToolsActivePortContent `
                    -Path $devToolsActivePortPath `
                    -ExpectedParent $webViewUserData
                [void](Assert-NonReparseDirectory `
                    -Path $webViewDataRoot `
                    -ExpectedParent $automationLocalData `
                    -Description "revalidated WebView2 host data root")
                [void](Assert-NonReparseDirectory `
                    -Path $webViewUserData `
                    -ExpectedParent $webViewDataRoot `
                    -Description "revalidated WebView2 user data directory")
                $devToolsEndpoint = ConvertFrom-DevToolsActivePort `
                    -Content $devToolsContent
            }
            catch {
                $devToolsEndpointFailure = $_.Exception.Message
                $devToolsEndpoint = $null
            }
            if ($null -ne $devToolsEndpoint) {
                break
            }
        }
        Start-Sleep -Milliseconds 250
    }
    if ($null -eq $devToolsEndpoint) {
        throw "installed WebView2 did not publish stable DevToolsActivePort within 30 seconds: $devToolsEndpointFailure"
    }
    $remoteDebuggingPort = $devToolsEndpoint.Port
    $debuggerBrowserPath = $devToolsEndpoint.BrowserPath
    $debuggerAddress = "127.0.0.1:$remoteDebuggingPort"

    $remoteDebuggerReady = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $automationProcess.Refresh()
        if ($automationProcess.HasExited) {
            throw "installed Console exited before exposing its bounded WebView2 debugger"
        }
        $debuggerListeners = @(Get-AttributedDebuggerListeners `
            -Port $remoteDebuggingPort `
            -ExpectedRuntimePath $webViewRuntimePath `
            -ExpectedOwnerSid $automationUser.SID.Value)
        if ($debuggerListeners.Count -gt 0) {
            $debuggerVersion = $null
            try {
                $debuggerVersion = Invoke-RestMethod `
                    -Uri "http://$debuggerAddress/json/version" `
                    -NoProxy `
                    -TimeoutSec 1
            }
            catch {
                # The listener can appear briefly before the CDP endpoint is ready.
            }
            if ($null -ne $debuggerVersion) {
                $debuggerSocket = [Uri]$debuggerVersion.webSocketDebuggerUrl
                if ($debuggerSocket.Scheme -eq "ws" -and
                    $debuggerSocket.Host -eq "127.0.0.1" -and
                    $debuggerSocket.Port -eq $remoteDebuggingPort -and
                    $debuggerSocket.AbsolutePath -eq $debuggerBrowserPath) {
                    $revalidatedDebuggerListeners = @(Get-AttributedDebuggerListeners `
                        -Port $remoteDebuggingPort `
                        -ExpectedRuntimePath $webViewRuntimePath `
                        -ExpectedOwnerSid $automationUser.SID.Value)
                    $listenerIdentities = @($debuggerListeners | ForEach-Object {
                        "$($_.ProcessId)|$($_.LocalAddress)|$($_.CreationDate.ToUniversalTime().Ticks)|$($_.ListenerCreationTime.ToUniversalTime().Ticks)"
                    } | Sort-Object)
                    $revalidatedListenerIdentities = @(
                        $revalidatedDebuggerListeners | ForEach-Object {
                            "$($_.ProcessId)|$($_.LocalAddress)|$($_.CreationDate.ToUniversalTime().Ticks)|$($_.ListenerCreationTime.ToUniversalTime().Ticks)"
                        } | Sort-Object
                    )
                    if ($listenerIdentities.Count -ne $revalidatedListenerIdentities.Count -or
                        ($listenerIdentities -join "`n") -ne
                            ($revalidatedListenerIdentities -join "`n")) {
                        throw "WebView2 debugger listener instance changed during CDP verification"
                    }
                    $remoteDebuggerReady = $true
                    break
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $remoteDebuggerReady) {
        throw "installed WebView2 debugger did not become ready on bounded loopback"
    }
    Write-Host "CI Windows: installed WebView2 debugger ready on bounded loopback"

    try {
        Invoke-BoundedNative `
            -FilePath (Get-Command python.exe -ErrorAction Stop).Source `
            -TimeoutSeconds 600 `
            -Arguments @(
                (Join-Path $root "tests\checks\console-windows-ui-proof.py"),
                "--application", $installedExecutable,
                "--debugger-address", $debuggerAddress,
                "--session-ready-marker", $sessionReadyMarker,
                "--output", $uiSmokeRoot
            )
    }
    catch {
        if (-not (Test-Path -LiteralPath $sessionReadyMarker -PathType Leaf)) {
            Write-Host "CI Windows: WebDriver session creation failed before test secrets existed"
            Get-Content -LiteralPath $driverOutput, $driverError -Tail 200 -ErrorAction SilentlyContinue
            Write-Host "CI Windows: EdgeDriver did not attach to the verified loopback debugger"

        }
        throw
    }
    $automationProcess.Refresh()
    if (-not $automationProcess.HasExited) {
        Stop-BoundedProcessTree -Process $automationProcess
    }
    $automationProcess = $null

    $debuggerClosed = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $remainingDebuggerListeners = @(Get-NetTCPConnection `
            -State Listen `
            -LocalPort $remoteDebuggingPort `
            -ErrorAction SilentlyContinue)
        if ($remainingDebuggerListeners.Count -eq 0) {
            $debuggerClosed = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $debuggerClosed) {
        throw "bounded WebView2 debugger remained after automation cleanup"
    }
    Stop-BoundedProcessTree -Process $driverProcess
    $driverProcess = $null

    $remainingAutomationProcesses = @(Get-CimInstance Win32_Process |
        Where-Object {
            [string]::Equals(
                $_.ExecutablePath,
                $installedExecutable,
                [StringComparison]::OrdinalIgnoreCase
            )
        })
    if ($remainingAutomationProcesses.Count -ne 0) {
        throw "automated Console process remained after WebDriver cleanup"
    }

    $normalEnvironment = $automationEnvironment.Clone()
    $normalEnvironment.WEBVIEW2_USER_DATA_FOLDER = $null
    $normalEnvironment.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = $null
    $process = Start-Process `
        -FilePath $installedExecutable `
        -Credential $automationCredential `
        -LoadUserProfile `
        -Environment $normalEnvironment `
        -PassThru
    $normalOwner = Get-ProcessOwnerIdentity -ProcessId $process.Id
    if (-not [string]::Equals(
        $normalOwner,
        $automationAccount,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "normal Console smoke test escaped the bounded standard-user account"
    }
    Start-Sleep -Seconds 10
    $process.Refresh()
    if ($process.HasExited) {
        throw "installed Console exited during the Windows smoke test"
    }

    $productProcessIds = [Collections.Generic.HashSet[uint32]]::new()
    [void]$productProcessIds.Add([uint32]$process.Id)
    do {
        $added = $false
        foreach ($candidate in Get-CimInstance Win32_Process) {
            if ($productProcessIds.Contains([uint32]$candidate.ParentProcessId) -and
                $productProcessIds.Add([uint32]$candidate.ProcessId)) {
                $added = $true
            }
        }
    } while ($added)
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $productProcessIds.Contains([uint32]$_.OwningProcess) })
    if ($listeners.Count -ne 0) {
        throw "installed Console or one of its children opened a TCP listener"
    }

    Stop-BoundedProcessTree -Process $process
    $process = $null

}
catch {
    $executionFailure = $_
}
finally {
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    $automationSid = if ($automationUserCreated -and $null -ne $automationUser) {
        $automationUser.SID.Value
    }
    else {
        $null
    }
    $trackedExecutablePaths = @(
        @(
            $installedExecutable,
            $installedHelper,
            $tauriDriverPath,
            $edgeDriverPath
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $ownerRequiredPaths = @()
    if (-not [string]::IsNullOrWhiteSpace($webViewRuntimePath)) {
        $ownerRequiredPaths += $webViewRuntimePath
    }

    Invoke-CleanupAction $cleanupFailures "automation process cleanup" {
        if ($null -ne $automationProcess) {
            Stop-BoundedProcessTree -Process $automationProcess
        }
    }
    Invoke-CleanupAction $cleanupFailures "driver process cleanup" {
        if ($null -ne $driverProcess) {
            Stop-BoundedProcessTree -Process $driverProcess
        }
    }
    Invoke-CleanupAction $cleanupFailures "Console process cleanup" {
        if ($null -ne $process) {
            Stop-BoundedProcessTree -Process $process
        }
    }
    Invoke-CleanupAction $cleanupFailures "attributed proof process drain" {
        $drainDeadline = [DateTime]::UtcNow.AddSeconds(15)
        $remainingAttributedProcesses = @(Get-AttributedProofProcesses `
            -AutomationSid $automationSid `
            -TrackedExecutablePaths $trackedExecutablePaths `
            -OwnerRequiredPaths $ownerRequiredPaths)
        while ($remainingAttributedProcesses.Count -ne 0 -and
            [DateTime]::UtcNow -lt $drainDeadline) {
            foreach ($remainingProcess in $remainingAttributedProcesses) {
                $remainingMilliseconds = Get-BoundedWaitMilliseconds `
                    -RemainingMilliseconds (
                        ($drainDeadline - [DateTime]::UtcNow).TotalMilliseconds
                    )
                if ($remainingMilliseconds -eq 0) {
                    break
                }
                $processBinding = Get-RevalidatedProofProcessHandle `
                    -Candidate $remainingProcess `
                    -AutomationSid $automationSid `
                    -TrackedExecutablePaths $trackedExecutablePaths `
                    -OwnerRequiredPaths $ownerRequiredPaths
                if ($null -ne $processBinding) {
                    try {
                        if ($processBinding.BoundHandle.IsInvalid -or
                            $processBinding.BoundHandle.IsClosed) {
                            throw "revalidated process handle was released before termination"
                        }
                        Stop-BoundedProcessInstance `
                            -Process $processBinding.Process `
                            -TimeoutMilliseconds $remainingMilliseconds
                    }
                    finally {
                        $processBinding.Process.Dispose()
                    }
                }
            }
            $sleepMilliseconds = Get-BoundedWaitMilliseconds `
                -RemainingMilliseconds (
                    ($drainDeadline - [DateTime]::UtcNow).TotalMilliseconds
                ) `
                -MaximumMilliseconds 250
            if ($sleepMilliseconds -ne 0) {
                Start-Sleep -Milliseconds $sleepMilliseconds
            }
            $remainingAttributedProcesses = @(Get-AttributedProofProcesses `
                -AutomationSid $automationSid `
                -TrackedExecutablePaths $trackedExecutablePaths `
                -OwnerRequiredPaths $ownerRequiredPaths)
        }
        if ($remainingAttributedProcesses.Count -ne 0) {
            $remainingDetails = @($remainingAttributedProcesses | ForEach-Object {
                $imageName = if ([string]::IsNullOrWhiteSpace($_.ExecutablePath)) {
                    "unknown"
                }
                else {
                    [IO.Path]::GetFileName($_.ExecutablePath)
                }
                "PID=$($_.ProcessId), image=$imageName, owner_sid=$($_.OwnerSid)"
            })
            throw "attributed proof processes remained active: $($remainingDetails -join '; ')"
        }
    }
    Invoke-CleanupAction $cleanupFailures "product and driver process absence" {
        $remainingTrackedProcesses = @(Get-AttributedProofProcesses `
            -AutomationSid $automationSid `
            -TrackedExecutablePaths $trackedExecutablePaths `
            -OwnerRequiredPaths $ownerRequiredPaths)
        if ($remainingTrackedProcesses.Count -ne 0) {
            throw "Console, driver or ephemeral-user process remained active"
        }
    }
    Invoke-CleanupAction $cleanupFailures "WebView2 debugger cleanup" {
        if ($null -ne $remoteDebuggingPort) {
            $remainingDebuggerListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object { $_.LocalPort -eq $remoteDebuggingPort })
            if ($remainingDebuggerListeners.Count -ne 0) {
                throw "listener remained on debugger port $remoteDebuggingPort"
            }
        }
    }

    if ($installationAttempted -and $null -ne $msi) {
        Invoke-CleanupAction $cleanupFailures "MSI uninstall" {
            $uninstall = Start-Process -FilePath "msiexec.exe" `
                -ArgumentList "/x `"$($msi.FullName)`" /qn /norestart" `
                -PassThru
            Wait-BoundedProcess `
                -Process $uninstall `
                -TimeoutSeconds 180 `
                -Operation "MSI uninstall" `
                -AllowedExitCodes @(0, 1605, 1614)
        }
    }
    Invoke-CleanupAction $cleanupFailures "MSI installation absence" {
        if ($null -ne $installedExecutable -and
            (Test-Path -LiteralPath $installedExecutable)) {
            throw "installed executable remained at $installedExecutable"
        }
        if ($null -ne $installedHelper -and
            (Test-Path -LiteralPath $installedHelper)) {
            throw "installed native helper remained at $installedHelper"
        }
        if ($null -ne $shortcut -and (Test-Path -LiteralPath $shortcut.FullName)) {
            throw "installed shortcut remained at $($shortcut.FullName)"
        }
        if ($installationAttempted) {
            $remainingShortcuts = @(Get-ChildItem `
                -Path $shortcutRoots `
                -Filter "*.lnk" `
                -Recurse `
                -File `
                -ErrorAction Stop | Where-Object { $_.BaseName -eq "Your Cloud" })
            $uninstallRegistryRoots = @(
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            $remainingRegistrations = @(
                foreach ($registryRoot in $uninstallRegistryRoots) {
                    if (-not (Test-Path -LiteralPath $registryRoot)) {
                        continue
                    }
                    foreach ($registration in Get-ChildItem `
                        -LiteralPath $registryRoot `
                        -ErrorAction Stop) {
                        $registrationProperties = Get-ItemProperty `
                            -LiteralPath $registration.PSPath `
                            -ErrorAction Stop
                        if ($null -ne $registrationProperties.PSObject.Properties["DisplayName"] -and
                            $registrationProperties.DisplayName -eq "Your Cloud") {
                            $registration
                        }
                    }
                }
            )
            if ($remainingShortcuts.Count -ne 0 -or
                $remainingRegistrations.Count -ne 0) {
                throw "Your Cloud MSI registration or shortcut remained after cleanup"
            }
        }
    }

    if ($null -ne $certificate) {
        $trustedCertificatePath = "Cert:\LocalMachine\TrustedPeople\$($certificate.Thumbprint)"
        $privateCertificatePath = "Cert:\CurrentUser\My\$($certificate.Thumbprint)"
        Invoke-CleanupAction $cleanupFailures "trusted synthetic certificate removal" {
            if (Test-Path -LiteralPath $trustedCertificatePath) {
                Remove-Item -LiteralPath $trustedCertificatePath -Force -ErrorAction Stop
            }
        }
        Invoke-CleanupAction $cleanupFailures "private synthetic certificate and key removal" {
            if (Test-Path -LiteralPath $privateCertificatePath) {
                Remove-Item -Path $privateCertificatePath -DeleteKey -Force -ErrorAction Stop
            }
        }
        Invoke-CleanupAction $cleanupFailures "synthetic certificate absence" {
            if ((Test-Path -LiteralPath $trustedCertificatePath) -or
                (Test-Path -LiteralPath $privateCertificatePath)) {
                throw "synthetic certificate remained in a Windows certificate store"
            }
        }
    }

    Invoke-CleanupAction $cleanupFailures "application data containment" {
        if ($null -ne $applicationData) {
            if ([string]::IsNullOrWhiteSpace($automationProfilePath)) {
                throw "ephemeral profile path is unavailable"
            }
            [void](Resolve-BoundedChildPath `
                -Root $automationProfilePath `
                -Path $applicationData `
                -Description "Windows Console test data")
        }
    }

    if ($automationUserCreated -and $null -ne $automationUser) {
        Invoke-CleanupAction $cleanupFailures "ephemeral profile removal" {
            $profile = $null
            for ($attempt = 0; $attempt -lt 40; $attempt++) {
                $profile = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
                    Where-Object { $_.SID -eq $automationSid } |
                    Select-Object -First 1
                if ($null -eq $profile -or -not $profile.Loaded) {
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            if ($null -ne $profile -and $profile.Loaded) {
                throw "ephemeral profile remained loaded"
            }
            if ($null -ne $profile) {
                if ([string]::IsNullOrWhiteSpace($profile.LocalPath) -or
                    -not [string]::Equals(
                        [IO.Path]::GetFullPath($profile.LocalPath),
                        [IO.Path]::GetFullPath($automationProfilePath),
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw "ephemeral profile path changed before removal"
                }
                Remove-CimInstance -InputObject $profile -ErrorAction Stop
                for ($attempt = 0; $attempt -lt 40; $attempt++) {
                    $profile = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
                        Where-Object { $_.SID -eq $automationSid } |
                        Select-Object -First 1
                    if ($null -eq $profile) {
                        break
                    }
                    Start-Sleep -Milliseconds 250
                }
                if ($null -ne $profile) {
                    throw "ephemeral profile registration remained after removal"
                }
            }
        }
        Invoke-CleanupAction $cleanupFailures "ephemeral account removal" {
            Remove-LocalUser -SID $automationUser.SID -ErrorAction Stop
        }
        Invoke-CleanupAction $cleanupFailures "ephemeral account and profile absence" {
            $remainingUser = Get-LocalUser -ErrorAction Stop |
                Where-Object { $_.SID.Value -eq $automationSid } |
                Select-Object -First 1
            $remainingProfile = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
                Where-Object { $_.SID -eq $automationSid } |
                Select-Object -First 1
            if ($null -ne $remainingUser -or
                $null -ne $remainingProfile -or
                ($null -ne $automationProfilePath -and
                    (Test-Path -LiteralPath $automationProfilePath))) {
                throw "ephemeral account, profile registration or profile directory remained for SID $automationSid"
            }
        }
    }
    Invoke-CleanupAction $cleanupFailures "application data absence" {
        if ($null -ne $applicationData -and
            (Test-Path -LiteralPath $applicationData)) {
            throw "application data remained at $applicationData"
        }
    }
    Invoke-CleanupAction $cleanupFailures "ephemeral credential disposal" {
        if ($null -ne $automationPassword) {
            $automationPassword.Dispose()
        }
    }

    Invoke-CleanupAction $cleanupFailures "temporary security material cleanup" {
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $temporaryRoot) {
            throw "temporary security material remained at $temporaryRoot"
        }
    }

    if ($cleanupFailures.Count -ne 0) {
        $cleanupMessage = "Windows CI cleanup verification failed:`n- " + (
            $cleanupFailures -join "`n- "
        )
        if ($null -ne $executionFailure) {
            $cleanupMessage += "`nExecution also failed: $($executionFailure.Exception.Message)"
        }
        throw $cleanupMessage
    }
}

if ($null -ne $executionFailure) {
    throw $executionFailure
}
if (-not (Test-Path -LiteralPath $proofReportPath -PathType Leaf)) {
    throw "Windows WebView2 proof report was not produced"
}
$proofReport = Get-Content -LiteralPath $proofReportPath -Raw | ConvertFrom-Json
if ($proofReport.result -ne "pass") {
    throw "Windows WebView2 proof report does not contain a passing result"
}
$proofReport | Add-Member -Force -NotePropertyName "github" -NotePropertyValue ([ordered]@{
    sha = $githubSha
    run_id = $githubRunId
    checkout_head_matches = $true
    worktree_clean_before_build = $true
})
$proofReport | Add-Member -Force -NotePropertyName "source_locks" -NotePropertyValue ([ordered]@{
    package_lock_sha256 = $packageLockSha256
    cargo_lock_sha256 = $cargoLockSha256
})
$proofReport | Add-Member -Force -NotePropertyName "verified_artifacts" -NotePropertyValue ([ordered]@{
    msi = [ordered]@{
        file_name = $msi.Name
        sha256 = $msiSha256
        executable_file_names = @(
            "your-cloud-console.exe",
            "your-cloud-native-bootstrap-assistant.exe"
        )
        administrative_image_contains_exact_installable_executable_file_set = $true
        authenticode_signer_matches_both_executables = $true
    }
    executable = [ordered]@{
        packaged_file_name = $packagedExecutable.Name
        packaged_sha256 = $packagedExecutableSha256
        installed_file_name = [IO.Path]::GetFileName($installedExecutable)
        installed_sha256 = $installedExecutableSha256
        installed_matches_package = $true
    }
    native_helper = [ordered]@{
        packaged_file_name = $packagedHelper.Name
        packaged_sha256 = $packagedHelperSha256
        installed_file_name = [IO.Path]::GetFileName($installedHelper)
        installed_sha256 = $installedHelperSha256
        installed_matches_package = $true
        installed_as_exact_console_sibling = $true
        packaged_and_installed_without_reparse_point = $true
        authenticode_signer_matches_console_and_msi = $true
        pe_gate = $peGateProof
    }
})
$proofReport | Add-Member -Force -NotePropertyName "cleanup" -NotePropertyValue ([ordered]@{
    result = "pass"
    enforcement = "blocking-script-exit"
    verified_absent = @(
        "msi-installation",
        "installed-native-helper",
        "synthetic-certificate-and-private-key",
        "ephemeral-standard-user-and-profile",
        "temporary-security-material",
        "product-and-driver-processes",
        "webview2-debugger-listener",
        "application-data"
    )
})
$serializedProof = $proofReport | ConvertTo-Json -Depth 20
$temporaryProofReport = "$proofReportPath.tmp"
[IO.File]::WriteAllText(
    $temporaryProofReport,
    $serializedProof + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
Move-Item -LiteralPath $temporaryProofReport -Destination $proofReportPath -Force

$proofFiles = @(Get-ChildItem -LiteralPath $uiSmokeRoot -Recurse -File -Force)
$expectedProofFileNames = @(
    "windows-local-access-1280x800.png",
    "windows-local-access-640x560.png",
    "windows-local-access-640x560-text-200.png",
    "windows-infrastructures-1280x800.png",
    "windows-infrastructures-640x560.png",
    "windows-infrastructures-640x560-text-200.png",
    "windows-association-1280x800.png",
    "windows-association-640x560.png",
    "windows-association-640x560-text-200.png",
    "windows-native-personal-consent.png",
    "windows-webview2-smoke.json"
) | Sort-Object
$observedProofFileNames = @($proofFiles | ForEach-Object { $_.Name } | Sort-Object)
$unexpectedProofFiles = @($proofFiles | Where-Object {
    $_.DirectoryName -ne $uiSmokeRoot -or $_.Length -le 0
})
$proofNameDifferences = @(
    Compare-Object `
        -ReferenceObject $expectedProofFileNames `
        -DifferenceObject $observedProofFileNames
)
$proofReports = @($proofFiles | Where-Object { $_.Extension -eq ".json" })
if ($unexpectedProofFiles.Count -ne 0 -or
    $proofNameDifferences.Count -ne 0 -or
    $proofReports.Count -ne 1 -or
    $proofReports[0].FullName -ne $proofReportPath) {
    throw "Windows proof artifact contains an unexpected file"
}

Write-Host "PASS: Windows MSI administrative image exposes exactly the same-signed installable Console and native helper executables"
Write-Host "PASS: packaged and installed helper hashes match, sibling paths are direct and non-reparse"
Write-Host "PASS: installed Console launched and opened no TCP listener"
Write-Host "PASS: Windows proof report is bound to run $githubRunId at $githubSha and cleanup is verified"
