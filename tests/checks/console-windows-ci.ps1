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
$builtExecutable = $null
$shortcut = $null
$installedExecutable = $null
$msiSha256 = $null
$builtExecutableSha256 = $null
$installedExecutableSha256 = $null
$packageLockSha256 = $null
$cargoLockSha256 = $null
$uiSmokeRoot = Join-Path $env:RUNNER_TEMP "your-cloud-windows-webview2-smoke"
$webViewUserData = $null
$tauriDriverPath = $null
$edgeDriverPath = $null
$webViewRuntimePath = $null
$remoteDebuggingPort = $null
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
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 10
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        return
    }
    try {
        & taskkill.exe /PID $Process.Id /T /F | Out-Null
    }
    catch {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            throw
        }
    }
    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "process $($Process.Id) remained active after ${TimeoutSeconds}s"
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

function Invoke-CleanupAction {
    param(
        [Parameter(Mandatory = $true)][Collections.Generic.List[string]]$Failures,
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

    $executables = @(Get-ChildItem `
        -LiteralPath (Join-Path $console "src-tauri\target\release") `
        -Filter "your-cloud-console.exe" -File)
    $installers = @(Get-ChildItem `
        -LiteralPath (Join-Path $console "src-tauri\target\release\bundle\msi") `
        -Filter "*.msi" -File)
    if ($executables.Count -ne 1 -or $installers.Count -ne 1) {
        throw "expected exactly one Windows executable and one MSI"
    }
    $builtExecutable = $executables[0]
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
    Assert-AuthenticodeSignature $builtExecutable.FullName $certificate.Thumbprint $signTool.FullName
    $builtExecutableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $builtExecutable.FullName
    ).Hash.ToLowerInvariant()
    Write-Host "CI Windows: verified built executable SHA-256 $builtExecutableSha256"

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
    $installedExecutable = $shell.CreateShortcut($shortcut.FullName).TargetPath
    if (-not (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) {
        throw "installed Console executable was not found"
    }
    Assert-AuthenticodeSignature $installedExecutable $certificate.Thumbprint $signTool.FullName
    $installedExecutableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $installedExecutable
    ).Hash.ToLowerInvariant()
    Write-Host "CI Windows: verified installed executable SHA-256 $installedExecutableSha256"
    if ($installedExecutableSha256 -ne $builtExecutableSha256) {
        throw "installed executable differs from the signed build output"
    }

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
    }
    if (-not $driverReady) {
        throw "tauri-driver did not become ready within 30 seconds"
    }

    $portReservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $portReservation.Start()
        $remoteDebuggingPort = ([Net.IPEndPoint]$portReservation.LocalEndpoint).Port
    }
    finally {
        $portReservation.Stop()
    }
    $debuggerAddress = "127.0.0.1:$remoteDebuggingPort"

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
    $webViewUserData = Join-Path $automationLocalData "your-cloud-windows-webview2-smoke\webview2"
    New-Item -ItemType Directory -Path $automationTemp, $webViewUserData -Force | Out-Null
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
        WEBVIEW2_USER_DATA_FOLDER = $webViewUserData
        WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$remoteDebuggingPort"
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

    $remoteDebuggerReady = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $automationProcess.Refresh()
        if ($automationProcess.HasExited) {
            throw "installed Console exited before exposing its bounded WebView2 debugger"
        }
        $allProcesses = @(Get-CimInstance Win32_Process)
        $automationProcessIds = [Collections.Generic.HashSet[uint32]]::new()
        [void]$automationProcessIds.Add([uint32]$automationProcess.Id)
        do {
            $added = $false
            foreach ($candidate in $allProcesses) {
                if ($automationProcessIds.Contains([uint32]$candidate.ParentProcessId) -and
                    $automationProcessIds.Add([uint32]$candidate.ProcessId)) {
                    $added = $true
                }
            }
        } while ($added)
        $debuggerListeners = @(Get-NetTCPConnection `
            -State Listen `
            -LocalPort $remoteDebuggingPort `
            -ErrorAction SilentlyContinue)
        if ($debuggerListeners.Count -gt 0) {
            foreach ($listener in $debuggerListeners) {
                if ($listener.LocalAddress -notin @("127.0.0.1", "::1")) {
                    throw "WebView2 debugger escaped the loopback interface"
                }
                if (-not $automationProcessIds.Contains([uint32]$listener.OwningProcess)) {
                    throw "reserved WebView2 debugger port was claimed by another process"
                }
            }
            try {
                $debuggerVersion = Invoke-RestMethod `
                    -Uri "http://$debuggerAddress/json/version" `
                    -NoProxy `
                    -TimeoutSec 1
                $debuggerSocket = [Uri]$debuggerVersion.webSocketDebuggerUrl
                if ($debuggerSocket.Scheme -eq "ws" -and
                    $debuggerSocket.Host -eq "127.0.0.1" -and
                    $debuggerSocket.Port -eq $remoteDebuggingPort -and
                    $debuggerSocket.AbsolutePath.StartsWith("/devtools/browser/")) {
                    $remoteDebuggerReady = $true
                    break
                }
            }
            catch {
                # The listener can appear briefly before the CDP endpoint is ready.
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
    Invoke-CleanupAction $cleanupFailures "product and driver process absence" {
        $trackedExecutablePaths = @(
            @(
                $installedExecutable,
                $tauriDriverPath,
                $edgeDriverPath,
                $webViewRuntimePath
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        if ($trackedExecutablePaths.Count -ne 0) {
            $remainingTrackedProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop |
                Where-Object {
                    if ([string]::IsNullOrWhiteSpace($_.ExecutablePath)) {
                        return $false
                    }
                    foreach ($trackedPath in $trackedExecutablePaths) {
                        if ([string]::Equals(
                            $_.ExecutablePath,
                            $trackedPath,
                            [StringComparison]::OrdinalIgnoreCase
                        )) {
                            return $true
                        }
                    }
                    return $false
                })
            if ($remainingTrackedProcesses.Count -ne 0) {
                throw "Console, driver or WebView2 process remained active"
            }
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
                Get-ChildItem -Path $uninstallRegistryRoots -ErrorAction Stop |
                    ForEach-Object {
                        Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
                    } |
                    Where-Object {
                        $null -ne $_.PSObject.Properties["DisplayName"] -and
                        $_.DisplayName -eq "Your Cloud"
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

    Invoke-CleanupAction $cleanupFailures "application data cleanup" {
        if ($null -ne $applicationData) {
            if ([string]::IsNullOrWhiteSpace($automationProfilePath)) {
                throw "ephemeral profile path is unavailable"
            }
            $profileRoot = [IO.Path]::GetFullPath(
                $automationProfilePath + [IO.Path]::DirectorySeparatorChar
            )
            $applicationDataPath = [IO.Path]::GetFullPath($applicationData)
            if (-not $applicationDataPath.StartsWith(
                $profileRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "Windows Console test data escaped the ephemeral profile"
            }
            if (Test-Path -LiteralPath $applicationDataPath) {
                Remove-Item -LiteralPath $applicationDataPath -Recurse -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $applicationDataPath) {
                throw "application data remained at $applicationDataPath"
            }
        }
    }

    $automationSid = $null
    if ($automationUserCreated -and $null -ne $automationUser) {
        $automationSid = $automationUser.SID.Value
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
                Remove-CimInstance -InputObject $profile -ErrorAction Stop
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
    }
    executable = [ordered]@{
        file_name = $builtExecutable.Name
        sha256 = $builtExecutableSha256
        installed_file_name = [IO.Path]::GetFileName($installedExecutable)
        installed_sha256 = $installedExecutableSha256
        installed_matches_build = $true
    }
})
$proofReport | Add-Member -Force -NotePropertyName "cleanup" -NotePropertyValue ([ordered]@{
    result = "pass"
    enforcement = "blocking-script-exit"
    verified_absent = @(
        "msi-installation",
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
$unexpectedProofFiles = @($proofFiles | Where-Object {
    $_.Extension.ToLowerInvariant() -notin @(".json", ".png")
})
$proofReports = @($proofFiles | Where-Object { $_.Extension -eq ".json" })
if ($unexpectedProofFiles.Count -ne 0 -or
    $proofReports.Count -ne 1 -or
    $proofReports[0].FullName -ne $proofReportPath) {
    throw "Windows proof artifact contains an unexpected file"
}

Write-Host "PASS: Windows MSI signed, timestamped, installed, launched and opened no TCP listener"
Write-Host "PASS: Windows proof report is bound to run $githubRunId at $githubSha and cleanup is verified"
