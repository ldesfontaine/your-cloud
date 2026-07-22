$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$console = Join-Path $root "console"
$temporaryRoot = Join-Path $env:RUNNER_TEMP ("your-cloud-windows-ci-" + [Guid]::NewGuid().ToString("N"))
$overridePath = Join-Path $temporaryRoot "tauri.windows-ci.conf.json"
$certificatePath = Join-Path $temporaryRoot "signer.cer"
$certificate = $null
$installed = $false
$process = $null
$driverProcess = $null
$msi = $null
$uiProofRoot = Join-Path $env:RUNNER_TEMP "your-cloud-windows-ui-proof"
$webViewUserData = Join-Path $temporaryRoot "webview2-user-data"
$sessionReadyMarker = Join-Path $temporaryRoot "webdriver-session-ready"
$applicationData = Join-Path $env:APPDATA "fr.your-cloud.console"

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

function Invoke-BoundedNative {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    $standardOutput = Join-Path $temporaryRoot ([Guid]::NewGuid().ToString("N") + ".stdout.log")
    $standardError = Join-Path $temporaryRoot ([Guid]::NewGuid().ToString("N") + ".stderr.log")
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $standardOutput `
        -RedirectStandardError $standardError
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            & taskkill.exe /PID $process.Id /T /F | Out-Null
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

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    if (Test-Path -LiteralPath $uiProofRoot) {
        Remove-Item -LiteralPath $uiProofRoot -Recurse -Force
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
        Invoke-Native `
            -FilePath npm `
            -Arguments @("run", "tauri", "--", "build", "--bundles", "msi", "--config", $overridePath)
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
    $msi = $installers[0]

    $signTool = Get-ChildItem `
        -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" `
        -File | Sort-Object FullName -Descending | Select-Object -First 1
    if ($null -eq $signTool) {
        throw "signtool.exe was not found"
    }
    Assert-AuthenticodeSignature $msi.FullName $certificate.Thumbprint $signTool.FullName
    Get-FileHash -Algorithm SHA256 -LiteralPath $msi.FullName | Format-List

    $install = Start-Process -FilePath "msiexec.exe" `
        -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" `
        -Wait -PassThru
    if ($install.ExitCode -ne 0) {
        throw "MSI installation failed with status $($install.ExitCode)"
    }
    $installed = $true

    $shortcutRoots = @(
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs")
    )
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

    $process = Start-Process -FilePath $installedExecutable -PassThru
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
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $productProcessIds.Contains([uint32]$_.OwningProcess) })
    if ($listeners.Count -ne 0) {
        throw "installed Console or one of its children opened a TCP listener"
    }

    & taskkill.exe /PID $process.Id /T /F | Out-Null
    $process.WaitForExit()
    $process = $null

    Write-Host "CI Windows: preparing the bounded WebView2 driver"
    $edgePath = Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe"
    if (-not (Test-Path -LiteralPath $edgePath -PathType Leaf)) {
        throw "Microsoft Edge executable was not found"
    }
    $edgeVersion = (Get-Item -LiteralPath $edgePath).VersionInfo.ProductVersion
    if ($edgeVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "Microsoft Edge version is not canonical"
    }
    $edgeDriverArchive = Join-Path $temporaryRoot "edgedriver_win64.zip"
    $edgeDriverDirectory = Join-Path $temporaryRoot "edgedriver"
    $edgeDriverUri = "https://msedgedriver.microsoft.com/$edgeVersion/edgedriver_win64.zip"
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
    $edgeDriverSignature = Get-AuthenticodeSignature -LiteralPath $edgeDriver.FullName
    if ($edgeDriverSignature.Status -ne "Valid" -or
        $edgeDriverSignature.SignerCertificate.Subject -notmatch '(^|, )O=Microsoft Corporation(,|$)') {
        throw "Microsoft Edge Driver signature is invalid or has an unexpected publisher"
    }
    if ($edgeDriver.VersionInfo.ProductVersion -ne $edgeVersion) {
        throw "Microsoft Edge and Microsoft Edge Driver versions differ"
    }
    $tauriDriver = Get-Command "tauri-driver.exe" -ErrorAction Stop
    $driverOutput = Join-Path $temporaryRoot "tauri-driver.stdout.log"
    $driverError = Join-Path $temporaryRoot "tauri-driver.stderr.log"
    $previousWebViewUserData = $env:WEBVIEW2_USER_DATA_FOLDER
    $previousAdditionalBrowserArguments = $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
    try {
        $env:WEBVIEW2_USER_DATA_FOLDER = $webViewUserData
        $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=0"
        $driverProcess = Start-Process `
            -FilePath $tauriDriver.Source `
            -ArgumentList @("--native-driver", $edgeDriver.FullName) `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $driverOutput `
            -RedirectStandardError $driverError
    }
    finally {
        if ($null -eq $previousWebViewUserData) {
            Remove-Item Env:\WEBVIEW2_USER_DATA_FOLDER -ErrorAction SilentlyContinue
        }
        else {
            $env:WEBVIEW2_USER_DATA_FOLDER = $previousWebViewUserData
        }
        if ($null -eq $previousAdditionalBrowserArguments) {
            Remove-Item Env:\WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS -ErrorAction SilentlyContinue
        }
        else {
            $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = $previousAdditionalBrowserArguments
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
    try {
        Invoke-Native `
            -FilePath python `
            -Arguments @(
                (Join-Path $root "tests\checks\console-windows-ui-proof.py"),
                "--application", $installedExecutable,
                "--webview-user-data", $webViewUserData,
                "--session-ready-marker", $sessionReadyMarker,
                "--output", $uiProofRoot
            )
    }
    catch {
        if (-not (Test-Path -LiteralPath $sessionReadyMarker -PathType Leaf)) {
            Write-Host "CI Windows: WebDriver session creation failed before test secrets existed"
            Get-Content -LiteralPath $driverOutput, $driverError -Tail 200 -ErrorAction SilentlyContinue

            $activePorts = @(Get-ChildItem `
                -LiteralPath $webViewUserData `
                -Filter "DevToolsActivePort" `
                -Recurse `
                -File `
                -ErrorAction SilentlyContinue)
            if ($activePorts.Count -eq 0) {
                Write-Host "CI Windows: no DevToolsActivePort file exists under the bounded WebView2 directory"
            }
            else {
                $webViewRoot = [IO.Path]::GetFullPath($webViewUserData + [IO.Path]::DirectorySeparatorChar)
                foreach ($activePort in $activePorts) {
                    $activePortPath = [IO.Path]::GetFullPath($activePort.FullName)
                    if (-not $activePortPath.StartsWith($webViewRoot, [StringComparison]::OrdinalIgnoreCase)) {
                        throw "DevToolsActivePort escaped the bounded WebView2 directory"
                    }
                    $relativePath = [IO.Path]::GetRelativePath($webViewUserData, $activePortPath)
                    Write-Host "CI Windows: DevToolsActivePort metadata path=$relativePath size=$($activePort.Length)"
                }
            }

            foreach ($policyRoot in @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
            )) {
                $policy = Get-ItemProperty `
                    -LiteralPath $policyRoot `
                    -Name "RemoteDebuggingAllowed" `
                    -ErrorAction SilentlyContinue
                if ($null -eq $policy) {
                    Write-Host "CI Windows: RemoteDebuggingAllowed is not configured at $policyRoot"
                }
                else {
                    Write-Host "CI Windows: RemoteDebuggingAllowed=$($policy.RemoteDebuggingAllowed) at $policyRoot"
                }
            }
        }
        throw
    }
    & taskkill.exe /PID $driverProcess.Id /T /F | Out-Null
    $driverProcess.WaitForExit()
    $driverProcess = $null

    Write-Host "PASS: Windows MSI signed, timestamped, installed, launched and opened no TCP listener"
}
finally {
    if ($null -ne $driverProcess -and -not $driverProcess.HasExited) {
        & taskkill.exe /PID $driverProcess.Id /T /F | Out-Null
    }
    if ($null -ne $process -and -not $process.HasExited) {
        & taskkill.exe /PID $process.Id /T /F | Out-Null
    }
    if ($installed -and $null -ne $msi) {
        $uninstall = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/x `"$($msi.FullName)`" /qn /norestart" `
            -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            Write-Warning "MSI cleanup failed with status $($uninstall.ExitCode)"
        }
    }
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath "Cert:\LocalMachine\TrustedPeople\$($certificate.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -ErrorAction SilentlyContinue
    }
    $appDataRoot = [IO.Path]::GetFullPath($env:APPDATA + [IO.Path]::DirectorySeparatorChar)
    $applicationDataPath = [IO.Path]::GetFullPath($applicationData)
    if (-not $applicationDataPath.StartsWith($appDataRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Windows Console test data escaped APPDATA"
    }
    if (Test-Path -LiteralPath $applicationDataPath) {
        Remove-Item -LiteralPath $applicationDataPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
