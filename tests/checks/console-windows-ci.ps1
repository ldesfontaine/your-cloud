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
$msi = $null

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
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=Your Cloud CI Synthetic" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(2)
    Export-Certificate -Cert $certificate -FilePath $certificatePath | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null

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
        Invoke-Native npm run tauri -- build --bundles msi --config $overridePath
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
    Assert-AuthenticodeSignature $executables[0].FullName $certificate.Thumbprint $signTool.FullName
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

    Write-Host "PASS: Windows MSI signed, timestamped, installed, launched and opened no TCP listener"
}
finally {
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
        Remove-Item -LiteralPath "Cert:\CurrentUser\Root\$($certificate.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
