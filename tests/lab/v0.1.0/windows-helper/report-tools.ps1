# Report the pinned toolchain the Windows evaluation machine holds.
#
# It reports rather than installs: provisioning this machine is manual and
# outside `labctl`, and a harness that repaired it silently would hide the day
# it drifted from the hosted runner it is supposed to pre-validate.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$toolchain = "1.94.1"
$node = "v24.18.0"
$target = "x86_64-pc-windows-msvc"

$failures = @()
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path

function Read-Version {
    param([string]$Executable, [string[]]$Arguments)
    $command = Get-Command $Executable -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $null }
    return (& $command.Source @Arguments 2>&1 | Select-Object -First 1)
}

$rustc = Read-Version -Executable "rustc" -Arguments @("+$toolchain", "--version")
if ($null -eq $rustc) {
    $failures += "no rustc on this machine"
} elseif ($rustc -notmatch "^rustc $([regex]::Escape($toolchain)) ") {
    $failures += "rustc announces '$rustc', not $toolchain"
}

$rustfmt = Read-Version -Executable "cargo" -Arguments @("+$toolchain", "fmt", "--version")
if ($null -eq $rustfmt) { $failures += "no cargo on this machine" }

$host_triple = Read-Version -Executable "rustup" -Arguments @("show", "active-toolchain")
if ($null -ne $host_triple -and $host_triple -notmatch [regex]::Escape($target)) {
    $failures += "the active toolchain is '$host_triple', not a $target one"
}

$nodeVersion = Read-Version -Executable "node" -Arguments @("--version")
if ($null -eq $nodeVersion) {
    $failures += "no node on this machine"
} elseif ($nodeVersion.Trim() -ne $node) {
    $failures += "node announces '$nodeVersion', not $node"
}

# The MSVC toolset and the Windows SDK: without them `link.exe` is missing and
# every suite below fails for a reason that says nothing about the helper.
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$vcvars = $null
if (Test-Path $vswhere) {
    $installPath = & $vswhere -products * -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null | Select-Object -First 1
    if ($installPath) {
        $candidate = Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $candidate) { $vcvars = $candidate }
    }
}
if ($null -eq $vcvars) { $failures += "no MSVC x64 build environment on this machine" }

# The Evergreen runtime the App's window needs. It is reported here so a
# machine that lost it says so before a graphical case blames the helper.
$webview2Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
$webview2 = if (Test-Path $webview2Key) { (Get-ItemProperty $webview2Key).pv } else { $null }
if ($null -eq $webview2) { $failures += "no WebView2 Evergreen runtime on this machine" }

Write-Output "os          = $((Get-CimInstance Win32_OperatingSystem).Caption) $([Environment]::OSVersion.Version)"
Write-Output "rustc       = $rustc"
Write-Output "rustfmt     = $rustfmt"
Write-Output "toolchain   = $host_triple"
Write-Output "node        = $nodeVersion"
Write-Output "vcvars      = $vcvars"
if ($vcvars) {
    $toolsRoot = Join-Path (Split-Path (Split-Path (Split-Path $vcvars))) "Tools\MSVC"
    Write-Output "msvc        = $((Get-ChildItem $toolsRoot | Select-Object -ExpandProperty Name) -join ', ')"
}
$sdkRoot = "C:\Program Files (x86)\Windows Kits\10\Include"
if (Test-Path $sdkRoot) {
    Write-Output "windows sdk = $((Get-ChildItem $sdkRoot | Select-Object -ExpandProperty Name) -join ', ')"
}
Write-Output "webview2    = $webview2"

if ($failures.Count -ne 0) {
    foreach ($failure in $failures) { Write-Output "FAILED: $failure" }
    exit 1
}
Write-Output "TOOLS_OK"
