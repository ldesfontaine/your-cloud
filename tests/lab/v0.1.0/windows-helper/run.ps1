# Run the Windows halves of the native helper contract on the evaluation machine.
#
# Each suite reproduces, argument for argument, the step the hosted native gate
# runs on its `windows-2025` runner. Reproducing them faithfully is the whole
# point: a suite rewritten to be convenient here would stop saying anything
# about the gate it pre-validates.
param(
    [Parameter(Mandatory = $true)][string]$Sources,
    [ValidateSet("release", "debug")][string]$Configuration = "release",
    [string[]]$Suite = @()
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$toolchain = "1.94.1"
$assistant = "your-cloud-native-bootstrap-assistant"
$protocol = "your-cloud-bootstrap-protocol"

$workspace = Join-Path $Sources "src-tauri"
if (-not (Test-Path -LiteralPath (Join-Path $workspace "Cargo.toml"))) {
    throw "no workspace at $workspace; synchronise the sources first"
}

# The MSVC environment. Rust's `x86_64-pc-windows-msvc` target links through
# `link.exe`, so a shell that never entered it fails on every suite for a
# reason that says nothing about the helper.
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "no Visual Studio installer inventory on this machine" }
$installPath = & $vswhere -products * -latest `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath 2>$null | Select-Object -First 1
if (-not $installPath) { throw "no MSVC x64 build tools on this machine" }
$vcvars = Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "no $vcvars on this machine" }
foreach ($line in (& cmd.exe /c "call `"$vcvars`" >nul 2>&1 && set")) {
    $split = $line.IndexOf("=")
    if ($split -gt 0) {
        Set-Item -Path ("Env:" + $line.Substring(0, $split)) -Value $line.Substring($split + 1)
    }
}
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path

# `honoursConfiguration` is false where the hosted gate itself never asks for a
# release build: the suspended-handle suite runs unoptimised there, and running
# it optimised here would observe something else.
$catalogue = @(
    @{
        name = "secret-crash-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "secret-crash-contract-test",
            "--test", "secret-crash-contract", "--", "--test-threads=1"
        )
    },
    @{
        name = "native-lib"
        honoursConfiguration = $true
        arguments = @("-p", $assistant, "--lib")
    },
    @{
        name = "protocol"
        honoursConfiguration = $true
        arguments = @("-p", $protocol)
    },
    @{
        name = "delayed-start-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "delayed-start-contract-test",
            "--test", "delayed-start-contract",
            "delay_before_process_main_cannot_renew_the_transmitted_ttl",
            "--", "--exact", "--test-threads=1"
        )
    },
    @{
        name = "parent-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "native-prompt-contract-test",
            "--test", "parent-contract",
            "console_parent_closes_one_job_before_reusing_the_boundary",
            "--", "--exact", "--test-threads=1"
        )
    },
    @{
        name = "windows-parent-spoof-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "windows-parent-spoof-contract-test",
            "--test", "windows-parent-spoof-contract",
            "declared_parent_cannot_authorize_an_attacker_owned_pipe",
            "--", "--exact", "--test-threads=1"
        )
    },
    @{
        name = "windows-agent-pipe-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "windows-agent-pipe-contract-test",
            "--test", "windows-agent-pipe-contract",
            "a_pipe_server_that_is_not_the_system_openssh_agent_is_refused",
            "--", "--exact", "--test-threads=1"
        )
    },
    @{
        name = "windows-live-prompt-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "windows-live-prompt-contract-test",
            "--test", "windows-live-prompt-contract",
            "live_prompt_refuses_target_step_action_and_expiration_mutations",
            "--", "--exact", "--test-threads=1"
        )
    },
    @{
        name = "windows-job-contract"
        honoursConfiguration = $false
        arguments = @(
            "-p", $assistant, "--features", "windows-contract-test",
            "--test", "windows-job-contract"
        )
    },
    @{
        name = "win32-dialog"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant,
            "native_prompt_windows::tests::win32_dialog_handles_consent_secret_tamper_and_lease_states",
            "--", "--ignored", "--exact", "--test-threads=1"
        )
    }
)

$selected = $catalogue
if ($Suite.Count -ne 0) {
    $unknown = @($Suite | Where-Object { $catalogue.name -notcontains $_ })
    if ($unknown.Count -ne 0) { throw "unknown suites: $($unknown -join ', ')" }
    $selected = @($catalogue | Where-Object { $Suite -contains $_.name })
}

# The Terminal Services session this run lives in. It is printed rather than
# checked because it decides what can be observed at all: a session opened by
# OpenSSH is session 0, whose window station is not interactive, and a modal
# dialog created there never gains `WS_VISIBLE`. A suite that looks for a
# visible window is therefore unobservable through this transport, and the
# number below is what says so instead of a shrug.
$session = (Get-Process -Id $PID).SessionId
Write-Output "session     = $session"
Write-Output "workspace   = $workspace"
Write-Output "configuration = $Configuration"

Push-Location $workspace
$results = [ordered]@{}
try {
    foreach ($entry in $selected) {
        $arguments = @("+$toolchain", "test", "--locked")
        if ($entry.honoursConfiguration -and $Configuration -eq "release") {
            $arguments += "--release"
        }
        $arguments += $entry.arguments
        Write-Output ""
        Write-Output "== $($entry.name) =="
        Write-Output "cargo $($arguments -join ' ')"
        & cargo @arguments
        $results[$entry.name] = $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

Write-Output ""
Write-Output "== verdict =="
$failed = 0
foreach ($name in $results.Keys) {
    $code = $results[$name]
    if ($code -eq 0) { Write-Output "ok     $name" }
    else { Write-Output "FAILED $name ($code)"; $failed += 1 }
}
if ($failed -ne 0) { exit 1 }
Write-Output "RUN_WINDOWS_HELPER_OK"
