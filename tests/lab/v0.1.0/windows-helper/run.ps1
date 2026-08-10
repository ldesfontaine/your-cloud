# Run the Windows halves of the native helper contract on the evaluation machine.
#
# Each suite reproduces, argument for argument, the step the hosted native gate
# runs on its `windows-2025` runner. Reproducing them faithfully is the whole
# point: a suite rewritten to be convenient here would stop saying anything
# about the gate it pre-validates.
param(
    [Parameter(Mandatory = $true)][string]$Sources,
    [ValidateSet("release", "debug")][string]$Configuration = "release",
    [string[]]$Suite = @(),
    [string]$Perimeter = "",
    [switch]$SystemAgent
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$toolchain = "1.94.1"
$assistant = "your-cloud-native-bootstrap-assistant"
$protocol = "your-cloud-bootstrap-protocol"

# Reading the window station this run was given. It is the one fact that says
# whether a suite looking for a visible window can be believed here.
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class WindowStation {
    [DllImport("user32.dll")] public static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern bool GetUserObjectInformationW(IntPtr hObj, int nIndex,
        StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);
}
"@

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

# The perimeter of a suite that needs one. It is a file rather than a command
# line because quoting a value through `ssh`, `cmd` and PowerShell in turn is a
# way to change it silently, and because the file is what makes the run
# auditable: it is printed back below, in full.
#
# It carries no secret and cannot: only names beginning with `YOUR_CLOUD_LAB_`
# are accepted, and what they hold is an address, a port, an account name, a
# public key fingerprint or a numeric identity. No key material ever travels
# here; the private keys of a run live in the machine's own agent and nowhere
# else.
$perimeterNames = @()
if ($Perimeter -ne "") {
    if (-not (Test-Path -LiteralPath $Perimeter)) { throw "no perimeter file at $Perimeter" }
    foreach ($line in (Get-Content -LiteralPath $Perimeter)) {
        if ($line.Trim() -eq "") { continue }
        $split = $line.IndexOf("=")
        if ($split -le 0) { throw "malformed perimeter line: $line" }
        $name = $line.Substring(0, $split)
        if ($name -cnotmatch '^YOUR_CLOUD_LAB_[A-Z0-9_]+$') {
            throw "a perimeter may only name YOUR_CLOUD_LAB_* variables, not $name"
        }
        Set-Item -Path ("Env:" + $name) -Value $line.Substring($split + 1)
        $perimeterNames += $name
    }
}

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
        # Les deux épreuves de cette suite pilotent le même service `ssh-agent`
        # et doivent donc rester sérialisées ; elles sont nommées ensemble
        # plutôt qu’une seule, parce que celle qui compte le plus est la
        # seconde — l’attestation vue par un compte sans droit administrateur.
        name = "windows-agent-pipe-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "windows-agent-pipe-contract-test",
            "--test", "windows-agent-pipe-contract",
            "--", "--test-threads=1"
        )
    },
    @{
        # Le transport personnel complet, depuis ce poste Windows vers une vraie
        # machine Linux. Elle exige un périmètre — adresse, compte, clé d'hôte,
        # empreintes — et l'agent OpenSSH de la machine tenant réellement
        # l'identité autorisée ; sans eux elle échoue en le disant, plutôt que
        # de se déclarer verte sans avoir rien joint.
        name = "windows-personal-transport-contract"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant, "--features", "windows-personal-transport-contract-test",
            "--test", "windows-personal-transport-contract",
            "--", "--test-threads=1"
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
    },
    @{
        # La sélection d'identité de la fenêtre d'accès personnel, pilotée dans
        # le processus du test. Elle n'interroge jamais la visibilité de la
        # fenêtre, ce qui est la seule raison pour laquelle elle est observable
        # depuis une session 0.
        name = "win32-identity-selection"
        honoursConfiguration = $true
        arguments = @(
            "-p", $assistant,
            "native_prompt_windows::tests::win32_identity_selection_binds_one_consent_to_one_chosen_fingerprint",
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

# Run one already-built suite under `LocalSystem`, and report its exit code.
#
# It exists for one reason, and it is a property of *this* machine rather than
# of Windows or of the helper. The OpenSSH agent stores an added key in the
# registry of the account that added it, protected by that account's DPAPI
# master key — which a logon holding no credentials does not have. A session
# opened by public key over `sshd`, which is the only way into this machine, is
# exactly such a logon: `CryptProtectData` answers "access denied" and
# `ssh-add` is refused by the agent before any key exists to test with. The one
# credentialed identity reachable from here is the service logon `LocalSystem`,
# so the identities of a run are added under it and the suite that must see
# them runs under it too.
#
# The hosted gate needs none of this: a runner logs its job account on with
# credentials and `ssh-add` behaves. So the catalogue keeps the plain
# `cargo test` the gate runs, and this path is taken only when the operator
# asks for it, which is what `-SystemAgent` says out loud.
#
# The build stays where it was — this machine's ordinary account — and only the
# test executable is handed to the task, so nothing under `target` changes
# owner behind the operator's back.
function Invoke-SuiteAsSystem {
    param([Parameter(Mandatory = $true)][string[]]$CargoArguments)

    $separator = [array]::IndexOf($CargoArguments, "--")
    $build = if ($separator -ge 0) { $CargoArguments[0..($separator - 1)] } else { $CargoArguments }
    Write-Output "cargo $($build -join ' ') --no-run --message-format=json"
    $executable = ""
    foreach ($line in (& cargo @build --no-run --message-format=json)) {
        if ($line -notlike "{*") { continue }
        $artifact = $line | ConvertFrom-Json
        if ($artifact.reason -ne "compiler-artifact") { continue }
        if (-not $artifact.executable) { continue }
        if ($artifact.target.name -ne "windows-personal-transport-contract") { continue }
        $executable = $artifact.executable
    }
    if ($executable -eq "") { throw "cargo built no test executable to run as SYSTEM" }

    $log = Join-Path $env:TEMP "your-cloud-system-suite.log"
    $wrapper = Join-Path $env:TEMP "your-cloud-system-suite.ps1"
    $task = "your-cloud-windows-personal-transport"
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue

    # The perimeter travels in the wrapper because a scheduled task carries no
    # environment of its own. Nothing else is put there: the task runs the exact
    # executable cargo just built, with the exact harness arguments.
    $lines = @()
    foreach ($name in $perimeterNames) {
        $value = (Get-Item -Path ("Env:" + $name)).Value
        $lines += ('$env:' + $name + " = '" + $value.Replace("'", "''") + "'")
    }
    $lines += ("& '" + $executable.Replace("'", "''") + "' --test-threads=1 *> '" + $log + "'")
    $lines += 'exit $LASTEXITCODE'
    Set-Content -LiteralPath $wrapper -Value $lines -Encoding ASCII

    Write-Output "SYSTEM $executable -- --test-threads=1"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`""
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $task
        $deadline = (Get-Date).AddMinutes(5)
        while ((Get-ScheduledTask -TaskName $task).State -ne "Ready" -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        if ((Get-ScheduledTask -TaskName $task).State -ne "Ready") {
            Stop-ScheduledTask -TaskName $task
            throw "the suite did not finish under SYSTEM within its bound"
        }
        $code = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
    }
    finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $log) {
        Get-Content -LiteralPath $log
        Remove-Item -LiteralPath $log -Force
    }
    # Published rather than returned: everything this function prints is part of
    # its output stream, and a returned code would arrive buried in it.
    $script:systemSuiteResult = $code
}

# The Terminal Services session this run lives in, and the window station it
# was given. Together they decide what can be observed at all: a session opened
# by OpenSSH is session 0, whose window station is a `Service-0x0-...$` and not
# the interactive `WinSta0`. A window shown there is a real window — the helper
# child really creates its `#32770` dialog, titled, and it was observed doing
# so — but `IsWindowVisible` answers zero for it, measured on this machine on
# 9 August 2026 with a plain form that .NET itself reported as visible.
#
# A suite that looks for a *visible* window is therefore unobservable through
# this transport, whatever the product does. Below, such a suite is declared
# not run and named with its reason, never green and never red: a red would say
# the product failed, and a green would say something was proven that nobody
# watched.
$session = (Get-Process -Id $PID).SessionId
$windowStationName = New-Object System.Text.StringBuilder 256
$windowStationNeeded = 0
[void][WindowStation]::GetUserObjectInformationW(
    [WindowStation]::GetProcessWindowStation(), 2,
    $windowStationName, 256, [ref]$windowStationNeeded)
$station = $windowStationName.ToString()
$interactiveStation = $station -eq "WinSta0"
Write-Output "session     = $session"
Write-Output "windowstation = $station$(if ($interactiveStation) { ' (interactive)' } else { ' (not interactive)' })"
Write-Output "workspace   = $workspace"
Write-Output "configuration = $Configuration"
foreach ($name in $perimeterNames) {
    Write-Output ("perimeter   = " + $name + "=" + (Get-Item -Path ("Env:" + $name)).Value)
}

# What each suite needs from the environment before it can say anything. A
# suite whose need is unmet is not run, unless the operator named it on the
# command line: asking for one suite by name is asking to see it try.
$unmetNeed = @{}
if (-not $interactiveStation) {
    $unmetNeed["windows-live-prompt-contract"] =
        "needs an interactive window station; this session holds $station, where a shown window reports IsWindowVisible=0"
}
if ($perimeterNames.Count -eq 0) {
    $unmetNeed["windows-personal-transport-contract"] =
        "needs a YOUR_CLOUD_LAB_* perimeter naming a real target, and none was carried"
}
$explicit = $Suite.Count -ne 0

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
        if (-not $explicit -and $unmetNeed.ContainsKey($entry.name)) {
            Write-Output "not run: $($unmetNeed[$entry.name])"
            $results[$entry.name] = "not_run"
        } elseif ($SystemAgent -and $entry.name -eq "windows-personal-transport-contract") {
            $script:systemSuiteResult = 1
            Invoke-SuiteAsSystem -CargoArguments $arguments
            $results[$entry.name] = $script:systemSuiteResult
        } else {
            Write-Output "cargo $($arguments -join ' ')"
            & cargo @arguments
            $results[$entry.name] = $LASTEXITCODE
        }
    }
}
finally {
    Pop-Location
}

Write-Output ""
Write-Output "== verdict =="
$failed = 0
$notRun = 0
foreach ($name in $results.Keys) {
    $code = $results[$name]
    if ($code -eq "not_run") { Write-Output "not run $name"; $notRun += 1 }
    elseif ($code -eq 0) { Write-Output "ok      $name" }
    else { Write-Output "FAILED  $name ($code)"; $failed += 1 }
}
if ($notRun -ne 0) {
    Write-Output ""
    Write-Output "$notRun suite(s) this environment cannot observe were not run:"
    foreach ($name in $results.Keys) {
        if ($results[$name] -eq "not_run") { Write-Output "  $name : $($unmetNeed[$name])" }
    }
    Write-Output "Naming one on the command line runs it anyway, and it may fail for this reason."
}
if ($failed -ne 0) { exit 1 }
Write-Output "RUN_WINDOWS_HELPER_OK"
