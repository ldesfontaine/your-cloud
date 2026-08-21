# Unpack the App native sources into the evaluation machine's work tree.
#
# Only the sources travel. The build cache is deliberately kept: rebuilding
# this workspace from nothing on four virtual processors costs far more than
# the copy it would replace.
param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Destination
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "no archive at $Archive"
}
New-Item -ItemType Directory -Force -Path $Destination | Out-Null

# Everything the previous synchronisation left, except the target directory.
$sources = Join-Path $Destination "src-tauri"
if (Test-Path -LiteralPath $sources) {
    Get-ChildItem -LiteralPath $sources -Force `
    | Where-Object { $_.Name -ne "target" } `
    | Remove-Item -Recurse -Force
}
Remove-Item -LiteralPath (Join-Path $Destination "package.json") -Force -ErrorAction SilentlyContinue

# `-m` is not a detail. Cargo decides freshness from modification times, and an
# archive that restored the times of the pilot station would hand back sources
# older than the artefacts already in the cache: the run would then silently
# test the previous synchronisation. Stamping every extracted file with the
# extraction time is what makes the cache safe to keep.
& tar.exe -x -m -z -f $Archive -C $Destination
if ($LASTEXITCODE -ne 0) { throw "tar refused $Archive with $LASTEXITCODE" }
Remove-Item -LiteralPath $Archive -Force

foreach ($required in @("src-tauri\Cargo.toml", "src-tauri\Cargo.lock", "package.json")) {
    $path = Join-Path $Destination $required
    if (-not (Test-Path -LiteralPath $path)) { throw "the synchronisation left no $required" }
}
Write-Output "sources synchronised into $Destination"
