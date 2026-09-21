<#
.SYNOPSIS
  Fresh-clone closure check.

.DESCRIPTION
  Clones this repository into a scratch directory using only committed sources,
  then configures, builds and tests that clone from scratch. This proves the
  closure claim is reproducible from the commit, not from a working tree that
  happens to contain generated or untracked files.

  There are no timeouts: the build and the test run complete naturally. A hang is
  a defect to diagnose, not something to hide behind a watchdog.

.PARAMETER SourceRepository
  Repository to clone. Defaults to the working tree this script lives in.

.PARAMETER WorkDirectory
  Scratch directory. Defaults to a fresh directory under the system temp path.

.PARAMETER BuildType
  CMake build type for the clone. Defaults to Release.

.EXAMPLE
  pwsh -File scripts/fresh-clone-check.ps1 -BuildType Debug
#>
[CmdletBinding()]
param(
  [string]$SourceRepository = "",
  [string]$WorkDirectory = "",
  [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"

function Get-VcvarsPath {
  <#
    Locates the MSVC developer environment script on Windows. Returns an empty
    string when Visual Studio's C++ toolset is not installed, in which case the
    caller relies on the ambient PATH.
  #>
  if (-not $IsWindows) { return "" }
  $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
  if ([string]::IsNullOrEmpty($programFilesX86)) { return "" }
  $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio/Installer/vswhere.exe"
  if (-not (Test-Path $vswhere)) { return "" }
  $installations = & $vswhere -all -products * -property installationPath
  foreach ($installation in $installations) {
    if ([string]::IsNullOrEmpty($installation)) { continue }
    $candidate = Join-Path $installation "VC/Auxiliary/Build/vcvars64.bat"
    $toolset = Join-Path $installation "VC/Tools/MSVC"
    if ((Test-Path $candidate) -and (Test-Path $toolset)) { return $candidate }
  }
  return ""
}

if ([string]::IsNullOrEmpty($SourceRepository)) {
  $SourceRepository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
if ([string]::IsNullOrEmpty($WorkDirectory)) {
  $WorkDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("sbf-fresh-clone-" + [guid]::NewGuid().ToString("N"))
}

Write-Host "source repository : $SourceRepository"
Write-Host "work directory    : $WorkDirectory"
Write-Host "build type        : $BuildType"

if (Test-Path $WorkDirectory) { Remove-Item -Recurse -Force $WorkDirectory }
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null

$clone = Join-Path $WorkDirectory "clone"
git clone --no-local --quiet $SourceRepository $clone
if ($LASTEXITCODE -ne 0) { throw "git clone failed" }

Push-Location $clone
try {
  # Nothing may be present that is not committed: the clone is the truth.
  $dirty = git status --porcelain
  if ($dirty) {
    Write-Host $dirty
    throw "the fresh clone is not clean"
  }
  Write-Host "clone commit      : $(git rev-parse HEAD)"

  # The three steps are driven from one generated batch file. That keeps the
  # developer environment, the working directory and the exit codes in a single
  # shell, instead of relying on nested-shell quoting for paths with spaces.
  $vcvars = Get-VcvarsPath
  if ($vcvars) { Write-Host "toolchain         : $vcvars" }

  $build = Join-Path $clone "build"
  $q = [char]34
  $driver = Join-Path $WorkDirectory "clone-check.bat"
  $driverLines = @("@echo off")
  if ($vcvars) { $driverLines += "call $q$vcvars$q >nul 2>&1" }
  $driverLines += "cmake -S $q$clone$q -B $q$build$q -G Ninja -DCMAKE_BUILD_TYPE=$BuildType -DSBF_BUILD_TESTS=ON -DSBF_BUILD_EXAMPLES=ON"
  $driverLines += "if errorlevel 1 exit /b 11"
  $driverLines += "cmake --build $q$build$q"
  $driverLines += "if errorlevel 1 exit /b 12"
  $driverLines += "ctest --test-dir $q$build$q --output-on-failure"
  $driverLines += "if errorlevel 1 exit /b 13"
  $driverLines += "exit /b 0"
  Set-Content -Path $driver -Value $driverLines -Encoding ASCII

  & cmd /c "$q$driver$q"
  switch ($LASTEXITCODE) {
    0  { }
    11 { throw "cmake configure failed" }
    12 { throw "build failed" }
    13 { throw "ctest failed" }
    default { throw "clone check driver failed with $LASTEXITCODE" }
  }

  Write-Host "FRESH CLONE CLOSURE: OK"
}
finally {
  Pop-Location
}
