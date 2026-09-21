<#
.SYNOPSIS
  End-to-end check of the installed artifacts.

.DESCRIPTION
  Installs the project into a scratch prefix and then runs a complete fabric
  using only the installed executables: three witnesses, one registry, one
  coordinator, an offline audit of the resulting durable store, and a controlled
  shutdown.

  The script waits on observable conditions (a published endpoint, an exit code)
  and never on a timer.

.PARAMETER BuildDirectory
  Existing build tree to install from. Defaults to "build".

.PARAMETER Prefix
  Install prefix. Defaults to a fresh directory under the system temp path.

.PARAMETER WorkDirectory
  Scratch directory for the run's durable state.

.PARAMETER Operations
  Number of mutations the installed coordinator attempts.
#>
[CmdletBinding()]
param(
  [string]$BuildDirectory = "build",
  [string]$Prefix = "",
  [string]$WorkDirectory = "",
  [int]$Operations = 5
)

$ErrorActionPreference = "Stop"

$repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($BuildDirectory)) {
  $BuildDirectory = Join-Path $repository $BuildDirectory
}
if ([string]::IsNullOrEmpty($Prefix)) {
  $Prefix = Join-Path ([System.IO.Path]::GetTempPath()) ("sbf-prefix-" + [guid]::NewGuid().ToString("N"))
}
if ([string]::IsNullOrEmpty($WorkDirectory)) {
  $WorkDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("sbf-installed-run-" + [guid]::NewGuid().ToString("N"))
}

$bin = Join-Path $Prefix "bin"
$tools = @{
  ctl         = Join-Path $bin "sbfctl.exe"
  registry    = Join-Path $bin "sbf-registry.exe"
  witness     = Join-Path $bin "sbf-witness.exe"
  coordinator = Join-Path $bin "sbf-coordinator.exe"
}

Write-Host "build directory : $BuildDirectory"
Write-Host "install prefix  : $Prefix"
Write-Host "work directory  : $WorkDirectory"

if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
if (Test-Path $WorkDirectory) { Remove-Item -Recurse -Force $WorkDirectory }
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null

Write-Host "===== install ====="
& cmake --install $BuildDirectory --prefix $Prefix
if ($LASTEXITCODE -ne 0) { throw "cmake --install failed" }

foreach ($tool in $tools.Values) {
  if (-not (Test-Path $tool)) { throw "installed tool missing: $tool" }
}
if (-not (Test-Path (Join-Path $Prefix "lib/cmake/SplitBrainFabric/SplitBrainFabricConfig.cmake"))) {
  throw "installed package config missing"
}

Write-Host "===== installed executables report their version ====="
foreach ($tool in $tools.Values) {
  # sbfctl takes a subcommand; the service tools take --version.
  if ((Split-Path $tool -Leaf) -eq "sbfctl.exe") { $version = & $tool version }
  else { $version = & $tool --version }
  if ($LASTEXITCODE -ne 0) { throw "$tool failed to report its version" }
  Write-Host ("  {0}: {1}" -f (Split-Path $tool -Leaf), $version)
}

function Wait-ForEndpoint {
  param([string]$AnnouncePath, [System.Diagnostics.Process]$Process)
  while ($true) {
    if (Test-Path $AnnouncePath) {
      $text = Get-Content $AnnouncePath -Raw -ErrorAction SilentlyContinue
      if (-not [string]::IsNullOrWhiteSpace($text)) {
        return ($text -split [char]10)[0].Trim()
      }
    }
    if ($Process.HasExited) { throw "process exited before publishing $AnnouncePath" }
    Start-Sleep -Milliseconds 20
  }
}

$started = @()
try {
  Write-Host "===== start three witnesses ====="
  $witnessEndpoints = @()
  for ($i = 0; $i -lt 3; $i++) {
    $announce = Join-Path $WorkDirectory "witness-$i.announce"
    $log = Join-Path $WorkDirectory "witness-$i.log"
    $process = Start-Process -FilePath $tools.witness -PassThru -NoNewWindow -ArgumentList @(
      "--id", "witness-$i", "--fault-domain", "rack-$i", "--port", "0", "--announce", $announce
    ) -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    $started += $process
    $endpoint = Wait-ForEndpoint -AnnouncePath $announce -Process $process
    $witnessEndpoints += $endpoint
    Write-Host "  witness-$i -> $endpoint"
  }

  Write-Host "===== start the registry ====="
  $registryAnnounce = Join-Path $WorkDirectory "registry.announce"
  $registryLog = Join-Path $WorkDirectory "registry.log"
  $registryArgs = @("--dir", (Join-Path $WorkDirectory "state"), "--store", "installed-store",
                    "--node", "registry-1", "--port", "0", "--announce", $registryAnnounce,
                    "--quorum", "threshold:2",
                    "--define", "domain-a:coordinator-a:fabric-policy:port-1,port-2")
  for ($i = 0; $i -lt 3; $i++) {
    # $($i) rather than $i: a bare "-$i:" would be read as a drive-qualified
    # variable reference and silently expand to nothing.
    $registryArgs += @("--witness", "witness-$($i):rack-$($i)@$($witnessEndpoints[$i])")
  }
  $registry = Start-Process -FilePath $tools.registry -PassThru -NoNewWindow -ArgumentList $registryArgs -RedirectStandardOutput $registryLog -RedirectStandardError "$registryLog.err"
  $started += $registry
  $registryEndpoint = Wait-ForEndpoint -AnnouncePath $registryAnnounce -Process $registry
  Write-Host "  registry -> $registryEndpoint"

  Write-Host "===== run a coordinator against the installed services ====="
  $coordinatorArgs = @("--node", "coordinator-a", "--domain", "domain-a",
                       "--scope", "port-1,port-2", "--registry", $registryEndpoint,
                       "--ops", "$Operations", "--operation", "switch-port")
  for ($i = 0; $i -lt 3; $i++) {
    $coordinatorArgs += @("--witness-target", "witness-$($i):rack-$($i)@$($witnessEndpoints[$i])")
  }
  $report = & $tools.coordinator @coordinatorArgs
  Write-Host "  $report"
  if ($LASTEXITCODE -ne 0) { throw "installed coordinator failed" }
  if ($report -notmatch "applied=$Operations") {
    throw "expected $Operations applied mutations, got: $report"
  }

  Write-Host "===== offline audit of the durable store ====="
  $audit = & $tools.ctl audit --dir (Join-Path $WorkDirectory "state") --store installed-store
  $audit | ForEach-Object { Write-Host "  $_" }
  if ($LASTEXITCODE -ne 0) { throw "offline audit failed" }
  # Join first: a PowerShell array compared with -match tests each element.
  $auditText = $audit -join [char]10
  if ($auditText -notmatch "AUDIT OK") { throw "offline audit did not report OK" }
  if ($auditText -notmatch "mutually_exclusive=1") { throw "effect history is not mutually exclusive" }
  if ($auditText -notmatch "fence_escapes=0") { throw "the effect history contains a fence escape" }

  Write-Host "===== controlled shutdown ====="
  & $tools.ctl shutdown --registry $registryEndpoint --node operator
  if ($LASTEXITCODE -ne 0) { throw "shutdown request failed" }
  $registry.WaitForExit()
  if ($registry.ExitCode -ne 0) { throw "registry exited with $($registry.ExitCode)" }

  Write-Host "INSTALLED ARTIFACT CHECK: OK"
}
finally {
  foreach ($process in $started) {
    if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
  }
}
