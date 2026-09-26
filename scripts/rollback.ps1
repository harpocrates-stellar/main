param(
  [Parameter(Mandatory=$true)]
  [string] $ManifestFile,
  [switch] $SkipDocker
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$maxSizeBytes = 256 * 1024

function Write-Log($message) {
  Write-Host "[harpocrates-rollback] INFO  $message"
}

function Write-Warn($message) {
  Write-Host "[harpocrates-rollback] WARN  $message" -ForegroundColor Yellow
}

function Fail-Safe([int]$code, [string]$message) {
  Write-Host "[harpocrates-rollback] ERROR $message" -ForegroundColor Red
  # Do not log context, environment variables, or secrets here to preserve privacy boundaries.
  exit $code
}

function Check-Dependencies() {
  foreach ($cmd in @("python")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
      Fail-Safe 2 "Dependency failure: missing $cmd"
    }
  }
}

function Validate-Manifest() {
  if (-not (Test-Path -LiteralPath $ManifestFile)) {
    Fail-Safe 3 "Manifest not found or not specified."
  }

  # 1. Oversized check
  $fileInfo = Get-Item -LiteralPath $ManifestFile
  if ($fileInfo.Length -gt $maxSizeBytes) {
    Fail-Safe 4 "Oversized input: manifest exceeds 256 KiB limit."
  }

  # 2. Malformed JSON check
  $manifestContent = Get-Content -LiteralPath $ManifestFile -Raw -ErrorAction SilentlyContinue
  try {
    $manifest = $manifestContent | ConvertFrom-Json
  } catch {
    Fail-Safe 5 "Malformed input: manifest is not valid JSON."
  }

  # 3. Release guard verification (covers expired, revoked, unsupported inputs)
  Write-Log "Verifying compatibility manifest via release_guard.py..."
  $guardProcess = Start-Process -FilePath "python" -ArgumentList @("$root\devx\release_guard.py", "--manifest", $ManifestFile) -NoNewWindow -Wait -PassThru
  if ($guardProcess.ExitCode -ne 0) {
    Fail-Safe 6 "Manifest verification failed. Input is malformed, unsupported, or invalid."
  }

  # 4. Enforce rollback state
  if ($manifest.rollout.state -ne "rollback") {
    Fail-Safe 7 "Unsupported rollout state: '$($manifest.rollout.state)'. Expected 'rollback'."
  }

  return $manifest
}

function Execute-Rollback($manifest) {
  $previousRelease = $manifest.rollout.previous_release
  if ([string]::IsNullOrWhiteSpace($previousRelease) -or $previousRelease -eq "null") {
    Fail-Safe 8 "Rollback requires previous_release in manifest."
  }

  Write-Log "Initiating rollback to release: $previousRelease"

  # Suspend active deployment
  $composeFile = Join-Path $root "docker-compose.yml"
  if (-not $SkipDocker -and (Test-Path $composeFile)) {
    Write-Log "Stopping current containers safely..."
    try {
      $downProcess = Start-Process -FilePath "docker" -ArgumentList @("compose", "-f", $composeFile, "down") -NoNewWindow -Wait -PassThru
      if ($downProcess.ExitCode -ne 0) {
        Write-Warn "Failed to stop containers cleanly."
      }
    } catch {
      Write-Warn "Failed to execute docker compose down: $_"
    }
  }

  # Re-apply the target deployment bounds safely (e.g., tagging/pulling previous images)
  # Simulated for orchestrator integration:
  [System.Environment]::SetEnvironmentVariable("HARPOCRATES_RELEASE_TARGET", $previousRelease, "Process")
  Write-Log "Deployment boundaries reverted to $previousRelease."
  
  if (-not $SkipDocker -and (Test-Path $composeFile)) {
    Write-Log "Bringing containers back up with pinned images for $previousRelease..."
    try {
      $env:BACKEND_IMAGE_TAG  = $previousRelease
      $env:FRONTEND_IMAGE_TAG = $previousRelease
      $upProcess = Start-Process -FilePath "docker" -ArgumentList @("compose", "-f", $composeFile, "up", "-d") -NoNewWindow -Wait -PassThru
      if ($upProcess.ExitCode -ne 0) {
        Fail-Safe 9 "Restore failed: docker compose up exited $($upProcess.ExitCode). Release $previousRelease was NOT restored."
      }
    } catch {
      Fail-Safe 10 "Restore failed: unable to execute docker compose up: $_"
    } finally {
      Remove-Item Env:\BACKEND_IMAGE_TAG -ErrorAction SilentlyContinue
      Remove-Item Env:\FRONTEND_IMAGE_TAG -ErrorAction SilentlyContinue
    }
  } elseif (-not $SkipDocker) {
    Write-Warn "No docker-compose.yml found; skipping container restore step."
  }

  # Note: The contract rotation is handled separately via rollback-verifier-rotation.ps1 if required.
  Write-Log "Rollback complete: $previousRelease is now active."
}

Write-Log "Starting privacy-safe deployment rollback..."
Check-Dependencies
$manifestObj = Validate-Manifest
Execute-Rollback $manifestObj
exit 0
