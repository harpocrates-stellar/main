$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$rollbackScript = Join-Path $root "scripts\rollback.ps1"
$tmpDir = Join-Path $root "tmp\rollback_test_$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

function Write-TestLog($message) {
  Write-Host "[test] $message" -ForegroundColor Cyan
}
function Fail-Test($message) {
  Write-Host "[test] ERROR: $message" -ForegroundColor Red
  Remove-Item -Recurse -Force $tmpDir
  exit 1
}

$baseManifest = Join-Path $root "release\compatibility-manifest.json"
$validManifest = Join-Path $tmpDir "valid_rollback.json"

$manifestData = Get-Content -Raw $baseManifest | ConvertFrom-Json
$manifestData.rollout.state = "rollback"
$manifestData.rollout.previous_release = "harpocrates-0.9.0"
$manifestData | ConvertTo-Json -Depth 10 | Set-Content $validManifest

Write-TestLog "1. Positive: valid rollback manifest"
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", $validManifest, "-SkipDocker") -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) { Fail-Test "Failed on valid rollback manifest" }

Write-TestLog "2. Negative: missing file"
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", "$tmpDir\nonexistent.json") -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -eq 0) { Fail-Test "Should have failed on missing file" }

Write-TestLog "3. Negative (Malformed): invalid JSON"
$malformed = Join-Path $tmpDir "malformed.json"
"{ invalid json" | Set-Content $malformed
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", $malformed) -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -eq 0) { Fail-Test "Should have failed on malformed JSON" }

Write-TestLog "4. Boundary (Oversized): manifest > 256 KiB"
$oversized = Join-Path $tmpDir "oversized.json"
Copy-Item $validManifest $oversized
$padding = New-Object byte[] (257 * 1024)
[io.file]::OpenWrite($oversized).Write($padding, 0, $padding.Length)
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", $oversized) -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -eq 0) { Fail-Test "Should have failed on oversized manifest" }

Write-TestLog "5. Negative (Unsupported state): rollout.state != rollback"
$unsupported = Join-Path $tmpDir "unsupported.json"
$manifestData.rollout.state = "active"
$manifestData | ConvertTo-Json -Depth 10 | Set-Content $unsupported
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", $unsupported) -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -eq 0) { Fail-Test "Should have failed on unsupported state" }

Write-TestLog "6. Negative (Missing previous_release)"
$noPrev = Join-Path $tmpDir "no_prev.json"
$manifestData.rollout.state = "rollback"
$manifestData.rollout.previous_release = $null
$manifestData | ConvertTo-Json -Depth 10 | Set-Content $noPrev
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", $noPrev) -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -eq 0) { Fail-Test "Should have failed on missing previous_release" }

Write-TestLog "7. Negative: failed restore exits non-zero"
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $rollbackScript, "-ManifestFile", $validManifest) -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -eq 0) { Fail-Test "Should have failed on missing docker" }

Write-TestLog "All tests passed successfully!"
Remove-Item -Recurse -Force $tmpDir
exit 0
