# ============================================================================
# 把仓库里的 USER/dsh-risk-gate 占位符换成你的 GitHub 账号
#   powershell -ExecutionPolicy Bypass -File scripts\set-repo.ps1 -Owner your-name
# ============================================================================
param(
  [Parameter(Mandatory = $true)][string]$Owner
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$targets = @(
  (Join-Path $root 'package.json'),
  (Join-Path $root 'README.md'),
  (Join-Path $root 'README.en.md')
)

$changed = 0
foreach ($file in $targets) {
  if (-not (Test-Path $file)) { continue }
  $text = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8)
  $next = $text.Replace('USER/dsh-risk-gate', "$Owner/dsh-risk-gate")
  if ($next -ne $text) {
    [IO.File]::WriteAllText($file, $next, (New-Object Text.UTF8Encoding($false)))
    Write-Host "[set-repo] 已更新 $file"
    $changed += 1
  } else {
    Write-Host "[set-repo] 无需改动 $file"
  }
}

if ($changed -eq 0) {
  Write-Host '[set-repo] 没有找到 USER/dsh-risk-gate 占位符（可能已经改过）。'
} else {
  Write-Host "[set-repo] 完成，owner = $Owner。记得复核 git diff 再提交。"
}
