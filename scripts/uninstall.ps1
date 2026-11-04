# ============================================================================
# dsh-risk-gate 卸载脚本：只摘掉本插件，不碰 dsh-purge 与其它插件。
#   powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1
# ============================================================================
param([string]$Profile = 'desktop')

$ErrorActionPreference = 'Stop'
$pluginName = 'dsh-risk-gate'
$homeDir = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$profileDir = Join-Path $homeDir "profiles\$Profile"
$pkgPath = Join-Path $profileDir 'package.json'
$linkPath = Join-Path $profileDir "node_modules\$pluginName"

if (-not (Test-Path $pkgPath)) { throw "找不到 profile：$pkgPath" }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Copy-Item $pkgPath "$pkgPath.bak-risk-gate-$stamp" -Force

$raw = [IO.File]::ReadAllText($pkgPath, [Text.Encoding]::UTF8)
$pkg = $raw | ConvertFrom-Json
if ($pkg.dependencies.PSObject.Properties[$pluginName]) {
  $pkg.dependencies.PSObject.Properties.Remove($pluginName)
}
$pkg.dsh.profile.bundles = @(@($pkg.dsh.profile.bundles) | Where-Object { $_ -ne $pluginName })

$tmp = "$pkgPath.risk-gate.tmp"
[IO.File]::WriteAllText($tmp, ($pkg | ConvertTo-Json -Depth 32), (New-Object Text.UTF8Encoding($false)))
try {
  [IO.File]::ReadAllText($tmp, [Text.Encoding]::UTF8) | ConvertFrom-Json | Out-Null
} catch {
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  throw 'JSON 校验失败，未改动 package.json'
}
Move-Item $tmp $pkgPath -Force

if (Test-Path $linkPath) {
  $item = Get-Item $linkPath -Force
  if ($item.LinkType -eq 'Junction') { Remove-Item $linkPath -Force } else { Write-Host "[risk-gate] $linkPath 不是 junction，未删除，请手工确认" }
}

Write-Host '[risk-gate] 已从 profile 摘除。完全退出 DSH 桌面端再打开即生效。'
Write-Host '[risk-gate] 规则与审计日志保留在 %USERPROFILE%\.dsh\risk-gate\，要清就手动删这个目录。'
