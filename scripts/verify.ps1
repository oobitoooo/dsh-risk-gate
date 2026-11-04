# ============================================================================
# dsh-risk-gate 体检：一次性看清四层是否都在（不启动 DSH，只读）
#   powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
# ============================================================================
param([string]$Profile = 'desktop')

$ErrorActionPreference = 'Continue'
$ok = $true
function Check($label, $pass, $detail) {
  if ($pass) { Write-Host ("  OK   {0}  {1}" -f $label, $detail) }
  else { Write-Host ("  FAIL {0}  {1}" -f $label, $detail) -ForegroundColor Red; $script:ok = $false }
}

$pluginDir = Split-Path -Parent $PSScriptRoot
$homeDir = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$profileDir = Join-Path $homeDir "profiles\$Profile"
$pkgPath = Join-Path $profileDir 'package.json'
$linkPath = Join-Path $profileDir 'node_modules\dsh-risk-gate'
$gateDir = Join-Path $homeDir 'risk-gate'
$policyPath = Join-Path $gateDir 'policy.json'
$auditPath = Join-Path $gateDir 'audit.jsonl'

Write-Host '[1] 插件本体'
Check 'lib/index.js' (Test-Path (Join-Path $pluginDir 'lib\index.js')) $pluginDir
Check 'package.json' (Test-Path (Join-Path $pluginDir 'package.json')) ''

Write-Host '[2] profile 接线'
if (Test-Path $pkgPath) {
  $pkg = [IO.File]::ReadAllText($pkgPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
  $dep = $pkg.dependencies.'dsh-risk-gate'
  $hasBundle = @($pkg.dsh.profile.bundles) -contains 'dsh-risk-gate'
  Check 'dependencies' ([bool]$dep) "$dep"
  Check 'bundles' $hasBundle ("count=" + @($pkg.dsh.profile.bundles).Count)
} else {
  Check 'package.json' $false $pkgPath
}
$linkDetail = '缺少，跑 install.ps1'
if (Test-Path $linkPath) {
  $item = Get-Item $linkPath -Force
  $linkDetail = ($item.Target -join ',')
}
Check 'node_modules junction' (Test-Path $linkPath) $linkDetail

Write-Host '[3] 策略与日志'
if (Test-Path $policyPath) {
  try {
    $policy = [IO.File]::ReadAllText($policyPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    Check 'policy.json' $true ("rules=" + @($policy.rules).Count + " roots=" + @($policy.protectedRoots).Count + " ttl=" + $policy.ttlMs)
  } catch {
    Check 'policy.json 可解析' $false $_.Exception.Message
  }
} else {
  Check 'policy.json' $false '还没生成（首次装载时写），或跑一次 DSH 让它落盘'
}
if (Test-Path $auditPath) {
  $recent = @(Get-Content $auditPath -Encoding UTF8 -Tail 3)
  Check 'audit.jsonl' $true ((Get-Item $auditPath).Length.ToString() + ' bytes')
  $recent | ForEach-Object { Write-Host ("       " + $_) }
} else {
  Write-Host '  --   audit.jsonl 还没有（闸门尚未拦过任何调用）'
}

Write-Host '[4] 与 dsh-purge 的关系'
$purgeCfg = Join-Path $profileDir 'cordis.patch.yml'
if (Test-Path $purgeCfg) {
  $txt = [IO.File]::ReadAllText($purgeCfg, [Text.Encoding]::UTF8)
  Check 'hooksDenyBypass 覆盖' ($txt -match 'hooksDenyBypass:\s*false') 'profile 层覆盖 dsh-purge 的 true'
} else {
  Write-Host '  --   profile 无 cordis.patch.yml'
}

Write-Host ''
if ($ok) { Write-Host '结论：四层齐全。改完规则热读生效；改了 package.json/bundles 才需要重启桌面端。' }
else { Write-Host '结论：有缺失项，先跑 scripts\install.ps1，再重启桌面端。' -ForegroundColor Red }
if ($ok) { exit 0 } else { exit 1 }
