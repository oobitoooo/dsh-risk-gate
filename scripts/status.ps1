# ============================================================================
# dsh-risk-gate 运行状态（只读）：策略 / 审计 / 待确认 / 启动埋点 / 活规则自检
#   powershell -ExecutionPolicy Bypass -File scripts\status.ps1
# ============================================================================
$ErrorActionPreference = 'Continue'
$pluginDir = Split-Path -Parent $PSScriptRoot
$homeDir = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$gateDir = Join-Path $homeDir 'risk-gate'
# node 探测：PATH → DSH 自带运行时（旧的位置因版本而异，逐个试）
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) {
  $candidates = @(
    (Join-Path $homeDir 'dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\DeepSeek Harness\resources\runtime\node\node.exe')
  )
  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) { $node = $candidate; break }
  }
}

Write-Host '=== 1. 启动埋点（最近 8 行）==='
$boot = Join-Path $gateDir 'boot.log'
if (Test-Path $boot) { Get-Content $boot -Encoding UTF8 -Tail 8 } else { Write-Host '  （无：插件还没在带埋点的版本下装载过）' }

Write-Host "`n=== 2. 策略 ==="
$policyPath = Join-Path $gateDir 'policy.json'
if (Test-Path $policyPath) {
  $p = [IO.File]::ReadAllText($policyPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
  Write-Host ("  规则 {0} 条：{1}" -f @($p.rules).Count, (($p.rules | ForEach-Object { $_.id + ':' + $_.label }) -join ' / '))
  Write-Host ("  保护路径 {0} 个 | 白名单 {1} 条 | 确认有效期 {2} 分钟" -f @($p.protectedRoots).Count, @($p.allow).Count, [int]($p.ttlMs / 60000))
} else { Write-Host '  policy.json 不存在' }

Write-Host "`n=== 3. 审计（最近 5 条）==="
$audit = Join-Path $gateDir 'audit.jsonl'
if (Test-Path $audit) {
  Write-Host ("  文件 {0} bytes" -f (Get-Item $audit).Length)
  Get-Content $audit -Encoding UTF8 -Tail 5 | ForEach-Object { Write-Host ('  ' + $_) }
} else { Write-Host '  （还没有拦截记录）' }

Write-Host "`n=== 4. 待确认 ==="
$pendingPath = Join-Path $gateDir 'pending.json'
if (Test-Path $pendingPath) {
  $pend = [IO.File]::ReadAllText($pendingPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
  $names = @($pend.PSObject.Properties.Name)
  if ($names.Count -eq 0) { Write-Host '  无' }
  else { $names | ForEach-Object { $v = $pend.$_; Write-Host ("  {0}  {1}  {2}" -f $v.code, $v.ruleId, $v.summary) } }
} else { Write-Host '  无' }

Write-Host "`n=== 5. 活规则自检（用当前 policy.json 跑样例）==="
if (-not $node) {
  Write-Host '  找不到 node，跳过自检（装一个 Node ≥18 或从 DSH 目录运行）'
  exit 0
}
& $node (Join-Path $pluginDir 'scripts\livecheck.mjs')
$code = $LASTEXITCODE
Write-Host ''
if ($code -eq 0) { Write-Host '结论：闸门在线，规则按预期分类。' } else { Write-Host '结论：有样例与预期不符，检查 policy.json。' -ForegroundColor Red }
exit $code
