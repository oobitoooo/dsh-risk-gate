# ============================================================================
# dsh-risk-gate 安装 / 修复脚本（幂等，可重复跑）
#   1) 在 desktop profile 的 package.json 里登记 link: 依赖与 bundle 条目
#   2) 在 profile 的 node_modules 建 junction
#   3) 在 profile 的 cordis.patch.yml 里补 hooksDenyBypass: false（可关）
#   4) 校验 JSON，失败自动回滚
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Profile web
# 改完需要重启 DSH 桌面端（关托盘图标再开）。
# ============================================================================
param(
  [string]$Profile = 'desktop',
  [switch]$SkipHooksOverride
)

$ErrorActionPreference = 'Stop'
$pluginDir = Split-Path -Parent $PSScriptRoot
$pluginName = 'dsh-risk-gate'
$homeDir = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$profileDir = Join-Path $homeDir "profiles\$Profile"
$pkgPath = Join-Path $profileDir 'package.json'
$patchPath = Join-Path $profileDir 'cordis.patch.yml'
$nodeModules = Join-Path $profileDir 'node_modules'
$linkPath = Join-Path $nodeModules $pluginName

function Write-Step($text) { Write-Host "[risk-gate] $text" }

if (-not (Test-Path $pkgPath)) {
  throw "找不到 profile：$pkgPath（先用桌面端打开一次 DSH，或指定 -Profile）"
}

# ---------------------------------------------------------------- 备份
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "$pkgPath.bak-risk-gate-$stamp"
Copy-Item $pkgPath $backup -Force
Write-Step "已备份 package.json -> $backup"

# ---------------------------------------------------------------- 改 package.json
$raw = [IO.File]::ReadAllText($pkgPath, [Text.Encoding]::UTF8)
$pkg = $raw | ConvertFrom-Json

$linkTarget = 'link:' + ($pluginDir -replace '\\', '/')
if (-not $pkg.dependencies.PSObject.Properties[$pluginName]) {
  $pkg.dependencies | Add-Member -NotePropertyName $pluginName -NotePropertyValue $linkTarget
  Write-Step "dependencies += $pluginName : $linkTarget"
} elseif ($pkg.dependencies.$pluginName -ne $linkTarget) {
  $pkg.dependencies.$pluginName = $linkTarget
  Write-Step "dependencies[$pluginName] 更新为 $linkTarget"
} else {
  Write-Step "dependencies[$pluginName] 已存在，跳过"
}

$bundles = @($pkg.dsh.profile.bundles)
if ($bundles -notcontains $pluginName) {
  $pkg.dsh.profile.bundles = @($bundles + $pluginName)
  Write-Step "bundles += $pluginName"
} else {
  Write-Step "bundles 已包含 $pluginName，跳过"
}

# 先写临时文件并回读校验，通过后再替换，避免写坏 profile 让宿主起不来
$tmp = "$pkgPath.risk-gate.tmp"
$json = $pkg | ConvertTo-Json -Depth 32
[IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
try {
  $check = [IO.File]::ReadAllText($tmp, [Text.Encoding]::UTF8) | ConvertFrom-Json
  if (-not $check.dsh.profile.bundles.Contains($pluginName)) { throw 'bundles 校验失败' }
} catch {
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  Copy-Item $backup $pkgPath -Force
  throw "package.json 写入校验失败，已回滚：$($_.Exception.Message)"
}
Move-Item $tmp $pkgPath -Force
Write-Step 'package.json 已更新并通过 JSON 校验'

# ---------------------------------------------------------------- junction
if (-not (Test-Path $nodeModules)) { New-Item -ItemType Directory -Path $nodeModules | Out-Null }
if (Test-Path $linkPath) {
  $item = Get-Item $linkPath -Force
  if ($item.LinkType -eq 'Junction' -and $item.Target -ne $pluginDir) {
    Remove-Item $linkPath -Force
    New-Item -ItemType Junction -Path $linkPath -Target $pluginDir | Out-Null
    Write-Step "junction 已重建 -> $pluginDir"
  } else {
    Write-Step 'junction 已存在，跳过'
  }
} else {
  New-Item -ItemType Junction -Path $linkPath -Target $pluginDir | Out-Null
  Write-Step "junction 已创建 -> $pluginDir"
}

# ---------------------------------------------------------------- hooksDenyBypass
# 只有在装了 dsh-purge 时才有意义：它的 bundle 默认 hooksDenyBypass: true。
$hasPurge = (@($pkg.dependencies.PSObject.Properties.Name) -match '^dsh-purge') -or
            (@($pkg.dsh.profile.bundles) -match '^dsh-purge')
if (-not $SkipHooksOverride -and $hasPurge -and (Test-Path $patchPath)) {
  $text = [IO.File]::ReadAllText($patchPath, [Text.Encoding]::UTF8)
  if ($text -notmatch 'hooksDenyBypass:\s*false') {
    $block = @"

# dsh-risk-gate: 让 hooks 类插件的 deny 真正生效（覆盖 dsh-purge bundle 里的 hooksDenyBypass: true）
- id: dsh-purge
  config:
    hooksDenyBypass: false
"@
    Copy-Item $patchPath "$patchPath.bak-risk-gate-$stamp" -Force
    [IO.File]::WriteAllText($patchPath, $text.TrimEnd() + $block + "`r`n", (New-Object Text.UTF8Encoding($false)))
    Write-Step 'cordis.patch.yml += dsh-purge.hooksDenyBypass: false'
  } else {
    Write-Step 'hooksDenyBypass 覆盖已存在，跳过'
  }
} elseif (-not $hasPurge) {
  Write-Step '未检测到 dsh-purge，跳过 hooksDenyBypass 覆盖'
}

# ---------------------------------------------------------------- 结果
Write-Host ''
Write-Step '安装完成。当前状态：'
Write-Host ("  plugin   : " + $pluginDir)
Write-Host ("  profile  : " + $profileDir)
Write-Host ("  link     : " + $linkPath)
Write-Host ''
Write-Host '下一步：'
Write-Host '  1) 完全退出 DSH 桌面端（含托盘图标），重新打开'
Write-Host '  2) 新会话里让我跑 risk_gate status 确认闸门已装载'
Write-Host '  3) 规则改 %USERPROFILE%\.dsh\risk-gate\policy.json，保存即生效，不用重启'
