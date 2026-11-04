# Changelog

All notable changes to this project. Format loosely follows Keep a Changelog; versions are semver.

## [1.0.1] — 2026-11-04

修两处误报（都是「读操作/正文提及被当成高危动作」）：

### Fixed

- **R3 把读取 hosts 当成写入**：原来只要命令里出现 `drivers\etc\hosts` 就拦，连 `Select-String`、`Get-Content` 都算。现在只有写入动词（`>`, `>>`, `Set-Content`, `Add-Content`, `Out-File`, `Copy-Item`, `Move-Item`, `Remove-Item`, `New-Item`, `Rename-Item`）后面跟 hosts 才拦。
- **R5 把任意正文里的 ssh 当成外连**：`\bssh\b` 会命中 `.ssh` 路径和“SSH 私钥”这类说明文字。现在要求出现在**命令位置**（行首或 `;` / `&` / `|` 之后）才算。
- **R5 把只读 REST 调用当成外发**：裸 `Invoke-RestMethod`（默认 GET）也被拦。现在只有带 `-Method POST/PUT/DELETE/PATCH` 或 `-Body` 才算外发。

回归：`smoke 33/33`、`livecheck 20/20`。

## [1.0.0] — 2026-11-04

首个可发布版本。

### Added

- `tools/pre-execute` 高危拦截 + `ctx.tools.guard()` 单调兜底，双门并存。
- 一次性确认编号：从用户消息读取，10 分钟过期，同命令重试复用编号。
- 默认 8 条规则（R1–R8）+ 关键路径保护（R9），覆盖删除、远端写入、系统配置、全局安装、外发、下载执行、强杀提权、代码起子进程。
- `policy.json` 热读配置：规则、保护路径、白名单、TTL、递归删除例外。
- 状态持久化：`pending.json`、`last-user.json`、`audit.jsonl`（2 MB 轮转）、`boot.log`。
- `risk_gate` 工具：`status / rules / pending / selftest / audit`。
- 系统提示段（插件自带），与 `AGENTS.md` 冗余，预设排除注入时仍然生效。
- 脚本：`install.ps1` / `uninstall.ps1` / `verify.ps1` / `status.ps1` / `livecheck.mjs` / `pack.mjs` / `set-repo.ps1`。
- 回归测试 33 条（假 ctx，不启动 DSH）。

### Fixed

- **guard 二次拒绝**：同一 dispatch 里 `pre-execute` 放行后，`guard` 因待确认项已被消费而重新发编号并拦截，导致「确认了也执行不了」。改为 `WeakSet` 记账，同一次调用只判一次。
- **确认状态不耐重载**：插件热重载/宿主重启后编号与用户消息丢失。改为落盘并在启动时恢复。
- **R1 过宽**：单文件 `Remove-Item -Force` 也被拦。改为只拦递归删除，关键路径另行判定。
- **链式绕过**：`git status; rm -rf .\src` 曾被误当成「工作区内小目录」放行。链式拼接现在不享受例外。
- 相对路径解析使用工具调用的 `workdir` 而非宿主 `process.cwd()`（宿主 cwd 不是用户工作区）。
