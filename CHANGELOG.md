# Changelog

All notable changes to this project. Format loosely follows Keep a Changelog; versions are semver.

## [1.3.1] — 2026-11-05

### Fixed

- **尾部截断检不出来**：checkpoint 原先每 20 行才写一次，链很短时（例如刚装完只有几行）删掉末尾几条再校验仍是 `ok: true`。现在每写一条审计就更新 `chain.checkpoint.json`，`risk_gate action=verify` 会用 `truncated` 字段报出截断。

回归：`smoke 62/62`。

## [1.3.0] — 2026-11-05

借鉴同期项目的三处设计（详见 [docs/CREDITS.md](docs/CREDITS.md)）。

### Added

- **HMAC 链式审计**（借鉴 dsh-guardwall）：`audit.jsonl` 每行带 `prev` / `h`，密钥 `chain.key`，每 20 行写 `chain.checkpoint.json`；`risk_gate action=verify` 可检出改行、换密钥、尾部截断。
- **落盘前脱敏**（借鉴 dsh-guardwall）：`ghp_` / `github_pat_` / `sk-` / `AKIA` / `Bearer` / `password=` 等替换为占位符，命令里的凭据不会原样进日志。
- **风险分级 + 阈值**（借鉴 dsh-guardwall 的 block/warn 与 dsh-approval-gate 的分级思路）：规则支持 `risk: 1–10`，`thresholds.block`（默认 7）/`thresholds.warn`（默认 4）；未达 block 的只写 `warn`/`observe` 不拦。
- `risk_gate status` 增加 `thresholds` / `chainHead`；新增 `action=verify`。

### Docs

- 新增 `docs/CREDITS.md`，README 增加「致谢」；写明借鉴了谁、借了什么，以及**没借鉴什么及原因**（模型预判、确认制学习）。

### 未采纳

- 用模型预判「安全/危险」（dsh-approval-gate 的做法）：破甲环境下模型在环里，不应同时当裁判。
- 「同一操作确认 N 次后自动放行」：与一次性编号语义冲突；改用显式「授权 N 分钟」。

回归：`smoke 61/61`（新增 9 条：脱敏、链校验、篡改检出、错密钥、风险分级）、`livecheck 20/20`。

## [1.2.2] — 2026-11-05

修 R2 的**结构性漏拦**：正则只认字面量 `git push`，而实际使用的 `& $git -C … push` 一次都没命中（审计里 R2 计数长期为 0）。

### Fixed

- 新增词法层 `looksLikeGitPush()`：切 token → 找 `git` / `git.exe` / `$变量` → 跳过带值选项（`-C` `-c` `--git-dir` …）→ 下一个裸词是 `push` 即命中。覆盖 `& $git … push`、`git.exe … push`、`$g push`、`git --no-pager push`。
- R2 正则补 `(^|[;&|])\s*push\s+(?:-u\s+)?(?:origin|upstream)\b`（命令位置的裸 push），flags 改为 `im`。
- **没有**采用「`& $var … push` 一律命中」的宽正则：实测会把 `& $node x.mjs | Select-String -Pattern "…push"` 误拦。

回归：`smoke 52/52`（新增 6 条 R2 正反例）、`livecheck 20/20`。

## [1.2.1] — 2026-11-05

同步发布：把仓库里的文档修正（`docs/PUBLISH.md` 的资产上传坑、tag 挪动说明）打进发行包，并修掉一处审计噪音。

### Fixed

- 同一条用户消息会经 `agent/pre-step` 与 `agent/inbox/inserted` 各触发一次，导致「授权」审计写两行。现在 2 秒内同文本只处理一次。

回归：`smoke 46/46`、`livecheck 20/20`。

## [1.2.0] — 2026-11-05

### Added

- **授权窗口（批量确认）**：用户回一句「授权 30 分钟」，窗口内高危操作直接放行，不再逐条要编号；上限 120 分钟，「取消授权」立即关闭。窗口内每次放行仍写 `audit.jsonl`（`decision: allow-by-grant` + 剩余分钟），`risk_gate status` 能看到剩余时长。
- 系统提示段同步说明：批量任务应先向用户说明要做的几件事，再请一句授权。
- `docs/social-preview.svg` / `.png`（1280×640）。

### Fixed

- R5 补上 `curl -F` / `--form`：同样是带 body 的 multipart 上传，此前不在外发规则里。
- 授权解析用 `(?![a-z0-9])` 而不是 `\b`：中文后面没有 ASCII 词边界，`\b` 会导致「授权 5 分钟」解析失败。

回归：`smoke 45/45`、`livecheck 20/20`。

## [1.1.1] — 2026-11-05

文档与可用性补齐，外加两处**误拦**修正。

### Fixed

- **here-string 里的字面文本不再参与规则匹配**：发布说明、文档片段里常出现示例命令（如 `dsh plugin add …`、`Remove-Item -Recurse …`），原先会被当成真动作误拦。现在按 PowerShell 的真实语法逐行解析，把 `@"…"@` / `@'…'@` 整段替换成占位符再匹配。
- **正文里的字面量 `@"…"@` 不再让 here-string 提前闭合**：第一版用一条正则一把梭，遇到“文档里写了 `@"…"@` 这个语法”就会在那里闭合，后半段内容漏出来继续被当成命令（真实踩过）。现在只有**单独一行**的 `"@` / `'@` 才算结束。
- 普通引号**不**剥离：`powershell -Command "Remove-Item -Recurse …"` 里层仍然会被拦。

### Added

- `docs/FAQ.md`：破甲为什么让审批失效、编号是不是密码、误拦怎么办、怎么彻底关掉、token 开销。
- `docs/banner.svg` + README 徽章（CI / release / license / node）。
- `examples/policy.strict.json`（递归删除一律确认、5 分钟过期）与 `examples/policy.relaxed.json`（`useWorkdirAsRoot`、500 条目上限）。
- `.github/ISSUE_TEMPLATE/bug_report.yml`、`config.yml`、`PULL_REQUEST_TEMPLATE.md`。
- `CONTRIBUTING.md`：改规则三条原则（只判操作数、不判提及、误报必须可关）、测试与发版流程。
- README 增加「文档」索引；安装命令改用 `latest/download`。

### Changed

- npm 包内新增 `examples/`、`CONTRIBUTING.md`、`docs/`（此前 docs 只在仓库里）。

回归：`smoke 39/39`、`livecheck 20/20`。

## [1.0.2] — 2026-11-04

### Fixed

- **R9 只看删除目标**：原来只要命令里出现 `C:\Program Files\…`、`C:\Windows\…` 这类路径，并且同一个命令里有任何删除动作，就整条判高危——哪怕那只是 `& "C:\Program Files\Git\cmd\git.exe" …` 在调用程序。现在新增 `deleteTargets()`，只解析 `Remove-Item / rm / del / rmdir / rd` 后面的**操作数**，再判断它是否落在保护路径里。
- 连带修正：R1 的「工作区内小目录免确认」也改用同一套删除目标解析，避免路过的路径被误当成删除目标。

回归：`smoke 36/36`（新增 3 条：删临时文件+引用 Program Files 的 git、只调用 Program Files、删 Program Files 里的文件）、`livecheck 20/20`。

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
