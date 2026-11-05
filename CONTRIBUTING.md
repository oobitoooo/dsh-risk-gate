# 贡献指南

## 环境

- Node ≥ 18（不需要 npm 依赖，全部用内置模块）
- DSH Desktop 或 `dsh web`（真机验证需要；纯规则开发不需要）

```sh
node --check lib/index.js     # 语法
node test/smoke.mjs           # 逻辑回归，假 ctx，不启动 DSH
node scripts/livecheck.mjs    # 用本机 policy.json 跑样例（没有就用内置默认）
node scripts/pack.mjs         # 打 tgz（无需 npm）
```

Windows 上另有 `scripts\verify.ps1`（四层接线体检）、`scripts\status.ps1`、`scripts\install.ps1`。

## 改规则的原则

1. **只判动作，不判提及**。一条规则应该匹配「要做的事」，不要匹配「文本里出现了某个词」。
   反例（1.0.0 的坑）：`\bssh\b` 会命中 `.ssh` 路径和文档里的 “SSH”；`\bhosts\b` 会命中 `Select-String hosts`。
   正例：`(^|[;&|])\s*ssh\s`（命令位置）、`(set-content|...)[^\n]*hosts`（写入动词 + 目标）。
2. **优先解析操作数**。删除类动作用 `deleteTargets()` 取操作数再判断，不要扫全命令。
3. **误报优先于漏报**，但误报必须可解释、可通过 `policy.json` 关掉。
4. 新规则要给 `test/smoke.mjs` 加两条：一条该拦、一条不该拦。

## 提交

- 一个 PR 一件事；提交信息用英文短句（`fix(r9): …`、`feat(rules): …`）
- 改行为要同步 `CHANGELOG.md`
- 版本号：规则/文档小改 `x.y.z+1`；新增规则或改确认协议 `x.y+1.0`；破坏性变更（改 `policy.json` 结构、去掉 `risk_gate` 工具）`x+1.0.0`
- 发版三步：改 `package.json` → 改 `CHANGELOG.md` → `node scripts/pack.mjs`，然后在 GitHub 建 Release 并上传 tgz

## 报告问题

用 `bug_report` 模板，附：

- 操作系统 / DSH 版本 / 本插件版本（`risk_gate status` 或 `scripts\status.ps1` 输出）
- 触发规则的那条工具调用（脱敏）
- `~/.dsh/risk-gate/audit.jsonl` 对应几行

不要贴真实令牌、`.env`、内网地址。
