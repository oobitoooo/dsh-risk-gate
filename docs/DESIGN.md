# 设计说明

## 目标与前提

破甲（`dsh-purge` / purge-community）拆掉了两类摩擦：**审批**与**沙箱**。这会带来一个副作用——破坏性动作不再经过人。

本项目只补回一件事：**高危动作执行前必须由人确认**。不撤销破甲，不改宿主，不引入新的权限系统。

## 为什么不用 approval

宿主被打补丁后，`@deepseek-ai/dsh-user-approval` 的实现变成（patch #9）：

```js
if (this.effectivePolicy(session) === "never") return "allowed-once";
return "allowed-once";
```

也就是说：

| 方案 | 结果 |
|---|---|
| 在配置里把 approval 调回 `ask` | 无效：代码层直接返回 `allowed-once` |
| 发 `kind: 'ask'` 让宿主弹窗 | 无效：同上，等于自动同意 |
| 让 dsh-purge 少打 #9 / #35 | 不可维护：purge 不支持按补丁禁用，升级会重打 |
| **自己实现「问人」** | 可行：不依赖 approval 服务 |

## 实现路径

```
工具调用
  └─ tools/pre-execute（waterfall，本插件 prepend）
       ├─ 命中规则且未确认 → { kind: 'deny', reason }   ← 主闸
       └─ 否则 next()
  └─ ctx.tools.guard（同步、单调）
       └─ 同一判定再兜一次：任何监听器把 deny 翻成 allow 都会被挡回去
  └─ 宿主 dispatch
```

放行凭据：**用户消息里出现一次性编号**。

```
agent/pre-step  → 捕获 payload.messages（UserMessage[]）→ 落盘 last-user.json
tools/pre-execute → 命中规则 → 生成/复用编号 → deny（reason 里带「请回复：确认 XXXXXXXX」）
                 → 下一次调用时：若用户消息含该编号 → 放行一次 → 删除记录
```

要点：

- **编号必须来自用户消息**。模型自己写 `确认 XXXXXXXX` 不算（它读到的是 `last-user.json` 里的原文，而那段原文是用户发的）。
- **一次性**：放行后立即删除记录，重放同一条命令会重新要确认。
- **同一调用只判一次**：`pre-execute` 与 `guard` 共用同一个 `exec` 对象，用 `WeakSet` 记账，避免「第一道放行、第二道又拦」。
- **状态持久化**：`pending.json` / `last-user.json` 落盘，热重载或宿主重启后 10 分钟内仍有效。

## R1 的例外设计

递归删除太常见（清 `dist`、清 `.agent/tmp`），全拦会让人去关掉插件。所以：

- 目标必须**全部**落在 `recursiveDelete.allowRoots` 下；
- 条目数 ≤ `maxEntries`（默认 200，数到上限+1 就停，不拖慢）；
- 含 `;` `|` `&&` 拼接的命令**不享受例外**（防 `git status; rm -rf .\src` 夹带）；
- 相对路径按工具调用的 `workdir` 解析——宿主进程的 `process.cwd()` 不是用户工作区。

## 已知取舍

- **正则不是语义分析**：拦的是命令文本，绕法存在（编码、间接调用）。真正的兜底是 `guard` 单调 + `audit.jsonl` 可追，而不是"保证 100% 拦截"。
- **默认保守**：`allowRoots` 默认空（除 `DSH_WORKSPACE` 环境变量），装完即"递归删除一律要确认"，用户显式放开才省事。
- **可被本机用户拆除**：删 bundle、清空规则都行。它是护栏，不是安全边界。
