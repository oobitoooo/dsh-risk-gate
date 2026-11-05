# FAQ

## 为什么要这个插件？破甲不是已经能干活了吗？

能干活，但**没人踩刹车**。`dsh-purge` 把审批拆了（patch #9 让每次审批请求直接 `allowed-once`），沙箱默认全开，拒绝话术中性化。结果是 `git push`、`Remove-Item -Recurse`、改注册表、装全局包、对外发数据这类动作不再经过任何人。

本插件不撤销破甲，只在**高危动作**前加一道机械闸：命中规则 → 宿主 `deny` → 模型把一次性编号转给你 → 你回编号 → 同一条调用放行一次。

## 为什么不直接让宿主弹审批框？

因为弹框已经被补丁焊死了。宿主被打补丁后的代码是：

```js
if (this.effectivePolicy(session) === "never") return "allowed-once";
return "allowed-once";
```

发 `kind: 'ask'` 等于自动同意；把 `policy.json` 的 approval 改回 `ask` 也没用；让 purge 少打 #9 不支持，升级还会重打。所以本插件**不调用 approval 服务**，自己实现「问人」。

## 编号是密码吗？能被伪造吗？

不是密码，是**人肉令牌**。

- 编号由插件生成（8 位十六进制），只对**那一条命令**有效、一次性、默认 10 分钟过期；
- 放行条件是「**用户消息**里出现这个编号」——模型自己写 `确认 XXXXXXXX` 不算（它读的是你的消息原文）；
- 能读你聊天记录的人当然能替你确认——这不是密码学签名，是「确认这一步确实由人做了」的凭证。

## 它能防住所有破坏性操作吗？

不能。它拦的是**工具调用参数**，不是意图：

- `python -c "print(1)"` 放行；`python -c "import os; os.system('rm -rf /')"` 会被 R8 拦；
- 正则存在误报（宁可多问）与漏报（编码、间接调用、别名）；
- 真正的兜底是 `ctx.tools.guard()` 的单调性（后续监听器无法把 deny 翻成 allow）+ `audit.jsonl` 可追溯。

## 为什么我的正常命令被拦了？

最常见的三类误报（1.0.x 已修）：

| 现象 | 原因 | 修法 |
|---|---|---|
| 只读 API / REST 调用被拦 | R5 把裸 `Invoke-RestMethod` 当外发 | 1.0.1：只有带 `-Method POST/PUT/DELETE` 或 `-Body` 才算 |
| 命令里提到 `ssh`、`.ssh` 被拦 | R5 用 `\bssh\b` 匹配任意文本 | 1.0.1：必须出现在命令位置 |
| 调用 `C:\Program Files\Git\git.exe` 又被判「动关键路径」 | R9 扫全命令里出现的路径 | 1.0.2：只看 `Remove-Item` 等动词的**操作数** |

还误报就改 `policy.json`（热读），别忍着。

## 递归删除为什么有时不问我？

R1 有例外：目标在 `recursiveDelete.allowRoots` 里、且条目数 ≤ `maxEntries`（默认 200）时直接放行。带 `;` `|` `&&` 拼接的命令**不享受**这个例外。

默认 `allowRoots` 为空（除非设了 `DSH_WORKSPACE`），所以装完是「递归删除一律要问」；想省事就把工作区路径写进去。

## 怎么彻底关掉？

任选其一：

- `powershell -File scripts\uninstall.ps1`（只摘插件）
- 从 profile 的 `package.json` 的 `dsh.profile.bundles` 里删掉 `"dsh-risk-gate"` 并重启
- 把 `policy.json` 的 `rules` 清空（不推荐：等于只留个空壳）

## 会影响 token 消耗吗？

会。插件注入一段约 500 字的系统提示（协议说明），并在每次工具调用前做一次正则匹配。相比破甲本身的 2 万字符注入，这点开销可以忽略；正则匹配是纯字符串操作，没有网络调用。
