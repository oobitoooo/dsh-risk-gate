# 兼容性

## 已验证组合

| 组件 | 版本 | 结果 |
|---|---|---|
| DSH Desktop | 0.2.1-rc.5 | ✅ 装机运行，`pre-execute` / `guard` / `systemPrompt.section` / `tools.register` 全部生效 |
| dsh-purge-community | 1.6.69 | ✅ 补丁全部保留，闸门叠加在其上 |
| Node | 24.x（桌面端自带） | ✅ |
| Node | 18 / 20 / 22 | ✅ CI 矩阵 |

## 依赖的宿主接口

| 接口 | 用途 | 缺失时 |
|---|---|---|
| `ctx.on('tools/pre-execute')` | 主闸 | 闸门失效，`boot.log` 里没有 `listeners registered` |
| `ctx.tools.guard()` | 单调兜底 | 只剩主闸，被后续监听器翻案的风险回来 |
| `ctx.on('agent/pre-step')` | 读用户消息 | 永远无法确认 → 所有命中规则的动作都执行不了 |
| `ctx.systemPrompt.section()` | 固定协议段 | 提示词层少一段，机械拦截仍在 |
| `ctx.tools.register()` | `risk_gate` 自检工具 | 只能用脚本查状态 |

`boot.log` 每个阶段一行，缺哪行就说明缺哪个接口：

```
boot: apply() entered
listeners registered
guard registered
prompt section registered
risk_gate tool registered
```

## 与 dsh-purge 补丁的关系

| purge 补丁 | 影响 | 本插件对策 |
|---|---|---|
| #9 审批自动放行 | `ask` 失效 | 不用 approval，改 `deny` + 用户编号 |
| #35 升级失败不抛错 | 沙箱提权不报错 | 不依赖提权结果，按工具参数判 |
| #59 Auto Review 直通 | 官方审查不再拦工具 | 自己的 `tools/pre-execute` 独立注册 |
| #7 / #8 / #10 默认策略 | 默认全开 | 与闸门无关，闸门只看调用 |
| #3 / #16 / #17 沙箱直通 | 写盘不设边界 | R9 兜关键路径（`C:\Windows`、`resources\app`、`.ssh`） |

## 与其它插件的共存

- `dsh-purge` 的 `hooksDenyBypass`：本插件的 `install.ps1` 会在 profile 层把它覆盖成 `false`（若检测到 purge）。这与本闸门无关，是让 hooks 类插件的 deny 同样生效。
- 任务调度器 / 子代理：闸门对每个 agent 独立记账，子代理要自己拿确认，行为是"子代理被拦 → 回报给主代理 → 主代理请你确认"。
- 只读工具（`read` / `grep` / `glob` / `screen_*`）：不看，零开销。

## 已知不兼容

- 宿主版本过旧、没有 `tools/pre-execute`（0.1.x 早期）→ 闸门装不上，`boot.log` 只有第一行。
- 把插件装进 `web` profile 却在桌面端使用（或反之）：两个 profile 各自挂载，按实际启动的那个装。
