# 致谢 / Credits

本项目的核心机制（`tools/pre-execute` 拦截 + 一次性编号 + 授权窗口）是独立实现的。
下面这些项目在同期解决相邻问题，其中三处设计直接借鉴，特此致谢。

## 直接借鉴

### [dsh-guardwall](https://github.com/iiiweiii/dsh-guardwall) · 作者 iiiweiii · MIT

DSH 的「安装前体检 + 运行时护栏」，与我们的定位相邻但侧重不同（它管插件供应链与输出泄露）。

借鉴了三处：

| 借鉴点 | 在本项目里的落地 |
|---|---|
| **HMAC 链式审计 + 尾部 checkpoint** | `audit.jsonl` 每条记录带 `prev` / `h`（HMAC-SHA256，密钥在 `risk-gate/chain.key`），每 20 条写一次 `chain.checkpoint.json`；`risk_gate action=verify` 逐行重算，能发现改行、换密钥、尾部截断 |
| **风险阈值 `blockThreshold` / `warnThreshold`** | 规则支持 `risk: 1–10`，policy 里配 `thresholds.block` / `thresholds.warn`：达到 block 才拦，中间档只写 `warn`，低档只写 `observe` |
| **输出侧脱敏** | `redact()` 在落盘前抹掉 `ghp_` / `github_pat_` / `sk-` / `AKIA` / Bearer / `password=` 等，避免命令里的凭据被审计日志原样留存 |

它 README 里那句「44/51 个是静态扫描，对运行时动态构造的命令全盲」，也是我们决定坚持运行时拦截而非静态扫描的原因之一。

### [dsh-approval-gate](https://github.com/moon09300731/dsh-approval-gate) · 作者 moon09300731 · MIT

「最小人工介入」的自动审批门控：Flash 预判 + 硬风险永远转人工 + 确认制学习。

借鉴的是**分级思路**：不是所有命中规则都等价，硬风险永远要人，其余可以按风险降级。我们把它落成 `risk` 数值 + 阈值，而不是引入模型判定——

**没有采用**的部分及原因：

- 用模型预判「安全/危险」：破甲环境下模型本身就在环里，让它同时当裁判会削弱证据链；本项目坚持「确定性规则 + 用户编号」。
- 确认制学习（同一操作确认 N 次后自动放行）：与「一次性编号」语义冲突，且破甲语境下等于把闸门慢慢拆掉。我们用显式的「授权 N 分钟」替代，时间到即失效。

### [anthropics/claude-code](https://github.com/anthropics/claude-code) · PreToolUse hooks / `permissionDecision`

Claude Code 的钩子协议是 `allow | deny | ask`。其中 [issue #39344](https://github.com/anthropics/claude-code/issues/39344)（`permissionDecision: 'ask'` 会静默覆盖 `permissions.deny`）恰好验证了本项目的取舍：**`ask` 在宿主侧不可靠时，只能靠 `deny` + 一次性的用户凭据**。我们的协议因此是 `deny` 而非 `ask`。

## 同期相邻项目（未借鉴代码，仅记录）

- [dsh-auto-approve](https://github.com/DNAlec/dsh-auto-approve) · DNAlec：关键词桶 + 判定模型，allow/reject/human 三分。
- [dsh-rule-engine](https://github.com/jilian-dsh/dsh-rule-engine) · jilian：解析 AGENTS.md 硬拦、`/guard` 命令、free-zone。
- [dsh-security-guard](https://github.com/bigclawd/dsh-security-guard) · bigclawd：运行时拦截 + 白名单 + `/scan`。
- [agent-guard-for-dsh](https://github.com/mokuyoaxis/agent-guard) · mokuyoaxis：文件/Git 操作的可恢复快照——「执行前留可回滚快照」这个方向我们还没做，记在路线图里。

## 上游

- [dsh-purge / purge-community](https://github.com/kingcharleslzy-ai/dsh-purge)：本项目是它的伴生护栏，没有它就没有「需要补一道闸」这个问题。
- [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)：`tools/pre-execute`、`ctx.tools.guard`、`systemPrompt.section` 等接口来自宿主。

## 许可与边界

以上项目均为各自作者所有，本仓库**未复制其源代码**，仅借鉴设计思路并以独立实现落地；如涉及具体代码引用会在此标注来源与许可。若你是作者并希望调整署名方式，请开 issue。
