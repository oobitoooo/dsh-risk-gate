# 发布到 GitHub

> 这里只写仓库侧要做的动作。**本仓库不替你 commit / push**——下面命令由你自己执行。

## 0. 先把占位符换成你的账号

`package.json` 与两份 README 里都有 `USER/dsh-risk-gate`。一条命令改掉：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\set-repo.ps1 -Owner 你的GitHub用户名
```

## 1. 建仓库并推送

```powershell
cd <这个目录>
C:\Program Files\Git\cmd\git.exe init -b main
C:\Program Files\Git\cmd\git.exe add .
C:\Program Files\Git\cmd\git.exe commit -m "feat: dsh-risk-gate 1.0.0 — human-in-the-loop gate for dsh-purge"
C:\Program Files\Git\cmd\git.exe remote add origin https://github.com/<你的账号>/dsh-risk-gate.git
C:\Program Files\Git\cmd\git.exe push -u origin main
```

## 2. 打包并上传 Release

```powershell
node scripts\pack.mjs      # 生成 dsh-risk-gate-1.0.0.tgz
```

在 GitHub 上 `Releases → Draft a new release`：

- Tag：`v1.0.0`（与 `package.json` 的 version 一致）
- 上传 `dsh-risk-gate-1.0.0.tgz`
- Release notes 直接抄 `CHANGELOG.md` 的 1.0.0 段

### 用 API 传资产的两个坑（都踩过）

```sh
# ✅ 正确：二进制直传
curl -X POST -H "Authorization: token $TOKEN" -H "Content-Type: application/gzip" \
     --data-binary "@dsh-risk-gate-1.2.0.tgz" \
     "https://uploads.github.com/repos/<owner>/<repo>/releases/<id>/assets?name=dsh-risk-gate-1.2.0.tgz"

# ❌ 错误：-F 是 multipart，GitHub 会把整个报文（含 --boundary）当成资产
curl -X POST ... -F "file=@dsh-risk-gate-1.2.0.tgz" ...
```

自检：下载回来读头两字节，应是 `31,139`（gzip），不是 `45,45`（`--`）。

GitHub 自动建的 tag 指向**建 Release 时的 main**；之后又推了提交的话，把 tag 挪过去：

```sh
curl -X PATCH -H "Authorization: token $TOKEN" -H "Content-Type: application/json" \
     -d '{"sha":"<new-sha>","force":true}' \
     https://api.github.com/repos/<owner>/<repo>/git/refs/tags/v1.2.0
```

装的时候用固定 URL：

```sh
dsh plugin --profile desktop add "https://github.com/<账号>/dsh-risk-gate/releases/download/v1.0.0/dsh-risk-gate-1.0.0.tgz"
```

想让人总拿最新版就把 `/v1.0.0/` 换成 `/latest/download/`。

## 3. 让 DSH 插件市场收录（可选）

`dsh.pub` / `dshmarket.com` 这类索引通常扫 GitHub 的 `dsh-plugin` topic。发布后：

1. 仓库 Settings → Topics 加：`dsh-plugin` `dsh` `deepseek-harness` `dsh-purge` `guardrail`
2. 仓库 Description 写清「dsh-purge 的伴生护栏」——索引抓的是 description 和 topics
3. 若要进 curated 市场，按其 README 提 PR / Issue

## 4. 发布前自检

```sh
node --check lib/index.js
node test/smoke.mjs          # 期望 33/33
node scripts/livecheck.mjs   # 期望通过（有 policy.json 时用它，没有就用内置默认）
node scripts/pack.mjs        # 期望打出 8 个文件左右
tar -tzf dsh-risk-gate-1.0.0.tgz   # 确认 package/ 前缀与文件齐全
```

## 5. 版本号约定

- 规则/文档小改：`1.0.x`
- 新增规则、改确认协议：`1.x.0`
- 破坏性变更（例如去掉 `risk_gate` 工具、改 `policy.json` 结构）：`2.0.0`

改版本要同时动三处：`package.json`、`CHANGELOG.md`、Release tag。
