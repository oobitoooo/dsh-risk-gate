# dsh-risk-gate

**A human-in-the-loop gate for "jailbroken" DSH setups.** A DeepSeek Harness plugin, usually paired with [`dsh-purge`](https://github.com/kingcharleslzy-ai/dsh-purge).

Purge removes the friction: approvals are auto-granted, the sandbox defaults to full access, and refusal wording is neutralised. The side effect is that `git push`, `Remove-Item -Recurse`, registry edits, global installs and outbound transfers **no longer stop for anyone**.

This plugin does not undo purge. It adds one mechanical gate in front of high-risk actions: the host `deny`s the call, the model must relay a one-time code to you, and the exact same call is only released after you reply with that code (one shot, 10-minute TTL).

```
You:  delete dist/ and rebuild
AI:   [risk-gate] blocked: recursive delete (R1) … reply "确认 8CFC6197" to allow
You:  确认 8CFC6197
AI:   (retries verbatim, delete succeeds)
```

## Why not just use approvals

`dsh-purge` patch #9 rewrites `@deepseek-ai/dsh-user-approval` so every request returns `allowed-once`:

```js
if (this.effectivePolicy(session) === "never") return "allowed-once";
return "allowed-once"; // no prompt, no fail-closed path
```

So `kind: 'ask'` equals "auto-approved", and flipping the config back to `ask` changes nothing. This plugin therefore never calls the approval service:

1. listens on `tools/pre-execute` and returns `deny` on a rule hit;
2. registers a `ctx.tools.guard()` as a **monotonic** backstop — a later listener cannot turn the denial back into permission;
3. releases the call only when the one-time code appears in a **user message** (captured from `agent/pre-step`; a code written by the model does not count);
4. the code is one-shot, reused for repeated attempts of the same command, and expires after 10 minutes.

## What it does not do

- never edits host files, never touches `app.asar`, never injects a persona;
- does not revert purge's other behaviours (continuous execution, tool limits, subagent depth stay as-is);
- no network calls at all;
- it is **not** a sandbox: it judges tool-call arguments, not intent.

## Install

```sh
dsh plugin --profile desktop add "https://github.com/oobitoooo/dsh-risk-gate/releases/latest/download/dsh-risk-gate-1.0.0.tgz"
# use `--profile web` for `dsh web`
```

Local development:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1            # desktop profile
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Profile web
```

Fully quit and reopen DSH afterwards.

## Rules (defaults)

| Rule | Covers |
|---|---|
| R1 | recursive delete / format (`Remove-Item -Recurse`, `rm -rf`, `rmtree`, `diskpart`). Exception: small directories (≤ `maxEntries` entries) under `recursiveDelete.allowRoots`; chained commands are never exempt |
| R2 | `git push`, `reset --hard`, `clean -f`, remote rewrites, release/repo deletion |
| R3 | registry, services, scheduled tasks, firewall, execution policy, Defender exclusions, hosts, takeown/icacls |
| R4 | global installs / plugin installs (`npm/pnpm -g`, `winget`, `choco`, `pip install`, `dsh plugin add`) |
| R5 | outbound connections / data transfer (`ssh/scp/nc/chisel/frp/ngrok`, POST with body) |
| R6 | download-and-execute / obfuscation (`\| iex`, `DownloadString`, `-EncodedCommand`, `FromBase64String`) |
| R7 | forced process kill / privilege escalation (`Stop-Process -Force`, `taskkill /f`, `runas`, `psexec`, `sudo`) |
| R8 | subprocesses inside `run_code` (`child_process`, `subprocess`, `os.system`) |
| R9 | delete/write of critical paths (`C:\Windows`, `Program Files`, `ProgramData`, `resources\app`, `.ssh`, `.credentials`) |

## Configuration

`$DSH_HOME/risk-gate/policy.json` (Windows: `%USERPROFILE%\.dsh\risk-gate\policy.json`), hot-reloaded on save:

```json
{
  "ttlMs": 600000,
  "rules": [{ "id": "R1", "label": "recursive delete", "flags": "i", "pattern": "remove-item[^\\n]*-recurse" }],
  "protectedRoots": ["c:\\\\windows", "\\\\resources\\\\app", "\\\\.ssh"],
  "recursiveDelete": { "allowRoots": ["C:\\\\work\\\\my-project"], "maxEntries": 200, "useWorkdirAsRoot": false },
  "allow": ["^\\s*git\\s+(status|diff|log|show|branch)\\b"]
}
```

Runtime artefacts: `audit.jsonl` (every block / allow-after-confirm, 2 MB rotation), `boot.log` (load stages), `pending.json`, `last-user.json`.

## Compatibility

| Scenario | Result |
|---|---|
| DSH desktop update | unaffected; re-run `scripts\verify.ps1` after restart |
| dsh-purge update / re-patch | unaffected (this plugin is not patched by purge) |
| dsh-purge uninstalled | gate keeps working; only purge's continuous execution disappears |
| profile reset | re-run `scripts\install.ps1` |
| without dsh-purge | also fine — it becomes a rule-based confirmation layer |

Verified: DSH Desktop 0.2.1-rc.5 + dsh-purge-community 1.6.69, Windows 11, Node 24.

## Develop / verify

```sh
node --check lib/index.js
node test/smoke.mjs        # 33 logic assertions, fake ctx, no DSH needed
node scripts/livecheck.mjs # 20 cases against the live policy.json
node scripts/pack.mjs      # build dsh-risk-gate-<version>.tgz without npm
```

## Boundaries

- Judges tool arguments, not intent; regex rules can be circumvented — the monotonic guard and `audit.jsonl` are the real backstop.
- Anyone with write access to the machine can disable it (remove the bundle, empty the policy). It is a guardrail, not a lock.
- A code only counts when it appears in a user message; cross-session or subagent confirmations do not transfer.

## License

MIT. Not affiliated with DeepSeek or the dsh-purge authors.
