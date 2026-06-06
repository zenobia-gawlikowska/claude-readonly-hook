# claude-readonly-hook

A [Claude Code](https://claude.ai/code) `PreToolUse` hook that **auto-approves Bash commands that are demonstrably read-only**, so you stop clicking "Yes" on things that obviously can't hurt anything.

---

## The problem

Claude Code asks for permission before running every Bash command it hasn't seen before. That's the right default — you don't want an AI silently deleting files or pushing to production.

But in practice a lot of prompted commands are completely harmless:

```bash
node -e "console.log(JSON.stringify(require('./package.json'), null, 2))"
cat ~/.npm/_logs/debug.log | tail -40
cd /some/repo && git log --oneline -5 && git show HEAD --stat
for dir in src/*/; do echo "=== $(basename "$dir") ==="; ls -1 "$dir"; done
```

Approving each of these adds friction without adding safety. A blanket `Bash(node *)` allowlist is dangerous — it approves `node -e "require('fs').writeFileSync(...)"` just as readily. The solution is a hook that understands *what the command actually does*.

---

## What it approves

Three independent checks, any of which can approve a command:

### Check A — Inline eval

Detects `node -e`, `node --eval`, `bun -e`, `bun --eval`, `python3 -c`, `python -c`, `deno eval`, and heredoc variants. Extracts the inline code and scans it against a blocklist of mutating APIs:

| Blocked category | Examples |
|---|---|
| Shell execution | `child_process`, `.exec(`, `.spawn(`, `execSync`, `subprocess` |
| File writes | `writeFileSync`, `appendFile`, `fs.unlink`, `fs.mkdir`, `shutil.*` |
| File deletes | `fs.rm(`, `unlinkSync`, `os.remove`, `os.rmdir` |
| Network mutations | `fetch` with POST/PUT/DELETE/PATCH, `axios.post/put/delete` |
| Process control | `process.exit(` |
| Python file opens | `open(..., 'w')`, `open(..., 'a')` |

If none of those appear → **approved**. Any hit → falls through to the normal permission prompt.

### Check B — Read-only pipeline

Splits the command on `|`, `&&`, `||`, `;` (quote-aware, so `;` inside string literals isn't treated as a separator) and checks that **every segment** is safe.

**Always-safe commands** (stdout-only regardless of flags):
```
cat  head  tail  grep  egrep  fgrep  rg  wc  uniq  cut  tr
column  jq  nl  tac  bat  less  more  ls  cd  echo  printf
file  stat  strings  hexdump  od  basename  dirname  realpath
date  which  type  sort*
```

`sort` is safe unless `-o`/`--output` is present (which writes to a file).

**`git` gets subcommand-level inspection** — not a blanket allow:

| Approved | Blocked |
|---|---|
| `log`, `show`, `diff`, `status`, `branch`, `tag` | `add`, `commit`, `push`, `pull`, `fetch` |
| `remote`, `ls-files`, `ls-tree`, `rev-parse` | `merge`, `rebase`, `reset`, `checkout` |
| `stash list/show`, `worktree list` | `stash pop/drop`, `worktree add/remove` |
| `config` (read flags only) | `config --unset`, `config --add`, `config -e` |

**`node`/`bun`/`python3`/`deno` segments inside pipelines** use the same Check A mutation scan on their inline code.

**Command substitutions** `$(...)` are recursively checked — `echo "$(basename "$dir")"` is approved because `basename` is safe.

A segment is always rejected if it contains `>` file redirect, `tee`, `curl`, `wget`, `rm`, `mv`, `sudo`, `chmod`, `chown`, `dd`.

### Check C — Read-only `for` loop

Detects `for VAR in PATTERN; do BODY; done`. Validates every statement in the body using the same logic as Check B (including `$(...)` substitutions). Approved if the body is entirely safe; blocked if it contains `rm`, `git add`, `cp`, mutating `node -e`, etc.

---

## What it never approves

- Anything with a write/delete/exec pattern not listed above
- Unknown commands — if it's not in the known-safe set, it falls through to the prompt
- Wildcards that could match dangerous flags (e.g. `awk`, `sed`, `find`, `fd` are excluded because they can all write files or execute shell commands)

The hook is conservative by design: **it only approves what it can prove is safe**.

---

## Installation

**Requirements:** Python 3 at `/usr/bin/python3` (standard macOS/Linux system Python).

### 1. Copy the hook script

```bash
mkdir -p ~/.claude/hooks
curl -o ~/.claude/hooks/readonly-eval-check.py \
  https://raw.githubusercontent.com/zenobia-gawlikowska/claude-readonly-hook/master/readonly-eval-check.py
```

Or clone the repo and copy:

```bash
git clone https://github.com/zenobia-gawlikowska/claude-readonly-hook.git
cp claude-readonly-hook/readonly-eval-check.py ~/.claude/hooks/
```

### 2. Wire it into Claude Code

Add the hook to `~/.claude/settings.json` (global — applies to all projects):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/python3 /Users/YOUR_USERNAME/.claude/hooks/readonly-eval-check.py",
            "timeout": 5,
            "statusMessage": "Checking command safety..."
          }
        ]
      }
    ]
  }
}
```

Replace `YOUR_USERNAME` with your actual username, or use `$HOME`:

```json
"command": "/usr/bin/python3 /Users/YOUR_USERNAME/.claude/hooks/readonly-eval-check.py"
```

> **Tip:** If you already have a `hooks` key or a `PreToolUse` array, merge the new entry — don't replace the existing one.

### 3. Reload hooks

Open `/hooks` in Claude Code, or restart the session. The hook is active immediately.

### 4. Verify

Ask Claude to run:
```bash
node -e "console.log('hook working')"
```
It should execute without a permission prompt.

---

## Running the tests

```bash
python3 ~/.claude/hooks/test_readonly_eval_check.py        # summary
python3 ~/.claude/hooks/test_readonly_eval_check.py -v     # verbose, all 94 cases
```

Exit code `0` = all pass. Exit code `1` = failures (output shows which).

---

## Excluded commands and why

| Command | Why excluded |
|---|---|
| `awk` | `print > "file"` writes files; `system("cmd")` executes shell |
| `sed` | `-i` edits files in-place |
| `diff` | `--output=<file>` writes a patch file |
| `find` | `-exec`/`-execdir` runs arbitrary commands; `-delete` deletes files |
| `fd` / `fdfind` | `--exec`/`-x` and `--exec-batch`/`-X` execute arbitrary commands |

---

## Scope

Global (`~/.claude/settings.json`) — covers every Claude Code project on this machine. If you want project-scoped behaviour instead, put the hook entry in `.claude/settings.json` inside your project and commit it.

---

## License

MIT
