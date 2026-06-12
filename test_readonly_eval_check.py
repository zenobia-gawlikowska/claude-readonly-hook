#!/usr/bin/env python3
"""
Test suite for readonly-eval-check.py

Run with:
    python3 ~/.claude/hooks/test_readonly_eval_check.py
    python3 ~/.claude/hooks/test_readonly_eval_check.py -v   # verbose
"""

import json
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).parent / "readonly-eval-check.py"
PYTHON = sys.executable

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_hook(command: str):
    """Run the hook with the given command. Returns 'allow'/'deny' or None."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    result = subprocess.run(
        [PYTHON, str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
    )
    if not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)
        return data["hookSpecificOutput"]["permissionDecision"]
    except Exception:
        return None


PASS = 0
FAIL = 0
VERBOSE = "-v" in sys.argv


def expect_approve(command: str, label: str) -> None:
    global PASS, FAIL
    decision = run_hook(command)
    ok = decision == "allow"
    PASS += ok
    FAIL += not ok
    if VERBOSE or not ok:
        status = "✅ PASS" if ok else "❌ FAIL"
        tag = "APPROVE" if ok else f"expected APPROVE, got {decision!r}"
        print(f"  {status}  [{tag}]  {label}")


def expect_block(command: str, label: str) -> None:
    global PASS, FAIL
    decision = run_hook(command)
    ok = decision != "allow"
    PASS += ok
    FAIL += not ok
    if VERBOSE or not ok:
        status = "✅ PASS" if ok else "❌ FAIL"
        tag = "BLOCKED" if ok else f"expected BLOCK, got {decision!r}"
        print(f"  {status}  [{tag}]  {label}")


def section(title: str) -> None:
    print(f"\n── {title}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

section("Check A — standalone inline eval")
expect_approve('node -e "console.log(process.env)"',                         "node -e read-only")
expect_approve('node --eval "console.log(Object.keys(require(\'./package.json\')))"', "node --eval read-only")
expect_approve('node -e "console.log(42)" 2>&1',                             "node -e with 2>&1")
expect_approve('bun -e "console.log(process.env)"',                          "bun -e read-only")
expect_approve('bun --eval "console.log(42)"',                               "bun --eval read-only")
expect_approve('python3 -c "import json; print(json.dumps({}))"',            "python3 -c read-only")
expect_approve('python -c "print(\'hello\')"',                               "python -c read-only")
expect_approve('deno eval "console.log(Deno.version)"',                      "deno eval read-only")

section("Check A — inline eval blocked (mutating code)")
expect_block('node -e "require(\'fs\').writeFileSync(\'x\',\'y\')"',         "node writeFileSync")
expect_block('node -e "require(\'child_process\').exec(\'rm /tmp/readonly-hook-test.txt\')"', "node child_process.exec")
expect_block('node -e "require(\'child_process\').spawn(\'sh\',[],{})"',     "node child_process.spawn")
expect_block('node -e "const {execSync}=require(\'child_process\');execSync(\'ls\')"', "node execSync")
expect_block('node -e "fs.appendFileSync(\'log\',\'x\')"',                   "node appendFileSync")
expect_block('node -e "fs.unlinkSync(\'file.txt\')"',                        "node unlinkSync")
expect_block('node -e "fs.mkdirSync(\'newdir\')"',                           "node mkdirSync")
expect_block('node -e "process.exit(1)"',                                    "node process.exit")
expect_block('node -e "fetch(\'http://x.com\',{method:\'POST\',body:\'x\'})"', "node fetch POST")
expect_block('python3 -c "open(\'f\',\'w\').write(\'x\')"',                  "python3 open write")
expect_block('python3 -c "import subprocess; subprocess.run([\'ls\'])"',     "python3 subprocess")
expect_block('python3 -c "import os; os.remove(\'file\')"',                  "python3 os.remove")
expect_block('python3 -c "import shutil; shutil.rmtree(\'dir\')"',           "python3 shutil.rmtree")

section("Check B — read-only pipelines approved")
expect_approve('cat /var/log/app.log | tail -40',                            "cat | tail")
expect_approve('cat /var/log/app.log | tail -40 | grep ERROR',               "cat | tail | grep")
expect_approve('grep -r ERROR src/ | wc -l',                                 "grep | wc")
expect_approve('grep -r ERROR src/ | sort | uniq -c',                        "grep | sort | uniq")
expect_approve('cat package.json | jq .dependencies',                        "cat | jq")
expect_approve('ls node_modules/ | grep svelte',                             "ls | grep")
expect_approve('echo "hello" | wc -c',                                       "echo | wc")
expect_approve('cat file.txt | head -20 | nl',                               "cat | head | nl")
expect_approve('ls -la | column -t',                                         "ls | column")
expect_approve('strings /usr/bin/node | grep version',                       "strings | grep")
expect_approve('hexdump -C file.bin | head -5',                              "hexdump | head")

section("Check B — cd and git compound commands")
expect_approve('cd /some/repo && git log --oneline -5',                      "cd && git log")
expect_approve('cd /repo && git log --oneline -5 && echo "---" && git show HEAD --stat', "cd && git log && git show")
expect_approve('git -C /some/path log --oneline -10',                        "git -C log")
expect_approve('git status | grep modified',                                 "git status | grep")
expect_approve('git diff HEAD~1 | head -50',                                 "git diff | head")
expect_approve('git log --oneline -5',                                       "git log")
expect_approve('git show HEAD --stat',                                       "git show --stat")
expect_approve('git branch -a',                                              "git branch -a")
expect_approve('git stash list',                                             "git stash list")
expect_approve('git stash show',                                             "git stash show")
expect_approve('git worktree list',                                          "git worktree list")
expect_approve('git config --get user.name',                                 "git config --get")
expect_approve('git config --list',                                          "git config --list")
expect_approve('git remote -v',                                              "git remote -v")
expect_approve('git ls-files src/',                                          "git ls-files")
expect_approve('git rev-parse HEAD',                                         "git rev-parse HEAD")
expect_approve('git reflog | head -20',                                      "git reflog | head")

section("Check B — inline eval segments inside pipelines")
expect_approve(
    'ls node_modules/ | grep svelte && node --eval "const s=require(\'/some/module\'); console.log(Object.keys(s))" 2>&1',
    "ls | grep && node --eval with ; in string and 2>&1",
)
expect_approve(
    'cat package.json | grep name && node -e "const p=require(\'./package.json\'); console.log(p.version)"',
    "cat | grep && node -e",
)
expect_approve(
    'python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get(\'name\'))" < package.json',
    "python3 -c reading stdin",
)

section("Check B — git mutations blocked")
expect_block('git push origin main',                                         "git push")
expect_block('git commit -m "fix"',                                          "git commit")
expect_block('git add .',                                                    "git add")
expect_block('git checkout main',                                            "git checkout")
expect_block('git reset --hard HEAD',                                        "git reset --hard")
expect_block('git merge feature-branch',                                     "git merge")
expect_block('git rebase main',                                              "git rebase")
expect_block('git stash pop',                                                "git stash pop")
expect_block('git stash drop',                                               "git stash drop")
expect_block('git worktree add ../new-wt main',                              "git worktree add")
expect_block('git config --unset user.name',                                 "git config --unset")
expect_block('git config --add section.key value',                           "git config --add")
expect_block('git config -e',                                                "git config -e")
expect_block('git clean -fd',                                                "git clean")
expect_block('git fetch origin',                                             "git fetch")

section("Check B — unsafe patterns blocked")
expect_block('cat file.log | grep foo > out.txt',                            "redirect to file")
expect_block('cat file.log | tee output.txt',                                "tee writes file")
expect_block('curl https://api.example.com | jq .',                         "curl blocked")
expect_block('wget https://example.com/file',                               "wget blocked")
expect_block('ls | rm /tmp/readonly-hook-test.txt',                          "rm in pipeline")
expect_block('echo x | sudo tee /etc/hosts',                                 "sudo blocked")
expect_block('cat file | sort -o sorted.txt',                                "sort -o writes")
expect_block('cat file.log | awk \'{print $1}\'',                            "awk excluded")
expect_block('cat file.txt | sed \'s/foo/bar/\'',                            "sed excluded")
expect_block('fd -e log --exec cat {}',                                      "fd --exec")
expect_block('diff --output=patch.diff a.txt b.txt',                         "diff --output")
expect_block('ls; git push origin main',                                     "; git push")
expect_block('cat file.log | node -e "require(\'fs\').writeFileSync(\'x\',\'y\')"', "node writeFileSync in pipeline")

section("Flag inspection — find")
expect_approve('find context toolkit -type f 2>/dev/null | sort',            "find -type f | sort")
expect_approve('find src -type f | head -80',                                "find -type f | head")
expect_approve('find . -path ./node_modules -prune -o -name "SKILL.md" -print 2>/dev/null | head', "find -path -prune -o -name -print")
expect_approve('find 10x-cli -maxdepth 3 -iname \'*a11y*\' -type d 2>/dev/null', "find -maxdepth -iname -type d")
expect_approve('cd /tmp && find . -name "*.json" -type f | sort',            "cd && find | sort")
expect_block('find . -name "*.log" -exec cat {} \\;',                        "find -exec")
expect_block('find /tmp -name "*.tmp" -delete',                              "find -delete")
expect_block('find . -ok rm {} \\;',                                         "find -ok")
expect_block('find . -execdir cat {} \\;',                                   "find -execdir")

section("Flag inspection — less / more / uniq / date")
expect_approve('cat file.log | less',                                        "less in pipeline — safe")
expect_approve('less file.log',                                              "less file — safe")
expect_block('less -o output.txt file.log',                                  "less -o writes log")
expect_block('less -O output.txt file.log',                                  "less -O overwrites log")
expect_block('less --log-file=out.txt file.log',                             "less --log-file writes")

expect_approve('cat file.log | more',                                        "more in pipeline — safe")
expect_block('more -o output.txt file.log',                                  "more -o writes log")

expect_approve('cat file | uniq',                                            "uniq stdin — safe")
expect_approve('uniq file.txt',                                              "uniq one arg — safe")
expect_approve('uniq -c file.txt',                                           "uniq -c — safe")
expect_block('uniq input.txt output.txt',                                    "uniq two positional args — writes")

expect_approve('date',                                                       "bare date — display only")
expect_approve('date "+%Y-%m-%d"',                                           "date with format — display only")
expect_approve('date "+%s"',                                                 "date unix timestamp format")
expect_block('date 0601120025',                                              "date positional — sets clock")

section("Check B — backtick substitutions")
expect_approve('echo `basename "$dir"`',                                    "backtick basename — safe")
expect_approve('echo `date "+%Y-%m-%d"`',                                   "backtick date — safe")
expect_block('echo `git add .`',                                            "backtick git add — mutating")
expect_block('echo `git push origin main`',                                 "backtick git push — mutating")
expect_block('echo `rm /tmp/readonly-hook-test.txt`',                       "backtick rm — mutating")
expect_block('echo `node -e "require(\'fs\').writeFileSync(\'x\',\'y\')"`', "backtick mutating node -e")

section("cd && for loop compound commands")
expect_approve(
    'cd /Users/zenobia.gawlikowska/Development/10x-cli && for skill in 10x-agents-md 10x-rule-review 10x-lesson; do echo "== $skill =="; git show HEAD:.claude/skills/$skill/SKILL.md 2>/dev/null | head -1 | grep -o "name: [^$]*"; git show HEAD:.claude/skills/$skill/SKILL.md 2>/dev/null | grep -A 3 "^description:" | head -4; echo ""; done',
    "cd && for with git show 2>/dev/null | grep | head",
)
expect_approve(
    'cd /Users/zenobia.gawlikowska/Development/10x-cli && for skill in 10x-tech-stack-selector 10x-bootstrapper; do echo "=== $skill ==="; git show HEAD:.claude/skills/$skill/SKILL.md 2>/dev/null | head -80; done',
    "cd && for with git show | head",
)
expect_approve(
    'git show HEAD:file.txt 2>/dev/null | head -20',
    "git show 2>/dev/null | head",
)
expect_approve(
    'git show HEAD:file.txt 2>/dev/null',
    "git show with stderr suppression",
)
expect_block(
    'cd /repo && git push 2>/dev/null',
    "cd && git push — still blocked despite 2>/dev/null",
)

section("Check C — read-only for loops")
expect_approve(
    'for dir in /Users/zenobia.gawlikowska/Development/ai-devkit/claude/skills/*/; do echo "=== $(basename "$dir") ==="; ls -1 "$dir" | head -20; done',
    "the exact failing command",
)
expect_approve(
    'for f in src/*.ts; do echo "$f"; head -5 "$f"; done',
    "for loop: echo + head",
)
expect_approve(
    'for f in *.json; do echo "--- $f ---"; cat "$f" | jq .name; done',
    "for loop: echo + cat | jq",
)
expect_approve(
    'for dir in */; do ls "$dir"; done',
    "for loop: just ls",
)
expect_block(
    'for f in *.txt; do rm "$f"; done',
    "for loop: rm in body",
)
expect_block(
    'for f in *.ts; do git add "$f"; done',
    "for loop: git add in body (mutating git)",
)
expect_block(
    'for f in *.ts; do cp "$f" /tmp/; done',
    "for loop: cp in body",
)
expect_block(
    'for f in *.ts; do node -e "require(\'fs\').writeFileSync(\'x\',\'y\')"; done',
    "for loop: mutating node -e in body",
)

section("Hook ignores non-Bash tools")
payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": "/tmp/x", "content": "y"}})
result = subprocess.run([PYTHON, str(HOOK)], input=payload, capture_output=True, text=True)
ok = result.stdout.strip() == ""
PASS += ok; FAIL += not ok
if VERBOSE or not ok:
    print(f"  {'✅ PASS' if ok else '❌ FAIL'}  [ignored]  Write tool ignored")

section("Hook survives malformed input")
for bad, label in [
    ("",                    "empty stdin"),
    ("not json",            "non-JSON stdin"),
    ('{"tool_name":"Bash"}', "missing tool_input"),
]:
    result = subprocess.run([PYTHON, str(HOOK)], input=bad, capture_output=True, text=True)
    ok = result.returncode == 0 and result.stdout.strip() == ""
    PASS += ok; FAIL += not ok
    if VERBOSE or not ok:
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}  [no crash]  {label}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
total = PASS + FAIL
print(f"\n{'─' * 40}")
print(f"  {PASS}/{total} passed", end="")
if FAIL:
    print(f"  ← {FAIL} FAILED ❌")
else:
    print("  ✅ all good")
print()
sys.exit(0 if FAIL == 0 else 1)
