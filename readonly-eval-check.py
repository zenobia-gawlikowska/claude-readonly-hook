#!/usr/bin/env python3
"""
PreToolUse hook — auto-approve Bash commands that are demonstrably read-only.

Three independent checks, either of which can approve:

A) Inline eval (node -e, python3 -c, bun --eval, deno eval, heredocs):
   Extract the inline code and scan for mutating API patterns.
   Approve if none found.

B) Read-only pipeline:
   Split on pipes / && / || / ; and check that EVERY segment's leading
   command is in the known-safe read-only set.
   $(...) and `...` command substitutions are extracted and validated
   recursively — a segment containing a mutating substitution is rejected.
   Approve if every segment is safe.

C) Read-only for loop:
   Detect `for VAR in PATTERN; do BODY; done` and validate every statement
   in the body with the same logic as Check B.
   Approve if the entire body is safe.

In all cases: if anything looks mutating or ambiguous → exit 0, no decision,
let the normal permission prompt handle it.
"""

import json
import re
import sys


# ---------------------------------------------------------------------------
# Pattern: does the command look like an inline eval?
# ---------------------------------------------------------------------------
INLINE_EVAL_RE = re.compile(
    r'^(?:node|bun)\s+(?:-e|--eval)\s+'
    r'|^python3?\s+-c\s+'
    r'|^deno\s+eval\s+',
    re.IGNORECASE,
)

HEREDOC_RE = re.compile(
    r'^(?:node|bun|python3?|deno)\b[^\n]*<<\s*[\'"]?(\w+)[\'"]?',
    re.IGNORECASE,
)


def extract_inline_code(command: str):
    """Return the inline code string, or None if the command isn't an inline eval."""
    m = INLINE_EVAL_RE.match(command)
    if m:
        code = command[m.end():].strip()
        # Strip one layer of matching outer quotes
        if len(code) >= 2 and code[0] in ('"', "'") and code[-1] == code[0]:
            code = code[1:-1]
        return code

    m = HEREDOC_RE.match(command)
    if m:
        newline = command.find("\n")
        return command[newline + 1:] if newline != -1 else ""

    return None


# ---------------------------------------------------------------------------
# Mutating-pattern blocklist — if ANY match, do not auto-approve
# ---------------------------------------------------------------------------
_MUTATING = [
    # Node/Bun: child_process / shell execution
    r"child_process",
    r"\.exec\s*\(",
    r"\.execSync\s*\(",
    r"\.spawn\s*\(",
    r"\.spawnSync\s*\(",
    r"\.fork\s*\(",
    r"execFileSync\s*\(",
    # Node/Bun: file writes & deletes
    r"fs\.writeFile",
    r"fs\.appendFile",
    r"fs\.unlink",
    r"fs\.rmdir",
    r"fs\.rm\b",
    r"fs\.mkdir",
    r"fs\.rename",
    r"fs\.copyFile",
    r"fs\.symlink",
    r"fs\.chmod",
    r"fs\.chown",
    r"fs\.truncate",
    r"writeFileSync",
    r"appendFileSync",
    r"unlinkSync",
    r"rmdirSync",
    r"mkdirSync",
    r"renameSync",
    # Network mutations
    r"""fetch\s*\([^)]*(?:method\s*:\s*['"](?:POST|PUT|DELETE|PATCH)|['"]POST['"]|['"]PUT['"]|['"]DELETE['"]|['"]PATCH['"])""",
    r"""axios\.(?:post|put|delete|patch)\s*\(""",
    # process.exit
    r"process\.exit\s*\(",
    # Python: file writes
    r"""open\s*\([^)]*['"]\s*[wa+]""",
    # Python: shell / OS mutations
    r"subprocess",
    r"os\.system\s*\(",
    r"os\.popen\s*\(",
    r"os\.remove\s*\(",
    r"os\.unlink\s*\(",
    r"os\.rmdir\s*\(",
    r"os\.mkdir\s*\(",
    r"os\.makedirs\s*\(",
    r"shutil\.",
    # Import of dangerous modules
    r"""require\s*\(\s*['"]child_process""",
    r"""import\s+.*child_process""",
]

MUTATING_RE = re.compile("|".join(_MUTATING), re.IGNORECASE | re.MULTILINE)


def is_mutating(code: str) -> bool:
    return bool(MUTATING_RE.search(code))


# ---------------------------------------------------------------------------
# Check B: read-only pipeline
# ---------------------------------------------------------------------------

# Commands that are always safe regardless of arguments.
READONLY_COMMANDS = {
    "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "ripgrep",
    "wc", "uniq", "cut", "tr", "column", "jq", "nl", "tac",
    "rev", "fold", "expand", "fmt", "comm", "numfmt", "strings",
    "hexdump", "od", "bat", "less", "more",
    "echo", "printf", "ls",
    "file", "stat", "basename", "dirname", "realpath",
    "date", "which", "type", "true", "false",
    "cd",   # changes directory only, no writes
    # Intentionally excluded — can write or execute:
    #   awk        — print > "file" writes; system() executes shell
    #   sed        — sed -i edits files in-place
    #   sort       — sort -o <file> writes output to a file
    #   diff       — diff --output=<file> writes a patch file
    #   find       — -exec/-execdir runs arbitrary commands; -delete deletes files
    #   fd/fdfind  — --exec/-x and --exec-batch/-X run arbitrary commands
    #   python3    — use -c form (handled by Check A)
}

# git subcommands that never mutate the repo or remote.
GIT_READONLY_SUBCOMMANDS = {
    "log", "show", "diff", "status", "branch", "tag",
    "remote", "ls-files", "ls-remote", "ls-tree",
    "rev-parse", "rev-list", "describe", "shortlog",
    "cat-file", "for-each-ref", "reflog", "blame", "grep",
    "stash", "worktree", "config",
    "notes", "fsck", "verify-commit", "verify-tag",
}

# git subcommands that are always mutating.
GIT_MUTATING_SUBCOMMANDS = {
    "add", "commit", "push", "pull", "fetch", "merge", "rebase",
    "reset", "checkout", "switch", "restore", "clean", "apply",
    "cherry-pick", "revert", "bisect", "rm", "mv", "init", "clone",
    "submodule", "am", "format-patch", "gc", "prune",
}


def is_git_readonly(tokens: list) -> bool:
    """Return True if this git invocation is read-only. tokens starts with 'git'."""
    # Skip option flags before the subcommand (e.g. git -C /path log ...)
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        if tokens[i] in ("-C", "--git-dir", "--work-tree"):
            i += 2  # these take a value argument
        else:
            i += 1
    if i >= len(tokens):
        return False

    sub = tokens[i]
    if sub in GIT_MUTATING_SUBCOMMANDS:
        return False
    if sub not in GIT_READONLY_SUBCOMMANDS:
        return False

    # Extra guard for subcommands that have mutating variants
    rest = tokens[i + 1:]
    if sub == "stash" and rest and rest[0] not in ("list", "show"):
        return False  # git stash pop/drop/push are mutating
    if sub == "worktree" and rest and rest[0] != "list":
        return False  # git worktree add/remove are mutating
    if sub == "config":
        mutating_flags = {"--add", "--unset", "--unset-all", "--rename-section",
                          "--remove-section", "--replace-all", "--write", "-e", "--edit"}
        if any(f in rest for f in mutating_flags):
            return False

    return True


# Segment-level patterns that make an otherwise safe command unsafe.
UNSAFE_SEGMENT_RE = re.compile(
    r"\bsudo\b"
    r"|\brm\b"
    r"|\bmv\b"
    r"|\bcp\b(?!\s+.*\|)"
    r"|\bchmod\b|\bchown\b"
    r"|\bcurl\b|\bwget\b"
    r"|\btee\b"
    r"|\bdd\b"
    r"|\binstall\b"
    r"|(?<!\d)>[^>&\d]",  # > file write, but not 2>/dev/null or >&1 (fd redirects)
    re.IGNORECASE,
)

def _quote_aware_split(command: str, two_char_ops, one_char_ops) -> list:
    """Generic quote-aware splitter parameterised by operator sets."""
    segments = []
    current = []
    in_single = in_double = False
    i = 0
    while i < len(command):
        c = command[i]
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
        elif not in_single and not in_double:
            two = command[i:i + 2]
            if two in two_char_ops:
                segments.append("".join(current))
                current = []
                i += 2
                continue
            elif c in one_char_ops:
                segments.append("".join(current))
                current = []
            else:
                current.append(c)
        else:
            current.append(c)
        i += 1
    if current:
        segments.append("".join(current))
    return segments


def split_compound(command: str) -> list:
    """Split on && and || only — keeps for..done blocks intact."""
    return _quote_aware_split(command, {"&&", "||"}, set())


def split_segments(command: str) -> list:
    """Split on |, ||, &&, ; — used for for-loop body validation."""
    return _quote_aware_split(command, {"&&", "||"}, {"|", ";"})


def strip_substitutions(segment: str):
    """
    Remove $(...) and `...` command substitutions from segment, returning
    (cleaned_text, list_of_inner_commands).
    Both forms are extracted and validated — a mutating substitution blocks
    the whole segment even if the outer command is safe.
    """
    inner_cmds = []
    cleaned = []
    i = 0
    while i < len(segment):
        if segment[i:i+2] == "$(":
            depth = 1
            j = i + 2
            while j < len(segment) and depth:
                if segment[j] == "(":
                    depth += 1
                elif segment[j] == ")":
                    depth -= 1
                j += 1
            inner_cmds.append(segment[i + 2:j - 1].strip())
            i = j
        elif segment[i] == "`":
            j = i + 1
            while j < len(segment) and segment[j] != "`":
                if segment[j] == "\\" and j + 1 < len(segment):
                    j += 1  # skip escaped character inside backtick expression
                j += 1
            inner_cmds.append(segment[i + 1:j].strip())
            i = j + 1
        else:
            cleaned.append(segment[i])
            i += 1
    return "".join(cleaned), inner_cmds


def is_safe_segment(segment: str) -> bool:
    """Return True if a single command segment (no pipes/&&) is read-only."""
    segment = segment.strip()
    if not segment:
        return True

    # Strip and validate $(...) substitutions first
    cleaned, subst_cmds = strip_substitutions(segment)
    for inner in subst_cmds:
        if not is_safe_segment(inner):
            return False

    cleaned = cleaned.strip()
    if not cleaned:
        return True

    if UNSAFE_SEGMENT_RE.search(cleaned):
        return False

    tokens = cleaned.split()
    while tokens and "=" in tokens[0] and not tokens[0].startswith("-"):
        tokens = tokens[1:]
    if not tokens:
        return True

    lead = tokens[0].split("/")[-1].lstrip("./")

    if lead == "git":
        return is_git_readonly(tokens)
    elif lead == "sort":
        # sort -o <file> / sort --output=<file> writes to a file
        return not any(t in ("-o", "--output") or t.startswith("--output=") for t in tokens[1:])
    elif lead in ("less", "more"):
        # less/more -o/-O/--log-file/--LOG-FILE copies output to a log file
        return not any(t in ("-o", "-O") or t.startswith(("--log-file", "--LOG-FILE")) for t in tokens[1:])
    elif lead == "uniq":
        # uniq [input [output]] — a second positional arg is an output file
        positional = [t for t in tokens[1:] if not t.startswith("-")]
        return len(positional) < 2
    elif lead == "date":
        # bare date or date "+format" is display-only
        # a bare positional like "date 0601120025" sets the system clock
        args = tokens[1:]
        if not args:
            return True  # bare date — display only
        non_flags = [t for t in args if not t.startswith("-")]
        # Strip surrounding quotes before checking for the + format prefix
        return all(t.strip("\"'").startswith("+") for t in non_flags)
    elif lead == "find":
        # Safe unless it uses flags that execute commands or delete files.
        mutating_find_flags = {"-exec", "-execdir", "-delete", "-ok"}
        return not any(t in mutating_find_flags for t in tokens[1:])
    elif lead in ("node", "bun", "python3", "python", "deno"):
        inline_code = extract_inline_code(segment.strip())
        return inline_code is not None and not is_mutating(inline_code)
    else:
        return lead in READONLY_COMMANDS


def is_readonly_pipeline(command: str) -> bool:
    """Return True only if every part of the command is read-only.

    Two-level split:
      1. Split on && / || to get compound parts — keeps for..done intact.
      2. For each part, check for loop first; otherwise split on | / ; and
         validate each segment individually.
    """
    for part in split_compound(command):
        part = part.strip()
        if not part:
            continue
        if is_readonly_for_loop(part):
            continue
        for segment in _quote_aware_split(part, set(), {"|", ";"}):
            if not is_safe_segment(segment):
                return False
    return True


# ---------------------------------------------------------------------------
# Check C: read-only for loop
# ---------------------------------------------------------------------------

# Matches:  for VAR in PATTERN; do BODY; done
# The body may contain semicolons and pipes — extracted as a group.
FOR_LOOP_RE = re.compile(
    r"^for\s+\w+\s+in\s+[^;]+;\s*do\s+(.+);\s*done\s*$",
    re.DOTALL,
)


def is_readonly_for_loop(command: str) -> bool:
    """Return True if a for loop iterates safely and its body is entirely read-only."""
    m = FOR_LOOP_RE.match(command.strip())
    if not m:
        return False

    body = m.group(1)  # everything between 'do' and '; done'

    # Validate every statement / pipeline in the body
    for segment in split_segments(body):
        if not is_safe_segment(segment):
            return False

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    if data.get("tool_name") != "Bash":
        sys.exit(0)

    command = (data.get("tool_input") or {}).get("command", "").strip()
    if not command:
        sys.exit(0)

    # Check A: inline eval
    inline_code = extract_inline_code(command)
    if inline_code is not None:
        if not is_mutating(inline_code):
            _approve("inline eval code is read-only")
        sys.exit(0)

    # Check B: read-only pipeline
    if is_readonly_pipeline(command):
        _approve("all pipeline segments are read-only commands")

    # Check C: read-only for loop
    if is_readonly_for_loop(command):
        _approve("for loop body is read-only")

    sys.exit(0)


def _approve(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
