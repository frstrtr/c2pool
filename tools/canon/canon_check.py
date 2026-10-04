#!/usr/bin/env python3
"""canon_check: check a c2pool checkout against the v37 design canon.

Reads docs/canon/CANON.yaml (the canon rules), docs/canon/DEVIATIONS.md (the
deviations register) and docs/canon/baseline.json (the recorded baseline),
runs every check against a checkout, prints a table, optionally writes a JSON
report, and exits non-zero on any NEW violation:

  * a rule that fails and has no open deviation in the register;
  * a check that passed in the baseline and fails now (a regression);
  * a failing check that has no baseline entry;
  * a forbidden-pattern count that grew over the baseline;
  * a required KAT that the baseline records as present and that is now
    missing from CMake, no longer built by CI, or failed in a given junit;
  * a pull request that touches consensus paths without a "Canon:" line in its
    body, or that names an unknown rule (only with --pr-body);
  * a register that does not match the canon (rule C09).

It also reports what can be tightened: a deviation whose rules all pass now
(close it in the register), a forbidden count below the baseline (lower the
baseline with --write-baseline), and a check that failed in the baseline and
passes now.

Python 3 standard library only. The repository does not use PyYAML, so
CANON.yaml is read by the small YAML subset parser below; --selftest compares
that parser with PyYAML when PyYAML happens to be installed.

Exit codes: 0 no new violation, 1 new violation(s), 2 usage or input error.
"""

import argparse
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

TOOL_VERSION = 1


class CanonError(Exception):
    """An input the checker cannot evaluate (exit code 2)."""


# =============================================================================
# 1. A small YAML subset parser
#
# Supported: block mappings and block sequences by indentation (spaces only),
# sequences of mappings ("- key: value"), flow sequences of scalars
# ("[a, 'b', 3]"), plain, single-quoted and double-quoted scalars, integers,
# true/false, null, and "#" comments. Not supported (rejected with an error):
# tabs, block scalars (| and >), anchors, aliases, flow mappings, multi-line
# plain scalars. Regexes belong in single quotes, where a backslash is literal.
# =============================================================================

_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*:(?:\s+(.*))?$")


def _strip_yaml_comment(s):
    out = []
    quote = None
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            out.append(c)
            if c == quote:
                if quote == "'" and i + 1 < len(s) and s[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                quote = None
            elif quote == '"' and c == "\\" and i + 1 < len(s):
                out.append(s[i + 1])
                i += 2
                continue
        else:
            if c == "#" and (i == 0 or s[i - 1] in " \t"):
                break
            if c in "'\"" and (i == 0 or s[i - 1] in " \t[,:-"):
                quote = c
            out.append(c)
        i += 1
    return "".join(out).rstrip()


def _split_flow(s, lineno):
    items, cur, quote, i = [], [], None, 0
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == quote:
                if quote == "'" and i + 1 < len(s) and s[i + 1] == "'":
                    cur.append("'")
                    i += 2
                    continue
                quote = None
            elif quote == '"' and c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == ",":
            items.append("".join(cur).strip())
            cur = []
        elif c in "[]{}":
            raise CanonError("yaml line %d: nested flow collections are not supported" % lineno)
        else:
            cur.append(c)
        i += 1
    if quote:
        raise CanonError("yaml line %d: unterminated quote in flow sequence" % lineno)
    last = "".join(cur).strip()
    if last or items:
        items.append(last)
    if any(x == "" for x in items):
        raise CanonError("yaml line %d: empty item in flow sequence" % lineno)
    return items


def _yaml_scalar(s, lineno):
    s = s.strip()
    if s == "":
        return None
    if s[0] == "'":
        if len(s) < 2 or s[-1] != "'":
            raise CanonError("yaml line %d: unterminated single-quoted scalar" % lineno)
        return s[1:-1].replace("''", "'")
    if s[0] == '"':
        if len(s) < 2 or s[-1] != '"':
            raise CanonError("yaml line %d: unterminated double-quoted scalar" % lineno)
        try:
            return json.loads(s)
        except ValueError:
            raise CanonError("yaml line %d: unsupported escape in double-quoted scalar" % lineno)
    if s[0] == "[":
        if s[-1] != "]":
            raise CanonError("yaml line %d: flow sequence must close on the same line" % lineno)
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_yaml_scalar(x, lineno) for x in _split_flow(inner, lineno)]
    if s[0] in "{&*!|>%@`":
        raise CanonError("yaml line %d: unsupported YAML construct %r" % (lineno, s[0]))
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    if s in ("null", "~", "Null"):
        return None
    if re.match(r"^-?[0-9]+$", s):
        return int(s)
    if ": " in s or s.endswith(":"):
        raise CanonError("yaml line %d: plain scalar contains ': ' (quote it)" % lineno)
    return s


def parse_yaml(text):
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise CanonError("yaml line %d: tab in indentation" % n)
        body = _strip_yaml_comment(raw)
        if not body.strip():
            continue
        if body.strip() in ("---", "..."):
            continue
        indent = len(body) - len(body.lstrip(" "))
        lines.append([indent, body.strip(), n])
    if not lines:
        return None
    value, i = _parse_node(lines, 0, lines[0][0])
    if i != len(lines):
        raise CanonError("yaml line %d: unexpected indentation" % lines[i][2])
    return value


def _is_seq_item(content):
    return content == "-" or content.startswith("- ")


def _parse_node(lines, i, indent):
    if _is_seq_item(lines[i][1]):
        return _parse_seq(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_seq(lines, i, indent):
    out = []
    while i < len(lines) and lines[i][0] == indent and _is_seq_item(lines[i][1]):
        lineno = lines[i][2]
        rest = lines[i][1][1:].strip()
        if rest == "":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_node(lines, i + 1, lines[i + 1][0])
            else:
                value, i = None, i + 1
        elif _KEY_RE.match(rest) and not rest.startswith(("'", '"')):
            # "- key: value": a mapping whose first key sits two columns in.
            lines[i] = [indent + 2, rest, lineno]
            value, i = _parse_map(lines, i, indent + 2)
        else:
            value, i = _yaml_scalar(rest, lineno), i + 1
        out.append(value)
    if i < len(lines) and lines[i][0] > indent:
        raise CanonError("yaml line %d: unexpected indentation" % lines[i][2])
    return out, i


def _parse_map(lines, i, indent):
    out = {}
    while i < len(lines) and lines[i][0] == indent and not _is_seq_item(lines[i][1]):
        content, lineno = lines[i][1], lines[i][2]
        m = _KEY_RE.match(content)
        if not m:
            raise CanonError("yaml line %d: expected 'key: value', got %r" % (lineno, content))
        key, rest = m.group(1), m.group(2)
        if key in out:
            raise CanonError("yaml line %d: duplicate key %r" % (lineno, key))
        if rest is None or rest.strip() == "":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_node(lines, i + 1, lines[i + 1][0])
            elif i + 1 < len(lines) and lines[i + 1][0] == indent and _is_seq_item(lines[i + 1][1]):
                value, i = _parse_seq(lines, i + 1, indent)
            else:
                value, i = None, i + 1
        else:
            value, i = _yaml_scalar(rest, lineno), i + 1
        out[key] = value
    if i < len(lines) and lines[i][0] > indent:
        raise CanonError("yaml line %d: unexpected indentation" % lines[i][2])
    return out, i


# =============================================================================
# 2. Files, globs and C/C++ comment stripping
# =============================================================================

C_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inc", ".inl")


def glob_to_re(pat):
    if pat.endswith("/"):
        pat += "**"
    parts = pat.split("/")
    out = []
    for idx, part in enumerate(parts):
        last = idx == len(parts) - 1
        if part == "**":
            out.append(".*" if last else "(?:[^/]+/)*")
            continue
        seg = []
        for c in part:
            if c == "*":
                seg.append("[^/]*")
            elif c == "?":
                seg.append("[^/]")
            else:
                seg.append(re.escape(c))
        out.append("".join(seg) + ("" if last else "/"))
    return re.compile("^" + "".join(out) + "$")


class Tree:
    """The checkout under test: its file list and cached file contents."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise CanonError("root %s is not a directory" % self.root)
        self._files = None
        self._text = {}
        self._code = {}

    def head(self):
        try:
            return subprocess.check_output(["git", "-C", self.root, "rev-parse", "HEAD"],
                                           stderr=subprocess.DEVNULL, text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    def files(self):
        if self._files is None:
            files = None
            try:
                out = subprocess.check_output(["git", "-C", self.root, "ls-files", "-z", "--cached", "--others",
                                               "--exclude-standard"],
                                              stderr=subprocess.DEVNULL)
                files = [f for f in out.decode("utf-8", "replace").split("\0") if f]
                files = [f for f in files if os.path.isfile(os.path.join(self.root, f))]
            except (OSError, subprocess.CalledProcessError):
                files = None
            if not files:
                files = []
                for d, dirs, names in os.walk(self.root):
                    dirs[:] = [x for x in dirs if x != ".git"]
                    for nm in names:
                        files.append(os.path.relpath(os.path.join(d, nm), self.root).replace(os.sep, "/"))
            self._files = sorted(files)
        return self._files

    def text(self, rel):
        if rel not in self._text:
            try:
                with open(os.path.join(self.root, rel), "r", encoding="utf-8", errors="replace") as f:
                    self._text[rel] = f.read()
            except OSError:
                self._text[rel] = None
        return self._text[rel]

    def code(self, rel):
        """The file with C/C++ comments and string literal contents blanked
        (same length, same line breaks), or the plain text for other files."""
        if rel not in self._code:
            t = self.text(rel)
            if t is not None and rel.endswith(C_EXTS):
                t = strip_c_comments(t)
            self._code[rel] = t
        return self._code[rel]

    def select(self, include, exclude=(), exts=None):
        inc = [glob_to_re(p) for p in include]
        exc = [glob_to_re(p) for p in exclude]
        out = []
        for f in self.files():
            if exts and not f.endswith(tuple(exts)):
                continue
            if any(r.match(f) for r in inc) and not any(r.match(f) for r in exc):
                out.append(f)
        return out


def strip_c_comments(t):
    out = list(t)
    n = len(t)
    i = 0

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = t[i]
        if c == "/" and i + 1 < n and t[i + 1] == "/":
            j = t.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and i + 1 < n and t[i + 1] == "*":
            j = t.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif c == '"':
            m = re.match(r'R"([^()\\ ]{0,16})\(', t[i - 1:i + 20]) if i > 0 and t[i - 1] == "R" else None
            if m:
                close = ")" + m.group(1) + '"'
                start = i + 1 + len(m.group(1)) + 1
                j = t.find(close, start)
                j = n if j < 0 else j
                blank(start, j)
                i = j + len(close)
                continue
            j = i + 1
            while j < n and t[j] != '"' and t[j] != "\n":
                j += 2 if t[j] == "\\" else 1
            blank(i + 1, min(j, n))
            i = j + 1
        elif c == "'":
            prev = t[i - 1] if i > 0 else ""
            prefix = prev in "uUL" or (prev == "8" and i > 1 and t[i - 2] == "u")
            if prev and (prev.isalnum() or prev == "_") and not prefix:
                i += 1  # digit separator such as 1'000'000
                continue
            j = i + 1
            while j < n and t[j] != "'" and t[j] != "\n" and j - i < 12:
                j += 2 if t[j] == "\\" else 1
            if j < n and t[j] == "'":
                blank(i + 1, j)
                i = j + 1
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


# =============================================================================
# 3. CMake test registry, the CI build list and ctest junit results
# =============================================================================

def _cmake_strip_comments(text):
    out = []
    for line in text.splitlines():
        res, quote = [], False
        for k, c in enumerate(line):
            if c == '"' and (k == 0 or line[k - 1] != "\\"):
                quote = not quote
            if c == "#" and not quote:
                break
            res.append(c)
        out.append("".join(res))
    return "\n".join(out)


def _cmake_commands(text):
    """Yield (name_lower, [args], lineno) for every command call."""
    clean = _cmake_strip_comments(text)
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean):
        depth, j, quote = 1, m.end(), False
        while j < len(clean) and depth:
            c = clean[j]
            if c == '"' and clean[j - 1] != "\\":
                quote = not quote
            elif not quote and c == "(":
                depth += 1
            elif not quote and c == ")":
                depth -= 1
            j += 1
        args = clean[m.end():j - 1]
        lineno = clean.count("\n", 0, m.start()) + 1
        toks = re.findall(r'"(?:[^"\\]|\\.)*"|[^\s()]+', args)
        yield m.group(1).lower(), [x.strip('"') for x in toks], lineno


def cmake_tests(tree):
    """Map ctest name -> {file, line, command} for every add_test() in the
    tree, expanding foreach(var ...) loops. Branches of if() are all read, so
    a test counts as registered when any configuration registers it."""
    tests = {}
    for rel in tree.select(["**/CMakeLists.txt", "**/*.cmake"], ["**/third_party/**", "**/vendor/**"]):
        text = tree.text(rel)
        if text is None or "add_test" not in text:
            continue
        lists, stack = {}, []
        for name, args, lineno in _cmake_commands(text):
            if name == "set" and args:
                lists[args[0]] = [a for a in args[1:] if "$" not in a and a not in ("CACHE", "PARENT_SCOPE")]
            elif name == "list" and len(args) >= 3 and args[0] == "APPEND":
                lists.setdefault(args[1], []).extend(a for a in args[2:] if "$" not in a)
            elif name == "foreach" and args:
                var, rest = args[0], args[1:]
                items = []
                if rest[:1] == ["IN"]:
                    mode = None
                    for a in rest[1:]:
                        if a in ("LISTS", "ITEMS"):
                            mode = a
                        elif mode == "LISTS":
                            items.extend(lists.get(a, []))
                        elif mode == "ITEMS":
                            items.append(a)
                elif rest[:1] != ["RANGE"]:
                    for a in rest:
                        m = re.match(r"^\$\{(\w+)\}$", a)
                        items.extend(lists.get(m.group(1), []) if m else [a])
                stack.append((var, items))
            elif name == "endforeach":
                if stack:
                    stack.pop()
            elif name == "add_test" and args:
                if args[0] == "NAME" and len(args) >= 2:
                    tname = args[1]
                    cmd = args[args.index("COMMAND") + 1] if "COMMAND" in args[:-1] else ""
                else:
                    tname, cmd = args[0], (args[1] if len(args) > 1 else "")
                pairs = [(tname, cmd)]
                for var, items in reversed(stack):
                    ref = "${%s}" % var
                    if any(ref in a or ref in b for a, b in pairs):
                        pairs = [(a.replace(ref, it), b.replace(ref, it)) for a, b in pairs for it in items]
                for a, b in pairs:
                    if "$" in a:
                        continue
                    tests.setdefault(a, {"file": rel, "line": lineno, "command": b})
    return tests


TOOL_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ci_build_targets(tree):
    """Targets that the tree's .github/workflows/build.yml builds, read by the
    function of the existing NOT_BUILT drift guard. The helper is loaded from
    the repository this tool lives in, never from the tree under test."""
    helper = os.path.join(TOOL_REPO, "tools", "ci", "check_test_target_allowlist.py")
    build_yml = os.path.join(tree.root, ".github", "workflows", "build.yml")
    if not (os.path.isfile(helper) and os.path.isfile(build_yml)):
        return None
    spec = importlib.util.spec_from_file_location("canon_ci_allowlist", helper)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return set(mod.build_yml_targets(build_yml))


def junit_results(paths):
    """Map test name -> 'pass' | 'fail' | 'notrun' from ctest --output-junit."""
    res = {}
    for p in paths:
        try:
            root = ET.parse(p).getroot()
        except (OSError, ET.ParseError) as e:
            raise CanonError("cannot read junit %s: %s" % (p, e))
        for tc in root.iter("testcase"):
            name = tc.get("name")
            if not name:
                continue
            status = (tc.get("status") or "run").lower()
            failed = tc.find("failure") is not None or tc.find("error") is not None
            skipped = tc.find("skipped") is not None
            if failed or status in ("fail", "failed"):
                v = "fail"
            elif skipped or status in ("notrun", "disabled"):
                v = "notrun"
            else:
                v = "pass"
            if res.get(name) != "fail":
                res[name] = v
    return res


# =============================================================================
# 4. The deviations register
# =============================================================================

OPEN_WORDS = ("open",)
CLOSED_WORDS = ("closed", "rejected", "withdrawn")


def parse_register(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise CanonError("cannot read register %s: %s" % (path, e))
    header, rows = None, {}
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        low = [c.lower() for c in cells]
        if header is None:
            if "id" in low and "status" in low and "canon rule" in low:
                header = low
            continue
        if set(s.replace("|", "").strip()) <= set("-: "):
            continue
        if len(cells) != len(header):
            raise CanonError("register line %d: %d cells, header has %d" % (lineno, len(cells), len(header)))
        row = dict(zip(header, cells))
        did = row["id"]
        if not re.match(r"^D[0-9]+$", did):
            continue
        status_word = (re.match(r"[a-z]+", row["status"].lower()) or [""])[0]
        row["rules"] = re.findall(r"\bC[0-9]{2}\b", row["canon rule"])
        row["state"] = status_word
        row["line"] = lineno
        if did in rows:
            raise CanonError("register line %d: duplicate id %s" % (lineno, did))
        rows[did] = row
    if header is None:
        raise CanonError("register %s has no table with 'id', 'canon rule' and 'status' columns" % path)
    return rows


# =============================================================================
# 5. Checks
# =============================================================================

def _scope_files(tree, canon, chk):
    include, exclude, exts = [], [], None
    if chk.get("scope"):
        sc = canon.get("scopes", {}).get(chk["scope"])
        if sc is None:
            raise CanonError("check %s: unknown scope %r" % (chk.get("name"), chk["scope"]))
        include += sc.get("include") or []
        exclude += sc.get("exclude") or []
        exts = sc.get("extensions")
    include += chk.get("paths") or []
    exclude += chk.get("exclude") or []
    if chk.get("extensions"):
        exts = chk["extensions"]
    if not include:
        raise CanonError("check %s: no scope and no paths" % chk.get("name"))
    return tree.select(include, exclude, exts)


def _compile(chk):
    try:
        return re.compile(chk["pattern"], re.M)
    except (KeyError, re.error) as e:
        raise CanonError("check %s: bad or missing pattern: %s" % (chk.get("name"), e))


def _matches(tree, files, rx, code_only):
    hits = []
    for rel in files:
        t = tree.code(rel) if code_only else tree.text(rel)
        if not t:
            continue
        for m in rx.finditer(t):
            hits.append((rel, t.count("\n", 0, m.start()) + 1, m))
    return hits


def load_allowlist(path):
    """Lines: '<path> <max count> <reason>'. Returns {path: (count, reason)}."""
    allow = {}
    try:
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 2)
                if len(parts) < 3 or not parts[1].isdigit():
                    raise CanonError("allowlist %s line %d: want '<path> <count> <reason>'" % (path, lineno))
                if parts[0] in allow:
                    raise CanonError("allowlist %s line %d: duplicate path" % (path, lineno))
                allow[parts[0]] = (int(parts[1]), parts[2])
    except OSError as e:
        raise CanonError("cannot read allowlist %s: %s" % (path, e))
    return allow


def check_forbidden(tree, canon, canon_dir, chk):
    files = _scope_files(tree, canon, chk)
    hits = _matches(tree, files, _compile(chk), chk.get("code_only", False))
    per_file = {}
    for rel, line, _ in hits:
        per_file.setdefault(rel, []).append(line)
    allow = load_allowlist(os.path.join(canon_dir, chk["allowlist"])) if chk.get("allowlist") else {}
    violations, allowed, stale = {}, {}, []
    for rel, lines in per_file.items():
        cap = allow.get(rel, (0, ""))[0]
        if cap:
            allowed[rel] = min(cap, len(lines))
        if len(lines) > cap:
            violations[rel] = lines[cap:] if cap else lines
    for rel, (cap, _) in allow.items():
        have = len(per_file.get(rel, []))
        if have < cap:
            stale.append("%s: allowlisted %d, found %d" % (rel, cap, have))
    count = sum(len(v) for v in violations.values())
    sample = ["%s:%d" % (rel, ln) for rel in sorted(violations) for ln in violations[rel]][:12]
    return {
        "status": "fail" if count else "pass",
        "count": count,
        "allowed": sum(allowed.values()),
        "per_file": {k: len(v) for k, v in sorted(violations.items())},
        "allowlist_slack": stale,
        "files_scanned": len(files),
        "detail": ("%d match(es) outside the allowlist" % count) if count else "none",
        "sample": sample,
    }


def check_required(tree, canon, canon_dir, chk):
    files = _scope_files(tree, canon, chk)
    hits = _matches(tree, files, _compile(chk), chk.get("code_only", False))
    need = int(chk.get("min_count", 1))
    ok = len(hits) >= need
    return {
        "status": "pass" if ok else "fail",
        "count": len(hits),
        "files_scanned": len(files),
        "detail": "%d match(es), need >= %d" % (len(hits), need),
        "sample": ["%s:%d" % (r, ln) for r, ln, _ in hits[:6]],
    }


def check_constant(tree, canon, canon_dir, chk):
    files = _scope_files(tree, canon, chk)
    rx = _compile(chk)
    if rx.groups < 1:
        raise CanonError("check %s: a constant pattern needs one capture group" % chk.get("name"))
    hits = _matches(tree, files, rx, chk.get("code_only", True))
    lo, hi = chk.get("min"), chk.get("max")
    values, bad = [], []
    for rel, ln, m in hits:
        raw = m.group(1)
        try:
            v = int(raw, 0)
        except ValueError:
            bad.append("%s:%d non-integer %r" % (rel, ln, raw))
            continue
        values.append(("%s:%d" % (rel, ln), v))
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            bad.append("%s:%d = %d (allowed %s..%s)" % (rel, ln, v, lo, hi))
    if not hits and not chk.get("absent_ok", False):
        bad.append("constant not found in %d file(s)" % len(files))
    return {
        "status": "fail" if bad else "pass",
        "values": ["%s = %d" % (loc, v) for loc, v in values],
        "files_scanned": len(files),
        "detail": "; ".join(bad) if bad else (", ".join("%d" % v for _, v in values) or "absent (allowed)"),
    }


def check_required_kat(tree, canon, canon_dir, chk, ctx):
    tests = ctx.tests(tree)
    targets = ctx.targets(tree)
    junit = ctx.junit
    kats, problems = {}, []
    for k in chk.get("kats") or []:
        reg = tests.get(k)
        e = {"registered": bool(reg), "built_in_ci": None, "junit": None}
        if reg:
            e["where"] = "%s:%d" % (reg["file"], reg["line"])
            if targets is None:
                e["built_in_ci"] = None
            else:
                e["built_in_ci"] = k in targets or reg.get("command") in targets
        if junit is not None:
            e["junit"] = junit.get(k, "absent")
        ok = e["registered"] and e["built_in_ci"] is not False and (junit is None or e["junit"] == "pass")
        e["ok"] = bool(ok)
        if not e["registered"]:
            problems.append("%s not registered in CMake" % k)
        elif e["built_in_ci"] is False:
            problems.append("%s not in the build.yml --target lists (NOT_BUILT in CI)" % k)
        elif junit is not None and e["junit"] != "pass":
            problems.append("%s junit: %s" % (k, e["junit"]))
        kats[k] = e
    return {
        "status": "fail" if problems else "pass",
        "kats": kats,
        "detail": "; ".join(problems) if problems else "%d KAT(s) registered and built in CI%s"
        % (len(kats), " and passed in the junit" if junit is not None else ""),
    }


CANON_LINE_RE = re.compile(r"^[ \t>*_-]*Canon:[ \t]*(.+?)[ \t*_]*$", re.M)


def parse_canon_line(body, known_ids):
    """Returns (ok, ids, message)."""
    m = CANON_LINE_RE.search(body or "")
    if not m:
        return False, [], "no 'Canon:' line in the PR body"
    val = m.group(1).strip()
    if re.match(r"^none\b", val, re.I):
        return True, [], "Canon: none"
    ids, unknown = [], []
    for tok in [x for x in re.split(r"[,\s]+", val) if x]:
        r = re.match(r"^(C[0-9]{2})(?:-(C[0-9]{2}))?[.;]?$", tok)
        if not r:
            unknown.append(tok)
            continue
        a = int(r.group(1)[1:])
        b = int(r.group(2)[1:]) if r.group(2) else a
        for x in range(min(a, b), max(a, b) + 1):
            ids.append("C%02d" % x)
    unknown += [i for i in ids if i not in known_ids]
    if not ids and not unknown:
        return False, [], "empty 'Canon:' line"
    if unknown:
        return False, ids, "unknown rule id(s) in the Canon line: %s" % ", ".join(unknown)
    return True, ids, "Canon: %s" % ", ".join(ids)


KAT_LINE_RE = re.compile(r"^[ \t>*_-]*KAT:[ \t]*(.+?)[ \t*_]*$", re.M)


def parse_kat_line(body, registered):
    """Returns (ok, names, message). 'KAT: none (reason)' needs a reason; every
    named test must be registered in the tree's CMake."""
    m = KAT_LINE_RE.search(body or "")
    if not m:
        return False, [], "no 'KAT:' line in the PR body"
    val = m.group(1).strip()
    if re.match(r"^none\b", val, re.I):
        if re.search(r"\(\s*\S.{2,}\)", val):
            return True, [], "KAT: none, with a reason"
        return False, [], "'KAT: none' needs a reason in parentheses"
    bare = re.sub(r"\([^)]*\)", " ", val)   # "(RED on master, GREEN here)" is commentary
    names = [x.strip("`.;:") for x in re.split(r"[,\s]+", bare) if x.strip("`.;:")]
    names = [x for x in names if x.upper() not in ("RED", "GREEN", "RED/GREEN", "AND")]
    if not names:
        return False, [], "empty 'KAT:' line"
    unknown = [x for x in names if x not in registered]
    if unknown:
        return False, names, "KAT(s) not registered in CMake: %s" % ", ".join(unknown)
    return True, names, "KAT: %s" % ", ".join(names)


def check_pr_body(tree, canon, canon_dir, chk, ctx):
    if ctx.pr_body is None:
        return {"status": "n/a", "detail": "no --pr-body given"}
    changed = ctx.changed_files or []
    pats = [glob_to_re(p) for p in chk.get("paths") or []]
    touched = sorted(f for f in changed if any(r.match(f) for r in pats))
    if not touched:
        return {"status": "pass", "detail": "no governed path touched (%d changed file(s))" % len(changed),
                "touched": []}
    line = chk.get("line", "Canon")
    if line == "Canon":
        ok, ids, msg = parse_canon_line(ctx.pr_body, ctx.rule_ids)
    elif line == "KAT":
        ok, ids, msg = parse_kat_line(ctx.pr_body, set(ctx.tests(tree)))
    else:
        raise CanonError("check %s: unknown pr_body line %r" % (chk.get("name"), line))
    return {"status": "pass" if ok else "fail", "detail": msg, "touched": touched[:20], "named": ids}


# =============================================================================
# 6. Evaluation and classification
# =============================================================================

class Ctx:
    def __init__(self, junit=None, pr_body=None, changed_files=None):
        self.junit = junit
        self.pr_body = pr_body
        self.changed_files = changed_files
        self.rule_ids = set()
        self._tests = None
        self._targets = False

    def tests(self, tree):
        if self._tests is None:
            self._tests = cmake_tests(tree)
        return self._tests

    def targets(self, tree):
        if self._targets is False:
            self._targets = ci_build_targets(tree)
        return self._targets


# A ruled rule is the design: failing it without an open deviation is a NEW
# violation. A proposed rule is a researched gate that still waits for an
# operator ruling: it is evaluated and reported, never fails the run, needs no
# deviation, and becomes ruled (state: ruled, ruling: ...) in the PR that
# records the ruling.
RULE_STATES = ("ruled", "proposed")

CHECKS = {
    "forbidden": check_forbidden,
    "required": check_required,
    "constant": check_constant,
}


def run(tree, canon, canon_dir, register, baseline, ctx):
    rules = canon.get("rules") or []
    if not rules:
        raise CanonError("CANON.yaml has no rules")
    ctx.rule_ids = {r.get("id") for r in rules}
    results, new, notes = [], [], []
    seen = set()
    for r in rules:
        rid = r.get("id")
        if not rid or not re.match(r"^C[0-9]{2}$", rid) or rid in seen:
            raise CanonError("bad or duplicate rule id %r" % rid)
        seen.add(rid)
        for f in ("statement", "source", "checks"):
            if not r.get(f):
                raise CanonError("rule %s: missing %s" % (rid, f))
        state = r.get("state", "ruled")
        if state not in RULE_STATES:
            raise CanonError("rule %s: state %r is not one of %s" % (rid, state, ", ".join(RULE_STATES)))
        if state == "ruled" and not r.get("ruling"):
            raise CanonError("rule %s: a ruled rule names its ruling (who, when)" % rid)
        if state == "proposed":
            if not r.get("waits_for"):
                raise CanonError("rule %s: a proposed rule names the ruling it waits for (waits_for)" % rid)
            if r.get("deviation"):
                raise CanonError("rule %s: a proposed rule has no deviation; it is not yet the design" % rid)
        res = {"id": rid, "title": r.get("title", ""), "deviations": list(r.get("deviation") or []),
               "state": state, "ruling": r.get("ruling"), "waits_for": r.get("waits_for"),
               "status_now": r.get("status_now"), "checks": []}
        names = set()
        for chk in r["checks"]:
            name, typ = chk.get("name"), chk.get("type")
            if not name or name in names:
                raise CanonError("rule %s: check without a unique name" % rid)
            names.add(name)
            if typ in CHECKS:
                c = CHECKS[typ](tree, canon, canon_dir, chk)
            elif typ == "required_kat":
                c = check_required_kat(tree, canon, canon_dir, chk, ctx)
            elif typ == "pr_body":
                c = check_pr_body(tree, canon, canon_dir, chk, ctx)
            elif typ == "register":
                c = {"status": "pending"}
            else:
                raise CanonError("rule %s check %s: unknown type %r" % (rid, name, typ))
            c["name"], c["type"] = name, typ
            res["checks"].append(c)
        results.append(res)

    # The register rule (C09) is evaluated last, over the other results.
    for res in results:
        for c in res["checks"]:
            if c["type"] == "register":
                c.update(check_register(results, register, canon))
    for res in results:
        st = [c["status"] for c in res["checks"]]
        res["status"] = "fail" if "fail" in st else ("n/a" if all(s == "n/a" for s in st) else "pass")

    # Classification against the register and the baseline.
    base_rules = (baseline or {}).get("rules", {})
    for res in results:
        rid = res["id"]
        open_devs = [d for d in res["deviations"] if register.get(d, {}).get("state") in OPEN_WORDS]
        res["open_deviations"] = open_devs
        bchecks = base_rules.get(rid, {}).get("checks", {})
        res["new"] = []
        for c in res["checks"]:
            b = bchecks.get(c["name"])
            if c["status"] == "fail":
                if c["type"] in ("register", "pr_body"):
                    res["new"].append("%s: %s" % (c["name"], c["detail"]))
                elif b is None:
                    res["new"].append("%s fails and has no baseline entry: %s" % (c["name"], c["detail"]))
                elif b.get("status") == "pass":
                    res["new"].append("%s regressed (pass in baseline): %s" % (c["name"], c["detail"]))
            if c["type"] == "forbidden" and b is not None:
                bc = b.get("count", 0)
                if c["count"] > bc:
                    grown = {f: n for f, n in c["per_file"].items() if n > b.get("per_file", {}).get(f, 0)}
                    res["new"].append("%s count grew %d -> %d (%s)" % (
                        c["name"], bc, c["count"], ", ".join("%s +%d" % (f, n - b.get("per_file", {}).get(f, 0))
                                                             for f, n in sorted(grown.items())) or "moved"))
                elif c["count"] < bc:
                    notes.append("%s %s: count fell %d -> %d; lower the baseline (--write-baseline)" % (
                        rid, c["name"], bc, c["count"]))
            if c["type"] == "required_kat" and b is not None:
                for k, e in c["kats"].items():
                    if b.get("kats", {}).get(k) and not e["ok"]:
                        msg = "%s: required KAT %s was present in the baseline and is now %s" % (
                            c["name"], k, "missing" if not e["registered"] else
                            ("not built in CI" if e["built_in_ci"] is False else "not passing (%s)" % e["junit"]))
                        if msg not in res["new"]:
                            res["new"].append(msg)
            if c["status"] == "pass" and b is not None and b.get("status") == "fail":
                notes.append("%s %s: failed in the baseline, passes now" % (rid, c["name"]))
            for s in c.get("allowlist_slack") or []:
                notes.append("%s %s: allowlist slack, tighten it: %s" % (rid, c["name"], s))
        if res["status"] == "fail" and not open_devs and not any(
                c["type"] in ("register", "pr_body") for c in res["checks"] if c["status"] == "fail"):
            res["new"].insert(0, "rule fails and has no open deviation in the register")
        if res["state"] == "proposed":
            for m in res["new"]:
                if "no open deviation" not in m:
                    notes.append("%s (proposed, waits for: %s) %s" % (rid, res["waits_for"], m))
            res["new"] = []
            res["verdict"] = "proposed"
        elif res["new"]:
            res["verdict"] = "NEW"
        elif res["status"] == "fail":
            res["verdict"] = "known"
        elif res["status"] == "n/a":
            res["verdict"] = "n/a"
        else:
            res["verdict"] = "ok"
        if res["status_now"] and res["status"] != "n/a" and res["status"] != res["status_now"]:
            notes.append("%s: status is %s, CANON.yaml records status_now %s; update it" % (
                rid, res["status"], res["status_now"]))
        for m in res["new"]:
            new.append("%s %s" % (rid, m))

    closable = []
    for did, row in sorted(register.items(), key=lambda kv: int(kv[0][1:])):
        if row["state"] not in OPEN_WORDS:
            continue
        mapped = [x for x in results if did in x["deviations"]]
        if mapped and all(x["status"] == "pass" for x in mapped):
            closable.append(did)
            notes.append("%s: every rule it maps to (%s) passes now; close it in the register with the closing PR" % (
                did, ", ".join(x["id"] for x in mapped)))
    return results, new, notes, closable


def check_register(results, register, canon):
    problems = []
    ids = {r["id"] for r in results}
    for res in results:
        if any(c["type"] == "register" for c in res["checks"]):
            continue
        for d in res["deviations"]:
            row = register.get(d)
            if row is None:
                problems.append("%s names %s, which is not in the register" % (res["id"], d))
            elif res["id"] not in row["rules"]:
                problems.append("%s names %s, but the register row of %s does not list %s" % (
                    res["id"], d, d, res["id"]))
    for d, row in register.items():
        if row["state"] not in OPEN_WORDS + CLOSED_WORDS:
            problems.append("%s: status %r is not one of open, closed, rejected, withdrawn" % (d, row["status"]))
        for rid in row["rules"]:
            if rid not in ids:
                problems.append("%s lists unknown rule %s" % (d, rid))
            else:
                rr = next(x for x in results if x["id"] == rid)
                if d not in rr["deviations"]:
                    problems.append("%s lists %s, but CANON.yaml rule %s does not name %s" % (d, rid, rid, d))
        if row["state"] in OPEN_WORDS and not row["rules"]:
            problems.append("%s is open but maps to no canon rule" % d)
    for res in results:
        if any(c["type"] == "register" for c in res["checks"]):
            continue
        if res.get("state") == "proposed":
            continue
        failing = any(c["status"] == "fail" and c["type"] != "pr_body" for c in res["checks"])
        if failing:
            if not [d for d in res["deviations"] if register.get(d, {}).get("state") in OPEN_WORDS]:
                problems.append("%s fails and maps to no open deviation" % res["id"])
    return {"status": "fail" if problems else "pass",
            "detail": "; ".join(problems) if problems else
            "every failing rule maps to an open deviation; register and canon agree",
            "problems": problems}


def make_baseline(results, head):
    out = {"comment": "Baseline of docs/canon/CANON.yaml. Regenerate with tools/canon/canon_check.py "
                      "--write-baseline only when a count fell or a ruled change was registered.",
           "commit": head, "rules": {}}
    for res in results:
        checks = {}
        for c in res["checks"]:
            if c["type"] in ("pr_body", "register"):
                continue
            e = {"status": c["status"]}
            if c["type"] == "forbidden":
                e["count"] = c["count"]
                e["per_file"] = c["per_file"]
            if c["type"] == "required_kat":
                e["kats"] = {k: bool(v["registered"] and v["built_in_ci"] is not False)
                             for k, v in c["kats"].items()}
            checks[c["name"]] = e
        out["rules"][res["id"]] = {"status": res["status"], "checks": checks}
    return out


def signature(results, new):
    return " ".join("%s:%s" % (r["id"], r["status"]) for r in results) + " new:%d" % len(new)


def print_table(results, new, notes, closable, head, out=sys.stdout):
    w = out.write
    w("canon_check: %s\n\n" % (head or "(no git head)"))
    w("%-4s %-6s %-8s %-10s %s\n" % ("RULE", "STATUS", "VERDICT", "DEVIATION", "CHECKS"))
    for r in results:
        first = True
        for c in r["checks"]:
            line = "%s=%s (%s)" % (c["name"], c["status"], c.get("detail", ""))
            if first:
                w("%-4s %-6s %-8s %-10s %s\n" % (r["id"], r["status"], r["verdict"],
                                               ",".join(r["deviations"]) or "-", line))
                first = False
            else:
                w("%-4s %-6s %-8s %-10s %s\n" % ("", "", "", "", line))
    w("\nNEW VIOLATIONS: %d\n" % len(new))
    for m in new:
        w("  NEW %s\n" % m)
    if closable:
        w("\nREGISTER UPDATE: deviation(s) closable now: %s\n" % ", ".join(closable))
    if notes:
        w("\nNOTES:\n")
        for m in notes:
            w("  %s\n" % m)


def gh_annotations(new, closable, notes):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for m in new:
        print("::error title=canon::%s" % m)
    for d in closable:
        print("::warning title=canon::deviation %s is closable: all its rules pass; update docs/canon/DEVIATIONS.md" % d)
    for m in notes:
        print("::notice title=canon::%s" % m)


# =============================================================================
# 7. Self-test
# =============================================================================

def selftest(canon_path):
    fails = []

    def ok(cond, what):
        if not cond:
            fails.append(what)

    y = parse_yaml("a: 1\nb:\n  - x\n  - 'y: z'\nc:\n- name: n\n  v: [1, 'two', \"3\"]\n  w: true\n# c\nd: ~\n")
    ok(y == {"a": 1, "b": ["x", "y: z"], "c": [{"name": "n", "v": [1, "two", "3"], "w": True}], "d": None},
       "yaml subset basic: %r" % (y,))
    ok(parse_yaml("p: 'a\\d+''b'  # comment\n") == {"p": "a\\d+'b"}, "yaml single quotes")
    for bad in ("a: |\n  x\n", "a:\n\tb: 1\n", "a: {b: 1}\n", "a: 1\na: 2\n"):
        try:
            parse_yaml(bad)
            fails.append("yaml accepted %r" % bad)
        except CanonError:
            pass  # expected: the YAML subset parser refuses this input
    ok(glob_to_re("src/impl/xmr/**").match("src/impl/xmr/a/b.hpp"), "glob **")
    ok(not glob_to_re("src/impl/xmr/*.hpp").match("src/impl/xmr/a/b.hpp"), "glob *")
    ok(glob_to_re("**/test/**").match("src/impl/xmr/test/x.cpp"), "glob leading **")
    ok(glob_to_re("src/c2pool/v37/xmr/").match("src/c2pool/v37/xmr/relay/a.hpp"), "glob dir prefix")
    src = 'int a = 1\'000; // Clock::now()\nauto s = "uncle";/* uncle\n */ x = R"(uncle)"; char c = \'"\';\n'
    st = strip_c_comments(src)
    ok("uncle" not in st and "Clock::now" not in st and st.count("\n") == src.count("\n") and len(st) == len(src),
       "comment stripping: %r" % st)
    ok(parse_canon_line("x\nCanon: C03, C07\n", {"C03", "C07"})[0], "canon line list")
    ok(parse_canon_line("Canon: C01-C10", {"C%02d" % i for i in range(1, 11)})[1] ==
       ["C%02d" % i for i in range(1, 11)], "canon line range")
    ok(parse_canon_line("Canon: none (non-consensus)", set())[0], "canon line none")
    ok(not parse_canon_line("no line here", set())[0], "canon line missing")
    ok(not parse_canon_line("Canon: C99", {"C01"})[0], "canon line unknown id")
    ok(parse_kat_line("KAT: xmr_a_kat, xmr_b_kat (RED on master, GREEN here)", {"xmr_a_kat", "xmr_b_kat"})[0],
       "kat line with commentary")
    ok(not parse_kat_line("KAT: xmr_a_kat stray", {"xmr_a_kat"})[0], "kat line rejects stray words")
    ok(parse_kat_line("KAT: xmr_a_kat, xmr_b_kat", {"xmr_a_kat", "xmr_b_kat"})[0], "kat line names")
    ok(not parse_kat_line("KAT: xmr_c_kat", {"xmr_a_kat"})[0], "kat line unknown test")
    ok(parse_kat_line("KAT: none (comment-only change)", set())[0], "kat line none with reason")
    ok(not parse_kat_line("KAT: none", set())[0], "kat line none without reason")
    ok(not parse_kat_line("no line", set())[0], "kat line missing")
    cm = ("set(L a_kat b_kat)\nforeach(k IN LISTS L)\n  add_test(NAME ${k} COMMAND ${k})\nendforeach()\n"
          "foreach(z c_kat d_kat)\n add_test(NAME ${z} COMMAND ${z})\nendforeach()\n"
          "add_test(NAME e_kat COMMAND e_bin --x) # add_test(NAME f_kat COMMAND f)\n")

    class _T(Tree):
        def __init__(self):
            super().__init__("/")

        def select(self, include, exclude=(), exts=None):
            return ["CMakeLists.txt"]

        def text(self, rel):
            return cm

    t = cmake_tests(_T())
    ok(sorted(t) == ["a_kat", "b_kat", "c_kat", "d_kat", "e_kat"] and t["e_kat"]["command"] == "e_bin",
       "cmake foreach expansion: %r" % sorted(t))

    if canon_path and os.path.isfile(canon_path):
        with open(canon_path, encoding="utf-8") as f:
            text = f.read()
        mine = parse_yaml(text)
        try:
            import yaml  # noqa: F401  (optional cross-check only)
            theirs = yaml.safe_load(text)
            ok(mine == theirs, "CANON.yaml: subset parser and PyYAML disagree")
            print("selftest: CANON.yaml parsed identically by the subset parser and PyYAML %s" % yaml.__version__)
        except ImportError:
            print("selftest: PyYAML not installed; subset parser only")
    for f in fails:
        print("SELFTEST FAIL: %s" % f)
    print("selftest: %s" % ("FAIL" if fails else "ok"))
    return 1 if fails else 0


# =============================================================================
# 8. CLI
# =============================================================================

def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.dirname(os.path.dirname(here))
    ap = argparse.ArgumentParser(description="Check a c2pool checkout against the v37 design canon.")
    ap.add_argument("--root", default=default_root, help="checkout to check (default: this repo)")
    ap.add_argument("--canon", help="CANON.yaml (default: <root>/docs/canon/CANON.yaml); its directory "
                                    "also holds the register, baseline and allowlists")
    ap.add_argument("--register", help="deviations register (default: from CANON.yaml)")
    ap.add_argument("--baseline", help="baseline JSON (default: from CANON.yaml)")
    ap.add_argument("--json", help="write the JSON report here")
    ap.add_argument("--junit", action="append", default=[], help="ctest --output-junit file(s); required KATs "
                                                                 "must pass in them")
    ap.add_argument("--pr-body", help="file with the pull request body (enables rule C10)")
    ap.add_argument("--changed-files", help="file listing the PR's changed paths, one per line")
    ap.add_argument("--base", help="git ref to diff against for the changed files (instead of --changed-files)")
    ap.add_argument("--write-baseline", action="store_true",
                    help="write the baseline from this run; refused while the run has new violations "
                         "against the existing baseline (the baseline only ratchets down)")
    ap.add_argument("--accept-new", action="store_true",
                    help="with --write-baseline: write it even over new violations (needs an operator ruling)")
    ap.add_argument("--selftest", action="store_true", help="run the parser and helper self-test")
    ap.add_argument("--quiet", action="store_true", help="print only new violations and the summary")
    a = ap.parse_args(argv)

    canon_path = os.path.abspath(a.canon or os.path.join(a.root, "docs", "canon", "CANON.yaml"))
    if a.selftest:
        return selftest(canon_path)
    try:
        with open(canon_path, encoding="utf-8") as f:
            canon = parse_yaml(f.read())
        if not isinstance(canon, dict):
            raise CanonError("CANON.yaml must be a mapping")
        canon_dir = os.path.dirname(canon_path)
        reg_path = os.path.abspath(a.register or os.path.join(canon_dir, canon.get("register", "DEVIATIONS.md")))
        base_path = os.path.abspath(a.baseline or os.path.join(canon_dir, canon.get("baseline", "baseline.json")))
        register = parse_register(reg_path)
        baseline = None
        if os.path.isfile(base_path):
            with open(base_path, encoding="utf-8") as f:
                baseline = json.load(f)
        tree = Tree(a.root)
        pr_body, changed = None, None
        if a.pr_body:
            with open(a.pr_body, encoding="utf-8", errors="replace") as f:
                pr_body = f.read()
            if a.changed_files:
                with open(a.changed_files, encoding="utf-8") as f:
                    changed = [x.strip() for x in f if x.strip()]
            elif a.base:
                out = subprocess.check_output(["git", "-C", tree.root, "diff", "--name-only", a.base + "...HEAD"],
                                              text=True)
                changed = [x.strip() for x in out.splitlines() if x.strip()]
            else:
                raise CanonError("--pr-body needs --changed-files or --base")
        ctx = Ctx(junit=junit_results(a.junit) if a.junit else None, pr_body=pr_body, changed_files=changed)
        results, new, notes, closable = run(tree, canon, canon_dir, register, baseline, ctx)
    except (CanonError, OSError, ValueError, subprocess.CalledProcessError) as e:
        print("canon_check: error: %s" % e, file=sys.stderr)
        return 2

    head = tree.head()
    if a.write_baseline:
        if new and baseline is not None and not a.accept_new:
            print("canon_check: baseline NOT written: %d new violation(s) against the existing baseline; "
                  "fix them, or pass --accept-new under an operator ruling" % len(new), file=sys.stderr)
            for m in new:
                print("  NEW %s" % m, file=sys.stderr)
            return 1
        b = make_baseline(results, head)
        with open(base_path, "w", encoding="utf-8") as f:
            json.dump(b, f, indent=2, sort_keys=True)
            f.write("\n")
        print("canon_check: baseline written to %s" % base_path)
        new = [m for m in new if "no baseline entry" not in m and "regressed" not in m and "grew" not in m]
    if a.quiet:
        for m in new:
            print("NEW %s" % m)
        if closable:
            print("REGISTER UPDATE: deviation(s) closable now: %s" % ", ".join(closable))
    else:
        print_table(results, new, notes, closable, head)
    print("\nSUMMARY: %s" % signature(results, new))
    gh_annotations(new, closable, notes)
    if a.json:
        rep = {
            "tool": "canon_check", "version": TOOL_VERSION,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "root": tree.root, "head": head, "canon": canon_path, "register": reg_path, "baseline": base_path,
            "junit": a.junit, "rules": results, "new_violations": new, "notes": notes,
            "closable_deviations": closable, "signature": signature(results, new),
        }
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2, default=str)
            f.write("\n")
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
