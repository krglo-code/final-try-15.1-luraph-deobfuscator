#!/usr/bin/env python3
"""
Safe static triage for Lua/Luau files.
Never imports, evaluates, compiles, or executes the target script.
Produces indicators and readable literal strings for manual review.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

PATTERNS = {
    "luraph_v15_1_header": r"Luraph\s+Obfuscator\s+v?15\.1",
    "luraph_encrypted_strings_v2": r"LPH_ENCSTR2",
    "luraph_encrypted_function": r"LPH_ENCFUNC",
    "superflow_blob_marker": r"_bsdata0",
    "flowauth_reference": r"flowauth",
    "virtual_machine_dispatch": r"\bwhile\b[\s\S]{0,300}?\b(?:opcode|instruction|dispatch)\b",
    "dynamic_loader": r"\b(?:loadstring|load)\s*\(",
    "environment_access": r"\b(?:getfenv|setfenv|_ENV)\b",
    "http_access": r"\b(?:HttpGet|http_request|request)\b",
    "executor_globals": r"\b(?:getgenv|identifyexecutor|getrenv|getrenv)\b",
}

# Lua quoted strings and long-bracket strings; strings are data, never evaluated.
STRING_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\[(=*)\[(.*?)\]\1\]',
    re.DOTALL,
)

def _scan_lua(source: str):
    """Yield (kind, value) tokens without evaluating Lua code.

    Handles quoted strings, long-bracket strings/comments, line comments,
    and ordinary code. This is intentionally a small lexer, not a parser.
    """
    i, n = 0, len(source)
    while i < n:
        if source.startswith("--", i):
            # Long comment: --[=[ ... ]=]
            m = re.match(r"--\[(=*)\[", source[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = source.find(close, i + m.end())
                end = n if j < 0 else j + len(close)
            else:
                j = source.find("\n", i + 2)
                end = n if j < 0 else j + 1
            yield "code", " " * (end - i)
            i = end
            continue
        if source[i] in "\"'":
            quote, j = source[i], i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                elif source[j] == quote:
                    j += 1
                    break
                else:
                    j += 1
            raw = source[i:j]
            yield "string", raw
            i = j
            continue
        if source[i] == "[":
            m = re.match(r"\[(=*)\[", source[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = source.find(close, i + m.end())
                end = n if j < 0 else j + len(close)
                yield "string", source[i:end]
                i = end
                continue
        # Emit code one character at a time; comments and strings are omitted
        # from the code stream used for marker matching.
        yield "code", source[i]
        i += 1


def _decode_lua_string(raw: str) -> str:
    if raw.startswith("["):
        m = re.match(r"\[(=*)\[(.*)\]\1\]$", raw, re.DOTALL)
        return m.group(2) if m else raw
    body = raw[1:-1]
    # Decode one escape at a time so a literal ``\\n`` is not mistaken
    # for a newline (Lua parses ``\\`` before the following ``n``).
    escapes = {"\\": "\\", '"': '"', "'": "'", "n": "\n", "r": "\r", "t": "\t"}
    return re.sub(r"\\(.)", lambda m: escapes.get(m.group(1), "\\" + m.group(1)), body)


def readable_strings(source: str, minimum: int = 4) -> list[str]:
    found, seen = [], set()
    for kind, raw in _scan_lua(source):
        if kind != "string":
            continue
        value = _decode_lua_string(raw)
        if len(value) >= minimum and any(c.isalpha() for c in value):
            if value not in seen:
                seen.add(value)
                found.append(value[:500])
    return found[:500]


def code_only(source: str) -> str:
    """Return code characters with comments and string contents blanked."""
    out = []
    for kind, value in _scan_lua(source):
        if kind == "code":
            out.append(value)
        else:
            out.append(" " * len(value))
    return "".join(out)

def analyze(path: Path) -> dict:
    raw = path.read_bytes()
    source = raw.decode("utf-8", "replace")
    indicators = []
    searchable = code_only(source)
    for name, pattern in PATTERNS.items():
        count = len(re.findall(pattern, searchable, re.IGNORECASE))
        if count:
            indicators.append({"name": name, "matches": count})
    return {
        "file": path.name,
        "bytes": len(raw),
        "lines": source.count("\n") + (1 if source else 0),
        "indicators": indicators,
        "readable_strings": readable_strings(source),
        "limitations": [
            "This is static triage, not a Luraph decryptor or devirtualizer.",
            "Encrypted constants and VM bytecode may remain opaque.",
            "No target code was executed; indicators can produce false positives.",
            "A complete source-level reconstruction cannot be guaranteed."
        ]
    }

def main() -> int:
    ap = argparse.ArgumentParser(description="Non-executing Lua/Luau static triage")
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", type=Path, help="JSON report path (default: stdout)")
    args = ap.parse_args()
    if not args.input.is_file():
        ap.error(f"input file does not exist: {args.input}")
    report = analyze(args.input)
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Static report written to {args.output}")
    else:
        print(rendered)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
