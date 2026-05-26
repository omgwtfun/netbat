"""Tokenizer and recursive-descent parser for JunOS hierarchical config format.

A Statement is a 3-tuple: (keyword, args, children)
  keyword  – first token of the statement (str)
  args     – list of tokens that follow keyword before { or ; (list[str])
  children – None for leaf statements ( ...;), list[Statement] for blocks ( ...{ })

Bracket notation  application [ junos-http junos-https ];  is flattened so that
the bracketed items are appended to args and children is None.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

Statement = Tuple[str, List[str], Optional[List]]

_STRUCTURAL = frozenset(["{", "}", "[", "]", ";"])


def tokenize(text: str) -> List[str]:
    """Convert JunOS config text to a flat list of tokens."""
    tokens: List[str] = []
    i = 0
    n = len(text)

    while i < n:
        c = text[i]

        if c.isspace():
            i += 1
            continue

        # Single-line comment
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue

        # Block comment
        if text[i : i + 2] == "/*":
            end = text.find("*/", i + 2)
            i = (end + 2) if end != -1 else n
            continue

        # Structural single-char tokens
        if c in _STRUCTURAL:
            tokens.append(c)
            i += 1
            continue

        # Double-quoted string – content without the surrounding quotes
        if c == '"':
            i += 1
            start = i
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 1
                i += 1
            tokens.append(text[start:i])
            i += 1  # skip closing "
            continue

        # Bare word (identifier, IP, etc.)
        start = i
        while i < n and not text[i].isspace() and text[i] not in _STRUCTURAL:
            i += 1
        if i > start:
            tokens.append(text[start:i])

    return tokens


def parse(tokens: List[str]) -> List[Statement]:
    """Parse a flat token list into a list of Statements."""
    pos = [0]  # mutable index shared across nested calls

    def parse_block() -> List[Statement]:
        stmts: List[Statement] = []
        while pos[0] < len(tokens) and tokens[pos[0]] != "}":
            stmt = _parse_statement()
            if stmt is not None:
                stmts.append(stmt)
        return stmts

    def _parse_statement() -> Optional[Statement]:
        if pos[0] >= len(tokens):
            return None

        keyword = tokens[pos[0]]
        pos[0] += 1

        # Collect args until we hit a structural token
        args: List[str] = []
        while pos[0] < len(tokens) and tokens[pos[0]] not in _STRUCTURAL:
            args.append(tokens[pos[0]])
            pos[0] += 1

        if pos[0] >= len(tokens):
            return (keyword, args, None)

        tok = tokens[pos[0]]

        if tok == ";":
            pos[0] += 1
            return (keyword, args, None)

        # Bracket notation:  key [ v1 v2 v3 ];
        if tok == "[":
            pos[0] += 1
            while pos[0] < len(tokens) and tokens[pos[0]] != "]":
                args.append(tokens[pos[0]])
                pos[0] += 1
            if pos[0] < len(tokens):
                pos[0] += 1  # skip ]
            if pos[0] < len(tokens) and tokens[pos[0]] == ";":
                pos[0] += 1
            return (keyword, args, None)

        # Block:  key args* { ... }
        if tok == "{":
            pos[0] += 1
            children = parse_block()
            if pos[0] < len(tokens) and tokens[pos[0]] == "}":
                pos[0] += 1
            return (keyword, args, children)

        return (keyword, args, None)

    return parse_block()


def parse_config(text: str) -> List[Statement]:
    """Parse JunOS hierarchical config text and return a Statement list."""
    return parse(tokenize(text))
