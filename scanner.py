# This Python file uses the following encoding: utf-8

"""
YaraScanner - Pure-logic YARA scanning, compilation, formatting, and validation.

No UI dependencies. Returns data or raises exceptions for the caller to handle.
"""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# Check if yara_x is available
try:
    import yara_x
    YARA_X_AVAILABLE = True
except ImportError:
    YARA_X_AVAILABLE = False

# Check if yaraast is available
try:
    import yaraast
    from yaraast.parser.better_parser import Parser
    from yaraast.codegen import CodeGenerator
    YARAAST_AVAILABLE = True
except ImportError:
    YARAAST_AVAILABLE = False


# ── Filesize pre-filter ────────────────────────────────────────────
#
# YARA conditions can express file-size constraints like `filesize < 500KB`.
# When every rule in a ruleset has such an upper bound, we can skip files
# that exceed the bound without reading them — a big win when the user
# points the scanner at a directory full of multi-GB files.
#
# Primary implementation: walk the yaraast AST and compute an interval
# ``(min_size, max_size)`` per rule, properly honouring boolean structure
# (``and`` = intersect, ``or`` = interval union, ``not`` = give up).
# Falls back to a conservative regex scan if yaraast is unavailable.
#
# INVARIANT: the returned interval must be a *superset* of the set of
# filesizes that could actually satisfy the condition, so ``can_skip``
# can never produce a false negative (skipping a file that might match).


@dataclass
class SizeBounds:
    """File-size bounds derived from a ruleset's conditions.

    ``min_size`` / ``max_size`` describe the inclusive range of file sizes
    that could still match *some* rule. ``max_size`` is ``None`` when the
    ruleset is unbounded above (i.e. no useful upper bound detected).
    """
    min_size: int = 0
    max_size: Optional[int] = None

    def is_useful(self) -> bool:
        """True iff we could actually skip *something* with these bounds."""
        return self.max_size is not None or self.min_size > 0

    def can_skip(self, file_size: int) -> bool:
        if self.max_size is not None and file_size > self.max_size:
            return True
        if file_size < self.min_size:
            return True
        return False


# Flip the operator when the operands are swapped (e.g. `N < filesize`
# becomes `filesize > N`).
_OP_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=",
            "==": "==", "!=": "!="}

# ── AST-based analysis (primary path, uses yaraast) ────────────────

# An "unbounded" interval: any non-negative file size is possible.
_UNBOUNDED: Tuple[int, Optional[int]] = (0, None)


def _is_filesize_identifier(node) -> bool:
    return (type(node).__name__ == "Identifier"
            and getattr(node, "name", None) == "filesize")


def _int_literal_value(node) -> Optional[int]:
    if type(node).__name__ == "IntegerLiteral":
        v = getattr(node, "value", None)
        if isinstance(v, int):
            return v
    return None


def _tighten_cmp(op: str, val: int) -> Tuple[int, Optional[int]]:
    """Interval for `filesize <op> val`.

    Clamps lower bound to 0 (filesize is unsigned).
    """
    if op == "<":
        return (0, max(-1, val - 1))
    if op == "<=":
        return (0, max(-1, val))
    if op == ">":
        return (max(0, val + 1), None)
    if op == ">=":
        return (max(0, val), None)
    if op == "==":
        return (max(0, val), val)
    # '!=' can't tighten an interval representation
    return _UNBOUNDED


def _bounds_and(a: Tuple[int, Optional[int]],
                b: Tuple[int, Optional[int]]) -> Tuple[int, Optional[int]]:
    """Intersect two intervals."""
    lo = max(a[0], b[0])
    if a[1] is None:
        hi = b[1]
    elif b[1] is None:
        hi = a[1]
    else:
        hi = min(a[1], b[1])
    return (lo, hi)


def _bounds_or(a: Tuple[int, Optional[int]],
               b: Tuple[int, Optional[int]]) -> Tuple[int, Optional[int]]:
    """Smallest interval containing both `a` and `b` (a SAFE superset
    of the actual set union — a disjoint union is approximated upwards).
    """
    lo = min(a[0], b[0])
    if a[1] is None or b[1] is None:
        hi: Optional[int] = None
    else:
        hi = max(a[1], b[1])
    return (lo, hi)


def _bounds_from_comparison(node) -> Tuple[int, Optional[int]]:
    """Extract the filesize bound from a comparison BinaryExpression.

    Returns the unbounded interval if the comparison doesn't directly
    constrain `filesize` against an integer literal (e.g. it references
    `filesize - 4` inside a function call, or compares against a
    non-literal expression).
    """
    op = getattr(node, "operator", None)
    if op not in ("<", "<=", ">", ">=", "==", "!="):
        return _UNBOUNDED
    left = getattr(node, "left", None)
    right = getattr(node, "right", None)
    if left is None or right is None:
        return _UNBOUNDED

    # Case 1: `filesize <op> N`
    if _is_filesize_identifier(left):
        v = _int_literal_value(right)
        if v is None:
            return _UNBOUNDED
        return _tighten_cmp(op, v)

    # Case 2: `N <op> filesize`
    if _is_filesize_identifier(right):
        v = _int_literal_value(left)
        if v is None:
            return _UNBOUNDED
        return _tighten_cmp(_OP_FLIP.get(op, op), v)

    return _UNBOUNDED


def _bounds_from_ast(node) -> Tuple[int, Optional[int]]:
    """Recursively compute the filesize interval satisfying ``node``.

    The returned interval is always a superset of the true satisfying
    set, so it's safe to use for pre-filtering. Nodes that we can't
    reason about return the unbounded interval (i.e. "no information").
    """
    if node is None:
        return _UNBOUNDED

    kind = type(node).__name__

    # Unwrap parentheses.
    if kind == "ParenthesesExpression":
        kids = list(node.children()) if callable(
            getattr(node, "children", None)) else []
        return _bounds_from_ast(kids[0]) if kids else _UNBOUNDED

    # `not X`, `defined X`, etc. — giving up is always safe.
    if kind == "UnaryExpression":
        return _UNBOUNDED

    if kind == "BinaryExpression":
        op = getattr(node, "operator", None)
        if op == "and":
            return _bounds_and(_bounds_from_ast(node.left),
                               _bounds_from_ast(node.right))
        if op == "or":
            return _bounds_or(_bounds_from_ast(node.left),
                              _bounds_from_ast(node.right))
        if op in ("<", "<=", ">", ">=", "==", "!="):
            return _bounds_from_comparison(node)
        # Arithmetic / bitwise / etc. — no filesize info at this level.
        return _UNBOUNDED

    # Any other node type (identifiers, literals, function calls,
    # string matches, `of` expressions, `for` loops …) carries no
    # filesize information on its own.
    return _UNBOUNDED


def _compute_bounds_via_ast(rule_text: str) -> Optional[SizeBounds]:
    """Try to compute bounds via the yaraast AST. Returns None on failure
    (yaraast missing, parse error, etc.) so the caller can fall back."""
    try:
        from yaraast.parser.better_parser import Parser  # type: ignore
    except Exception:
        return None

    try:
        ast = Parser().parse(rule_text)
    except Exception:
        return None

    rules = getattr(ast, "rules", None) or []
    if not rules:
        return None

    per_rule: List[Tuple[int, Optional[int]]] = []
    for rule in rules:
        cond = getattr(rule, "condition", None)
        if cond is None:
            return None  # Rule has no condition? Bail safely.
        try:
            per_rule.append(_bounds_from_ast(cond))
        except Exception:
            return None  # Unexpected AST shape — give up cleanly.

    # A file can be skipped only if NO rule could possibly match it.
    # Global min = min of per-rule mins (smallest file that might match).
    # Global max = max of per-rule maxes (biggest file that might match),
    #              or None if any rule is unbounded above.
    global_min = min(rb[0] for rb in per_rule)
    maxes = [rb[1] for rb in per_rule]
    global_max: Optional[int]
    if any(m is None for m in maxes):
        global_max = None
    else:
        global_max = max(m for m in maxes)  # type: ignore[arg-type]

    return SizeBounds(min_size=global_min, max_size=global_max)


# ── Regex fallback (used when yaraast is unavailable) ──────────────

_UNIT_MULTIPLIERS = {
    "": 1,
    "B": 1,
    "KB": 1024,
    "MB": 1024 ** 2,
}

# `filesize <op> N [unit]`
_FILESIZE_LHS_RE = re.compile(
    r"\bfilesize\s*(<=|<|>=|>|==|!=)\s*"
    r"(0x[0-9a-fA-F]+|\d+)\s*(KB|MB|B)?",
    re.IGNORECASE,
)
# `N [unit] <op> filesize`
_FILESIZE_RHS_RE = re.compile(
    r"(0x[0-9a-fA-F]+|\d+)\s*(KB|MB|B)?\s*"
    r"(<=|<|>=|>|==|!=)\s*filesize\b",
    re.IGNORECASE,
)


def _parse_number(literal: str) -> int:
    return int(literal, 16) if literal.lower().startswith("0x") else int(literal)


def _apply_unit(value: int, unit: Optional[str]) -> int:
    return value * _UNIT_MULTIPLIERS[(unit or "").upper()]


def _strip_comments(text: str) -> str:
    """Strip // line comments and /* block comments */ from YARA source."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def _extract_conditions(rule_text: str) -> List[str]:
    """Return the condition text of each rule in *rule_text* via
    brace-matching. Fallback path only."""
    text = _strip_comments(rule_text)
    out: List[str] = []
    i = 0
    while i < len(text):
        m = re.search(r"\brule\s+\w+[^{]*\{", text[i:])
        if not m:
            break
        brace_open = i + m.end() - 1
        depth = 0
        j = brace_open
        while j < len(text):
            ch = text[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(text):
            return out
        body = text[brace_open + 1:j]
        cm = re.search(r"\bcondition\s*:", body)
        if cm is not None:
            out.append(body[cm.end():].strip())
        i = j + 1
    return out


def _condition_is_parseable(cond: str) -> bool:
    """Conservative: bail on `or`/`not`. Fallback path only."""
    cleaned = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', " ", cond)
    if re.search(r"\bor\b", cleaned, re.IGNORECASE):
        return False
    if re.search(r"\bnot\b", cleaned, re.IGNORECASE):
        return False
    return True


def _tighten(lo: int, hi: Optional[int], op: str,
             val: int) -> Tuple[int, Optional[int]]:
    """Apply one `filesize <op> val` constraint. Fallback path only."""
    if op == "<":
        new_hi = val - 1
        return (lo, new_hi if hi is None else min(hi, new_hi))
    if op == "<=":
        return (lo, val if hi is None else min(hi, val))
    if op == ">":
        return (max(lo, val + 1), hi)
    if op == ">=":
        return (max(lo, val), hi)
    if op == "==":
        return (max(lo, val), val if hi is None else min(hi, val))
    return (lo, hi)


def _rule_size_bounds_regex(cond: str) -> Optional[Tuple[int, Optional[int]]]:
    if not _condition_is_parseable(cond):
        return None
    lo: int = 0
    hi: Optional[int] = None
    for m in _FILESIZE_LHS_RE.finditer(cond):
        op = m.group(1)
        n = _parse_number(m.group(2))
        size = _apply_unit(n, m.group(3))
        lo, hi = _tighten(lo, hi, op, size)
    for m in _FILESIZE_RHS_RE.finditer(cond):
        n = _parse_number(m.group(1))
        size = _apply_unit(n, m.group(2))
        op = _OP_FLIP[m.group(3)]
        lo, hi = _tighten(lo, hi, op, size)
    return (lo, hi)


def _compute_bounds_via_regex(rule_text: str) -> SizeBounds:
    """Conservative regex-based bounds (fallback when yaraast is absent)."""
    conditions = _extract_conditions(rule_text)
    if not conditions:
        return SizeBounds()

    per_rule: List[Tuple[int, Optional[int]]] = []
    for cond in conditions:
        rb = _rule_size_bounds_regex(cond)
        if rb is None:
            return SizeBounds()
        per_rule.append(rb)

    if not per_rule:
        return SizeBounds()

    global_min = min(rb[0] for rb in per_rule)
    maxes = [rb[1] for rb in per_rule]
    global_max: Optional[int]
    if any(m is None for m in maxes):
        global_max = None
    else:
        global_max = max(m for m in maxes)  # type: ignore[arg-type]
    return SizeBounds(min_size=global_min, max_size=global_max)


def compute_size_bounds(rule_text: str) -> SizeBounds:
    """Compute the inclusive ``(min_size, max_size)`` range that could
    still match *any* rule in *rule_text*.

    Uses the yaraast AST when available (handles ``and``/``or``/``not``
    properly, unit-resolves literals, and is resilient to condition
    complexity). Falls back to a conservative regex scan if yaraast
    isn't installed or parsing fails.
    """
    ast_bounds = _compute_bounds_via_ast(rule_text)
    if ast_bounds is not None:
        return ast_bounds
    return _compute_bounds_via_regex(rule_text)


def format_size(n: int) -> str:
    """Human-readable byte count (for logs)."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    return f"{n / (1024 ** 3):.2f} GB"


class YaraScanner:
    """Pure-logic YARA scanning, compilation, formatting, and validation."""

    def format_with_yara_x(self, text: str) -> str:
        """
        Format YARA rules using yara-x Formatter.

        Returns:
            Formatted YARA rule text

        Raises:
            Exception: If formatting fails
        """
        if not YARA_X_AVAILABLE:
            raise RuntimeError("yara-x is not installed")

        try:
            from io import BytesIO, StringIO

            # First, try to compile the rule to validate syntax
            yara_x.compile(text)

            # Create formatter and format the source text to StringIO buffer
            formatter = yara_x.Formatter()
            output_buffer = StringIO()
            input_buffer = BytesIO(text.encode('utf-8'))

            formatter.format(input_buffer, output_buffer)
            formatted = output_buffer.getvalue()

            input_buffer.close()
            output_buffer.close()

            return formatted.rstrip()

        except Exception as e:
            raise Exception(f"yara-x formatting failed: {str(e)}")

    def format_with_ast(self, text: str) -> str:
        """
        Format YARA rules using yaraast AST parser (fallback).

        Returns:
            Formatted YARA rule text

        Raises:
            Exception: If AST parsing fails
        """
        if not YARAAST_AVAILABLE:
            raise RuntimeError("yaraast is not installed")

        try:
            parser = Parser()
            ast = parser.parse(text)
            codegen = CodeGenerator()
            formatted = codegen.generate(ast)
            return formatted.rstrip()
        except Exception as e:
            raise Exception(f"yaraast parsing failed: {str(e)}")

    def validate_syntax(self, text: str) -> dict:
        """Validate YARA syntax using yaraast and provide detailed feedback."""
        if not YARAAST_AVAILABLE:
            return {"valid": None, "message": "yaraast not available for syntax validation"}

        try:
            parser = Parser()
            ast = parser.parse(text)

            rules_info = []
            total_strings = 0
            total_tags = 0

            for rule in ast.rules:
                rule_info = {
                    'name': rule.name,
                    'tags': list(rule.tags) if hasattr(rule, 'tags') and rule.tags else [],
                    'strings': len(rule.strings) if hasattr(rule, 'strings') and rule.strings else 0,
                    'meta': len(rule.meta) if hasattr(rule, 'meta') and rule.meta else 0,
                    'has_condition': hasattr(rule, 'condition') and rule.condition is not None
                }
                rules_info.append(rule_info)
                total_strings += rule_info['strings']
                total_tags += len(rule_info['tags'])

            return {
                "valid": True,
                "rules_count": len(rules_info),
                "total_strings": total_strings,
                "total_tags": total_tags,
                "rules_info": rules_info,
                "message": f"\u2713 Syntax valid: {len(rules_info)} rules, {total_strings} strings, {total_tags} tags"
            }

        except Exception as e:
            return {
                "valid": False,
                "message": f"\u2717 Syntax error: {str(e)}",
                "error": str(e)
            }

    def get_rule_info(self, text: str) -> str:
        """Get detailed information about YARA rules using AST analysis."""
        if not YARAAST_AVAILABLE:
            return "yaraast not available - install with: pip install yaraast[all]"

        try:
            validation = self.validate_syntax(text)
            if not validation["valid"]:
                return f"Syntax Error: {validation['message']}"

            info_lines = [
                f"\U0001f4ca YARA Rule Analysis:",
                f"  Rules: {validation['rules_count']}",
                f"  Total Strings: {validation['total_strings']}",
                f"  Total Tags: {validation['total_tags']}",
                ""
            ]

            for i, rule in enumerate(validation['rules_info'], 1):
                info_lines.append(f"Rule {i}: {rule['name']}")
                info_lines.append(f"  \U0001f4c4 Strings: {rule['strings']}")
                info_lines.append(f"  \U0001f3f7\ufe0f  Tags: {', '.join(rule['tags']) if rule['tags'] else 'None'}")
                info_lines.append(f"  \U0001f4ca Meta: {rule['meta']} entries")
                info_lines.append(f"  \u2705 Condition: {'Yes' if rule['has_condition'] else 'No'}")
                info_lines.append("")

            return '\n'.join(info_lines)

        except Exception as e:
            return f"Analysis failed: {str(e)}"

    def compile_rules(self, rule_text: str):
        """
        Compile YARA rules and return compiled rules object.

        Returns:
            Compiled rules object

        Raises:
            RuntimeError: If yara-x is not available
            Exception: If compilation fails
        """
        if not YARA_X_AVAILABLE:
            raise RuntimeError("YARA-X not installed. Please install with: pip install yara-x")

        return yara_x.compile(rule_text)

    def scan_file(self, rules, file_path: Path) -> dict:
        """
        Scan a single file and return result data.

        Returns:
            dict with keys: 'hit' (bool), 'filename', 'filepath', 'md5', 'sha1', 'sha256',
            and if hit: 'file_data', 'matched_rules'
        """
        data = file_path.read_bytes()
        md5_hash = hashlib.md5(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        results = rules.scan(data)

        filename = file_path.name
        filepath = str(file_path)

        base = {
            'filename': filename,
            'filepath': filepath,
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash,
        }

        if results.matching_rules:
            matched_rules = self._extract_match_details(results.matching_rules)
            return {**base, 'hit': True, 'file_data': data, 'matched_rules': matched_rules}
        else:
            return {**base, 'hit': False}

    def _extract_match_details(self, matching_rules) -> List[Dict]:
        """Extract detailed information from matching rules."""
        matched_rules = []

        for rule in matching_rules:
            rule_info = {
                'identifier': rule.identifier,
                'namespace': rule.namespace,
                'tags': list(rule.tags) if hasattr(rule, 'tags') else [],
                'metadata': dict(rule.metadata) if hasattr(rule, 'metadata') else {},
                'patterns': []
            }

            has_string_matches = False
            for pattern in rule.patterns:
                if pattern.matches:
                    has_string_matches = True
                    pattern_info = {
                        'identifier': pattern.identifier,
                        'matches': [
                            {
                                'offset': match.offset,
                                'length': match.length
                            } for match in pattern.matches
                        ]
                    }
                    rule_info['patterns'].append(pattern_info)

            # If rule matched but has no string pattern matches (condition-based match)
            if not has_string_matches:
                rule_info['patterns'].append({
                    'identifier': 'Condition-based match',
                    'matches': [{'offset': 0, 'length': 0}]
                })

            matched_rules.append(rule_info)

        return matched_rules

    def scan_files(self, rules, files: List[Path],
                   progress_callback: Optional[Callable[[int, int], None]] = None) -> dict:
        """
        Scan multiple files.

        Args:
            rules: Compiled YARA rules
            files: List of file paths to scan
            progress_callback: Optional callback(scanned_count, total_count) for progress updates

        Returns:
            dict with keys: 'hits' (list), 'misses' (list), 'stats' (dict with scanned/matches/errors),
            'error_messages' (list of str)
        """
        hits = []
        misses = []
        error_messages = []
        stats = {'scanned': 0, 'matches': 0, 'errors': 0}
        total = len(files)

        for file_path in files:
            stats['scanned'] += 1

            if progress_callback and stats['scanned'] % 10 == 0:
                progress_callback(stats['scanned'], total)

            try:
                result = self.scan_file(rules, file_path)
                if result['hit']:
                    stats['matches'] += 1
                    # Remove the 'hit' key before storing
                    result.pop('hit')
                    hits.append(result)
                else:
                    result.pop('hit')
                    misses.append(result)
            except PermissionError:
                stats['errors'] += 1
            except Exception as e:
                stats['errors'] += 1
                error_messages.append(f"\u2717 Error scanning {file_path}: {e}")

        return {
            'hits': hits,
            'misses': misses,
            'stats': stats,
            'error_messages': error_messages
        }
