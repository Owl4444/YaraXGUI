# This Python file uses the following encoding: utf-8

"""
YaraScanner - Pure-logic YARA scanning, compilation, formatting, and validation.

No UI dependencies. Returns data or raises exceptions for the caller to handle.
"""

import hashlib
import re
from yarax_editor import Compiler, format_source
from yarax_editor.lexer import significant
from yaraxgui.editor.services import APP_COMPILE_OPTIONS, mask_source, validate_source
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# Check if yara_x is available
try:
    import yara_x
    YARA_X_AVAILABLE = True
except ImportError:
    YARA_X_AVAILABLE = False

# ── Filesize pre-filter ────────────────────────────────────────────
#
# YARA conditions can express file-size constraints like `filesize < 500KB`.
# When every rule in a ruleset has such an upper bound, we can skip files
# that exceed the bound without reading them — a big win when the user
# points the scanner at a directory full of multi-GB files.
#
# Project-owned analysis recognizes complete conjunctions of simple size
# comparisons. The shared lexer protects literals and comments. Conditions
# outside this subset remain unbounded and go through the normal scanner.
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
    return mask_source(text, kinds={"comment"})


def _extract_conditions(rule_text: str) -> List[str]:
    """Return the condition text of each rule in *rule_text* via
    brace-matching over lexically classified source."""
    source = _strip_comments(rule_text)
    code = mask_source(rule_text)
    out = []
    depth = 0
    condition_start = None
    in_rule = False
    tokens = significant(code)
    for index, token in enumerate(tokens):
        word = code[token.span.start:token.span.end]
        if word == "rule" and depth == 0:
            in_rule = True
        elif word == "{" and in_rule:
            depth += 1
        elif word == "}" and in_rule:
            depth -= 1
            if depth == 0:
                if condition_start is None:
                    return []
                out.append(source[condition_start:token.span.start].strip())
                condition_start = None
                in_rule = False
        elif (word == "condition" and depth == 1 and index + 1 < len(tokens)
              and code[tokens[index + 1].span.start:tokens[index + 1].span.end] == ":"):
            condition_start = tokens[index + 1].span.end
    # A partial final rule must not leave bounds computed from earlier rules.
    return [] if in_rule or depth else out


def _condition_is_parseable(cond: str) -> bool:
    """Only optimize complete conjunctions of simple filesize comparisons.

    Comparisons inside a with-binding, loop or another expression are not
    necessarily constraints on matching. Unknown grammar must remain unbounded.
    """
    text = _strip_comments(cond)
    position = depth = 0
    need_atom = True
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        if need_atom:
            if text[position] == "(":
                depth += 1
                position += 1
                continue
            match = (_FILESIZE_LHS_RE.match(text, position)
                     or _FILESIZE_RHS_RE.match(text, position)
                     or re.compile(r"(?:true|false)\b").match(text, position))
            if not match:
                return False
            position = match.end()
            need_atom = False
        elif text[position] == ")" and depth:
            position += 1
            depth -= 1
        else:
            match = re.compile(r"and\b").match(text, position)
            if not match:
                return False
            position = match.end()
            need_atom = True
    return not need_atom and depth == 0


def _tighten(lo: int, hi: Optional[int], op: str,
             val: int) -> Tuple[int, Optional[int]]:
    """Apply one `filesize <op> val` constraint. Used by the conservative size analyser."""
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
    cond = _strip_comments(cond)
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
    """Project-owned conservative bounds over lexically isolated conditions."""
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
    """Return conservative bounds using project-owned source analysis.

    Complex conditions are left unbounded. This may scan more files, but
    cannot exclude matches based on a partial understanding of an expression.
    """
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

    def format_rules(self, text: str) -> str:
        """Batch formatting through the project-owned editor toolkit."""
        return format_source(text, compiler=Compiler(APP_COMPILE_OPTIONS))

    def validate_syntax(self, text: str) -> dict:
        return validate_source(text)

    def get_rule_info(self, text: str) -> str:
        """Get rule information from the same compiler used for scanning."""

        try:
            validation = self.validate_syntax(text)
            if not validation["valid"]:
                return validation["message"]

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
            'file_size': len(data),
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
