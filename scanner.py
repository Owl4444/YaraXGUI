# This Python file uses the following encoding: utf-8

"""
YaraScanner - Pure-logic YARA scanning, compilation, formatting, and validation.

No UI dependencies. Returns data or raises exceptions for the caller to handle.
"""

import hashlib
from pathlib import Path
from typing import Callable, Dict, List, Optional

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
