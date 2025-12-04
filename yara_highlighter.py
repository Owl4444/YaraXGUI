from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

# Check if yaraast is available for AST-based highlighting
try:
    from yaraast.parser.better_parser import Parser
    YARAAST_AVAILABLE = True
except ImportError:
    YARAAST_AVAILABLE = False

def _fmt(color: str, bold=False, italic=False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    if italic:
        f.setFontItalic(True)
    return f

class YaraHighlighter(QSyntaxHighlighter):
    """
    Lightweight YARA highlighter for PySide6 with theme support.
    Highlights:
      - sections/keywords, logic ops, built-ins, string modifiers, modules (before '.')
      - string ids ($a), counts/offsets (#a, @a[i]), numbers
      - string/regex/hex literals, // and /* ... */ comments
    """

    def __init__(self, document, theme=None):
        super().__init__(document)
        
        # Store theme for updates
        self.current_theme = theme
        
        # Enhanced AST caching for performance
        self._cached_text = ""
        self._cached_ast = None
        self._cached_identifiers = []
        self._last_text_hash = None
        
        # Performance thresholds - AST ONLY mode
        self._max_file_size_for_ast = 100000  # 100KB limit for AST parsing
        self._ast_enabled = True
        
        # Initialize with default or theme colors
        self.init_theme_colors()
        
        # Build highlighting rules
        self.setup_rules()

    def init_theme_colors(self):
        """Initialize syntax highlighting colors based on current theme"""
        if self.current_theme and hasattr(self.current_theme, 'colors'):
            # Use theme-specific syntax colors
            colors = self.current_theme.colors
            
            # Use the new syntax-specific colors if available
            if hasattr(colors, 'syntax_keyword'):
                self.fmt_decl      = _fmt(colors.syntax_keyword, bold=True)     # rule, import, private, global
                self.fmt_logic     = _fmt(colors.syntax_logic)                  # and, or, not, any, all, of, them
                self.fmt_builtin   = _fmt(colors.syntax_builtin)               # filesize, entrypoint, uint8, etc.
                self.fmt_modifiers = _fmt(colors.syntax_modifier)              # ascii, wide, nocase, fullword
                self.fmt_module    = _fmt(colors.syntax_module, bold=True)     # pe, elf, math, hash
                self.fmt_symref    = _fmt(colors.syntax_symbol)                # $a, #a, @a[0]
                self.fmt_number    = _fmt(colors.syntax_number)                # 42, 0x1A, etc.
                self.fmt_string    = _fmt(colors.syntax_string)                # "text", 'text'
                self.fmt_regex     = _fmt(colors.syntax_regex)                 # /pattern/flags
                self.fmt_hexstr    = _fmt(colors.syntax_hex)                   # { 41 42 43 }
                self.fmt_comment   = _fmt(colors.syntax_comment, italic=True)  # // and /* */
                
                # Enhanced AST-based highlighting formats
                self.fmt_identifier = _fmt(getattr(colors, 'syntax_identifier', colors.syntax_symbol))  # Rule names, identifiers
                self.fmt_meta_key   = _fmt(getattr(colors, 'syntax_meta_key', colors.syntax_builtin))  # Meta keys
                self.fmt_tag        = _fmt(getattr(colors, 'syntax_tag', colors.syntax_modifier))      # Rule tags
                self.fmt_condition  = _fmt(getattr(colors, 'syntax_condition', colors.syntax_logic))   # Condition keywords
                self.fmt_operator   = _fmt(getattr(colors, 'syntax_operator', colors.syntax_logic))    # Operators +, -, *, etc.
                self.fmt_literal    = _fmt(getattr(colors, 'syntax_literal', colors.syntax_string))    # String/hex literals
                self.fmt_function   = _fmt(getattr(colors, 'syntax_function', colors.syntax_module))   # Function calls
                self.fmt_section    = _fmt(getattr(colors, 'syntax_section', colors.syntax_keyword))   # meta:, strings:, condition:
            else:
                # Fallback to old system for compatibility
                if self.current_theme.name == "Dark":
                    # Dark theme colors (VS Code style)
                    self.fmt_decl      = _fmt("#569cd6", bold=True)
                    self.fmt_logic     = _fmt("#c586c0")
                    self.fmt_builtin   = _fmt("#4ec9b0")
                    self.fmt_modifiers = _fmt("#dcdcaa")
                    self.fmt_module    = _fmt("#4fc1ff", bold=True)
                    self.fmt_symref    = _fmt("#9cdcfe")
                    self.fmt_number    = _fmt("#b5cea8")
                    self.fmt_string    = _fmt("#ce9178")
                    self.fmt_regex     = _fmt("#d19a66")
                    self.fmt_hexstr    = _fmt("#d7ba7d")
                    self.fmt_comment   = _fmt("#6a9955", italic=True)
                    # Enhanced AST formats
                    self.fmt_identifier = _fmt("#FFA366")  # Light orange for identifiers
                    self.fmt_meta_key   = _fmt("#4ec9b0")
                    self.fmt_tag        = _fmt("#dcdcaa")
                    self.fmt_condition  = _fmt("#c586c0")
                    self.fmt_operator   = _fmt("#d4d4d4")
                    self.fmt_literal    = _fmt("#ce9178")
                    self.fmt_function   = _fmt("#4fc1ff", bold=True)
                    self.fmt_section    = _fmt("#569cd6", bold=True)
                else:
                    # Light theme colors (VS Code light style)
                    self.fmt_decl      = _fmt("#0000ff", bold=True)
                    self.fmt_logic     = _fmt("#af00db")
                    self.fmt_builtin   = _fmt("#267f99")
                    self.fmt_modifiers = _fmt("#795e26")
                    self.fmt_module    = _fmt("#001080", bold=True)
                    self.fmt_symref    = _fmt("#001080")
                    self.fmt_number    = _fmt("#098658")
                    self.fmt_string    = _fmt("#a31515")
                    self.fmt_regex     = _fmt("#811f3f")
                    self.fmt_hexstr    = _fmt("#795e26")
                    self.fmt_comment   = _fmt("#008000", italic=True)
                    # Enhanced AST formats
                    self.fmt_identifier = _fmt("#D2691E")  # Darker orange for light theme
                    self.fmt_meta_key   = _fmt("#267f99")
                    self.fmt_tag        = _fmt("#795e26")
                    self.fmt_condition  = _fmt("#af00db")
                    self.fmt_operator   = _fmt("#af00db")
                    self.fmt_literal    = _fmt("#a31515")
                    self.fmt_function   = _fmt("#001080", bold=True)
                    self.fmt_section    = _fmt("#0000ff", bold=True)
        else:
            # Default colors (dark theme fallback)
            self.fmt_decl      = _fmt("#5EA1FF", bold=True)
            self.fmt_logic     = _fmt("#FF8AE2")
            self.fmt_builtin   = _fmt("#33C2C2")
            self.fmt_modifiers = _fmt("#E2B714")
            self.fmt_module    = _fmt("#8CE99A", bold=True)
            self.fmt_symref    = _fmt("#7CD5FF")
            self.fmt_number    = _fmt("#9CDCFE")
            self.fmt_string    = _fmt("#CE9178")
            self.fmt_regex     = _fmt("#D19A66")
            self.fmt_hexstr    = _fmt("#E5C07B")
            self.fmt_comment   = _fmt("#6A9955", italic=True)
            # Enhanced AST formats
            self.fmt_identifier = _fmt("#FFA366")  # Light orange for identifiers
            self.fmt_meta_key   = _fmt("#33C2C2")
            self.fmt_tag        = _fmt("#E2B714")
            self.fmt_condition  = _fmt("#FF8AE2")
            self.fmt_operator   = _fmt("#FF8AE2")
            self.fmt_literal    = _fmt("#CE9178")
            self.fmt_function   = _fmt("#8CE99A", bold=True)
            self.fmt_section    = _fmt("#5EA1FF", bold=True)

    def update_theme(self, theme):
        """Update highlighter theme and re-highlight document"""
        self.current_theme = theme
        self.init_theme_colors()
        self.setup_rules()
        # Clear AST cache to force re-parsing with new theme
        self._cached_text = ""
        self._cached_ast = None
        # Force re-highlighting of the entire document
        self.rehighlight()

    def clear_ast_cache(self):
        """Clear the AST cache to force re-parsing on next highlight."""
        self._cached_text = ""
        self._cached_ast = None
        self._cached_identifiers = []
        self._last_text_hash = None
    
    def set_ast_enabled(self, enabled: bool):
        """Enable or disable AST-based highlighting for performance control."""
        self._ast_enabled = enabled and YARAAST_AVAILABLE
        if not enabled:
            self.clear_ast_cache()
            
    def set_ast_file_size_limit(self, limit: int):
        """Set the maximum file size (in characters) for AST parsing."""
        self._max_file_size_for_ast = limit
        
    def get_ast_status(self) -> dict:
        """Get current AST highlighting status and performance info."""
        return {
            'ast_available': YARAAST_AVAILABLE,
            'ast_enabled': self._ast_enabled,
            'file_size_limit': self._max_file_size_for_ast,
            'cache_active': bool(self._cached_ast),
            'cached_identifiers_count': len(self._cached_identifiers)
        }

    def setup_rules(self):
        """AST-only mode - no regex rules needed"""
        pass  # All highlighting is done via AST token extraction

    def parse_yara_ast(self, full_text: str):
        """Parse YARA text to AST - AST ONLY mode, no fallbacks."""
        if not YARAAST_AVAILABLE:
            return None
            
        # Check file size threshold - show message box once per session and disable highlighting
        if len(full_text) > self._max_file_size_for_ast:
            if not self._size_warning_shown:
                self._size_warning_shown = True
                self._show_size_warning(len(full_text))
            # Return None immediately to disable highlighting for large files
            return None
            
        # Create a simple hash for change detection
        import hashlib
        text_hash = hashlib.md5(full_text.encode('utf-8')).hexdigest()
        
        # Use cached AST if text hasn't changed
        if (self._last_text_hash == text_hash and 
            self._cached_ast is not None):
            return self._cached_ast
            
        try:
            parser = Parser()
            ast = parser.parse(full_text)
            
            # Cache the result with hash
            self._cached_text = full_text
            self._cached_ast = ast
            self._last_text_hash = text_hash
            
            # Pre-compute all tokens for better performance
            self._cached_identifiers = self._extract_all_tokens_from_ast(ast, full_text)
            
            return ast
        except Exception as e:
            # If parsing fails, clear cache and NO HIGHLIGHTING
            print(f"AST parsing failed: {e}, no highlighting will be applied")
            self._cached_text = ""
            self._cached_ast = None
            self._cached_identifiers = []
            self._last_text_hash = None
            return None

    def highlight_with_ast(self, block_text: str, block_start: int, full_text: str) -> bool:
        """
        Pure AST-based highlighting - no fallbacks, AST ONLY.
        
        Args:
            block_text: Text of the current block being highlighted
            block_start: Character position where this block starts in the full document
            full_text: Complete document text
            
        Returns:
            True if AST highlighting was successful, False for no highlighting
        """
        if not YARAAST_AVAILABLE:
            return False
            
        # Parse AST (uses caching internally)
        ast = self.parse_yara_ast(full_text)
        if not ast:
            return False  # No highlighting if AST fails
            
        try:
            # Use cached tokens for better performance
            tokens = self._cached_identifiers
            if not tokens:
                tokens = self._extract_all_tokens_from_ast(ast, full_text)
                self._cached_identifiers = tokens
            
            # Highlight tokens that fall within this block
            block_end = block_start + len(block_text)
            
            # Pre-filter tokens for this block (performance optimization)
            # Include tokens that OVERLAP with this block (not just fit entirely within)
            relevant_tokens = [
                token_info for token_info in tokens 
                if (token_info['position'] < block_end and 
                    token_info['position'] + token_info['length'] > block_start)
            ]
            
            # Apply highlighting only to relevant tokens
            for token_info in relevant_tokens:
                pos = token_info['position']
                length = token_info['length']
                token_type = token_info['type']
                token_end = pos + length
                
                # Calculate the portion of this token that falls within this block
                highlight_start = max(pos, block_start)
                highlight_end = min(token_end, block_end)
                
                # Calculate relative position within block
                rel_pos = highlight_start - block_start
                rel_length = highlight_end - highlight_start
                
                # Choose format based on token type
                fmt = self._get_format_for_token_type(token_type)
                if fmt and rel_length > 0:
                    self.setFormat(rel_pos, rel_length, fmt)
            
            return True
            
        except Exception as e:
            print(f"AST highlighting error: {e}")
            return False
    
    def _get_format_for_token_type(self, token_type: str):
        """Map token types to formatting styles."""
        format_map = {
            # Core language elements
            'keyword': self.fmt_decl,           # rule, import, private, global
            'section': self.fmt_section,        # meta:, strings:, condition:
            'logic': self.fmt_logic,            # and, or, not, any, all
            'builtin': self.fmt_builtin,        # filesize, uint32, etc.
            'modifier': self.fmt_modifiers,     # ascii, wide, nocase
            'module': self.fmt_module,          # pe, elf, math, hash
            
            # AST-derived elements
            'rule_name': self.fmt_identifier,   # Rule names
            'import_module': self.fmt_module,   # Import module names
            'tag': self.fmt_tag,                # Rule tags
            'meta_key': self.fmt_meta_key,      # Meta keys
            'string_identifier': self.fmt_symref,    # $variables
            'string_reference': self.fmt_symref,     # #var, @var[0]
            'string_modifier': self.fmt_modifiers,   # String modifiers
            'function_call': self.fmt_function,      # Function calls
            'module_reference': self.fmt_module,     # Module.* references
            'operator': self.fmt_operator,           # ==, !=, +, -, etc.
            
            # Literals and patterns
            'number': self.fmt_number,          # 42, 0x1A, 10KB
            'string_literal': self.fmt_string,  # "text"
            'regex': self.fmt_regex,            # /pattern/flags
            'hex_pattern': self.fmt_hexstr,     # { 41 42 43 }
            'comment': self.fmt_comment,        # // and /* */
        }
        
        return format_map.get(token_type, None)





    def highlightBlock(self, text: str) -> None:
        """
        Pure AST-based highlighting ONLY. No regex fallback.
        If AST fails or file is too large, NO highlighting is applied.
        """
        # Check if highlighting is completely disabled
        if not self._ast_enabled:
            # If AST is disabled (usually due to large file size), don't highlight at all
            return
            
        # Only try AST-based highlighting - no fallbacks
        if YARAAST_AVAILABLE:
            # Get the full document text for AST parsing
            full_text = self.document().toPlainText()
            
            # Check file size before any processing
            if len(full_text) > self._max_file_size_for_ast:
                # File too large - disable all highlighting to maintain performance
                return
            
            # Calculate this block's position in the full document
            block = self.currentBlock()
            block_start = block.position()
            
            # Try AST highlighting - if it fails, no highlighting at all
            if self.highlight_with_ast(text, block_start, full_text):
                # AST highlighting succeeded
                return
        
        # If we reach here, either yaraast is unavailable, AST disabled, or AST failed
        # In AST-ONLY mode, we apply NO highlighting rather than fallback
    
    def _show_size_warning(self, file_size: int):
        """Show warning message box for oversized files."""
        try:
            from PySide6.QtWidgets import QMessageBox
            size_kb = file_size // 1024
            limit_kb = self._max_file_size_for_ast // 1024
            
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("File Too Large for Syntax Highlighting")
            msg.setText(f"File size ({size_kb}KB) exceeds the limit ({limit_kb}KB)")
            msg.setInformativeText("Syntax highlighting has been disabled for this file to maintain performance.\n\nThe file will load normally without highlighting.")
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()
        except Exception as e:
            print(f"Could not show size warning dialog: {e}")
            print(f"File too large ({file_size} chars) for AST-based syntax highlighting")
    
    def _extract_all_tokens_from_ast(self, ast, full_text: str) -> list:
        """
        Extract ALL available keyword tokens and elements from AST.
        This is the comprehensive AST-only extraction method.
        
        Returns:
            List of dicts with keys: 'position', 'length', 'text', 'type'
        """
        tokens = []
        import re
        
        try:
            # Extract ALL YARA keywords first
            self._extract_yara_keywords(full_text, tokens)
            
            # Extract imports
            if hasattr(ast, 'imports') and ast.imports:
                for imp in ast.imports:
                    import_name = str(imp).strip('"\'')
                    import_pos = full_text.find(f'"{import_name}"')
                    if import_pos == -1:
                        import_pos = full_text.find(f"'{import_name}'")
                    if import_pos >= 0:
                        tokens.append({
                            'position': import_pos + 1,  # Skip quote
                            'length': len(import_name),
                            'text': import_name,
                            'type': 'import_module'
                        })
            
            # Process each rule
            for rule in ast.rules:
                # Rule name
                if hasattr(rule, 'name') and rule.name:
                    rule_pattern = f"rule\\s+{re.escape(rule.name)}\\b"
                    match = re.search(rule_pattern, full_text)
                    if match:
                        name_start = match.start() + match.group().find(rule.name)
                        tokens.append({
                            'position': name_start,
                            'length': len(rule.name),
                            'text': rule.name,
                            'type': 'rule_name'
                        })
                
                # Rule tags
                if hasattr(rule, 'tags') and rule.tags:
                    for tag in rule.tags:
                        tag_text = str(tag)
                        rule_start = full_text.find(f"rule {rule.name}")
                        if rule_start >= 0:
                            # Look for tags after rule name but before opening brace
                            colon_pos = full_text.find(':', rule_start)
                            brace_pos = full_text.find('{', rule_start)
                            search_end = min(colon_pos if colon_pos > 0 else len(full_text), 
                                           brace_pos if brace_pos > 0 else len(full_text))
                            
                            tag_pos = full_text.find(tag_text, rule_start, search_end)
                            if tag_pos >= 0:
                                tokens.append({
                                    'position': tag_pos,
                                    'length': len(tag_text),
                                    'text': tag_text,
                                    'type': 'tag'
                                })
                
                # Meta section and keys
                if hasattr(rule, 'meta') and rule.meta:
                    meta_section_start = full_text.find("meta:", full_text.find(f"rule {rule.name}"))
                    if meta_section_start >= 0:
                        # Highlight "meta:" section keyword
                        tokens.append({
                            'position': meta_section_start,
                            'length': 4,  # "meta"
                            'text': 'meta',
                            'type': 'section'
                        })
                        
                        # Meta keys
                        for key, value in rule.meta.items():
                            key_pos = full_text.find(key, meta_section_start)
                            if key_pos >= 0:
                                tokens.append({
                                    'position': key_pos,
                                    'length': len(key),
                                    'text': key,
                                    'type': 'meta_key'
                                })
                
                # Strings section and identifiers
                if hasattr(rule, 'strings') and rule.strings:
                    strings_section_start = full_text.find("strings:", full_text.find(f"rule {rule.name}"))
                    if strings_section_start >= 0:
                        # Highlight "strings:" section keyword
                        tokens.append({
                            'position': strings_section_start,
                            'length': 7,  # "strings"
                            'text': 'strings',
                            'type': 'section'
                        })
                        
                        # String identifiers
                        for string_def in rule.strings:
                            if hasattr(string_def, 'identifier'):
                                identifier = string_def.identifier
                                id_pos = full_text.find(identifier, strings_section_start)
                                if id_pos >= 0:
                                    tokens.append({
                                        'position': id_pos,
                                        'length': len(identifier),
                                        'text': identifier,
                                        'type': 'string_identifier'
                                    })
                            
                            # String modifiers (ascii, wide, nocase, etc.)
                            if hasattr(string_def, 'modifiers') and string_def.modifiers:
                                for modifier in string_def.modifiers:
                                    mod_text = str(modifier)
                                    # Search after the string definition
                                    search_start = strings_section_start
                                    mod_pos = full_text.find(mod_text, search_start)
                                    if mod_pos >= 0:
                                        tokens.append({
                                            'position': mod_pos,
                                            'length': len(mod_text),
                                            'text': mod_text,
                                            'type': 'string_modifier'
                                        })
                
                # Condition section
                condition_section_start = full_text.find("condition:", full_text.find(f"rule {rule.name}"))
                if condition_section_start >= 0:
                    # Highlight "condition:" section keyword
                    tokens.append({
                        'position': condition_section_start,
                        'length': 9,  # "condition"
                        'text': 'condition',
                        'type': 'section'
                    })
                
                # Extract condition elements if available
                if hasattr(rule, 'condition') and rule.condition:
                    condition_start = condition_section_start + 10  # after "condition:"
                    condition_end = full_text.find('}', condition_start)
                    if condition_end > condition_start:
                        condition_text = full_text[condition_start:condition_end]
                        
                        # Find function calls (e.g., uint32(0), pe.checksum)
                        func_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
                        for match in re.finditer(func_pattern, condition_text):
                            func_name = match.group(1)
                            if func_name not in ['and', 'or', 'not', 'any', 'all', 'of', 'them', 'for', 'in']:
                                func_pos = condition_start + match.start(1)
                                tokens.append({
                                    'position': func_pos,
                                    'length': len(func_name),
                                    'text': func_name,
                                    'type': 'function_call'
                                })
                        
                        # Find module references (e.g., pe.*, math.*, etc.)
                        module_pattern = r'\b(pe|elf|macho|dotnet|dex|cuckoo|hash|math|magic|time)\.'
                        for match in re.finditer(module_pattern, condition_text):
                            module_name = match.group(1)
                            module_pos = condition_start + match.start(1)
                            tokens.append({
                                'position': module_pos,
                                'length': len(module_name),
                                'text': module_name,
                                'type': 'module_reference'
                            })
                        
                        # Find operators and special symbols
                        operator_pattern = r'(==|!=|<=|>=|<|>|\+|\-|\*|\/|%|&|\||\^|~|<<|>>)'
                        for match in re.finditer(operator_pattern, condition_text):
                            op = match.group(1)
                            op_pos = condition_start + match.start()
                            tokens.append({
                                'position': op_pos,
                                'length': len(op),
                                'text': op,
                                'type': 'operator'
                            })
        
        except Exception as e:
            print(f"Error extracting tokens from AST: {e}")
        
        return tokens

    def _extract_yara_keywords(self, full_text: str, tokens: list):
        """Extract all YARA language keywords from text using comprehensive token search."""
        import re
        
        # Comprehensive YARA keywords with their types
        yara_keywords = {
            # Core declarations
            'rule': 'keyword',
            'import': 'keyword', 
            'include': 'keyword',
            'private': 'keyword',
            'global': 'keyword',
            
            # Sections
            'meta': 'section',
            'strings': 'section', 
            'condition': 'section',
            
            # Logic operators
            'and': 'logic',
            'or': 'logic',
            'not': 'logic',
            'true': 'logic',
            'false': 'logic',
            
            # Quantifiers
            'any': 'logic',
            'all': 'logic', 
            'of': 'logic',
            'them': 'logic',
            'for': 'logic',
            'in': 'logic',
            'at': 'logic',
            'matches': 'logic',
            'defined': 'logic',
            'contains': 'logic',
            'startswith': 'logic',
            'endswith': 'logic',
            'icontains': 'logic',
            'iequals': 'logic',
            
            # Built-in functions
            'filesize': 'builtin',
            'entrypoint': 'builtin',
            'uint8': 'builtin',
            'uint16': 'builtin',
            'uint32': 'builtin', 
            'uint64': 'builtin',
            'int8': 'builtin',
            'int16': 'builtin',
            'int32': 'builtin',
            'int64': 'builtin',
            'uint8be': 'builtin',
            'uint16be': 'builtin',
            'uint32be': 'builtin',
            'uint64be': 'builtin',
            'int8be': 'builtin',
            'int16be': 'builtin', 
            'int32be': 'builtin',
            'int64be': 'builtin',
            
            # String modifiers
            'ascii': 'modifier',
            'wide': 'modifier',
            'nocase': 'modifier',
            'fullword': 'modifier',
            'private': 'modifier',
            'xor': 'modifier',
            'base64': 'modifier',
            'base64wide': 'modifier',
            
            # Modules (when followed by dot)
            'pe': 'module',
            'elf': 'module',
            'macho': 'module',
            'dotnet': 'module', 
            'dex': 'module',
            'cuckoo': 'module',
            'hash': 'module',
            'math': 'module',
            'magic': 'module',
            'time': 'module',
        }
        
        # Extract each keyword with proper word boundaries
        for keyword, token_type in yara_keywords.items():
            # Use word boundaries to avoid partial matches
            if token_type == 'module':
                # Modules should be followed by a dot
                pattern = f"\\b{re.escape(keyword)}\\s*\\."
                for match in re.finditer(pattern, full_text):
                    tokens.append({
                        'position': match.start(),
                        'length': len(keyword),
                        'text': keyword,
                        'type': token_type
                    })
            else:
                # Regular keywords with word boundaries
                pattern = f"\\b{re.escape(keyword)}\\b"
                for match in re.finditer(pattern, full_text):
                    tokens.append({
                        'position': match.start(),
                        'length': len(keyword),
                        'text': keyword,
                        'type': token_type
                    })
        
        # Extract additional patterns
        self._extract_additional_tokens(full_text, tokens)
    
    def _extract_additional_tokens(self, full_text: str, tokens: list):
        """Extract additional token patterns like symbols, numbers, strings."""
        import re
        
        # String identifiers ($name, $*, etc.)
        for match in re.finditer(r'\$[A-Za-z_][A-Za-z0-9_]*\*?', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'string_identifier'
            })
        
        # Count/offset operators (#name, @name, @name[n])
        for match in re.finditer(r'[#@][A-Za-z_][A-Za-z0-9_]*(?:\[\d+\])?', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'string_reference'
            })
        
        # Hexadecimal numbers
        for match in re.finditer(r'\b0x[0-9A-Fa-f]+\b', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'number'
            })
        
        # Decimal numbers (be careful not to match parts of identifiers)
        for match in re.finditer(r'\b\d+(?:[KMG]B)?\b', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'number'
            })
        
        # String literals
        for match in re.finditer(r'"(?:[^"\\]|\\.)*"', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'string_literal'
            })
        
        # Regex patterns
        for match in re.finditer(r'/(?:\\.|[^/\\])+/[imsxA]*', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'regex'
            })
        
        # Hex patterns
        for match in re.finditer(r'\{[^}]*\}', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'hex_pattern'
            })
        
        # Comments
        for match in re.finditer(r'//[^\r\n]*', full_text):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'comment'
            })
        
        # Multi-line comments
        for match in re.finditer(r'/\*.*?\*/', full_text, re.DOTALL):
            tokens.append({
                'position': match.start(),
                'length': match.end() - match.start(),
                'text': match.group(),
                'type': 'comment'
            })
    
    def highlight_with_regex(self, text: str) -> None:
        """
        Fallback regex-based highlighting for when AST parsing fails.
        Provides basic but reliable highlighting for invalid/incomplete YARA syntax.
        """
        # Basic YARA keywords
        keywords = [
            'rule', 'meta', 'strings', 'condition', 'import', 'include', 'private', 'global',
            'and', 'or', 'not', 'all', 'any', 'them', 'for', 'of', 'in', 'contains',
            'matches', 'startswith', 'endswith', 'icontains', 'iequals', 'istartswith', 'iendswith'
        ]
        
        # Highlight keywords
        for keyword in keywords:
            pattern = QRegularExpression(f'\\b{keyword}\\b')
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_decl)
        
        # Highlight string variables ($var)
        pattern = QRegularExpression(r'\$[a-zA-Z_][a-zA-Z0-9_]*\*?')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_symref)
        
        # Highlight string literals
        pattern = QRegularExpression(r'"(?:[^"\\]|\\.)*"')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_string)
        
        # Highlight hex strings
        pattern = QRegularExpression(r'\{[^}]*\}')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_hexstr)
        
        # Highlight regex patterns
        pattern = QRegularExpression(r'/(?:[^/\\]|\\.)+/[gimx]*')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_regex)
        
        # Highlight numbers
        pattern = QRegularExpression(r'\b\d+\b')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_number)
        
        # Highlight comments (// and /* */)
        pattern = QRegularExpression(r'//.*$')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_comment)
        
        pattern = QRegularExpression(r'/\*.*?\*/')
        iterator = pattern.globalMatch(text)
        while iterator.hasNext():
            match = iterator.next()
            self.setFormat(match.capturedStart(), match.capturedLength(), self.fmt_comment)


