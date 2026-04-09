# -*- coding: utf-8 -*-
"""Modal dialog for building a CyberChef-style *recipe* of transforms.

A recipe is an ordered list of operations.  Each operation has its own
parameters and the whole chain is applied sequentially to the chosen
scope (selection / marked regions / entire file).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QComboBox, QRadioButton,
                               QButtonGroup, QCheckBox, QFormLayout, QFrame,
                               QSpinBox, QGroupBox, QScrollArea, QSplitter,
                               QWidget, QDialogButtonBox, QMessageBox,
                               QSizePolicy, QToolButton, QPlainTextEdit)


# ── Preview-size persistence ──────────────────────────────────────
#
# The user-visible "Show N bytes" spinner lives in the preview box.
# The chosen value is persisted to the same config/settings.json the
# rest of the app uses, under the key `transform_preview_bytes`.

PREVIEW_BYTES_MIN = 16
PREVIEW_BYTES_MAX = 4096
PREVIEW_BYTES_DEFAULT = 256
PREVIEW_BYTES_STEP = 16
_SETTINGS_KEY = "transform_preview_bytes"


def _settings_path() -> Path:
    # hex_editor/ → parent → config/settings.json
    return Path(__file__).resolve().parent.parent / "config" / "settings.json"


def _load_preview_bytes() -> int:
    try:
        p = _settings_path()
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            value = int(data.get(_SETTINGS_KEY, PREVIEW_BYTES_DEFAULT))
            return max(PREVIEW_BYTES_MIN, min(PREVIEW_BYTES_MAX, value))
    except Exception:
        pass
    return PREVIEW_BYTES_DEFAULT


def _save_preview_bytes(value: int) -> None:
    try:
        p = _settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        settings: dict = {}
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                settings = json.load(f)
        settings[_SETTINGS_KEY] = int(value)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        # Non-fatal — the spinner value just won't persist across sessions.
        pass

from .transforms import (REGISTRY, TransformSpec, TransformParam, TransformError,
                         RecipeStep, apply_recipe, find_spec,
                         debug_log_clear, debug_log_get)


# ── Hex-dump helper (used by the preview panel) ───────────────────

def _hex_dump(data: bytes, max_bytes: int = 128, row_width: int = 16) -> str:
    """Render *data* as classic `offset  hex  |ascii|` rows.

    Renders at most *max_bytes* bytes; if more data is available an
    ellipsis line is appended. Non-printable bytes render as `.` in the
    ASCII gutter. Returns an empty string for empty input.
    """
    if not data or max_bytes <= 0:
        return ""
    view = data[:max_bytes]
    lines: list[str] = []
    for row in range(0, len(view), row_width):
        chunk = view[row:row + row_width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Align hex column to full row width for neat ascii gutter.
        hex_part = f"{hex_part:<{row_width * 3 - 1}}"
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{row:08x}  {hex_part}  |{ascii_part}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


@dataclass
class TransformRequest:
    """What the user chose: a recipe + a scope to apply it to."""
    steps: list[RecipeStep] = field(default_factory=list)
    scope: str = "selection"  # "selection" | "regions" | "entire"


# ── Recipe-step widget ─────────────────────────────────────────────

class _RecipeStepWidget(QFrame):
    """A single editable step in the recipe (header + per-op param form)."""

    move_up_requested = Signal(object)
    move_down_requested = Signal(object)
    remove_requested = Signal(object)
    params_changed = Signal()
    enabled_toggled = Signal(object)

    def __init__(self, spec: TransformSpec, index: int, parent=None):
        super().__init__(parent)
        self.spec = spec
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 8)
        layout.setSpacing(4)

        # Header row: enable toggle, number, op name, move/remove buttons
        header = QHBoxLayout()
        header.setSpacing(4)

        # Enable/disable checkbox — disabled steps pass-through without
        # running, so the user can A/B a recipe without losing the op.
        self._enable_check = QCheckBox()
        self._enable_check.setChecked(True)
        self._enable_check.setToolTip(
            "Enabled — uncheck to bypass this step (pass-through)."
        )
        self._enable_check.toggled.connect(self._on_enable_toggled)
        header.addWidget(self._enable_check)

        self._num_label = QLabel(f"{index + 1}.")
        self._num_label.setStyleSheet("font-weight: bold;")
        self._num_label.setFixedWidth(22)
        header.addWidget(self._num_label)

        self._name_label = QLabel(spec.name)
        self._name_label.setStyleSheet("font-weight: bold;")
        header.addWidget(self._name_label, 1)

        self._cat_label = QLabel(f"[{spec.category}]")
        self._cat_label.setStyleSheet("color: gray; font-size: 9pt;")
        header.addWidget(self._cat_label)

        up_btn = QToolButton()
        up_btn.setText("\u25B2")  # ▲
        up_btn.setToolTip("Move up")
        up_btn.setFixedSize(24, 22)
        up_btn.clicked.connect(lambda: self.move_up_requested.emit(self))
        header.addWidget(up_btn)

        dn_btn = QToolButton()
        dn_btn.setText("\u25BC")  # ▼
        dn_btn.setToolTip("Move down")
        dn_btn.setFixedSize(24, 22)
        dn_btn.clicked.connect(lambda: self.move_down_requested.emit(self))
        header.addWidget(dn_btn)

        rm_btn = QToolButton()
        rm_btn.setText("\u2715")  # ✕
        rm_btn.setToolTip("Remove from recipe")
        rm_btn.setFixedSize(24, 22)
        rm_btn.clicked.connect(lambda: self.remove_requested.emit(self))
        header.addWidget(rm_btn)

        layout.addLayout(header)

        # Params form
        self._param_widgets: dict[str, QWidget] = {}
        if spec.params:
            form = QFormLayout()
            form.setContentsMargins(22, 2, 0, 0)
            form.setSpacing(3)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
            mono = QFont("Cascadia Code", 9)
            mono.setStyleHint(QFont.StyleHint.Monospace)

            for p in spec.params:
                w = self._build_param_widget(p, mono)
                self._param_widgets[p.key] = w
                form.addRow(f"{p.label}:", w)
            layout.addLayout(form)

        if spec.help:
            help_lbl = QLabel(spec.help)
            help_lbl.setWordWrap(True)
            help_lbl.setStyleSheet("color: gray; font-size: 9pt;")
            help_lbl.setContentsMargins(22, 0, 0, 0)
            layout.addWidget(help_lbl)

    def _build_param_widget(self, p: TransformParam, mono_font: QFont) -> QWidget:
        if p.kind == "choice":
            cb = QComboBox()
            for c in p.choices:
                cb.addItem(c)
            if p.default:
                idx = cb.findText(p.default)
                if idx >= 0:
                    cb.setCurrentIndex(idx)
            cb.currentIndexChanged.connect(lambda _i: self.params_changed.emit())
            return cb
        if p.kind == "int":
            sb = QSpinBox()
            sb.setRange(-2**31, 2**31 - 1)
            if p.default:
                try:
                    sb.setValue(int(p.default))
                except ValueError:
                    pass
            sb.valueChanged.connect(lambda _v: self.params_changed.emit())
            return sb
        if p.kind == "multiline":
            pte = QPlainTextEdit()
            pte.setPlaceholderText(p.placeholder)
            pte.setPlainText(p.default)
            pte.setFont(mono_font)
            pte.setTabChangesFocus(False)
            # Comfortable writing area — the recipe/preview splitter lets
            # the user give it even more room when needed.
            pte.setMinimumHeight(220)
            pte.setSizePolicy(QSizePolicy.Policy.Expanding,
                              QSizePolicy.Policy.Expanding)
            pte.textChanged.connect(lambda: self.params_changed.emit())
            # The parent _RecipeStepWidget uses a Fixed vertical size policy
            # by default; switch to Expanding so it can grow with the editor.
            self.setSizePolicy(QSizePolicy.Policy.Expanding,
                               QSizePolicy.Policy.Expanding)
            self.setMinimumHeight(260)
            return pte
        # "text" or "hex"
        le = QLineEdit()
        le.setPlaceholderText(p.placeholder)
        le.setText(p.default)
        if p.kind == "hex":
            le.setFont(mono_font)
        le.textChanged.connect(lambda _t: self.params_changed.emit())
        return le

    def set_index(self, index: int):
        self._num_label.setText(f"{index + 1}.")

    def is_enabled_step(self) -> bool:
        return self._enable_check.isChecked()

    def set_enabled_step(self, enabled: bool):
        # Block signals so seeding values from a saved recipe doesn't
        # trigger a spurious preview rebuild from the checkbox handler.
        self._enable_check.blockSignals(True)
        self._enable_check.setChecked(enabled)
        self._enable_check.blockSignals(False)
        self._apply_enabled_style(enabled)

    def _on_enable_toggled(self, checked: bool):
        self._apply_enabled_style(checked)
        self.enabled_toggled.emit(self)

    def _apply_enabled_style(self, enabled: bool):
        # Dim the header when disabled so the recipe makes visual sense
        # at a glance. We don't disable the form widgets — the user may
        # still want to edit params while bypassing the step.
        if enabled:
            self._name_label.setStyleSheet("font-weight: bold;")
            self._cat_label.setStyleSheet("color: gray; font-size: 9pt;")
            self._num_label.setStyleSheet("font-weight: bold;")
        else:
            self._name_label.setStyleSheet(
                "font-weight: bold; color: gray; text-decoration: line-through;"
            )
            self._cat_label.setStyleSheet("color: gray; font-size: 9pt;")
            self._num_label.setStyleSheet("font-weight: bold; color: gray;")

    def get_params(self) -> dict:
        out: dict = {}
        for key, w in self._param_widgets.items():
            if isinstance(w, QComboBox):
                out[key] = w.currentText()
            elif isinstance(w, QSpinBox):
                out[key] = w.value()
            elif isinstance(w, QPlainTextEdit):
                out[key] = w.toPlainText()
            elif isinstance(w, QLineEdit):
                out[key] = w.text()
        return out

    def set_params(self, params: dict):
        """Pre-populate widget values from a saved params dict."""
        for key, value in params.items():
            w = self._param_widgets.get(key)
            if w is None:
                continue
            if isinstance(w, QComboBox):
                idx = w.findText(str(value))
                if idx >= 0:
                    w.setCurrentIndex(idx)
            elif isinstance(w, QSpinBox):
                try:
                    w.setValue(int(value))
                except (TypeError, ValueError):
                    pass
            elif isinstance(w, QLineEdit):
                w.setText("" if value is None else str(value))


# ── Main dialog ────────────────────────────────────────────────────

class TransformDialog(QDialog):
    """Pick a recipe of operations, then the scope, then Apply."""

    def __init__(self, has_selection: bool, region_count: int,
                 probe_bytes: bytes = b"", parent=None,
                 initial_steps: list[RecipeStep] | None = None,
                 edit_mode: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Modify Transform Recipe" if edit_mode
                            else "Apply Transform Recipe")
        self.setMinimumSize(720, 860)

        self._has_selection = has_selection
        self._region_count = region_count
        self._probe_bytes = probe_bytes
        self._edit_mode = edit_mode
        self._result: TransformRequest | None = None
        self._step_widgets: list[_RecipeStepWidget] = []

        layout = QVBoxLayout(self)

        # Operation picker + add button
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Add operation:"))
        self._op_combo = QComboBox()
        self._populate_ops()
        top_row.addWidget(self._op_combo, 1)
        add_btn = QPushButton("+ Add to Recipe")
        add_btn.setDefault(False)
        add_btn.setAutoDefault(False)
        add_btn.clicked.connect(self._on_add_step)
        top_row.addWidget(add_btn)
        layout.addLayout(top_row)

        # Recipe/preview are stacked in a QSplitter so the user can drag
        # the divider to grow whichever one they care about — handy for
        # the multiline Python-script editor.
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        # Recipe area (scrollable)
        recipe_box = QGroupBox("Recipe (operations are applied in order)")
        recipe_box_layout = QVBoxLayout(recipe_box)
        recipe_box_layout.setContentsMargins(6, 6, 6, 6)

        self._recipe_container = QWidget()
        self._recipe_layout = QVBoxLayout(self._recipe_container)
        self._recipe_layout.setContentsMargins(0, 0, 0, 0)
        self._recipe_layout.setSpacing(6)
        self._empty_label = QLabel(
            "Recipe is empty — pick an operation above and click “Add to Recipe”."
        )
        self._empty_label.setStyleSheet("color: gray; padding: 12px;")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._recipe_layout.addWidget(self._empty_label)
        self._recipe_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._recipe_container)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        recipe_box_layout.addWidget(scroll)
        recipe_box.setMinimumHeight(180)
        splitter.addWidget(recipe_box)

        # Preview — three stacked panes: input dump, output dump, debug log.
        # Debug log captures `print()` from Python-script ops plus errors.
        preview_box = QGroupBox("Preview")
        preview_layout = QVBoxLayout(preview_box)
        preview_layout.setContentsMargins(6, 6, 6, 6)
        preview_layout.setSpacing(3)

        mono = QFont("Cascadia Code", 9)
        mono.setStyleHint(QFont.StyleHint.Monospace)

        # Header row: "Show N bytes" spinner + "Step" picker.
        self._preview_bytes = _load_preview_bytes()
        self._focused_step: int = -1  # index of the step being inspected
        header_row = QHBoxLayout()
        header_row.setSpacing(6)
        header_row.addWidget(QLabel("Show:"))
        self._preview_size_spin = QSpinBox()
        self._preview_size_spin.setRange(PREVIEW_BYTES_MIN, PREVIEW_BYTES_MAX)
        self._preview_size_spin.setSingleStep(PREVIEW_BYTES_STEP)
        self._preview_size_spin.setValue(self._preview_bytes)
        self._preview_size_spin.setSuffix(" bytes")
        self._preview_size_spin.setToolTip(
            f"How many bytes of input/output to render in the preview "
            f"({PREVIEW_BYTES_MIN}–{PREVIEW_BYTES_MAX}). Persists across sessions."
        )
        self._preview_size_spin.valueChanged.connect(self._on_preview_size_changed)
        header_row.addWidget(self._preview_size_spin)

        header_row.addSpacing(12)
        header_row.addWidget(QLabel("Inspect step:"))
        self._step_combo = QComboBox()
        self._step_combo.setMinimumWidth(220)
        self._step_combo.setToolTip(
            "Which recipe step's input/output to show in the preview panes. "
            "Defaults to the last step (= final recipe output)."
        )
        self._step_combo.currentIndexChanged.connect(self._on_focused_step_changed)
        header_row.addWidget(self._step_combo, 1)
        header_row.addStretch(0)
        preview_layout.addLayout(header_row)

        self._preview_in_label = QLabel("Input:")
        self._preview_in_label.setStyleSheet("font-weight: bold;")
        preview_layout.addWidget(self._preview_in_label)
        self._preview_in = QPlainTextEdit()
        self._preview_in.setReadOnly(True)
        self._preview_in.setFont(mono)
        self._preview_in.setMinimumHeight(90)
        self._preview_in.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        preview_layout.addWidget(self._preview_in)

        self._preview_out_label = QLabel("Output:")
        self._preview_out_label.setStyleSheet("font-weight: bold;")
        preview_layout.addWidget(self._preview_out_label)
        self._preview_out = QPlainTextEdit()
        self._preview_out.setReadOnly(True)
        self._preview_out.setFont(mono)
        self._preview_out.setMinimumHeight(90)
        self._preview_out.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        preview_layout.addWidget(self._preview_out)

        self._preview_debug_label = QLabel("Debug / stdout:")
        self._preview_debug_label.setStyleSheet("font-weight: bold;")
        preview_layout.addWidget(self._preview_debug_label)
        self._preview_debug = QPlainTextEdit()
        self._preview_debug.setReadOnly(True)
        self._preview_debug.setFont(mono)
        self._preview_debug.setFixedHeight(80)
        self._preview_debug.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._preview_debug.setPlaceholderText(
            "print(...) from Python scripts and transform errors appear here."
        )
        preview_layout.addWidget(self._preview_debug)

        preview_box.setMinimumHeight(220)
        splitter.addWidget(preview_box)
        # Give the recipe a little more room than the preview by default —
        # the multiline Python editor benefits from the extra height.
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([420, 320])
        layout.addWidget(splitter, 1)

        # Scope
        scope_box = QGroupBox("Scope")
        scope_layout = QHBoxLayout(scope_box)
        self._scope_group = QButtonGroup(self)

        self._rb_selection = QRadioButton("Current selection")
        self._rb_regions = QRadioButton(f"Marked regions ({region_count})")
        self._rb_entire = QRadioButton("Entire file")

        for rb in (self._rb_selection, self._rb_regions, self._rb_entire):
            self._scope_group.addButton(rb)
            scope_layout.addWidget(rb)
        scope_layout.addStretch(1)

        self._rb_selection.setEnabled(has_selection)
        self._rb_regions.setEnabled(region_count > 0)

        if region_count > 0:
            self._rb_regions.setChecked(True)
        elif has_selection:
            self._rb_selection.setChecked(True)
        else:
            self._rb_entire.setChecked(True)
        layout.addWidget(scope_box)

        # In edit mode the bytes to operate on are fixed (taken from the
        # original log entry), so the scope picker is meaningless.
        if edit_mode:
            scope_box.setVisible(False)

        # Buttons
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel
        )
        apply_btn = btn_box.button(QDialogButtonBox.StandardButton.Apply)
        apply_btn.setText("Save Changes" if edit_mode else "Apply")
        apply_btn.setDefault(True)
        apply_btn.clicked.connect(self._on_apply)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

        # Pre-populate steps if we're modifying an existing recipe.
        if initial_steps:
            for step in initial_steps:
                spec = find_spec(step.spec_name)
                if spec is None:
                    continue
                self._add_step_widget(spec, step.params)

        # Initial preview + step-picker combo
        self._rebuild_step_combo()
        self._update_preview()

    # ── Combo population ────────────────────────────────────────

    def _populate_ops(self):
        current_cat = None
        for spec in REGISTRY:
            if spec.category != current_cat:
                current_cat = spec.category
                self._op_combo.addItem(f"── {spec.category} ──")
                hdr_index = self._op_combo.count() - 1
                self._op_combo.model().item(hdr_index).setEnabled(False)
            self._op_combo.addItem(spec.name, userData=spec.name)

        # Select first real op
        for i in range(self._op_combo.count()):
            if self._op_combo.itemData(i):
                self._op_combo.setCurrentIndex(i)
                break

    # ── Recipe management ──────────────────────────────────────

    def _on_add_step(self):
        name = self._op_combo.currentData()
        if not name:
            return
        spec = find_spec(name)
        if spec is None:
            return
        self._add_step_widget(spec)
        # Focus the newly-added step so the preview reflects what the user
        # just dropped onto the recipe — more intuitive than sticking to
        # whatever step was previously selected.
        self._focused_step = len(self._step_widgets) - 1
        self._rebuild_step_combo()
        self._update_preview()

    def _add_step_widget(self, spec: TransformSpec, params: dict | None = None):
        """Append a recipe step card and (optionally) seed its parameters."""
        self._empty_label.setVisible(False)
        step_widget = _RecipeStepWidget(spec, len(self._step_widgets), self)
        if params:
            step_widget.set_params(params)
        step_widget.move_up_requested.connect(self._on_move_up)
        step_widget.move_down_requested.connect(self._on_move_down)
        step_widget.remove_requested.connect(self._on_remove)
        step_widget.params_changed.connect(self._update_preview)
        step_widget.enabled_toggled.connect(self._on_step_enabled_toggled)
        # Insert before the trailing stretch (last item in layout)
        insert_pos = self._recipe_layout.count() - 1
        self._recipe_layout.insertWidget(insert_pos, step_widget)
        self._step_widgets.append(step_widget)

    def _on_move_up(self, step_widget: _RecipeStepWidget):
        idx = self._step_widgets.index(step_widget)
        if idx == 0:
            return
        # Swap in the model list, then re-anchor the widget in the layout.
        self._step_widgets[idx - 1], self._step_widgets[idx] = (
            self._step_widgets[idx], self._step_widgets[idx - 1])
        self._recipe_layout.removeWidget(step_widget)
        target_pos = self._recipe_layout.indexOf(self._step_widgets[idx])
        self._recipe_layout.insertWidget(target_pos, step_widget)
        self._renumber_steps()
        self._rebuild_step_combo()
        self._update_preview()

    def _on_move_down(self, step_widget: _RecipeStepWidget):
        idx = self._step_widgets.index(step_widget)
        if idx >= len(self._step_widgets) - 1:
            return
        self._step_widgets[idx], self._step_widgets[idx + 1] = (
            self._step_widgets[idx + 1], self._step_widgets[idx])
        self._recipe_layout.removeWidget(step_widget)
        target_pos = self._recipe_layout.indexOf(self._step_widgets[idx]) + 1
        self._recipe_layout.insertWidget(target_pos, step_widget)
        self._renumber_steps()
        self._rebuild_step_combo()
        self._update_preview()

    def _on_remove(self, step_widget: _RecipeStepWidget):
        if step_widget not in self._step_widgets:
            return
        self._step_widgets.remove(step_widget)
        self._recipe_layout.removeWidget(step_widget)
        step_widget.setParent(None)
        step_widget.deleteLater()
        self._renumber_steps()
        self._empty_label.setVisible(not self._step_widgets)
        self._rebuild_step_combo()
        self._update_preview()

    def _on_step_enabled_toggled(self, _step_widget: _RecipeStepWidget):
        # Toggling enabled can change step names shown in the combo
        # (we append a "(disabled)" marker), so rebuild it alongside
        # the preview.
        self._rebuild_step_combo()
        self._update_preview()

    def _renumber_steps(self):
        for i, w in enumerate(self._step_widgets):
            w.set_index(i)

    # ── Preview ────────────────────────────────────────────────

    def _current_steps(self) -> list[RecipeStep]:
        return [
            RecipeStep(spec_name=sw.spec.name, params=sw.get_params())
            for sw in self._step_widgets
        ]

    def _current_enabled_flags(self) -> list[bool]:
        return [sw.is_enabled_step() for sw in self._step_widgets]

    def _current_scope(self) -> str:
        if self._rb_selection.isChecked():
            return "selection"
        if self._rb_regions.isChecked():
            return "regions"
        return "entire"

    def _on_preview_size_changed(self, value: int):
        self._preview_bytes = int(value)
        _save_preview_bytes(self._preview_bytes)
        self._update_preview()

    def _on_focused_step_changed(self, index: int):
        # Guard against spurious signals fired during _rebuild_step_combo.
        if getattr(self, "_rebuilding_step_combo", False):
            return
        if index < 0:
            return
        self._focused_step = index
        self._update_preview()

    def _rebuild_step_combo(self):
        """Sync the step-picker combo with the current recipe order.

        Tries to preserve the focused step when the caller adds/removes/
        reorders steps. Disabled steps stay visible with a marker so the
        user can still inspect them. Called whenever the recipe list
        changes.
        """
        self._rebuilding_step_combo = True
        try:
            steps = self._current_steps()
            enabled = self._current_enabled_flags()
            prev_focused = self._focused_step
            self._step_combo.clear()
            if not steps:
                self._step_combo.addItem("(no steps)")
                self._step_combo.setEnabled(False)
                self._focused_step = -1
                return
            self._step_combo.setEnabled(True)
            total = len(steps)
            for i, step in enumerate(steps):
                marker = "" if enabled[i] else " (disabled)"
                self._step_combo.addItem(
                    f"{i + 1} of {total}: {step.spec_name}{marker}"
                )
            # Default to the LAST step so the preview matches the final
            # output of the recipe (the pre-existing behaviour).
            if prev_focused < 0 or prev_focused >= total:
                self._focused_step = total - 1
            else:
                self._focused_step = prev_focused
            self._step_combo.setCurrentIndex(self._focused_step)
        finally:
            self._rebuilding_step_combo = False

    def _compute_step_outputs(
        self,
        probe: bytes,
        steps: list[RecipeStep],
        enabled: list[bool] | None = None,
    ) -> tuple[list[bytes], int, str | None]:
        """Run *steps* on *probe* one at a time, returning per-step results.

        If *enabled* is given, disabled steps are passed through unchanged
        (their ``outputs[i+1] == outputs[i]``) so the per-step preview
        still lines up with the widget list.

        Returns ``(outputs, failed_at, err_msg)`` where:
          * ``outputs[0]`` is the probe itself,
          * ``outputs[i+1]`` is the bytes produced after running ``steps[i]``,
          * ``failed_at`` is the index of the step that crashed
            (``-1`` if none did),
          * ``err_msg`` is the error message for the crashed step.
        """
        outputs: list[bytes] = [probe]
        for i, step in enumerate(steps):
            if enabled is not None and not enabled[i]:
                # Bypassed step — keep the alignment with the widget list.
                outputs.append(outputs[-1])
                continue
            spec = find_spec(step.spec_name)
            if spec is None:
                return outputs, i, f"Unknown operation: {step.spec_name}"
            try:
                out = spec.func(outputs[-1], step.params)
            except TransformError as e:
                return outputs, i, str(e)
            except Exception as e:  # pragma: no cover — defensive
                return outputs, i, f"{type(e).__name__}: {e}"
            outputs.append(out)
        return outputs, -1, None

    def _set_preview_error(self, log_lines: list[str], err: str):
        self._preview_out_label.setText("Output: (error)")
        self._preview_out.setPlainText("")
        body = "\n".join(log_lines + [f"[error] {err}"])
        self._preview_debug.setPlainText(body)
        self._preview_debug.setStyleSheet(
            "background-color: #3a1e1e; color: #f0b0b0;"
        )

    def _update_preview(self):
        max_bytes = self._preview_bytes
        probe = self._probe_bytes[:max_bytes]

        # Reset debug-log styling; recipes append to it via transforms.debug_log_*.
        self._preview_debug.setStyleSheet("")

        # No steps: show the raw probe as "input", nothing as "output".
        if not self._step_widgets:
            self._preview_in_label.setText(f"Input:  {len(probe)} bytes")
            self._preview_in.setPlainText(_hex_dump(probe, max_bytes=max_bytes))
            self._preview_out_label.setText("Output:")
            self._preview_out.setPlainText("(add operations to the recipe)")
            self._preview_debug.setPlainText("")
            return

        if not probe:
            self._preview_in_label.setText("Input:  0 bytes")
            self._preview_in.setPlainText("")
            self._preview_out_label.setText("Output:")
            self._preview_out.setPlainText("(no input to preview)")
            self._preview_debug.setPlainText("")
            return

        # Clamp the focused step into the current recipe range.
        steps = self._current_steps()
        enabled_flags = self._current_enabled_flags()
        focused = self._focused_step
        if focused < 0 or focused >= len(steps):
            focused = len(steps) - 1

        debug_log_clear()
        outputs, failed_at, err = self._compute_step_outputs(
            probe, steps, enabled_flags
        )
        log_lines = debug_log_get()

        # `outputs[i]` = input to step i, `outputs[i+1]` = output of step i.
        # The input to the focused step is always available (since we fail
        # AT a step, not before it), so render that first.
        step_name = steps[focused].spec_name
        disabled_tag = "" if enabled_flags[focused] else " [disabled]"
        step_in = outputs[focused] if focused < len(outputs) else b""
        self._preview_in_label.setText(
            f"Input to step {focused + 1} ({step_name}){disabled_tag}:  "
            f"{len(step_in)} bytes"
        )
        self._preview_in.setPlainText(_hex_dump(step_in, max_bytes=max_bytes))

        # Output of the focused step: only available if the chain succeeded
        # up to AND INCLUDING this step.
        if failed_at == -1 or failed_at > focused:
            step_out = outputs[focused + 1]
            out_label = (
                f"Output of step {focused + 1} ({step_name}){disabled_tag}:  "
                f"{len(step_out)} bytes"
            )
            if not enabled_flags[focused]:
                out_label += "  (pass-through)"
            self._preview_out_label.setText(out_label)
            self._preview_out.setPlainText(_hex_dump(step_out, max_bytes=max_bytes))
            # Show any captured print() output from all the steps that ran.
            self._preview_debug.setPlainText(
                "\n".join(log_lines) if log_lines else ""
            )
            return

        # The focused step itself (or an earlier step) failed.
        if failed_at == focused:
            self._set_preview_error(
                log_lines,
                f"step {focused + 1} ({step_name}): {err}",
            )
        else:
            # An earlier step died — the focused step's input is also missing.
            crashed_name = steps[failed_at].spec_name
            self._preview_in_label.setText(
                f"Input to step {focused + 1} ({step_name}):  "
                f"unavailable — step {failed_at + 1} ({crashed_name}) failed"
            )
            self._preview_in.setPlainText("")
            self._set_preview_error(
                log_lines,
                f"step {failed_at + 1} ({crashed_name}): {err}",
            )

    # ── Apply / result ─────────────────────────────────────────

    def _on_apply(self):
        if not self._step_widgets:
            QMessageBox.warning(
                self, "Empty recipe",
                "Add at least one operation to the recipe before applying.",
            )
            return
        all_steps = self._current_steps()
        flags = self._current_enabled_flags()
        # Drop disabled steps — they're purely UI state and should not
        # appear in the resulting recipe log entry.
        steps = [s for s, en in zip(all_steps, flags) if en]
        if not steps:
            QMessageBox.warning(
                self, "No active steps",
                "Every step in the recipe is disabled. Enable at least "
                "one step before applying.",
            )
            return
        # Validate the full recipe on probe bytes (or a dummy)
        probe = self._probe_bytes or b"test"
        try:
            apply_recipe(probe, steps)
        except TransformError as e:
            QMessageBox.warning(self, "Invalid recipe", str(e))
            return
        except Exception:
            # Let the window surface the real error
            pass
        self._result = TransformRequest(
            steps=steps,
            scope=self._current_scope(),
        )
        self.accept()

    def get_request(self) -> TransformRequest | None:
        return self._result
