# -*- coding: utf-8 -*-
"""Disassembler and control-flow-graph widget for the hex editor."""

import math
from collections import deque
from typing import List, Tuple, Optional

from PySide6.QtCore import Qt, Signal, QThread, QRectF, QPointF, QAbstractTableModel, QModelIndex
from PySide6.QtGui import (QFont, QColor, QPen, QPainter, QPolygonF,
                           QPainterPath, QBrush, QKeySequence, QShortcut, QFontMetricsF)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QComboBox, QPushButton, QProgressBar,
                               QTableView, QApplication,
                               QAbstractItemView, QTabWidget,
                               QGraphicsView, QGraphicsScene,
                               QGraphicsRectItem, QGraphicsPathItem,
                               QGraphicsEllipseItem, QCheckBox, QGraphicsSimpleTextItem)

try:
    import capstone
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# ── Data structures ─────────────────────────────────────────────────

from .cfg_layout import layered_layout
from .disasm_address import executable_address_map

from .disasm_analysis import (DisasmInstruction, BasicBlock, CallGraphNode,
                              DisasmResult, build_cfg, build_call_graph, classify_instruction)


# ── Architecture presets ────────────────────────────────────────────

ARCH_PRESETS = [
    ("Auto-detect", None, None),
    ("x86-16", None, None),
    ("x86-32", None, None),
    ("x86-64", None, None),
    ("ARM", None, None),
    ("ARM Thumb", None, None),
    ("ARM64", None, None),
    ("MIPS32", None, None),
    ("MIPS64", None, None),
    ("PPC32", None, None),
    ("PPC64", None, None),
]


def _resolve_arch(preset_name: str):
    """Return (cs_arch, cs_mode) for a preset name. Requires capstone."""
    CS = capstone
    mapping = {
        "x86-16": (CS.CS_ARCH_X86, CS.CS_MODE_16),
        "x86-32": (CS.CS_ARCH_X86, CS.CS_MODE_32),
        "x86-64": (CS.CS_ARCH_X86, CS.CS_MODE_64),
        "ARM": (CS.CS_ARCH_ARM, CS.CS_MODE_ARM),
        "ARM Thumb": (CS.CS_ARCH_ARM, CS.CS_MODE_THUMB),
        "ARM64": (CS.CS_ARCH_ARM64, CS.CS_MODE_ARM),
        "MIPS32": (CS.CS_ARCH_MIPS, CS.CS_MODE_MIPS32),
        "MIPS64": (CS.CS_ARCH_MIPS, CS.CS_MODE_MIPS64),
        "PPC32": (CS.CS_ARCH_PPC, CS.CS_MODE_32),
        "PPC64": (CS.CS_ARCH_PPC, CS.CS_MODE_64),
    }
    return mapping.get(preset_name, (CS.CS_ARCH_X86, CS.CS_MODE_64))


def _auto_detect_arch(buffer):
    """Use PE/ELF parsers to guess capstone arch/mode. Falls back to x86-64."""
    CS = capstone
    if buffer is None:
        return CS.CS_ARCH_X86, CS.CS_MODE_64, "x86-64"

    raw = buffer.read(0, min(64, buffer.size()))
    if len(raw) < 4:
        return CS.CS_ARCH_X86, CS.CS_MODE_64, "x86-64"

    # Try PE
    if raw[:2] == b'MZ':
        try:
            from .pe_parser import PeParser
            pe = PeParser(buffer)
            info = pe.parse()
            if info:
                m = info.machine
                pe_map = {
                    0x014C: (CS.CS_ARCH_X86, CS.CS_MODE_32, "x86-32"),
                    0x8664: (CS.CS_ARCH_X86, CS.CS_MODE_64, "x86-64"),
                    0x01C0: (CS.CS_ARCH_ARM, CS.CS_MODE_ARM, "ARM"),
                    0x01C4: (CS.CS_ARCH_ARM, CS.CS_MODE_THUMB, "ARM Thumb"),
                    0xAA64: (CS.CS_ARCH_ARM64, CS.CS_MODE_ARM, "ARM64"),
                }
                if m in pe_map:
                    return pe_map[m]
        except Exception:
            pass

    # Try ELF
    if raw[:4] == b'\x7fELF':
        try:
            from .elf_parser import ElfParser
            elf = ElfParser(buffer)
            info = elf.parse()
            if info:
                em = info.e_machine
                is64 = info.is_64bit
                elf_map = {
                    0x03: (CS.CS_ARCH_X86, CS.CS_MODE_32, "x86-32"),
                    0x3E: (CS.CS_ARCH_X86, CS.CS_MODE_64, "x86-64"),
                    0x28: (CS.CS_ARCH_ARM, CS.CS_MODE_ARM, "ARM"),
                    0xB7: (CS.CS_ARCH_ARM64, CS.CS_MODE_ARM, "ARM64"),
                    0x08: (CS.CS_ARCH_MIPS, CS.CS_MODE_MIPS64 if is64 else CS.CS_MODE_MIPS32, "MIPS64" if is64 else "MIPS32"),
                    0x15: (CS.CS_ARCH_PPC, CS.CS_MODE_64, "PPC64"),
                    0x14: (CS.CS_ARCH_PPC, CS.CS_MODE_64 if is64 else CS.CS_MODE_32, "PPC64" if is64 else "PPC32"),
                }
                if em in elf_map:
                    arch, mode, name = elf_map[em]
                    if info.is_big_endian:
                        mode |= CS.CS_MODE_BIG_ENDIAN
                        name += " (big endian)"
                    return arch, mode, name
        except Exception:
            pass

    return CS.CS_ARCH_X86, CS.CS_MODE_64, "x86-64"


# ── Disassembly thread ──────────────────────────────────────────────

class _DisassembleThread(QThread):
    progress = Signal(int)
    finished_results = Signal(DisasmResult)

    def __init__(self, code: bytes, base_offset: int, arch, mode, syntax, buffer=None):
        super().__init__()
        self._code = code
        self._base = base_offset
        self._arch = arch
        self._mode = mode
        self._syntax = syntax
        self._buffer = buffer
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            self._decode()
        except Exception as exc:
            if not self._cancelled:
                self.finished_results.emit(DisasmResult(base_offset=self._base, error=str(exc)))

    def _decode(self):
        result = DisasmResult(base_offset=self._base)

        if self._arch is None:
            arch, mode, name = _auto_detect_arch(self._buffer)
            result.arch_name = name
        else:
            arch, mode = self._arch, self._mode
            for pname, _, _ in ARCH_PRESETS[1:]:
                if _resolve_arch(pname) == (arch, mode):
                    result.arch_name = pname
                    break

        try:
            md = capstone.Cs(arch, mode)
            md.detail = True
            md.skipdata = True
            if self._syntax == "AT&T" and arch == capstone.CS_ARCH_X86:
                md.syntax = capstone.CS_OPT_SYNTAX_ATT
        except Exception as e:
            result.error = str(e)
            self.finished_results.emit(result)
            return

        mapping = executable_address_map(self._buffer)
        virtual_base = mapping.virtual_base(self._base, len(self._code))
        decode_base = self._base if virtual_base is None else virtual_base
        result.warning = "Linear sweep; function boundaries are inferred"
        if mapping.ranges and virtual_base is None:
            result.warning += "; selection spans unmapped ranges, addresses treated as raw offsets"

        # Phase 1: disassemble (0-90%)
        instructions = []
        total = len(self._code)
        count = 0
        for insn in md.disasm(self._code, decode_base):
            if self._cancelled:
                return
            di = DisasmInstruction(
                address=self._base + insn.address - decode_base,
                size=insn.size,
                raw_bytes=bytes(insn.bytes),
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
            )
            classify_instruction(insn, di, arch)
            if virtual_base is not None and di.branch_target is not None:
                di.branch_target = mapping.file_offset(di.branch_target)

            instructions.append(di)
            count += insn.size
            if count % 1024 < insn.size:
                pct = int(count / total * 90) if total else 90
                self.progress.emit(min(pct, 90))

        result.instructions = instructions
        self.progress.emit(90)

        if self._cancelled:
            return

        # Phase 2: build CFG (90-95%)
        supported_cfg = arch in (capstone.CS_ARCH_X86, capstone.CS_ARCH_ARM, capstone.CS_ARCH_ARM64)
        if supported_cfg:
            result.basic_blocks = build_cfg(instructions)
        else:
            result.warning += "; CFG / call analysis unavailable for this architecture"
        if any(i.is_data for i in instructions):
            result.warning += "; undecoded data breaks control flow"
        self.progress.emit(95)

        if self._cancelled:
            return

        # Phase 3: build call graph (95-100%)
        if supported_cfg:
            result.call_graph = build_call_graph(instructions)
        self.progress.emit(100)
        self.finished_results.emit(result)

# ── Listing table widget ────────────────────────────────────────────

_CLR_JUMP = QColor("#E0A020")   # amber
_CLR_CALL = QColor("#4090E0")   # blue
_CLR_RET = QColor("#E04040")    # red
_CLR_DEFAULT = QColor("#D0D0D0")


_CLR_INDIRECT = QColor("#806060")  # dim for indirect annotation


class DisasmTableModel(QAbstractTableModel):
    """Virtual listing: no per-instruction table widgets or eager cell allocation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.instructions = []

    def set_instructions(self, instructions):
        self.beginResetModel()
        self.instructions = instructions
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.instructions)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else 2

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return ("File offset", "Instruction")[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.instructions):
            return None
        insn = self.instructions[index.row()]
        if role == Qt.ItemDataRole.ForegroundRole:
            return _CLR_CALL if insn.is_call else _CLR_RET if insn.is_ret else _CLR_JUMP if insn.is_jump else None
        if role == Qt.ItemDataRole.ToolTipRole:
            if insn.target_address is not None:
                target = f"Target address: 0x{insn.target_address:X}"
                return target + (f"; file offset: 0x{insn.branch_target:X}" if insn.branch_target is not None
                                 else "; no file-backed mapping")
            return insn.raw_bytes.hex(" ")
        if role == Qt.ItemDataRole.DisplayRole:
            if index.column() == 0:
                return f"0x{insn.address:08X}"
            text = f"{insn.mnemonic:<8s} {insn.op_str}"
            if insn.is_indirect:
                text += "   ; [indirect]"
            elif insn.branch_target is not None:
                text += f"   ; file -> 0x{insn.branch_target:X}"
            return text
        return None


class DisasmTableWidget(QWidget):
    navigate_requested = Signal(int, int)
    follow_requested = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._model = DisasmTableModel(self)
        self._table = QTableView(self)
        self._table.setModel(self._model)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(0, 150)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.doubleClicked.connect(self._on_double_click)
        font = QFont("Cascadia Code", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._table.setFont(font)
        layout.addWidget(self._table)

    def clear(self):
        self._model.set_instructions([])

    def populate(self, instructions, base_offset):
        self._model.set_instructions(instructions)

    def _on_double_click(self, index):
        if 0 <= index.row() < len(self._model.instructions):
            insn = self._model.instructions[index.row()]
            if (insn.is_call or insn.is_jump) and insn.branch_target is not None:
                self.follow_requested.emit(insn.branch_target)
            else:
                self.navigate_requested.emit(insn.address, insn.size)


# ── CFG block graphics item ────────────────────────────────────────

_BLOCK_PAD = 8
_BLOCK_BG = QColor("#1E1E2E")
_BLOCK_BORDER = QColor("#555570")
_BLOCK_BORDER_SEL = QColor("#8888CC")


class _BlockItem(QGraphicsRectItem):

    def __init__(self, block: BasicBlock, base_offset: int, view: 'CfgGraphicsView'):
        super().__init__()
        self._block = block
        self._base_offset = base_offset
        self._view = view
        self._lines: List[Tuple[str, QColor]] = []

        self._font = QFont("Cascadia Code", 9)
        self._font.setStyleHint(QFont.StyleHint.Monospace)
        metrics = QFontMetricsF(self._font)
        self._line_height = math.ceil(metrics.height()) + 2
        instructions = block.instructions
        omitted = 0
        if view.compact_blocks and len(instructions) > 16:
            omitted = len(instructions) - 14
            instructions = instructions[:10] + instructions[-4:]
        noun = "instruction" if len(block.instructions) == 1 else "instructions"
        self._lines.append((f"Block 0x{block.start_addr:X} · {len(block.instructions)} {noun}", _CLR_DEFAULT))
        for index, insn in enumerate(instructions):
            if omitted and index == 10:
                self._lines.append((f"… {omitted} instructions hidden", QColor("#A0A0B8")))
            text = f"0x{insn.address:08X}  {insn.mnemonic:8s} {insn.op_str}"
            if insn.is_indirect:
                text += "  [indirect]"
            if insn.is_call:
                color = _CLR_CALL
            elif insn.is_ret:
                color = _CLR_RET
            elif insn.is_jump:
                color = _CLR_JUMP
            else:
                color = _CLR_DEFAULT
            self._lines.append((text, color))

        self._lines.extend((text, QColor("#E0B870")) for text in block.exits)
        max_w = max((metrics.horizontalAdvance(t) for t, _ in self._lines), default=120)
        h = len(self._lines) * self._line_height + _BLOCK_PAD * 2
        self.setRect(0, 0, max(max_w + _BLOCK_PAD * 2, 160), h)
        self.setToolTip("\n".join(f"0x{i.address:X}  {i.mnemonic} {i.op_str}" for i in block.instructions))
        self.setPen(QPen(_BLOCK_BORDER, 1))
        self.setBrush(QBrush(_BLOCK_BG))
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemUsesExtendedStyleOption, True)
        self.setCursor(Qt.CursorShape.SizeAllCursor)

    def itemChange(self, change, value):
        if change == QGraphicsRectItem.GraphicsItemChange.ItemPositionHasChanged:
            if not self._view._laying_out:
                self._view._rebuild_edges()
        return super().itemChange(change, value)

    def paint(self, painter: QPainter, option, widget=None):
        # Draw background + border manually to control selection highlight
        r = self.rect()
        painter.setBrush(QBrush(_BLOCK_BG))
        border = _BLOCK_BORDER_SEL if self.isSelected() else _BLOCK_BORDER
        painter.setPen(QPen(border, 1.5 if self.isSelected() else 1))
        painter.drawRect(r)

        # Expanded blocks may contain thousands of lines; paint only the viewport.
        if abs(painter.worldTransform().m11()) < 0.2:
            return
        painter.setFont(self._font)
        first = max(0, int((option.exposedRect.top() - _BLOCK_PAD) // self._line_height))
        last = min(len(self._lines), int(option.exposedRect.bottom() // self._line_height) + 1)
        y = _BLOCK_PAD + (first + 1) * self._line_height - 3
        for text, color in self._lines[first:last]:
            painter.setPen(QPen(color))
            painter.drawText(_BLOCK_PAD, y, text)
            y += self._line_height

    @property
    def block(self) -> BasicBlock:
        return self._block


# ── Edge waypoint handle ───────────────────────────────────────────

_WP_RADIUS = 5
_WP_COLOR = QColor("#606080")
_WP_HOVER = QColor("#9090C0")


class _WaypointHandle(QGraphicsEllipseItem):
    """Draggable control point on an edge. Rebuilds edges when moved."""

    def __init__(self, x: float, y: float, edge_key: Tuple[int, int, str],
                 view: 'CfgGraphicsView'):
        super().__init__(-_WP_RADIUS, -_WP_RADIUS, _WP_RADIUS * 2, _WP_RADIUS * 2)
        self.setPos(x, y)
        self._edge_key = edge_key
        self._view = view
        self.setPen(QPen(_WP_COLOR, 1))
        self.setBrush(QBrush(_WP_COLOR))
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setCursor(Qt.CursorShape.SizeAllCursor)
        self.setZValue(1)
        self.setAcceptHoverEvents(True)

    def hoverEnterEvent(self, event):
        self.setBrush(QBrush(_WP_HOVER))
        self.setPen(QPen(_WP_HOVER, 1.5))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setBrush(QBrush(_WP_COLOR))
        self.setPen(QPen(_WP_COLOR, 1))
        super().hoverLeaveEvent(event)

    def itemChange(self, change, value):
        if change == QGraphicsEllipseItem.GraphicsItemChange.ItemPositionHasChanged:
            # Update stored waypoint position and rebuild edges
            self._view._update_waypoint(self._edge_key, value)
        return super().itemChange(change, value)


# ── Helper: connect edge to nearest border point of a rect ─────────

def _border_point(rect: QRectF, target: QPointF) -> QPointF:
    """Find the point on rect's border closest to target, clamped to edges."""
    cx, cy = rect.center().x(), rect.center().y()
    tx, ty = target.x(), target.y()
    dx = tx - cx
    dy = ty - cy
    if abs(dx) < 0.1 and abs(dy) < 0.1:
        return QPointF(cx, rect.bottom())

    hw, hh = rect.width() / 2, rect.height() / 2
    # Scale factors to hit each edge
    candidates = []
    if abs(dx) > 0.01:
        sx = hw / abs(dx)
        py = cy + dy * sx
        if rect.top() <= py <= rect.bottom():
            candidates.append(QPointF(cx + hw if dx > 0 else cx - hw, py))
    if abs(dy) > 0.01:
        sy = hh / abs(dy)
        px = cx + dx * sy
        if rect.left() <= px <= rect.right():
            candidates.append(QPointF(px, cy + hh if dy > 0 else cy - hh))
    if not candidates:
        return QPointF(cx, rect.bottom())
    # Return the one closest to target
    return min(candidates, key=lambda p: (p.x() - tx) ** 2 + (p.y() - ty) ** 2)


# ── CFG graphics view ──────────────────────────────────────────────

_EDGE_TAKEN = QColor("#E04040")      # red
_EDGE_FALLTHROUGH = QColor("#40C040")  # green
_EDGE_UNCONDITIONAL = QColor("#888888")  # gray



class CfgGraphicsView(QGraphicsView):
    navigate_requested = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.compact_blocks = True
        self.show_handles = False
        self._laying_out = False
        self._blocks = []
        self._ranks = {}
        self.setBackgroundBrush(QColor("#14141F"))
        self._base_offset = 0
        self._block_items: dict[int, _BlockItem] = {}
        self._edge_defs: List[Tuple[int, int, str]] = []  # (src_addr, dst_addr, edge_type)
        self._edge_gfx: list = []  # edge path + arrow items to rebuild
        self._wp_handles: list = []  # waypoint handle items
        # Per-edge waypoint: edge_key -> QPointF
        self._waypoints: dict[Tuple[int, int, str], QPointF] = {}

    def clear(self):
        self._blocks = []
        self._ranks.clear()
        self._scene.clear()
        self._block_items.clear()
        self._edge_defs.clear()
        self._edge_gfx.clear()
        self._wp_handles.clear()
        self._waypoints.clear()

    # ── Graph layout ────────────────────────────────────────────────

    def populate(self, blocks: List[BasicBlock], base_offset: int):
        self.clear()
        self._blocks = blocks
        if not blocks:
            return
        self._base_offset = base_offset
        if len(blocks) > 1500:
            message = self._scene.addText(f"{len(blocks):,} blocks — select a smaller byte range to view the CFG.")
            message.setDefaultTextColor(_CLR_DEFAULT)
            self.resetTransform()
            self.centerOn(message)
            return
        self._laying_out = True
        try:
            self._block_items = {bb.start_addr: _BlockItem(bb, base_offset, self) for bb in blocks}
            self._edge_defs = [(bb.start_addr, target, kind) for bb in blocks
                               for target, kind in bb.successors if target in self._block_items]
            sizes = {addr: (item.rect().width(), item.rect().height())
                     for addr, item in self._block_items.items()}
            positions, self._ranks = layered_layout(sizes, self._edge_defs)
            for addr, item in self._block_items.items():
                item.setPos(*positions[addr])
                self._scene.addItem(item)
        finally:
            self._laying_out = False
        self._rebuild_edges()
        self.resetTransform()
        self.centerOn(self._block_items[blocks[0].start_addr])

    def fit_graph(self):
        if self._block_items:
            self.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
            if self.transform().m11() > 1:
                self.resetTransform()

    def reset_layout(self):
        self.populate(self._blocks, self._base_offset)

    def set_compact(self, enabled):
        self.compact_blocks = enabled
        self.reset_layout()

    def set_handles_visible(self, enabled):
        self.show_handles = enabled
        for handle in self._wp_handles:
            handle.setVisible(enabled)

    # ── Edge drawing (called on populate and on every node drag) ──

    def _rebuild_edges(self):
        """Full rebuild: remove old edges + handles, draw new ones."""
        for item in self._edge_gfx:
            self._scene.removeItem(item)
        self._edge_gfx.clear()
        for wh in self._wp_handles:
            self._scene.removeItem(wh)
        self._wp_handles.clear()
        self._rebuild_paths_only(create_handles=True)

    def _rebuild_paths_only(self, create_handles: bool = False):
        """Rebuild edge paths + arrows. Optionally create waypoint handles."""
        succ_count: dict[int, int] = {}
        for sa, _, _ in self._edge_defs:
            succ_count[sa] = succ_count.get(sa, 0) + 1

        rects = [it.sceneBoundingRect() for it in self._block_items.values()]
        outer_left = min((r.left() for r in rects), default=0)
        outer_right = max((r.right() for r in rects), default=0)
        row_bottom = {}
        for addr, item in self._block_items.items():
            rank = self._ranks.get(addr, 0)
            row_bottom[rank] = max(row_bottom.get(rank, -float("inf")), item.sceneBoundingRect().bottom())
        incoming = {}
        for edge in self._edge_defs:
            incoming.setdefault(edge[1], []).append(edge)
        target_ports = {}
        for target, edges in incoming.items():
            edges.sort(key=lambda e: self._block_items[e[0]].sceneBoundingRect().center().x())
            for index, edge in enumerate(edges):
                target_ports[edge] = (index - (len(edges) - 1) / 2) * min(18, self._block_items[target].rect().width() / (len(edges) + 1))
        lane_index = 0
        for src_addr, dst_addr, edge_type in self._edge_defs:
            src = self._block_items.get(src_addr)
            dst = self._block_items.get(dst_addr)
            if src is None or dst is None:
                continue

            color = {
                "taken": _EDGE_TAKEN,
                "fallthrough": _EDGE_FALLTHROUGH,
            }.get(edge_type, _EDGE_UNCONDITIONAL)

            ek = (src_addr, dst_addr, edge_type)
            src_r = src.sceneBoundingRect()
            dst_r = dst.sceneBoundingRect()
            wp = self._waypoints.get(ek)

            if wp is not None:
                # User waypoint: route through it
                src_pt = _border_point(src_r, wp)
                dst_pt = _border_point(dst_r, wp)
                path = QPainterPath()
                path.moveTo(src_pt)
                path.quadTo(wp, dst_pt)
                handle_pt = wp
            else:
                spread = min(24, src_r.width() * 0.15) if succ_count.get(src_addr, 0) > 1 else 0
                sx = src_r.center().x() + (-spread if edge_type == "fallthrough" else spread)
                src_pt = QPointF(sx, src_r.bottom())
                dst_pt = QPointF(dst_r.center().x() + target_ports[ek], dst_r.top())
                path = QPainterPath(src_pt)
                gap = dst_r.top() - src_r.bottom()
                # Adjacent ranks have an empty gutter for an orthogonal bend.
                adjacent = self._ranks.get(dst_addr, 0) == self._ranks.get(src_addr, 0) + 1
                if adjacent and gap >= 24:
                    bottom = row_bottom[self._ranks[src_addr]]
                    mid_y = bottom + (dst_r.top() - bottom) / 2
                    points = [QPointF(sx, mid_y), QPointF(dst_pt.x(), mid_y), dst_pt]
                else:
                    # Back edges, self loops and long edges use distinct exterior lanes.
                    lane = lane_index * 12 + 36
                    lane_index += 1
                    left = edge_type == "fallthrough"
                    lane_x = outer_left - lane if left else outer_right + lane
                    bottom = row_bottom[self._ranks[src_addr]]
                    points = [QPointF(sx, bottom + 20),
                              QPointF(lane_x, bottom + 20),
                              QPointF(lane_x, dst_r.top() - 20),
                              QPointF(dst_pt.x(), dst_r.top() - 20), dst_pt]
                for point in points:
                    path.lineTo(point)
                handle_pt = path.pointAtPercent(0.5)

            ei = QGraphicsPathItem(path)
            ei.setPen(QPen(color, 1.5))
            ei.setZValue(-1)
            self._scene.addItem(ei)
            self._edge_gfx.append(ei)

            arrow = self._make_arrowhead(path, color)
            self._scene.addItem(arrow)
            self._edge_gfx.append(arrow)

            label = QGraphicsSimpleTextItem({"taken": "T", "fallthrough": "F"}.get(edge_type, "J"))
            label.setBrush(QBrush(color))
            label.setPos(src_pt.x() + 4, src_pt.y() + 2)
            label.setToolTip({"taken": "Branch taken", "fallthrough": "Fallthrough", "unconditional": "Unconditional jump"}.get(edge_type, edge_type))
            self._scene.addItem(label)
            self._edge_gfx.append(label)

            if create_handles:
                h = _WaypointHandle(handle_pt.x(), handle_pt.y(), ek, self)
                self._scene.addItem(h)
                h.setVisible(self.show_handles)
                self._wp_handles.append(h)

        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-30, -30, 30, 30))

    def _update_waypoint(self, edge_key: Tuple[int, int, str], pos: QPointF):
        """Called by _WaypointHandle when dragged — store position and rebuild edges only."""
        self._waypoints[edge_key] = QPointF(pos)
        # Rebuild only path+arrow graphics (handles stay in place during drag)
        for item in self._edge_gfx:
            self._scene.removeItem(item)
        self._edge_gfx.clear()
        self._rebuild_paths_only()

    def _make_arrowhead(self, edge_path: QPainterPath, color: QColor) -> QGraphicsPathItem:
        """Create an arrowhead at the end of the path, pointing in the direction of arrival."""
        size = 6
        end = edge_path.pointAtPercent(1.0)
        angle = math.radians(edge_path.angleAtPercent(1.0))
        dx, dy = math.cos(angle), -math.sin(angle)
        px, py = -dy, dx
        base = QPointF(end.x() - dx * size * 1.5, end.y() - dy * size * 1.5)
        p1 = QPointF(base.x() + px * size, base.y() + py * size)
        p2 = QPointF(base.x() - px * size, base.y() - py * size)
        tri = QPolygonF([end, p1, p2, end])
        ap = QPainterPath()
        ap.addPolygon(tri)
        arrow = QGraphicsPathItem(ap)
        arrow.setPen(QPen(color, 1))
        arrow.setBrush(QBrush(color))
        arrow.setZValue(-1)
        return arrow

    # ── Interaction ─────────────────────────────────────────────────

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        current = self.transform().m11()
        if (factor > 1 and current < 4) or (factor < 1 and current > 0.08):
            target = min(4, current * factor) if factor > 1 else max(0.08, current * factor)
            self.scale(target / current, target / current)
        event.accept()

    def mouseDoubleClickEvent(self, event):
        item = self.itemAt(event.pos())
        while item and not isinstance(item, _BlockItem):
            item = item.parentItem()
        if isinstance(item, _BlockItem):
            bb = item.block
            self.navigate_requested.emit(bb.start_addr, bb.end_addr - bb.start_addr)
        else:
            super().mouseDoubleClickEvent(event)


# ── Call graph node item ────────────────────────────────────────────

_CG_NODE_W = 160
_CG_NODE_H = 44
_CG_BG = QColor("#1E2E1E")
_CG_BORDER = QColor("#557055")
_CG_TEXT = QColor("#C0E0C0")
_CG_SUB = QColor("#80A080")


class _CallNodeItem(QGraphicsRectItem):

    def __init__(self, node: CallGraphNode):
        super().__init__()
        self._node = node
        self.setRect(0, 0, _CG_NODE_W, _CG_NODE_H)
        self.setPen(QPen(_CG_BORDER, 1.5))
        self.setBrush(QBrush(_CG_BG))
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemIsSelectable, True)

    def paint(self, painter: QPainter, option, widget=None):
        super().paint(painter, option, widget)
        font = QFont("Cascadia Code", 9)
        font.setStyleHint(QFont.StyleHint.Monospace)
        painter.setFont(font)
        painter.setPen(QPen(_CG_TEXT))
        painter.drawText(8, 18, self._node.label)
        painter.setPen(QPen(_CG_SUB))
        font.setPointSize(7)
        painter.setFont(font)
        painter.drawText(8, 34, f"{self._node.insn_count} insns")

    def bottom_center(self) -> QPointF:
        r = self.sceneBoundingRect()
        return QPointF(r.center().x(), r.bottom())

    def top_center(self) -> QPointF:
        r = self.sceneBoundingRect()
        return QPointF(r.center().x(), r.top())

    @property
    def node(self) -> CallGraphNode:
        return self._node


# ── Call graph graphics view ───────────────────────────────────────

_CG_EDGE = QColor("#4090E0")
_CG_V_GAP = 50
_CG_H_GAP = 30


class CallGraphView(QGraphicsView):
    navigate_requested = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self._base_offset = 0

    def clear(self):
        self._scene.clear()

    def populate(self, call_graph: List[CallGraphNode], base_offset: int):
        self._scene.clear()
        if not call_graph:
            return

        if len(call_graph) > 1500:
            message = self._scene.addText(f"{len(call_graph):,} inferred functions — select a smaller byte range to view the call graph.")
            self.resetTransform()
            self.centerOn(message)
            return

        self._base_offset = base_offset

        # Assign depth via BFS from roots (nodes with no callers)
        addr_to_node = {n.address: n for n in call_graph}
        roots = [n for n in call_graph if not n.callers]
        if not roots:
            roots = [call_graph[0]]

        depth_map = {}  # address -> depth
        visited = set()
        queue = deque((r.address, 0) for r in roots)
        for addr, _ in queue:
            visited.add(addr)

        while queue:
            addr, d = queue.popleft()
            if addr in depth_map:
                depth_map[addr] = max(depth_map[addr], d)
            else:
                depth_map[addr] = d
            node = addr_to_node.get(addr)
            if node:
                for callee in node.callees:
                    if callee not in visited:
                        visited.add(callee)
                        queue.append((callee, d + 1))

        # Nodes not reached — assign depth 0
        for n in call_graph:
            if n.address not in depth_map:
                depth_map[n.address] = 0

        # Group by depth
        depth_groups = {}
        for addr, d in depth_map.items():
            depth_groups.setdefault(d, []).append(addr)

        # Layout: rows by depth, centered horizontally
        node_items = {}
        y = 0
        for d in sorted(depth_groups.keys()):
            addrs = sorted(depth_groups[d])
            row_w = len(addrs) * (_CG_NODE_W + _CG_H_GAP) - _CG_H_GAP
            x_start = -row_w / 2
            for i, addr in enumerate(addrs):
                node = addr_to_node.get(addr)
                if node is None:
                    continue
                item = _CallNodeItem(node)
                x = x_start + i * (_CG_NODE_W + _CG_H_GAP)
                item.setPos(x, y)
                self._scene.addItem(item)
                node_items[addr] = item
            y += _CG_NODE_H + _CG_V_GAP

        # Draw edges
        for n in call_graph:
            src = node_items.get(n.address)
            if src is None:
                continue
            for callee_addr in n.callees:
                dst = node_items.get(callee_addr)
                if dst is None:
                    continue

                src_pt = src.bottom_center()
                dst_pt = dst.top_center()

                path = QPainterPath()
                if dst_pt.y() <= src_pt.y():
                    # Back edge (recursion) — route right
                    right_x = max(src_pt.x(), dst_pt.x()) + _CG_NODE_W * 0.7
                    path.moveTo(src_pt)
                    path.lineTo(right_x, src_pt.y())
                    path.lineTo(right_x, dst_pt.y())
                    path.lineTo(dst_pt)
                else:
                    mid_y = (src_pt.y() + dst_pt.y()) / 2
                    path.moveTo(src_pt)
                    path.cubicTo(src_pt.x(), mid_y, dst_pt.x(), mid_y, dst_pt.x(), dst_pt.y())

                edge = QGraphicsPathItem(path)
                edge.setPen(QPen(_CG_EDGE, 1.5))
                self._scene.addItem(edge)

                # Arrowhead
                size = 5
                tip = dst_pt
                p1 = QPointF(tip.x() - size, tip.y() - size * 1.5)
                p2 = QPointF(tip.x() + size, tip.y() - size * 1.5)
                tri_path = QPainterPath()
                tri_path.addPolygon(QPolygonF([tip, p1, p2, tip]))
                arrow = QGraphicsPathItem(tri_path)
                arrow.setPen(QPen(_CG_EDGE, 1))
                arrow.setBrush(QBrush(_CG_EDGE))
                self._scene.addItem(arrow)

        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-30, -30, 30, 30))

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def mouseDoubleClickEvent(self, event):
        item = self.itemAt(event.pos())
        while item and not isinstance(item, _CallNodeItem):
            item = item.parentItem()
        if isinstance(item, _CallNodeItem):
            self.navigate_requested.emit(item.node.address, 1)
        else:
            super().mouseDoubleClickEvent(event)


# ── Main disassembly dock widget ────────────────────────────────────

_FOLLOW_CHUNK = 0x4000  # bytes to read when following a branch


class DisasmWidget(QWidget):
    """Dock content widget: arch selector, disassemble button, listing + CFG tabs, history navigation."""

    navigate_requested = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer = None
        self._code: Optional[bytes] = None
        self._base_offset = 0
        self._thread: Optional[_DisassembleThread] = None
        self._workers = set()
        QApplication.instance().aboutToQuit.connect(self.shutdown)
        self._back_stack: List[Tuple[bytes, int]] = []    # back history
        self._forward_stack: List[Tuple[bytes, int]] = []  # forward history

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Controls row
        ctrl = QHBoxLayout()

        self._btn_back = QPushButton("\u2190")
        self._btn_back.setToolTip("Back (Alt+Left / Backspace / Esc)")
        self._btn_back.setEnabled(False)
        self._btn_back.setFixedWidth(32)
        self._btn_back.clicked.connect(self._on_back)
        ctrl.addWidget(self._btn_back)

        self._btn_fwd = QPushButton("\u2192")
        self._btn_fwd.setToolTip("Forward (Alt+Right)")
        self._btn_fwd.setEnabled(False)
        self._btn_fwd.setFixedWidth(32)
        self._btn_fwd.clicked.connect(self._on_forward)
        ctrl.addWidget(self._btn_fwd)

        # Keyboard shortcuts for history navigation
        for key in ("Alt+Left", "Backspace", "Escape"):
            sc = QShortcut(QKeySequence(key), self)
            sc.activated.connect(self._on_back)
        sc_fwd = QShortcut(QKeySequence("Alt+Right"), self)
        sc_fwd.activated.connect(self._on_forward)

        ctrl.addWidget(QLabel("Arch:"))
        self._arch_combo = QComboBox()
        for name, _, _ in ARCH_PRESETS:
            self._arch_combo.addItem(name)
        self._arch_combo.setCurrentIndex(0)
        ctrl.addWidget(self._arch_combo)

        ctrl.addWidget(QLabel("Syntax:"))
        self._syntax_combo = QComboBox()
        self._syntax_combo.addItems(["Intel", "AT&T"])
        ctrl.addWidget(self._syntax_combo)

        self._btn_disasm = QPushButton("Disassemble")
        self._btn_disasm.clicked.connect(self._on_disassemble)
        ctrl.addWidget(self._btn_disasm)

        self._btn_cancel = QPushButton("Cancel")
        self._btn_cancel.setEnabled(False)
        self._btn_cancel.clicked.connect(self._on_cancel)
        ctrl.addWidget(self._btn_cancel)

        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setMaximum(100)
        self._progress.setTextVisible(True)
        self._progress.hide()
        layout.addWidget(self._progress)

        # Tab widget
        self._tabs = QTabWidget()

        self._listing = DisasmTableWidget()
        self._listing.navigate_requested.connect(self.navigate_requested)
        self._listing.follow_requested.connect(self._on_follow)
        self._tabs.addTab(self._listing, "Listing")

        self._cfg_view = CfgGraphicsView()
        self._cfg_view.navigate_requested.connect(self.navigate_requested)
        cfg_page = QWidget()
        cfg_layout = QVBoxLayout(cfg_page)
        cfg_layout.setContentsMargins(0, 0, 0, 0)
        graph_tools = QHBoxLayout()
        for title, callback in (("Fit graph", self._cfg_view.fit_graph),
                                ("100%", self._cfg_view.resetTransform),
                                ("Reset layout", self._cfg_view.reset_layout)):
            button = QPushButton(title)
            button.clicked.connect(callback)
            graph_tools.addWidget(button)
        compact = QCheckBox("Compact blocks")
        compact.setChecked(True)
        compact.toggled.connect(self._cfg_view.set_compact)
        graph_tools.addWidget(compact)
        handles = QCheckBox("Edge handles")
        handles.toggled.connect(self._cfg_view.set_handles_visible)
        graph_tools.addWidget(handles)
        graph_tools.addStretch()
        cfg_layout.addLayout(graph_tools)
        legend = QLabel("T: branch taken   F: fallthrough   J: jump · Wheel: zoom · Drag: pan / move block")
        legend.setWordWrap(True)
        cfg_layout.addWidget(legend)
        cfg_layout.addWidget(self._cfg_view)
        self._tabs.addTab(cfg_page, "CFG")

        self._cg_view = CallGraphView()
        self._cg_view.navigate_requested.connect(self.navigate_requested)
        self._tabs.addTab(self._cg_view, "Call Graph")

        layout.addWidget(self._tabs)

        # Status label
        self._status = QLabel("")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)

    # ── Public API ──────────────────────────────────────────────────

    def set_buffer(self, buf):
        self._on_cancel()
        self._thread = None
        self._btn_disasm.setEnabled(True)
        self._btn_cancel.setEnabled(False)
        self._progress.hide()
        self._buffer = buf
        self._code = None
        self._back_stack.clear()
        self._forward_stack.clear()
        self._btn_back.setEnabled(False)
        self._btn_fwd.setEnabled(False)
        self._listing.clear()
        self._cfg_view.clear()
        self._cg_view.clear()
        self._status.setText("")

    def disassemble_bytes(self, code: bytes, base_offset: int = 0):
        """Entry point from the context menu."""
        self._code = code
        self._base_offset = base_offset
        self._on_disassemble()

    # ── Navigation ──────────────────────────────────────────────────

    def _update_nav_buttons(self):
        self._btn_back.setEnabled(len(self._back_stack) > 0)
        self._btn_fwd.setEnabled(len(self._forward_stack) > 0)

    def _on_follow(self, target_addr: int):
        """Follow a branch/call target — push current state, disassemble at target."""
        if self._buffer is None:
            return
        buf_size = self._buffer.size()
        if target_addr < 0 or target_addr >= buf_size:
            self._status.setText(
                f"Target 0x{target_addr:X} is outside buffer range (0x0 - 0x{buf_size - 1:X})")
            return

        # Push current state onto back stack, clear forward stack
        if self._code is not None:
            self._back_stack.append((self._code, self._base_offset))
        self._forward_stack.clear()

        # Read a chunk from target address
        read_len = min(_FOLLOW_CHUNK, buf_size - target_addr)
        chunk = self._buffer.read(target_addr, read_len)
        self._code = bytes(chunk)
        self._base_offset = target_addr
        self._update_nav_buttons()
        self._on_disassemble()

    def _on_back(self):
        """Go back to the previous disassembly."""
        if not self._back_stack:
            return
        # Push current state onto forward stack
        if self._code is not None:
            self._forward_stack.append((self._code, self._base_offset))
        self._code, self._base_offset = self._back_stack.pop()
        self._update_nav_buttons()
        self._on_disassemble()

    def _on_forward(self):
        """Go forward to the next disassembly."""
        if not self._forward_stack:
            return
        # Push current state onto back stack
        if self._code is not None:
            self._back_stack.append((self._code, self._base_offset))
        self._code, self._base_offset = self._forward_stack.pop()
        self._update_nav_buttons()
        self._on_disassemble()

    # ── Internal ────────────────────────────────────────────────────

    def _on_disassemble(self):
        if not _HAS_CAPSTONE:
            self._status.setText("Error: capstone library not installed. Run: pip install capstone")
            return
        if self._code is None or len(self._code) == 0:
            self._status.setText("No bytes to disassemble.")
            return

        # Resolve arch
        preset = self._arch_combo.currentText()
        if preset == "Auto-detect":
            arch, mode = None, None  # thread will auto-detect
        else:
            arch, mode = _resolve_arch(preset)

        syntax = self._syntax_combo.currentText()

        # Cancel any running thread
        if self._thread and self._thread.isRunning():
            self._thread.cancel()

        self._thread = _DisassembleThread(
            self._code, self._base_offset, arch, mode, syntax, self._buffer
        )
        self._workers.add(self._thread)
        self._thread.progress.connect(self._on_progress)
        self._thread.finished_results.connect(self._on_results)
        self._thread.finished.connect(self._on_thread_done)

        self._btn_disasm.setEnabled(False)
        self._btn_cancel.setEnabled(True)
        self._progress.setValue(0)
        self._progress.show()
        self._status.setText("Disassembling...")

        self._thread.start()

    def _on_cancel(self):
        if self._thread:
            self._thread.cancel()
            self._status.setText("Disassembly cancelled")

    def shutdown(self):
        for worker in self._workers:
            worker.cancel()
        for worker in self._workers:
            worker.wait()

    def _current_result(self):
        sender = self.sender()
        return sender is None or (sender is self._thread and not sender._cancelled)

    def _on_progress(self, pct: int):
        if self._current_result():
            self._progress.setValue(pct)

    def _on_results(self, result: DisasmResult):
        if not self._current_result():
            return
        if result.error:
            self._status.setText(f"Error: {result.error}")
            self._listing.clear()
            self._cfg_view.clear()
            self._cg_view.clear()
            return

        self._listing.populate(result.instructions, result.base_offset)
        self._cfg_view.populate(result.basic_blocks, result.base_offset)
        self._cg_view.populate(result.call_graph, result.base_offset)

        n_insn = len(result.instructions)
        n_blk = len(result.basic_blocks)
        n_funcs = len(result.call_graph)
        depth = len(self._back_stack)
        depth_str = f" (depth {depth})" if depth > 0 else ""
        self._status.setText(
            f"{n_insn} instructions, {n_blk} basic blocks, "
            f"{n_funcs} inferred functions — {result.arch_name}{depth_str}\n{result.warning}"
        )

    def _on_thread_done(self):
        worker = self.sender()
        if worker:
            self._workers.discard(worker)
            worker.deleteLater()
        if worker is not self._thread:
            return
        self._thread = None
        self._btn_disasm.setEnabled(True)
        self._btn_cancel.setEnabled(False)
        self._progress.hide()
