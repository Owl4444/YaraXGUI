# -*- coding: utf-8 -*-
"""Disassembler and control-flow-graph widget for the hex editor."""

import math
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

from PySide6.QtCore import Qt, Signal, QThread, QRectF, QPointF
from PySide6.QtGui import (QFont, QColor, QPen, QPainter, QPolygonF,
                           QPainterPath, QBrush, QKeySequence, QShortcut)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QComboBox, QPushButton, QProgressBar,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QAbstractItemView, QTabWidget,
                               QGraphicsView, QGraphicsScene,
                               QGraphicsRectItem, QGraphicsPathItem,
                               QGraphicsEllipseItem)

try:
    import capstone
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# ── Data structures ─────────────────────────────────────────────────

@dataclass
class DisasmInstruction:
    address: int
    size: int
    raw_bytes: bytes
    mnemonic: str
    op_str: str
    is_jump: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_unconditional: bool = False
    branch_target: Optional[int] = None
    is_indirect: bool = False  # True when call/jmp target is memory/register (not calculable)


@dataclass
class BasicBlock:
    start_addr: int
    end_addr: int
    instructions: List[DisasmInstruction] = field(default_factory=list)
    successors: List[Tuple[int, str]] = field(default_factory=list)  # (addr, edge_type)


@dataclass
class CallGraphNode:
    address: int
    label: str  # "sub_XXXX" or "0xXXXX"
    callees: List[int] = field(default_factory=list)   # addresses this function calls
    callers: List[int] = field(default_factory=list)    # addresses that call this function
    insn_count: int = 0


@dataclass
class DisasmResult:
    instructions: List[DisasmInstruction] = field(default_factory=list)
    basic_blocks: List[BasicBlock] = field(default_factory=list)
    call_graph: List[CallGraphNode] = field(default_factory=list)
    arch_name: str = ""
    base_offset: int = 0
    error: str = ""


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
                    0x14: (CS.CS_ARCH_PPC, CS.CS_MODE_64 if is64 else CS.CS_MODE_32, "PPC64" if is64 else "PPC32"),
                }
                if em in elf_map:
                    return elf_map[em]
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
        result = DisasmResult(base_offset=self._base)

        if self._arch is None:
            arch, mode, name = _auto_detect_arch(self._buffer)
            result.arch_name = name
        else:
            arch, mode = self._arch, self._mode
            for pname, _, _ in ARCH_PRESETS:
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

        # Phase 1: disassemble (0-90%)
        instructions = []
        total = len(self._code)
        count = 0
        for insn in md.disasm(self._code, self._base):
            if self._cancelled:
                return
            di = DisasmInstruction(
                address=insn.address,
                size=insn.size,
                raw_bytes=bytes(insn.bytes),
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
            )
            # Classify instruction groups
            try:
                groups = list(insn.groups)
            except (AttributeError, capstone.CsError):
                groups = []

            if groups:
                di.is_jump = capstone.CS_GRP_JUMP in groups
                di.is_call = capstone.CS_GRP_CALL in groups
                di.is_ret = capstone.CS_GRP_RET in groups

                try:
                    operands = list(insn.operands)
                except (AttributeError, capstone.CsError):
                    operands = []

                # Extract branch target
                if arch == capstone.CS_ARCH_X86:
                    if di.is_jump:
                        di.is_unconditional = (insn.id == capstone.x86.X86_INS_JMP)
                    if di.is_jump or di.is_call:
                        found_imm = False
                        for op in operands:
                            if op.type == capstone.x86.X86_OP_IMM:
                                di.branch_target = op.imm
                                found_imm = True
                                break
                        if not found_imm:
                            di.is_indirect = True
                elif arch == capstone.CS_ARCH_ARM64:
                    if di.is_jump:
                        di.is_unconditional = insn.mnemonic in ('b',)
                    if di.is_jump or di.is_call:
                        found_imm = False
                        for op in operands:
                            if op.type == capstone.arm64.ARM64_OP_IMM:
                                di.branch_target = op.imm
                                found_imm = True
                                break
                        if not found_imm:
                            di.is_indirect = True
                elif arch == capstone.CS_ARCH_ARM:
                    if di.is_jump:
                        di.is_unconditional = insn.mnemonic in ('b', 'b.w')
                    if di.is_jump or di.is_call:
                        found_imm = False
                        for op in operands:
                            if op.type == capstone.arm.ARM_OP_IMM:
                                di.branch_target = op.imm
                                found_imm = True
                                break
                        if not found_imm:
                            di.is_indirect = True

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
        result.basic_blocks = self._build_cfg(instructions)
        self.progress.emit(95)

        if self._cancelled:
            return

        # Phase 3: build call graph (95-100%)
        result.call_graph = self._build_call_graph(instructions)
        self.progress.emit(100)
        self.finished_results.emit(result)

    def _build_cfg(self, instructions: List[DisasmInstruction]) -> List[BasicBlock]:
        if not instructions:
            return []

        addr_to_idx = {insn.address: i for i, insn in enumerate(instructions)}

        # Leader identification
        leaders = {instructions[0].address}
        for insn in instructions:
            if insn.is_jump or insn.is_call or insn.is_ret:
                if insn.branch_target is not None and insn.branch_target in addr_to_idx:
                    leaders.add(insn.branch_target)
                # Instruction after branch/ret is a leader
                idx = addr_to_idx.get(insn.address)
                if idx is not None and idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].address)

        sorted_leaders = sorted(leaders)
        blocks = []

        for li, leader_addr in enumerate(sorted_leaders):
            if leader_addr not in addr_to_idx:
                continue
            start_idx = addr_to_idx[leader_addr]
            # Block ends at next leader or end of instructions
            if li + 1 < len(sorted_leaders):
                next_leader = sorted_leaders[li + 1]
                end_idx = addr_to_idx.get(next_leader, len(instructions))
            else:
                end_idx = len(instructions)

            block_insns = instructions[start_idx:end_idx]
            if not block_insns:
                continue

            bb = BasicBlock(
                start_addr=block_insns[0].address,
                end_addr=block_insns[-1].address + block_insns[-1].size,
                instructions=block_insns,
            )

            last = block_insns[-1]
            if last.is_ret:
                pass  # no successors
            elif last.is_jump:
                if last.branch_target is not None and last.branch_target in addr_to_idx:
                    if last.is_unconditional:
                        bb.successors.append((last.branch_target, "unconditional"))
                    else:
                        bb.successors.append((last.branch_target, "taken"))
                        # fallthrough
                        if end_idx < len(instructions):
                            bb.successors.append((instructions[end_idx].address, "fallthrough"))
                elif not last.is_unconditional and end_idx < len(instructions):
                    bb.successors.append((instructions[end_idx].address, "fallthrough"))
            else:
                # Normal fallthrough
                if end_idx < len(instructions):
                    bb.successors.append((instructions[end_idx].address, "fallthrough"))

            blocks.append(bb)

        return blocks

    def _build_call_graph(self, instructions: List[DisasmInstruction]) -> List[CallGraphNode]:
        if not instructions:
            return []

        addr_set = {insn.address for insn in instructions}

        # Identify function entries: start of code + all call targets within range
        call_targets = set()
        for insn in instructions:
            if insn.is_call and insn.branch_target is not None and insn.branch_target in addr_set:
                call_targets.add(insn.branch_target)

        # The first instruction is always a function entry
        func_entries = sorted({instructions[0].address} | call_targets)

        # Map each instruction to its owning function (the highest func_entry <= insn.address)
        def owning_func(addr):
            best = func_entries[0]
            for fe in func_entries:
                if fe <= addr:
                    best = fe
                else:
                    break
            return best

        # Count instructions per function and collect calls
        func_calls = {fe: [] for fe in func_entries}  # fe -> [callee_addr]
        func_insn_count = {fe: 0 for fe in func_entries}

        for insn in instructions:
            owner = owning_func(insn.address)
            func_insn_count[owner] = func_insn_count.get(owner, 0) + 1
            if insn.is_call and insn.branch_target is not None and insn.branch_target in addr_set:
                func_calls[owner].append(insn.branch_target)

        # Build nodes
        nodes = {}
        for fe in func_entries:
            nodes[fe] = CallGraphNode(
                address=fe,
                label=f"sub_{fe:X}",
                callees=sorted(set(func_calls.get(fe, []))),
                insn_count=func_insn_count.get(fe, 0),
            )

        # Fill callers
        for fe, node in nodes.items():
            for callee_addr in node.callees:
                if callee_addr in nodes:
                    nodes[callee_addr].callers.append(fe)

        return [nodes[fe] for fe in func_entries]


# ── Listing table widget ────────────────────────────────────────────

_CLR_JUMP = QColor("#E0A020")   # amber
_CLR_CALL = QColor("#4090E0")   # blue
_CLR_RET = QColor("#E04040")    # red
_CLR_DEFAULT = QColor("#D0D0D0")


_CLR_INDIRECT = QColor("#806060")  # dim for indirect annotation


class DisasmTableWidget(QWidget):
    navigate_requested = Signal(int, int)
    follow_requested = Signal(int)  # branch target address to follow

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(self)
        self._table.setColumnCount(2)
        self._table.setHorizontalHeaderLabels(["Address", "Instruction"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.doubleClicked.connect(self._on_double_click)

        font = QFont("Cascadia Code", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._table.setFont(font)

        layout.addWidget(self._table)
        self._instructions: List[DisasmInstruction] = []
        self._base_offset = 0

    def clear(self):
        self._table.setRowCount(0)
        self._instructions.clear()

    def populate(self, instructions: List[DisasmInstruction], base_offset: int):
        self._instructions = instructions
        self._base_offset = base_offset
        self._table.setRowCount(len(instructions))

        for row, insn in enumerate(instructions):
            if insn.is_call:
                color = _CLR_CALL
            elif insn.is_ret:
                color = _CLR_RET
            elif insn.is_jump:
                color = _CLR_JUMP
            else:
                color = _CLR_DEFAULT

            addr_item = QTableWidgetItem(f"0x{insn.address:08X}")
            addr_item.setForeground(color)
            self._table.setItem(row, 0, addr_item)

            # Compact instruction: "mnemonic  operands  ; annotation"
            text = f"{insn.mnemonic:<8s} {insn.op_str}"
            if insn.is_indirect:
                text += "   ; [indirect]"
            elif insn.branch_target is not None and (insn.is_call or insn.is_jump):
                text += f"   ; -> 0x{insn.branch_target:X}"

            insn_item = QTableWidgetItem(text)
            insn_item.setForeground(color)
            self._table.setItem(row, 1, insn_item)

    def _on_double_click(self, index):
        row = index.row()
        if 0 <= row < len(self._instructions):
            insn = self._instructions[row]
            # Follow resolved branch targets
            if (insn.is_call or insn.is_jump) and insn.branch_target is not None:
                self.follow_requested.emit(insn.branch_target)
            else:
                # Addresses are file offsets (base_offset = file offset of selection start)
                self.navigate_requested.emit(insn.address, insn.size)


# ── CFG block graphics item ────────────────────────────────────────

_BLOCK_PAD = 8
_LINE_H = 14
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

        for insn in block.instructions:
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

        max_w = max((len(t) for t, _ in self._lines), default=10) * 7 + _BLOCK_PAD * 2
        h = len(self._lines) * _LINE_H + _BLOCK_PAD * 2
        self.setRect(0, 0, max(max_w, 120), h)
        self.setPen(QPen(_BLOCK_BORDER, 1))
        self.setBrush(QBrush(_BLOCK_BG))
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsRectItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setCursor(Qt.CursorShape.SizeAllCursor)

    def itemChange(self, change, value):
        if change == QGraphicsRectItem.GraphicsItemChange.ItemPositionHasChanged:
            self._view._rebuild_edges()
        return super().itemChange(change, value)

    def paint(self, painter: QPainter, option, widget=None):
        # Draw background + border manually to control selection highlight
        r = self.rect()
        painter.setBrush(QBrush(_BLOCK_BG))
        border = _BLOCK_BORDER_SEL if self.isSelected() else _BLOCK_BORDER
        painter.setPen(QPen(border, 1.5 if self.isSelected() else 1))
        painter.drawRect(r)

        font = QFont("Cascadia Code", 8)
        font.setStyleHint(QFont.StyleHint.Monospace)
        painter.setFont(font)
        y = _BLOCK_PAD + _LINE_H - 2
        for text, color in self._lines:
            painter.setPen(QPen(color))
            painter.drawText(_BLOCK_PAD, y, text)
            y += _LINE_H

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

_V_GAP = 40
_H_GAP = 80


class CfgGraphicsView(QGraphicsView):
    navigate_requested = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self._base_offset = 0
        self._block_items: dict[int, _BlockItem] = {}
        self._edge_defs: List[Tuple[int, int, str]] = []  # (src_addr, dst_addr, edge_type)
        self._edge_gfx: list = []  # edge path + arrow items to rebuild
        self._wp_handles: list = []  # waypoint handle items
        # Per-edge waypoint: edge_key -> QPointF
        self._waypoints: dict[Tuple[int, int, str], QPointF] = {}

    def clear(self):
        self._scene.clear()
        self._block_items.clear()
        self._edge_defs.clear()
        self._edge_gfx.clear()
        self._wp_handles.clear()
        self._waypoints.clear()

    # ── Graph layout ────────────────────────────────────────────────

    def populate(self, blocks: List[BasicBlock], base_offset: int):
        self._scene.clear()
        self._block_items.clear()
        self._edge_defs.clear()
        self._edge_gfx.clear()
        self._wp_handles.clear()
        self._waypoints.clear()
        if not blocks:
            return
        self._base_offset = base_offset

        addr_to_bb = {bb.start_addr: bb for bb in blocks}

        # Create block graphics items
        for bb in blocks:
            self._block_items[bb.start_addr] = _BlockItem(bb, base_offset, self)

        # ── DFS layout: fallthrough stays in column, taken branches right ──
        row_of: dict[int, int] = {}
        col_of: dict[int, int] = {}
        visited: set[int] = set()
        col_alloc = [0]

        def dfs(addr: int, row: int, col: int):
            if addr in visited or addr not in addr_to_bb:
                return
            visited.add(addr)
            row_of[addr] = row
            col_of[addr] = col
            bb = addr_to_bb[addr]
            ft = [a for a, t in bb.successors if t == "fallthrough"]
            tk = [a for a, t in bb.successors if t in ("taken", "unconditional")]
            for a in ft:
                dfs(a, row + 1, col)
            for a in tk:
                if a not in visited:
                    col_alloc[0] += 1
                    dfs(a, row + 1, col_alloc[0])

        dfs(blocks[0].start_addr, 0, 0)

        for bb in blocks:
            if bb.start_addr not in visited:
                row_of[bb.start_addr] = max(row_of.values(), default=-1) + 1
                col_of[bb.start_addr] = 0

        # ── Compute pixel positions ──
        max_w = max((it.rect().width() for it in self._block_items.values()), default=120)
        col_pitch = max_w + _H_GAP

        max_h_per_row: dict[int, float] = {}
        for addr, item in self._block_items.items():
            r = row_of.get(addr, 0)
            max_h_per_row[r] = max(max_h_per_row.get(r, 0), item.rect().height())

        row_y: dict[int, float] = {}
        y = 0.0
        for r in sorted(max_h_per_row):
            row_y[r] = y
            y += max_h_per_row[r] + _V_GAP

        for addr, item in self._block_items.items():
            c = col_of.get(addr, 0)
            r = row_of.get(addr, 0)
            ix = c * col_pitch + (max_w - item.rect().width()) / 2
            iy = row_y.get(r, 0)
            item.setPos(ix, iy)
            self._scene.addItem(item)

        # ── Collect edge definitions ──
        for bb in blocks:
            n_succ = len(bb.successors)
            for succ_addr, edge_type in bb.successors:
                if bb.start_addr in self._block_items and succ_addr in self._block_items:
                    self._edge_defs.append((bb.start_addr, succ_addr, edge_type))

        self._rebuild_edges()

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
                # Auto-route
                n = succ_count.get(src_addr, 1)
                if n >= 2:
                    spread = min(20, src_r.width() * 0.15)
                    sx = src_r.center().x() + (-spread if edge_type == "fallthrough" else spread)
                else:
                    sx = src_r.center().x()
                sy = src_r.bottom()
                dst_pt = _border_point(dst_r, QPointF(sx, sy))
                dx, dy = dst_pt.x(), dst_pt.y()
                src_pt = QPointF(sx, sy)
                is_back = dst_r.center().y() <= src_r.center().y()

                path = QPainterPath()
                if is_back:
                    off_x = max(src_r.right(), dst_r.right()) + 40
                    mid = QPointF(off_x, (sy + dy) / 2)
                    src_pt = _border_point(src_r, mid)
                    dst_pt = _border_point(dst_r, mid)
                    path.moveTo(src_pt)
                    path.cubicTo(QPointF(off_x, src_pt.y()), QPointF(off_x, dst_pt.y()), dst_pt)
                    handle_pt = QPointF(off_x, (src_pt.y() + dst_pt.y()) / 2)
                elif abs(sx - dx) < 5 and abs(sy - dy) < (src_r.height() + _V_GAP + 20):
                    path.moveTo(src_pt)
                    path.lineTo(dst_pt)
                    handle_pt = QPointF((sx + dx) / 2, (sy + dy) / 2)
                else:
                    mid_y = (sy + dy) / 2
                    path.moveTo(src_pt)
                    path.cubicTo(QPointF(sx, mid_y), QPointF(dx, mid_y), dst_pt)
                    handle_pt = QPointF((sx + dx) / 2, mid_y)

            ei = QGraphicsPathItem(path)
            ei.setPen(QPen(color, 1.5))
            ei.setZValue(-1)
            self._scene.addItem(ei)
            self._edge_gfx.append(ei)

            arrow = self._make_arrowhead(path, color)
            self._scene.addItem(arrow)
            self._edge_gfx.append(arrow)

            if create_handles:
                h = _WaypointHandle(handle_pt.x(), handle_pt.y(), ek, self)
                self._scene.addItem(h)
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
        t_back = max(0.0, 1.0 - 0.02)
        before = edge_path.pointAtPercent(t_back)
        dx = end.x() - before.x()
        dy = end.y() - before.y()
        length = math.sqrt(dx * dx + dy * dy)
        if length < 0.01:
            dx, dy = 0, 1
        else:
            dx /= length
            dy /= length
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
        self.scale(factor, factor)

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

        self._base_offset = base_offset

        # Assign depth via BFS from roots (nodes with no callers)
        addr_to_node = {n.address: n for n in call_graph}
        roots = [n for n in call_graph if not n.callers]
        if not roots:
            roots = [call_graph[0]]

        depth_map = {}  # address -> depth
        visited = set()
        queue = [(r.address, 0) for r in roots]
        for addr, _ in queue:
            visited.add(addr)

        while queue:
            addr, d = queue.pop(0)
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
        self._tabs.addTab(self._cfg_view, "CFG")

        self._cg_view = CallGraphView()
        self._cg_view.navigate_requested.connect(self.navigate_requested)
        self._tabs.addTab(self._cg_view, "Call Graph")

        layout.addWidget(self._tabs)

        # Status label
        self._status = QLabel("")
        layout.addWidget(self._status)

    # ── Public API ──────────────────────────────────────────────────

    def set_buffer(self, buf):
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
            self._thread.wait(2000)

        self._thread = _DisassembleThread(
            self._code, self._base_offset, arch, mode, syntax, self._buffer
        )
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
        if self._thread and self._thread.isRunning():
            self._thread.cancel()

    def _on_progress(self, pct: int):
        self._progress.setValue(pct)

    def _on_results(self, result: DisasmResult):
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
            f"{n_funcs} functions — {result.arch_name}{depth_str}"
        )

    def _on_thread_done(self):
        self._btn_disasm.setEnabled(True)
        self._btn_cancel.setEnabled(False)
        self._progress.hide()
