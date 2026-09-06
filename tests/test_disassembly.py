import struct

import capstone as cs
import pytest
from PySide6.QtCore import Qt

from hex_editor.cfg_layout import layered_layout
from hex_editor.disasm_address import AddressMap
from hex_editor.disasm_analysis import BasicBlock, DisasmInstruction, build_cfg
from hex_editor.disasm_widget import CfgGraphicsView, DisasmTableModel, _DisassembleThread


def decode(code, arch=cs.CS_ARCH_X86, mode=cs.CS_MODE_64, base=0x1000):
    worker = _DisassembleThread(bytes.fromhex(code), base, arch, mode, "Intel")
    results = []
    worker.finished_results.connect(results.append)
    worker.run()
    assert len(results) == 1
    assert not results[0].error
    return results[0]


def test_arm64_bit_test_uses_target_not_bit_number():
    result = decode("40001836 1f2003d5 c0035fd6", cs.CS_ARCH_ARM64, 0)
    assert result.instructions[0].branch_target == 0x1008
    assert result.basic_blocks[0].successors == [(0x1008, "taken"), (0x1004, "fallthrough")]


@pytest.mark.parametrize("code,arch,mode", [
    ("ffe0 90c3", cs.CS_ARCH_X86, cs.CS_MODE_64),
    ("00001fd6 1f2003d5", cs.CS_ARCH_ARM64, 0),
    ("10ff2fe1 0000a0e1", cs.CS_ARCH_ARM, 0),
])
def test_indirect_unconditional_jump_has_no_false_fallthrough(code, arch, mode):
    result = decode(code, arch, mode)
    assert not result.basic_blocks[0].successors
    assert "target unknown" in result.basic_blocks[0].exits[0]


def test_arm_conditional_return_preserves_only_fallthrough():
    result = decode("1eff2f11 0000a0e1", cs.CS_ARCH_ARM, 0)
    assert result.basic_blocks[0].successors == [(0x1004, "fallthrough")]
    assert result.basic_blocks[0].exits == ["Return"]


def test_arm_pop_pc_is_a_return():
    result = decode("0080bde8 0000a0e1", cs.CS_ARCH_ARM, 0)
    assert result.instructions[0].is_ret
    assert not result.basic_blocks[0].successors


def test_trap_and_skipped_data_break_flow():
    result = decode("0f0b 90c3")
    assert not result.basic_blocks[0].successors
    instructions = [DisasmInstruction(0, 1, b"\x90", "nop", ""),
                    DisasmInstruction(1, 1, b"\x06", ".byte", "6", is_data=True),
                    DisasmInstruction(2, 1, b"\xc3", "ret", "", is_ret=True)]
    blocks = build_cfg(instructions)
    assert not blocks[0].successors
    assert not blocks[1].successors


def test_cross_section_branch_is_mapped_to_correct_file_offset(monkeypatch):
    from hex_editor import disasm_widget
    monkeypatch.setattr(disasm_widget, "executable_address_map", lambda buffer: AddressMap([
        (0x100, 0x401000, 0x100), (0x500, 0x402000, 0x100)]))
    result = decode("e9fb0f0000", base=0x100)
    insn = result.instructions[0]
    assert insn.address == 0x100
    assert insn.target_address == 0x402000
    assert insn.branch_target == 0x500


def test_unmapped_virtual_target_is_never_used_as_file_offset(monkeypatch):
    from hex_editor import disasm_widget
    monkeypatch.setattr(disasm_widget, "executable_address_map", lambda buffer: AddressMap([(0x100, 0x401000, 0x100)]))
    result = decode("e9fb0f0000", base=0x100)
    assert result.instructions[0].branch_target is None
    assert result.instructions[0].target_address == 0x402000


def test_raw_arch_label_and_unsupported_cfg_are_explicit():
    assert decode("90c3").arch_name == "x86-64"
    result = decode("00000000", cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32)
    assert result.instructions
    assert not result.basic_blocks
    assert "unavailable" in result.warning


@pytest.mark.parametrize("code,arch,mode", [
    ("01000010", cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
    ("48000008", cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN),
])
def test_listing_only_architectures_still_resolve_direct_targets(code, arch, mode):
    result = decode(code, arch, mode)
    assert result.instructions[0].branch_target == 0x1008
    assert not result.instructions[0].is_indirect


def test_elf_big_endian_auto_detection():
    from hex_editor.disasm_widget import _auto_detect_arch
    raw = bytearray(64)
    raw[:7] = b"\x7fELF\x02\x02\x01"
    struct.pack_into(">HHI", raw, 16, 2, 0x15, 1)

    class Buffer:
        def read(self, offset, size):
            return bytes(raw[offset:offset + size])

        def size(self):
            return len(raw)

    arch, mode, name = _auto_detect_arch(Buffer())
    assert arch == cs.CS_ARCH_PPC
    assert mode & cs.CS_MODE_BIG_ENDIAN
    assert "big endian" in name


def test_join_is_below_both_forward_predecessors():
    sizes = {n: (200, 60) for n in range(5)}
    edges = [(0, 1, "fallthrough"), (0, 2, "taken"), (1, 4, "unconditional"),
             (2, 3, "fallthrough"), (3, 4, "unconditional")]
    positions, ranks = layered_layout(sizes, edges)
    assert ranks[4] > ranks[1] and ranks[4] > ranks[3]
    assert positions[4][1] > positions[3][1]


def test_layout_handles_deep_graph_and_cycles_without_recursion():
    sizes = {n: (100, 40) for n in range(3000)}
    edges = [(n, n + 1, "fallthrough") for n in range(2999)] + [(2999, 0, "taken")]
    positions, ranks = layered_layout(sizes, edges)
    assert len(positions) == 3000
    assert ranks[2999] == 2999


def test_disconnected_regions_do_not_form_a_wide_strip():
    positions, ranks = layered_layout({n: (200, 60) for n in range(20)}, [])
    assert len({x for x, y in positions.values()}) == 1
    assert len(set(ranks.values())) == 20


def test_self_loop_has_visible_route(app):
    view = CfgGraphicsView()
    view.populate(decode("ebfe").basic_blocks, 0x1000)
    assert len(view._edge_defs) == 1
    assert view._edge_gfx[0].path().length() > 100
    view.deleteLater()


def test_rendered_blocks_do_not_overlap_and_loops_have_visible_paths(app):
    view = CfgGraphicsView()
    result = decode("83f8007407b801000000eb05b802000000c3")
    result.basic_blocks[-1].successors.append((0x1000, "taken"))
    view.populate(result.basic_blocks, 0x1000)
    rects = [item.sceneBoundingRect() for item in view._block_items.values()]
    for i, left in enumerate(rects):
        assert all(not left.intersects(right) for right in rects[i + 1:])
    assert all(not handle.isVisible() for handle in view._wp_handles)
    for index in range(0, len(view._edge_gfx), 3):
        path = view._edge_gfx[index].path()
        assert path.length() > 20
        for sample in range(1, 100):
            point = path.pointAtPercent(sample / 100)
            assert all(not rect.adjusted(1, 1, -1, -1).contains(point) for rect in rects)
    view.clear()
    view.reset_layout()
    assert not view._block_items
    view.deleteLater()


def test_compact_block_preserves_branch_and_can_expand(app):
    insns = [DisasmInstruction(i, 1, b"\x90", "nop", "") for i in range(100)]
    insns[-1].mnemonic = "ret"
    insns[-1].is_ret = True
    view = CfgGraphicsView()
    view.populate(build_cfg(insns), 0)
    compact_height = view._block_items[0].rect().height()
    assert any("hidden" in text for text, _ in view._block_items[0]._lines)
    assert any("ret" in text for text, _ in view._block_items[0]._lines)
    view.set_compact(False)
    assert view._block_items[0].rect().height() > compact_height
    view.deleteLater()


def test_virtual_listing_returns_data_on_demand(app):
    model = DisasmTableModel()
    insn = DisasmInstruction(0x10, 1, b"\xc3", "ret", "", is_ret=True)
    model.set_instructions([insn] * 100000)
    assert model.rowCount() == 100000
    assert model.data(model.index(99999, 0), Qt.ItemDataRole.DisplayRole) == "0x00000010"
    model.set_instructions([])
    assert model.rowCount() == 0


def test_cancelled_worker_cannot_repopulate_new_buffer(app):
    from hex_editor.disasm_widget import DisasmWidget
    widget = DisasmWidget()
    widget._arch_combo.setCurrentText("x86-64")
    widget.disassemble_bytes(b"\x90" * 50000)
    widget.set_buffer(None)
    widget.shutdown()
    app.processEvents()
    assert widget._listing._model.rowCount() == 0
    assert not widget._cfg_view._block_items
    assert not widget._workers
    assert widget._btn_disasm.isEnabled()
    widget.deleteLater()
