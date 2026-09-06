"""Disassembly data and control-flow analysis, independent of Qt rendering."""

from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from bisect import bisect_right

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
    is_data: bool = False
    is_terminal: bool = False
    conditional_return: bool = False
    target_address: Optional[int] = None  # Original decoder address, including external targets


@dataclass
class BasicBlock:
    start_addr: int
    end_addr: int
    instructions: List[DisasmInstruction] = field(default_factory=list)
    successors: List[Tuple[int, str]] = field(default_factory=list)  # (addr, edge_type)
    exits: List[str] = field(default_factory=list)


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
    warning: str = ""


def classify_instruction(insn, di: DisasmInstruction, arch: int):
    """Read targets from architecture operands, never from formatted assembly."""
    import capstone as cs
    di.is_data = insn.id == 0
    if di.is_data:
        return
    groups = insn.groups
    di.is_jump = cs.CS_GRP_JUMP in groups
    di.is_call = cs.CS_GRP_CALL in groups
    di.is_ret = cs.CS_GRP_RET in groups or cs.CS_GRP_IRET in groups
    operands = insn.operands
    immediate_type = None
    if arch == cs.CS_ARCH_X86:
        immediate_type = cs.x86.X86_OP_IMM
        di.is_unconditional = insn.id in (cs.x86.X86_INS_JMP, cs.x86.X86_INS_LJMP)
        di.is_terminal = insn.id in (cs.x86.X86_INS_UD2, cs.x86.X86_INS_HLT, cs.x86.X86_INS_INT3)
    elif arch == cs.CS_ARCH_ARM64:
        immediate_type = cs.arm64.ARM64_OP_IMM
        di.is_unconditional = insn.mnemonic in ("b", "br", "braa", "brab", "braaz", "brabz")
        di.is_terminal = insn.mnemonic in ("brk", "hlt", "udf")
    elif arch == cs.CS_ARCH_ARM:
        immediate_type = cs.arm.ARM_OP_IMM
        unconditional = insn.cc in (cs.arm.ARM_CC_AL, cs.arm.ARM_CC_INVALID)
        di.is_unconditional = di.is_jump and unconditional and insn.id in (cs.arm.ARM_INS_B, cs.arm.ARM_INS_BX)
        if (insn.id == cs.arm.ARM_INS_BX and operands
                and operands[0].type == cs.arm.ARM_OP_REG
                and operands[0].reg == cs.arm.ARM_REG_LR):
            di.is_ret = True
            di.is_jump = False
            di.conditional_return = not unconditional
        stack_restore = (insn.id == cs.arm.ARM_INS_POP or
                         (insn.id == cs.arm.ARM_INS_LDM and insn.writeback and operands
                          and operands[0].type == cs.arm.ARM_OP_REG
                          and operands[0].reg == cs.arm.ARM_REG_SP))
        if stack_restore and any(
                op.type == cs.arm.ARM_OP_REG and op.reg == cs.arm.ARM_REG_PC for op in operands):
            di.is_ret = True
            di.is_jump = False
            di.conditional_return = not unconditional
        if not di.is_ret and not di.is_call and cs.arm.ARM_REG_PC in insn.regs_access()[1]:
            di.is_jump = True
            di.is_unconditional = unconditional
        if insn.id not in (cs.arm.ARM_INS_B, cs.arm.ARM_INS_BL, cs.arm.ARM_INS_BLX,
                           cs.arm.ARM_INS_CBZ, cs.arm.ARM_INS_CBNZ):
            # An arithmetic immediate on a PC write is not a direct destination.
            immediate_type = None
        di.is_terminal = insn.mnemonic == "udf"
    elif arch == cs.CS_ARCH_MIPS:
        immediate_type = cs.mips.MIPS_OP_IMM
    elif arch == cs.CS_ARCH_PPC:
        immediate_type = cs.ppc.PPC_OP_IMM
    if di.is_jump or di.is_call:
        # TBZ/TBNZ have two immediates: the bit index precedes the destination.
        immediates = [op.imm for op in operands if op.type == immediate_type]
        if immediates:
            di.branch_target = immediates[-1]
            di.target_address = di.branch_target
        else:
            di.is_indirect = True


def build_cfg(instructions: List[DisasmInstruction]) -> List[BasicBlock]:
    if not instructions:
        return []

    addr_to_idx = {insn.address: i for i, insn in enumerate(instructions)}

    # Leader identification
    leaders = {instructions[0].address}
    for insn in instructions:
        if insn.is_jump or insn.is_call or insn.is_ret or insn.is_terminal or insn.is_data:
            if insn.branch_target is not None and insn.branch_target in addr_to_idx:
                leaders.add(insn.branch_target)
            # Instruction after branch/ret is a leader
            idx = addr_to_idx.get(insn.address)
            if idx is not None and idx + 1 < len(instructions):
                leaders.add(instructions[idx + 1].address)
        if insn.is_data:
            leaders.add(insn.address)
    for previous, current in zip(instructions, instructions[1:]):
        if previous.address + previous.size != current.address:
            leaders.add(current.address)

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
        next_addr = last.address + last.size
        can_fallthrough = (end_idx < len(instructions)
                           and instructions[end_idx].address == next_addr
                           and not instructions[end_idx].is_data)
        if last.is_data:
            bb.exits.append("Undecoded data — flow unknown")
        elif last.is_terminal:
            bb.exits.append("Trap / stop")
        elif last.is_ret:
            bb.exits.append("Return")
            if last.conditional_return and can_fallthrough:
                bb.successors.append((next_addr, "fallthrough"))
        elif last.is_jump:
            if last.branch_target is not None and last.branch_target in addr_to_idx:
                if last.is_unconditional:
                    bb.successors.append((last.branch_target, "unconditional"))
                else:
                    bb.successors.append((last.branch_target, "taken"))
                    # fallthrough
                    if can_fallthrough:
                        bb.successors.append((next_addr, "fallthrough"))
            else:
                target = last.target_address if last.target_address is not None else last.branch_target
                bb.exits.append(f"Branch outside selection: 0x{target:X}" if target is not None
                                else "Indirect branch — target unknown")
                if not last.is_unconditional and can_fallthrough:
                    bb.successors.append((next_addr, "fallthrough"))
        else:
            # Normal fallthrough
            if can_fallthrough:
                bb.successors.append((next_addr, "fallthrough"))
            else:
                bb.exits.append("End of decoded selection — flow unknown")

        blocks.append(bb)

    return blocks

def build_call_graph(instructions: List[DisasmInstruction]) -> List[CallGraphNode]:
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
        return func_entries[bisect_right(func_entries, addr) - 1]

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
