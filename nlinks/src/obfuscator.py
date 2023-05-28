from typing import Optional, List, Dict, Tuple, Any
import string
import re
import struct
from itertools import count
import random
import json

import networkx
from numba import jit


AMD64_REGS = {
    "rax": (0, 8),
    "eax": (0, 4),
    "ax": (0, 2),
    "al": (0, 1),
    "ah": (1, 1),
    "rcx": (8, 8),
    "ecx": (8, 4),
    "cx": (8, 2),
    "cl": (8, 1),
    "ch": (9, 1),
    "rdx": (16, 8),
    "edx": (16, 4),
    "dx": (16, 2),
    "dl": (16, 1),
    "dh": (17, 1),
    "rbx": (24, 8),
    "ebx": (24, 4),
    "bx": (24, 2),
    "bl": (24, 1),
    "bh": (25, 1),
    "rsi": (32, 8),
    "esi": (32, 4),
    "si": (32, 2),
    "sil": (32, 1),
    "rdi": (40, 8),
    "edi": (40, 4),
    "di": (40, 2),
    "dil": (40, 1),
    "rsp": (48, 8),
    "esp": (48, 4),
    "sp": (48, 2),
    "rbp": (56, 8),
    "ebp": (56, 4),
    "bp": (56, 2),
    "r8": (64, 8),
    "r8d": (64, 4),
    "r8b": (64, 1),
    "r9": (72, 8),
    "r9d": (72, 4),
    "r9b": (72, 1),
    "r10": (80, 8),
    "r10d": (80, 4),
    "r10b": (80, 1),
    "r11": (88, 8),
    "r11d": (88, 4),
    "r11b": (88, 1),
    "r12": (96, 8),
    "r12d": (96, 4),
    "r12b": (96, 1),
    "r13": (104, 8),
    "r13d": (104, 4),
    "r14": (112, 8),
    "r14d": (112, 4),
    "r15": (120, 8),
    "r15d": (120, 4),
    "t0": (128, 8),
    "t1": (136, 8),
    "t2": (144, 8),
}

BRANCH_OPCODES = {
    "jmp",
    "je",
    "jne",
    "jb",
    "jbe",
    "ja",
    "jae",
    "jl",
    "jle",
    "jg",
    "jge",
    # "call",
    # "ret",
}
BRANCH_WITH_FALLTHROUGH_OPCODES = {
    "je",
    "jne",
    "jb",
    "jbe",
    "ja",
    "jae",
    "jl",
    "jle",
    "jg",
    "jge",
}

VM_OPCODE = {
    "add": 13,
    "sub": 14,
    "xor": 15,
    "sal": 16,
    "and": 17,
    "or": 18,
    "jmp": 20,
    "je": 21,
    "jne": 22,
    "ja": 23,
    "jae": 24,
    "jb": 25,
    "jbe": 26,
    "jg": 27,
    "jge": 28,
    "jl": 29,
    "jle": 30,
    "call": 31,
    "ret": 32,
    "lea": 33,
    "mov": 34,
    "ak0": 40,
    "ak1": 41,
    "ak2": 42,
}

VM_OPTYPE = {
    "reg": 1,
    "imm": 2,
    "mem": 3,
    "memreg": 4,
}
VM_OPCODE_BRANCH = {"jmp", "je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "call"}


class AsmLine:
    def __init__(self, opcode: str, operands: Optional[List[str]]):
        self.opcode = opcode
        self.operands = operands

    @property
    def is_branch(self):
        return self.opcode in BRANCH_OPCODES

    @property
    def has_fallthrough(self):
        return self.opcode in BRANCH_WITH_FALLTHROUGH_OPCODES

    @staticmethod
    def from_raw_line(line: str) -> "AsmLine":
        line = line.strip(" \t")
        if "\t" in line:
            items = line.split("\t")
            assert len(items) == 2
            opcode = items[0].strip(" ")
            operands = [item.strip(" ") for item in items[1].split(",")]
            return AsmLine(opcode, operands)
        return AsmLine(line, None)

    @staticmethod
    def is_mem_operand(operand: str) -> bool:
        return AsmLine.parse_mem_operand(operand) is not None

    @staticmethod
    def parse_mem_operand(operand: str) -> Optional[Tuple[int, int, str]]:
        m = re.match(r"(\S+) PTR (-{0,1}\d+)\[(\S+)\]", operand)
        if not m:
            return None
        match m.group(1):
            case "QWORD":
                size = 8
            case "DWORD":
                size = 4
            case "WORD":
                size = 2
            case "BYTE":
                size = 1
            case _:
                raise NotImplementedError(f"Unsupported operand type {m.group(1)}")
        return size, int(m.group(2)), m.group(3)


class AsmBlock:
    def __init__(
        self,
        lines: List[AsmLine],
        label: Optional[str] = None,
        successor_labels: Optional[List[Tuple[str, bool]]] = None,
        fallthrough: Optional[bool] = None,
    ):
        self.label = label
        self.lines = lines
        self.successor_labels: Optional[List[str]] = successor_labels
        self.fallthrough = fallthrough

    def add_line(self, line: AsmLine):
        self.lines.append(line)
        if line.is_branch and line.operands:
            self.add_successor(line.operands[0])
        if line.is_branch and line.has_fallthrough:
            self.fallthrough = True

    @property
    def last_line_branches(self):
        if not self.lines:
            return False
        return self.lines[-1].is_branch

    def add_successor(self, label: str, fallthrough: bool = False):
        if label is None:
            breakpoint()
        if self.successor_labels is None:
            self.successor_labels = []
        self.successor_labels.append((label, fallthrough))

    def __repr__(self):
        return f"<AsmBlock {self.label}>"


class AsmFunc:
    def __init__(self, name: str, lines: List[str]):
        self.name = name
        self.func = self.from_raw_lines(name, lines)

    @staticmethod
    def from_raw_lines(func_name: str, asm_lines: List[str]) -> networkx.DiGraph:
        g = networkx.DiGraph()

        label_counter = count()

        blocks: Dict[str, AsmBlock] = {}
        curr_block = AsmBlock([], label=func_name)
        blocks[curr_block.label] = curr_block

        for idx, line in enumerate(asm_lines):
            if line.endswith(":"):
                # it's a label - we terminate the current block and start a new block if the current block *is not*
                # just created
                if curr_block.lines:
                    last_block = curr_block
                    curr_block = AsmBlock([], label=line.strip(":"))
                    blocks[curr_block.label] = curr_block

                    if last_block is not None and (last_block.fallthrough or not last_block.last_line_branches):
                        last_block.add_successor(curr_block.label, fallthrough=True)
                else:
                    # the current block is just created. we update its label
                    if not curr_block.label:
                        curr_block.label = line.strip(":")
                        blocks[curr_block.label] = curr_block
            else:
                asm_line = AsmLine.from_raw_line(line.strip(" \t"))
                if asm_line.is_branch:
                    # the branch instruction terminates the current block
                    last_block = curr_block
                    last_block.add_line(asm_line)
                    # look ahead: does it have a label?
                    if idx + 1 < len(asm_lines) and asm_lines[idx + 1].endswith(":"):
                        # yes! extract the label
                        new_label = asm_lines[idx + 1].strip(":")
                    else:
                        # let's assign a label
                        new_label = f"lbl_{next(label_counter)}"
                    curr_block = AsmBlock([], label=new_label)
                    if curr_block.label is not None:
                        blocks[curr_block.label] = curr_block
                        last_block.add_successor(curr_block.label, fallthrough=True)
                else:
                    curr_block.add_line(asm_line)
        blocks[curr_block.label] = curr_block

        for b in blocks.values():
            g.add_node(b)
            if b.successor_labels:
                for successor_label, _ in b.successor_labels:
                    successor = blocks[successor_label]
                    g.add_edge(b, successor)

        return g


class VmOp:
    @staticmethod
    def from_asm_op(asm_op: str, vm_block: "VmBlock", tmp_reg: str) -> "VmOp":
        if asm_op in AMD64_REGS:
            return VmRegOp(*AMD64_REGS[asm_op], reg_name=asm_op)
        if all(ch in string.digits for ch in asm_op):
            # immediate
            return VmImmOp(int(asm_op))
        if asm_op.startswith("-") and all(ch in string.digits for ch in asm_op[1:]):
            # negative immediate
            return VmImmOp(int(asm_op))
        if AsmLine.is_mem_operand(asm_op):
            # convert complex AMD64 memory operands to a simple MemReg operand
            size, offset, reg_name = AsmLine.parse_mem_operand(asm_op)
            if "+" in reg_name:
                # the sum of two registers
                reg0_name, reg1_name = reg_name.split("+")
                reg0 = VmRegOp(*AMD64_REGS[reg0_name], reg_name=reg0_name)
                reg1 = VmRegOp(*AMD64_REGS[reg1_name], reg_name=reg1_name)
                reg = VmRegOp(*AMD64_REGS["t0"], reg_name="t0")
                stmt = VmStmt("add", reg, reg0, reg1)
                vm_block.stmts.append(stmt)
            else:
                # only one register
                reg = VmRegOp(*AMD64_REGS[reg_name], reg_name=reg_name)
            stmt = VmStmt("add", VmRegOp(*AMD64_REGS[tmp_reg], reg_name=tmp_reg), VmImmOp(offset), reg)
            vm_block.stmts.append(stmt)
            return VmMemRegOp(AMD64_REGS[tmp_reg][0], size, reg_name=tmp_reg)
        # mem - we don't really support other types of mem operands for now
        raise NotImplementedError("VmMemOp is not supported yet")

    def assemble(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError()


class VmImmOp(VmOp):
    def __init__(self, value: int):
        self.value = value & 0xFFFF_FFFF_FFFF_FFFF

    def assemble(self) -> Tuple[bytes, bytes]:
        return VM_OPTYPE["imm"].to_bytes(1, "little"), self.value.to_bytes(8, "little")


class VmRegOp(VmOp):
    def __init__(self, offset: int, size: int, reg_name: Optional[str] = None):
        self.offset = offset
        self.size = size
        self.reg_name = reg_name

    def assemble(self) -> Tuple[bytes, bytes]:
        return VM_OPTYPE["reg"].to_bytes(1, "little"), ((self.offset << 8) | self.size).to_bytes(8, "little")


class VmMemOp(VmOp):
    def __init__(self, addr: int, mem_size: int):
        self.addr = addr
        self.mem_size = mem_size

    def assemble(self) -> Tuple[bytes, bytes]:
        return VM_OPTYPE["mem"].to_bytes(1, "little"), ((self.addr << 8) | self.mem_size).to_bytes(8, "little")


class VmMemRegOp(VmOp):
    def __init__(self, offset: int, mem_size: int, reg_name: Optional[str] = None):
        self.offset = offset
        self.mem_size = mem_size
        self.reg_name = reg_name

    def assemble(self) -> Tuple[bytes, bytes]:
        return VM_OPTYPE["memreg"].to_bytes(1, "little"), ((self.offset << 8) | self.mem_size).to_bytes(8, "little")


class VmSymbol:
    def __init__(self, name: str, symbol_type: str):
        self.name = name
        self.type = symbol_type


class VmStmt:
    def __init__(
        self,
        opcode,
        op0: Optional[VmOp] = None,
        op1: Optional[VmOp] = None,
        op2: Optional[VmOp] = None,
        raw_ops: Optional[List[Any]] = None,
    ):
        self.opcode = opcode
        self.op0 = op0
        self.op1 = op1
        self.op2 = op2
        self.raw_ops = raw_ops

    def assemble(self) -> Tuple[bytes, Dict]:
        """
        Raw instruction format:
          opcode (2 bytes)
          op0_type  (1 byte)
          op0  (8 bytes)
          op1_type  (1 byte)
          op1  (8 bytes)
          op2_type  (1 byte)
          op2  (8 bytes)
        """
        opcode = VM_OPCODE[self.opcode].to_bytes(2, "little")
        dummy_type, dummy_op = bytes([VM_OPTYPE["imm"]]), b"\x00" * 8
        op0_type, op0 = self.op0.assemble() if self.op0 is not None else (dummy_type, dummy_op)
        op1_type, op1 = self.op1.assemble() if self.op1 is not None else (dummy_type, dummy_op)
        op2_type, op2 = self.op2.assemble() if self.op2 is not None else (dummy_type, dummy_op)
        data = b"".join([opcode, op0_type, op0, op1_type, op1, op2_type, op2])
        if self.opcode in VM_OPCODE_BRANCH:
            if self.raw_ops:
                assert len(self.raw_ops) == 1
                assert self.op0 is None
                # op0 is the symbol
                if self.opcode == "call":
                    tbl = {2 + 1: VmSymbol(self.raw_ops[0], "function")}
                else:
                    tbl = {2 + 1: VmSymbol(self.raw_ops[0], "label")}
                return data, tbl
        else:
            return data, {}


class VmBlock:
    def __init__(self, label: str, stmts: List[VmStmt], successor_labels: Optional[List[str]] = None):
        self.label = label
        self.stmts = stmts
        self.successor_labels = successor_labels

    def assemble(self) -> Tuple[bytes, Dict]:
        symbol_table = {}
        raw_bytes = []
        offset = 0
        for stmt in self.stmts:
            stmt_bytes, stmt_symbol_table = stmt.assemble()
            raw_bytes.append(stmt_bytes)
            for off, sym in stmt_symbol_table.items():
                symbol_table[offset + off] = sym
            offset += len(stmt_bytes)
        return b"".join(raw_bytes), symbol_table

    @staticmethod
    def from_asm_block(asm_block: AsmBlock) -> "VmBlock":
        vm_block = VmBlock(
            asm_block.label,
            [],
            successor_labels=[label for label, _ in asm_block.successor_labels] if asm_block.successor_labels else None,
        )
        cmp_op0, cmp_op1 = None, None
        for asm_line in asm_block.lines:
            match asm_line.opcode:
                case asm_line.opcode if asm_line.opcode.startswith("."):
                    # it's an directive
                    pass
                case "cmp":
                    # we delay statement creation until the conditional jump
                    cmp_op0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    cmp_op1 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                case "test":
                    # we delay statement creation until the conditional jump
                    arg0 = VmRegOp(*AMD64_REGS["t0"], reg_name="t0")
                    arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t1")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t2")
                    stmt0 = VmStmt("and", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt0)
                    cmp_op0 = arg0
                    cmp_op1 = VmImmOp(0)
                case "je":
                    assert cmp_op0 is not None
                    assert cmp_op1 is not None
                    stmt = VmStmt("je", None, cmp_op0, cmp_op1, raw_ops=[asm_line.operands[0]])
                    vm_block.stmts.append(stmt)
                    cmp_op0, cmp_op1 = None, None
                case "jne":
                    assert cmp_op0 is not None
                    assert cmp_op1 is not None
                    stmt = VmStmt("jne", None, cmp_op0, cmp_op1, raw_ops=[asm_line.operands[0]])
                    vm_block.stmts.append(stmt)
                    cmp_op0, cmp_op1 = None, None
                case "jg":
                    assert cmp_op0 is not None
                    assert cmp_op1 is not None
                    stmt = VmStmt("jg", None, cmp_op0, cmp_op1, raw_ops=[asm_line.operands[0]])
                    vm_block.stmts.append(stmt)
                    cmp_op0, cmp_op1 = None, None
                case "ja":
                    assert cmp_op0 is not None
                    assert cmp_op1 is not None
                    stmt = VmStmt("ja", None, cmp_op0, cmp_op1, raw_ops=[asm_line.operands[0]])
                    vm_block.stmts.append(stmt)
                    cmp_op0, cmp_op1 = None, None
                case "add":
                    arg0 = arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    stmt = VmStmt("add", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt)
                case "sub":
                    arg0 = arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    stmt = VmStmt("sub", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt)
                case "and":
                    arg0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    if isinstance(arg0, VmRegOp) and arg0.size == 4:
                        arg0.size = 8
                    arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t1")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t2")
                    stmt = VmStmt("and", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt)
                case "or":
                    arg0 = arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    stmt = VmStmt("or", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt)
                case "xor":
                    arg0 = arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    stmt = VmStmt("xor", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt)
                case "sal":
                    arg0 = arg1 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg2 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    stmt = VmStmt("sal", arg0, arg1, arg2)
                    vm_block.stmts.append(stmt)
                case "ret":
                    stmt = VmStmt("ret")
                    vm_block.stmts.append(stmt)
                case "call":
                    stmt = VmStmt("call", raw_ops=[asm_line.operands[0]])
                    vm_block.stmts.append(stmt)
                case "jmp":
                    stmt = VmStmt("jmp", raw_ops=[asm_line.operands[0]])
                    vm_block.stmts.append(stmt)
                case "lea":
                    # we only support the following format:
                    #     lea  reg0, const[reg1]
                    arg0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    assert isinstance(arg0, VmRegOp)
                    m = re.match(r"(-{0,1}\d+)\[(\S+)\]", asm_line.operands[1])
                    assert m is not None
                    offset, reg_name = m.group(1), m.group(2)
                    arg2 = VmOp.from_asm_op(reg_name, vm_block, "t0")
                    assert isinstance(arg2, VmRegOp)
                    stmt = VmStmt("add", arg0, VmImmOp(int(offset)), arg2)
                    vm_block.stmts.append(stmt)
                case "mov":
                    arg0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg1 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    if isinstance(arg0, VmRegOp) and arg0.size == 4:
                        arg0.size = 8
                    stmt = VmStmt("mov", arg0, arg1)
                    vm_block.stmts.append(stmt)
                case "movabs":
                    arg0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg1 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    if isinstance(arg0, VmRegOp) and arg0.size == 4:
                        arg0.size = 8
                    stmt = VmStmt("mov", arg0, arg1)
                    vm_block.stmts.append(stmt)
                case "movzx":
                    arg0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    arg1 = VmOp.from_asm_op(asm_line.operands[1], vm_block, "t1")
                    stmt = VmStmt("mov", arg0, arg1)
                    vm_block.stmts.append(stmt)
                case "push":
                    arg0 = VmOp.from_asm_op(asm_line.operands[0], vm_block, "t0")
                    stmt = VmStmt("mov", VmMemRegOp(*AMD64_REGS["rsp"], reg_name="rsp"), arg0)
                    vm_block.stmts.append(stmt)
                    stmt = VmStmt(
                        "sub",
                        VmRegOp(*AMD64_REGS["rsp"], reg_name="rsp"),
                        VmRegOp(*AMD64_REGS["rsp"], reg_name="rsp"),
                        VmImmOp(8),
                    )
                    vm_block.stmts.append(stmt)
                case "leave":
                    # mov rsp, rbp
                    arg_rsp = VmOp.from_asm_op("rsp", vm_block, "t0")
                    arg_rbp = VmOp.from_asm_op("rbp", vm_block, "t0")
                    stmt_mov = VmStmt("mov", arg_rsp, arg_rbp)
                    vm_block.stmts.append(stmt_mov)
                    # pop rbp
                    stmt_pop = VmStmt("mov", arg_rbp, VmMemRegOp(*AMD64_REGS["rsp"], reg_name="rsp"))
                    vm_block.stmts.append(stmt_pop)
                    stmt_add = VmStmt("add", arg_rsp, arg_rsp, VmImmOp(8))
                    vm_block.stmts.append(stmt_add)
                case other:
                    raise NotImplementedError(f'"{other}" is not supported')

        if asm_block.fallthrough or not asm_block.last_line_branches:
            if asm_block.successor_labels:
                fallthrough_label = next(iter(label for label, ft in asm_block.successor_labels if ft is True))
                vm_block.stmts.append(VmStmt("jmp", raw_ops=[fallthrough_label]))

        return vm_block


class VmFunc:
    def __init__(self, name: str, blocks: Dict[str, VmBlock]):
        self.name = name
        self.blocks = blocks

    def assemble(self, extern_func_table: List[str]) -> bytes:
        """
        Flatten the control-flow graph and generate bytes for each block.
        """
        symbol_table = {}
        block_to_offset: Dict[str, int] = {}
        r = []

        stack = [self.blocks[self.name]]
        offset = 0
        while stack:
            curr_block = stack.pop(0)

            # assemble the block
            block_bytes, block_symbol_table = curr_block.assemble()
            r.append(block_bytes)
            block_to_offset[curr_block.label] = offset
            for off, sym in block_symbol_table.items():
                symbol_table[offset + off] = sym
            offset += len(block_bytes)

            # extend the stack with successors
            if curr_block.successor_labels:
                for succ_label in curr_block.successor_labels:
                    if succ_label not in block_to_offset:
                        succ = self.blocks[succ_label]
                        if succ not in stack:
                            stack.append(succ)

        # back-patch the bytes
        raw_bytes = self.backpatch(b"".join(r), symbol_table, block_to_offset, extern_func_table)
        return raw_bytes

    def backpatch(
        self,
        raw_bytes: bytes,
        symbol_table: Dict[int, VmSymbol],
        block_to_offset: Dict[str, int],
        extern_func_table: List[str],
    ) -> bytes:
        """
        Fix references and generate function call entries.

        After back-patching, VmStmt.raw_ops should be None for all VM statements
        """

        for offset, symbol in symbol_table.items():
            if symbol.type == "label":
                block_offset = block_to_offset[symbol.name]
                raw_bytes = raw_bytes[:offset] + block_offset.to_bytes(8, "little") + raw_bytes[offset + 8 :]
            elif symbol.type == "function":
                if symbol.name not in extern_func_table:
                    raise ValueError(f"Unsupported external function call {symbol.name}!")
                    # extern_func_table.append(symbol.name)
                    # func_idx = len(extern_func_table) - 1
                else:
                    func_idx = extern_func_table.index(symbol.name)
                raw_bytes = raw_bytes[:offset] + func_idx.to_bytes(8, "little") + raw_bytes[offset + 8 :]
        return raw_bytes


def find_func(asm_lines: List[str], func_name: str) -> Tuple[int, int]:
    start_lineno = None
    end_lineno = None
    for idx, line in enumerate(asm_lines):
        if line == f"{func_name}:":
            start_lineno = idx
        if line.strip(" \t") == ".cfi_endproc":
            end_lineno = idx + 1
            break
    if start_lineno is None or end_lineno is None:
        raise Exception(f"Function {func_name} is not found")
    return start_lineno, end_lineno


def extract_func(asm_lines: List[str], func_name: str) -> Optional[AsmFunc]:
    """ """
    start_lineno, end_lineno = find_func(asm_lines, func_name)
    return AsmFunc(func_name, asm_lines[start_lineno:end_lineno])


def translate(asm_func: AsmFunc) -> VmFunc:
    """
    Translate x86-64 assembly code to VM instructions on a block-by-block basis.
    """

    d = {}
    for asm_block in asm_func.func.nodes:
        vm_block = VmBlock.from_asm_block(asm_block)
        d[vm_block.label] = vm_block

    d[asm_func.name].stmts.insert(0, VmStmt("ak0"))
    d[asm_func.name].stmts.insert(0, VmStmt("ak1"))
    d[asm_func.name].stmts.insert(0, VmStmt("ak2"))

    return VmFunc(asm_func.name, d)


def to_hexstring(b: bytes) -> str:
    lst = ["\\x" + "%02x" % bb for bb in b]
    return "".join(lst)


@jit(nopython=True)
def encipher(v, k):
    y = v[0] & 0xFFFF_FFFF
    z = v[1] & 0xFFFF_FFFF
    sum = 0
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        sum += delta
        sum &= 0xFFFF_FFFF
        y += (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1]
        y &= 0xFFFF_FFFF
        z += (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3]
        z &= 0xFFFF_FFFF

    return y, z


@jit(nopython=True)
def encrypt(data: List[int], key: Tuple[int]) -> List[int]:
    chunks = []
    for i in range(0, len(data), 2):
        v = [data[i], data[i + 1]]
        v = encipher(v, key)
        chunks.append(v[0])
        chunks.append(v[1])
    return chunks


EXTERN_FUNCTION_TABLE = [
    "read@PLT",
    "printf@PLT",
]


VM_OPCODE_LIST = []


def generate_shuffled_opcodes() -> None:
    # shuffle VM_OPCODE
    global VM_OPCODE_LIST
    global VM_OPCODE

    opcode_keys = list(VM_OPCODE.keys())
    VM_OPCODE_LIST.append(VM_OPCODE)
    for i in range(20):
        vm_opcode_dict = {}
        opcodes = set()
        for opcode_key in opcode_keys:
            opcode = random.randint(0, 0xFFFF)
            while opcode in opcodes:
                opcode = random.randint(0, 0xFFFF)
            opcodes.add(opcode)
            vm_opcode_dict[opcode_key] = opcode
        VM_OPCODE_LIST.append(vm_opcode_dict)


def select_opcodes(config_path: str, vm_opcodes_set: Optional[int]) -> None:
    global VM_OPCODE
    if vm_opcodes_set is None:
        VM_OPCODE = random.choice(VM_OPCODE_LIST)
    else:
        VM_OPCODE = VM_OPCODE_LIST[vm_opcodes_set]
    with open(config_path, "w") as f:
        f.write(json.dumps(list(sorted(VM_OPCODE.items()))))


def obfuscate(asm_path: str, passphrase: Optional[bytes], config_path: str, vm_opcodes_set: Optional[int]) -> str:
    select_opcodes(config_path, vm_opcodes_set)

    with open(asm_path, "r") as f:
        asm_code = f.read()
        with open("/tmp/dst.s", "w") as ff:
            ff.write(asm_code)
        lines = asm_code.split("\n")
    # find the main function
    func = extract_func(lines, "main")
    vm_func = translate(func)

    raw_bytes = vm_func.assemble(EXTERN_FUNCTION_TABLE)
    # pad the program
    if len(raw_bytes) % 8 != 0:
        raw_bytes += b"\x00" * (8 - (len(raw_bytes) % 8))
    with open("/tmp/fuck.bin", "wb") as f:
        f.write(raw_bytes)

    if passphrase:
        # encrypt the bytes
        key = tuple(
            [struct.unpack("<I", passphrase[0:4])[0], struct.unpack("<I", passphrase[4:8])[0], 0x13371338, 0x1339133A]
        )
        raw_bytes_chunks = []
        for i in range(0, len(raw_bytes), 4):
            raw_bytes_chunks.append(struct.unpack("<I", raw_bytes[i : i + 4])[0])
        raw_bytes_chunks = encrypt(raw_bytes_chunks, key)
        raw_bytes = b"".join([struct.pack("<I", q) for q in raw_bytes_chunks])

        new_main_func = f"""
main:
    sub rsp, 88
    lea rdi, .CODE[rip]
    mov esi, {len(raw_bytes)}
    call decrypt_and_run_code
    add rsp, 88
    ret
"""
    else:
        new_main_func = f"""
main:
    sub rsp, 88
    lea rdi, .CODE[rip]
    mov esi, {len(raw_bytes)}
    call run_code
    add rsp, 88
    ret
"""

    # replace the existing main function
    start_lineno, end_lineno = find_func(lines, "main")
    lines = lines[:start_lineno] + [new_main_func] + lines[end_lineno:]

    # add the code
    vm_code_str = to_hexstring(raw_bytes)
    lines = (
        lines[:3]
        + [
            f"""
.CODE:
    .string "{vm_code_str}"
"""
        ]
        + lines[3:]
    )

    return "\n".join(lines)
