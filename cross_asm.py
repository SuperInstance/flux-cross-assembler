#!/usr/bin/env python3
"""FLUX Cross-Assembler — dual-target cloud/edge bytecode compiler.

Compiles .fluxasm source to either cloud (4-byte fixed-width) or
edge (variable-width 1-3 byte) FLUX bytecode.

Usage:
    python3 cross_asm.py --target cloud program.fluxasm -o program.fbc
    python3 cross_asm.py --target edge program.fluxasm -o program.fbc
    python3 cross_asm.py --disassemble program.fbc
    python3 cross_asm.py --test
"""

import argparse
import struct
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


# ── Cloud ISA v2 Opcodes (4-byte fixed) ──────────────────────────────────

class CloudOp(IntEnum):
    NOP     = 0x00
    MOV     = 0x01
    LOAD    = 0x02
    STORE   = 0x03
    JMP     = 0x04
    JZ      = 0x05
    JNZ     = 0x06
    CALL    = 0x07
    IADD    = 0x08
    ISUB    = 0x09
    IMUL    = 0x0A
    IDIV    = 0x0B
    IMOD    = 0x0C
    INEG    = 0x0D
    INC     = 0x0E
    DEC     = 0x0F
    IAND    = 0x10
    IOR     = 0x11
    IXOR    = 0x12
    INOT    = 0x13
    ISHL    = 0x14
    ISHR    = 0x15
    ROTL    = 0x16
    ROTR    = 0x17
    ICMP    = 0x18
    IEQ     = 0x19
    ILT     = 0x1A
    ILE     = 0x1B
    IGT     = 0x1C
    IGE     = 0x1D
    TEST    = 0x1E
    SETCC   = 0x1F
    PUSH    = 0x20
    POP     = 0x21
    DUP     = 0x22
    SWAP    = 0x23
    ROT     = 0x24
    ENTER   = 0x25
    LEAVE   = 0x26
    ALLOCA  = 0x27
    MEMCPY  = 0x28
    MEMSET  = 0x29
    MREGION = 0x2A
    MOVI    = 0x2B
    MOVI16  = 0x2C
    LOAD8   = 0x2D
    STORE8  = 0x2E
    JE      = 0x2F
    HALT    = 0x80
    # ISA v3 extensions
    EVOLVE  = 0x90
    INSTINCT = 0x91
    WITNESS  = 0x92
    CONF    = 0x93
    MERGE   = 0x94
    SNAPSHOT = 0x95
    RESTORE  = 0x96
    # A2A
    A2A_TELL     = 0xA0
    A2A_ASK      = 0xA1
    A2A_BROADCAST = 0xA2
    A2A_DELEGATE  = 0xA3
    # Float
    FADD    = 0x40
    FSUB    = 0x41
    FMUL    = 0x42
    FDIV    = 0x43
    FNEG    = 0x44
    FABS    = 0x45
    FMIN    = 0x46
    FMAX    = 0x47


# ── Edge ISA v3 Opcodes (variable-width) ──────────────────────────────────

class EdgeOp(IntEnum):
    # 1-byte instructions (0x00-0x7F)
    NOP         = 0x00
    ADD_R0      = 0x01
    SUB_R0      = 0x02
    AND_R0      = 0x03
    OR_R0       = 0x04
    XOR_R0      = 0x05
    NOT_R0      = 0x06
    SHL_R0      = 0x07
    SHR_R0      = 0x08
    INC_R0      = 0x09
    DEC_R0      = 0x0A
    NEG_R0      = 0x0B
    PUSH_R0     = 0x10
    POP_R0      = 0x11
    DUP         = 0x12
    SWAP        = 0x13
    DROP        = 0x14
    HALT        = 0x20
    RET         = 0x21
    IRET        = 0x22
    SLEEP       = 0x28
    WAKE        = 0x29
    WDOG_RESET  = 0x2A
    CONF_READ   = 0x30
    CONF_SET    = 0x31
    ENERGY_READ = 0x38
    ENERGY_SYNC = 0x39
    TRUST_READ  = 0x40
    TRUST_QUERY = 0x41
    # 2-byte instructions (0x80-0xBF)
    CADD        = 0x80
    CSUB        = 0x81
    CMUL        = 0x82
    CDIV        = 0x83
    ADD_IMM     = 0x84
    SUB_IMM     = 0x85
    MUL_IMM     = 0x86
    DIV_IMM     = 0x87
    MOV_REG     = 0x90
    CMP_REG     = 0x94
    CONF_SET4   = 0xB0
    CONF_DEC    = 0xB2
    CONF_INC    = 0xB3
    BCOND       = 0xA0
    # 3-byte instructions (0xC0-0xFF)
    CALL_ADDR   = 0xC0
    JMP_ADDR    = 0xC1
    LD_ADDR     = 0xC8
    ST_ADDR     = 0xC9
    LDI         = 0xCA
    ATP_QUERY   = 0xD6
    ATP_SPEND   = 0xD1
    MSG_SEND    = 0xE0
    MSG_RECV    = 0xE1
    MSG_POLL    = 0xE4
    TRUST_VERIFY = 0xDE
    INST_LISTEN = 0xFB
    INST_REST   = 0xF4
    BRK         = 0xF8
    ILLEGAL     = 0xF9
    UNDEF       = 0xFF


# ── Semantic Instruction (frontend) ──────────────────────────────────────

@dataclass
class Instruction:
    mnemonic: str
    operands: List[str] = field(default_factory=list)
    label: Optional[str] = None
    comment: Optional[str] = None
    line: int = 0


class CrossAssembler:
    """Dual-target FLUX assembler."""

    def __init__(self, target: str = "cloud"):
        self.target = target
        self.instructions: List[Instruction] = []
        self.labels: Dict[str, int] = {}
        self.bytecode: bytearray = bytearray()

    def parse(self, source: str) -> 'CrossAssembler':
        """Parse .fluxasm source into semantic instructions."""
        instructions = []
        for line_no, line in enumerate(source.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith(';') or line.startswith('//'):
                continue
            if ':' in line and not line.startswith((' ', '\t')):
                parts = line.split(':', 1)
                label = parts[0].strip()
                rest = parts[1].strip()
                if rest:
                    inst = self._parse_instruction(rest, line_no)
                    inst.label = label
                    instructions.append(inst)
                else:
                    inst = Instruction(mnemonic="__LABEL__", line=line_no)
                    inst.label = label
                    instructions.append(inst)
                continue
            inst = self._parse_instruction(line, line_no)
            instructions.append(inst)
        self.instructions = instructions
        return self

    def _parse_instruction(self, text: str, line_no: int) -> Instruction:
        if ';' in text:
            text, comment = text.split(';', 1)
            comment = comment.strip()
        else:
            comment = None
        parts = text.split()
        mnemonic = parts[0].upper()
        operands = [p.strip().rstrip(',') for p in parts[1:]] if len(parts) > 1 else []
        return Instruction(mnemonic=mnemonic, operands=operands, comment=comment, line=line_no)

    def _resolve_operand(self, op: str) -> int:
        op = op.strip()
        if op.upper().startswith('R') and op[1:].isdigit():
            return int(op[1:])
        if op.startswith('0x') or op.startswith('0X'):
            return int(op, 16)
        if op.lstrip('-').isdigit():
            return int(op)
        if op in self.labels:
            return self.labels[op]
        raise ValueError(f"Cannot resolve operand: {op}")

    def assemble_cloud(self) -> bytes:
        self.bytecode = bytearray()
        offset = 0
        for inst in self.instructions:
            if inst.mnemonic == "__LABEL__":
                self.labels[inst.label] = offset
                continue
            offset += 4
        for inst in self.instructions:
            if inst.mnemonic == "__LABEL__":
                continue
            self.bytecode.extend(self._emit_cloud(inst))
        return bytes(self.bytecode)

    def assemble_edge(self) -> bytes:
        self.bytecode = bytearray()
        inst_offsets = []
        offset = 0
        for inst in self.instructions:
            if inst.mnemonic == "__LABEL__":
                self.labels[inst.label] = offset
                continue
            size = self._edge_instruction_size(inst)
            inst_offsets.append((inst, offset))
            offset += size
        for inst, _ in inst_offsets:
            self.bytecode.extend(self._emit_edge(inst))
        return bytes(self.bytecode)

    def _edge_instruction_size(self, inst: Instruction) -> int:
        mn = inst.mnemonic
        one_byte = {'NOP', 'HALT', 'RET', 'IRET', 'SLEEP', 'WAKE', 'WDOG_RESET',
                     'CONF_READ', 'CONF_SET', 'ENERGY_READ', 'ENERGY_SYNC',
                     'TRUST_READ', 'TRUST_QUERY', 'DUP', 'SWAP', 'DROP',
                     'PUSH', 'POP', 'INC', 'DEC', 'NEG', 'NOT',
                     'INST_LISTEN', 'INST_REST', 'BRK', 'ILLEGAL'}
        if mn in one_byte:
            return 1
        three_byte = {'CALL', 'JMP', 'LD', 'ST', 'LDI', 'ATP_QUERY', 'ATP_SPEND',
                       'MSG_SEND', 'MSG_RECV', 'MSG_POLL', 'TRUST_VERIFY'}
        if mn in three_byte:
            return 3
        return 2

    def _emit_cloud(self, inst: Instruction) -> bytes:
        mn = inst.mnemonic
        ops = inst.operands
        op_map = {
            'NOP': CloudOp.NOP, 'HALT': CloudOp.HALT,
            'IADD': CloudOp.IADD, 'ADD': CloudOp.IADD,
            'ISUB': CloudOp.ISUB, 'SUB': CloudOp.ISUB,
            'IMUL': CloudOp.IMUL, 'MUL': CloudOp.IMUL,
            'IDIV': CloudOp.IDIV, 'DIV': CloudOp.IDIV,
            'IMOD': CloudOp.IMOD, 'MOD': CloudOp.IMOD,
            'INEG': CloudOp.INEG, 'NEG': CloudOp.INEG,
            'INC': CloudOp.INC, 'DEC': CloudOp.DEC,
            'IAND': CloudOp.IAND, 'AND': CloudOp.IAND,
            'IOR': CloudOp.IOR, 'OR': CloudOp.IOR,
            'IXOR': CloudOp.IXOR, 'XOR': CloudOp.IXOR,
            'INOT': CloudOp.INOT, 'NOT': CloudOp.INOT,
            'PUSH': CloudOp.PUSH, 'POP': CloudOp.POP,
            'DUP': CloudOp.DUP, 'SWAP': CloudOp.SWAP,
            'MOV': CloudOp.MOV, 'MOVI': CloudOp.MOVI,
            'JMP': CloudOp.JMP, 'JZ': CloudOp.JZ, 'JNZ': CloudOp.JNZ,
            'CALL': CloudOp.CALL,
            'EVOLVE': CloudOp.EVOLVE, 'INSTINCT': CloudOp.INSTINCT,
            'WITNESS': CloudOp.WITNESS, 'CONF': CloudOp.CONF,
            'FADD': CloudOp.FADD, 'FSUB': CloudOp.FSUB,
            'CADD': CloudOp.IADD, 'CSUB': CloudOp.ISUB,
            'CMUL': CloudOp.IMUL, 'CDIV': CloudOp.IDIV,
        }
        opcode = op_map.get(mn)
        if opcode is None:
            raise ValueError(f"Unknown mnemonic: {mn}")
        if len(ops) == 0:
            return bytes([opcode, 0, 0, 0])
        elif len(ops) == 1:
            a = self._resolve_operand(ops[0]) & 0xFF
            return bytes([opcode, a, 0, 0])
        elif len(ops) == 2:
            a = self._resolve_operand(ops[0]) & 0xFF
            b = self._resolve_operand(ops[1]) & 0xFF
            return bytes([opcode, a, b, 0])
        else:
            a = self._resolve_operand(ops[0]) & 0xFF
            b = self._resolve_operand(ops[1]) & 0xFF
            c = self._resolve_operand(ops[2]) & 0xFF
            return bytes([opcode, a, b, c])

    def _emit_edge(self, inst: Instruction) -> bytes:
        mn = inst.mnemonic
        ops = inst.operands
        if mn == 'NOP': return bytes([EdgeOp.NOP])
        if mn == 'HALT': return bytes([EdgeOp.HALT])
        if mn == 'RET': return bytes([EdgeOp.RET])
        if mn == 'DUP': return bytes([EdgeOp.DUP])
        if mn == 'SWAP': return bytes([EdgeOp.SWAP])
        if mn == 'INST_LISTEN': return bytes([EdgeOp.INST_LISTEN])
        if mn == 'INST_REST': return bytes([EdgeOp.INST_REST])
        if mn in ('INC', 'DEC', 'NEG', 'NOT', 'PUSH', 'POP'):
            rm = {'INC': EdgeOp.INC_R0, 'DEC': EdgeOp.DEC_R0,
                   'NEG': EdgeOp.NEG_R0, 'NOT': EdgeOp.NOT_R0,
                   'PUSH': EdgeOp.PUSH_R0, 'POP': EdgeOp.POP_R0}
            return bytes([rm[mn]])
        if mn == 'CADD':
            imm = self._resolve_operand(ops[0]) & 0xFF if ops else 0
            return bytes([EdgeOp.CADD, imm])
        if mn == 'CSUB':
            imm = self._resolve_operand(ops[0]) & 0xFF if ops else 0
            return bytes([EdgeOp.CSUB, imm])
        if mn in ('ADD', 'SUB', 'MUL', 'DIV', 'IADD', 'ISUB', 'IMUL', 'IDIV'):
            im = {'ADD': EdgeOp.ADD_IMM, 'SUB': EdgeOp.SUB_IMM,
                   'MUL': EdgeOp.MUL_IMM, 'DIV': EdgeOp.DIV_IMM,
                   'IADD': EdgeOp.ADD_IMM, 'ISUB': EdgeOp.SUB_IMM,
                   'IMUL': EdgeOp.MUL_IMM, 'IDIV': EdgeOp.DIV_IMM}
            imm = self._resolve_operand(ops[0]) & 0xFF if ops else 0
            return bytes([im[mn], imm])
        if mn in ('CSUB', 'CMUL', 'CDIV'):
            eo = {'CSUB': EdgeOp.CSUB, 'CMUL': EdgeOp.CMUL, 'CDIV': EdgeOp.CDIV}
            imm = self._resolve_operand(ops[0]) & 0xFF if ops else 0
            return bytes([eo[mn], imm])
        if mn in ('LDI', 'MOVI'):
            reg = self._resolve_operand(ops[0]) & 0xFF if ops else 0
            val = self._resolve_operand(ops[1]) & 0xFFFF if len(ops) > 1 else 0
            return bytes([EdgeOp.LDI, reg, val & 0xFF, (val >> 8) & 0xFF])
        if mn == 'JMP':
            addr = self._resolve_operand(ops[0]) & 0xFFFF if ops else 0
            return bytes([EdgeOp.JMP_ADDR, addr & 0xFF, (addr >> 8) & 0xFF])
        if mn == 'MSG_SEND':
            reg = self._resolve_operand(ops[0]) & 0xFF if ops else 0
            addr = self._resolve_operand(ops[1]) & 0xFFFF if len(ops) > 1 else 0
            return bytes([EdgeOp.MSG_SEND, reg, addr & 0xFF, (addr >> 8) & 0xFF])
        raise ValueError(f"Unknown edge mnemonic: {mn}")

    def assemble(self) -> bytes:
        if self.target == "cloud":
            return self.assemble_cloud()
        return self.assemble_edge()

    def disassemble(self, bytecode: bytes) -> List[str]:
        if self.target == "cloud":
            return self._disassemble_cloud(bytecode)
        return self._disassemble_edge(bytecode)

    def _disassemble_cloud(self, bc: bytes) -> List[str]:
        lines = []
        cn = {op.value: op.name for op in CloudOp}
        for i in range(0, len(bc), 4):
            chunk = bc[i:i+4]
            if len(chunk) < 4: chunk += b'\x00' * (4 - len(chunk))
            name = cn.get(chunk[0], f"OP_{chunk[0]:02x}")
            args = f"r{chunk[1]}, r{chunk[2]}, r{chunk[3]}" if any(chunk[1:]) else ""
            lines.append(f"  {i:04x}: {name:16} {args}")
        return lines

    def _disassemble_edge(self, bc: bytes) -> List[str]:
        lines = []
        en1 = {op.value: op.name for op in EdgeOp if op.value < 0x80}
        en2 = {op.value: op.name for op in EdgeOp if 0x80 <= op.value < 0xC0}
        en3 = {op.value: op.name for op in EdgeOp if op.value >= 0xC0}
        i = 0
        while i < len(bc):
            b0 = bc[i]
            if b0 < 0x80:
                lines.append(f"  {i:04x}: {en1.get(b0, f'OP_{b0:02x}')}")
                i += 1
            elif b0 < 0xC0:
                a = bc[i+1] if i+1 < len(bc) else 0
                lines.append(f"  {i:04x}: {en2.get(b0, f'OP_{b0:02x}'):16} 0x{a:02x}")
                i += 2
            else:
                a1 = bc[i+1] if i+1 < len(bc) else 0
                a2 = bc[i+2] if i+2 < len(bc) else 0
                lines.append(f"  {i:04x}: {en3.get(b0, f'OP_{b0:02x}'):16} 0x{a1:02x} 0x{a2:02x}")
                i += 3
        return lines


def run_tests():
    passed = 0
    failed = 0
    tests = []

    # Test 1: Cloud NOP
    bc = CrossAssembler("cloud").parse("NOP").assemble_cloud()
    tests.append(("Cloud NOP", bc == bytes([0x00, 0, 0, 0])))

    # Test 2: Cloud MOVI
    bc = CrossAssembler("cloud").parse("MOVI R0, 42").assemble_cloud()
    tests.append(("Cloud MOVI R0,42", bc == bytes([0x2B, 0, 42, 0])))

    # Test 3: Cloud IADD
    bc = CrossAssembler("cloud").parse("IADD R0, R1, R2").assemble_cloud()
    tests.append(("Cloud IADD", bc == bytes([0x08, 0, 1, 2])))

    # Test 4: Edge NOP
    bc = CrossAssembler("edge").parse("NOP").assemble_edge()
    tests.append(("Edge NOP", bc == bytes([0x00])))

    # Test 5: Edge HALT
    bc = CrossAssembler("edge").parse("HALT").assemble_edge()
    tests.append(("Edge HALT", bc == bytes([0x20])))

    # Test 6: Edge CADD
    bc = CrossAssembler("edge").parse("CADD 0x01").assemble_edge()
    tests.append(("Edge CADD", bc == bytes([0x80, 0x01])))

    # Test 7: Edge LDI
    bc = CrossAssembler("edge").parse("LDI R8, 5").assemble_edge()
    tests.append(("Edge LDI R8,5", bc == bytes([0xCA, 8, 5, 0])))

    # Test 8: Multi-instruction cloud
    src = "MOVI R1, 3\nMOVI R2, 4\nIADD R0, R1, R2\nHALT"
    bc = CrossAssembler("cloud").parse(src).assemble_cloud()
    ok = (len(bc) == 16 and bc[:4] == bytes([0x2B, 1, 3, 0])
          and bc[8:12] == bytes([0x08, 0, 1, 2]))
    tests.append(("Cloud program (16 bytes)", ok))

    # Test 9: Same program edge
    bc_e = CrossAssembler("edge").parse(src).assemble_edge()
    tests.append(("Edge program (< 16 bytes)", len(bc_e) < 16))

    # Test 10: Cloud disassembly round-trip
    asm = CrossAssembler("cloud")
    bc = bytes.fromhex("2b0103002b0204000800010280")
    lines = asm.disassemble(bc)
    tests.append(("Cloud disasm", 'MOVI' in lines[0] and 'HALT' in lines[3]))

    # Test 11: Edge disassembly
    bc = bytes([0xCA, 8, 5, 0, 0xB0, 0x0F, 0xFB, 0x80, 0x01, 0x0A, 0x20])
    lines = CrossAssembler("edge").disassemble(bc)
    tests.append(("Edge disasm", 'LDI' in lines[0] and 'HALT' in lines[-1]))

    # Test 12: Density comparison
    cloud_bc = CrossAssembler("cloud").parse(src).assemble_cloud()
    edge_bc = CrossAssembler("edge").parse(src).assemble_edge()
    ratio = len(edge_bc) / len(cloud_bc)
    tests.append((f"Density: edge={len(edge_bc)}B cloud={len(cloud_bc)}B ({ratio:.1%})", ratio < 1.0))

    for name, ok in tests:
        status = "✅" if ok else "❌"
        print(f"  {status} {name}")
        if ok: passed += 1
        else: failed += 1

    print(f"\n  Results: {passed}/{passed+failed} passed")
    return passed, failed


def main():
    parser = argparse.ArgumentParser(description="FLUX Cross-Assembler")
    parser.add_argument("--target", choices=["cloud", "edge"], default="cloud")
    parser.add_argument("--disassemble", action="store_true")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("input", nargs="?", help="Input .fluxasm file")
    parser.add_argument("--test", action="store_true", help="Run tests")
    args = parser.parse_args()

    if args.test:
        run_tests()
        return

    if not args.input:
        print("Error: provide an input file or --test", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        source = f.read()

    asm = CrossAssembler(args.target)

    if args.disassemble:
        with open(args.input, 'rb') as f:
            bytecode = f.read()
        for line in asm.disassemble(bytecode):
            print(line)
    else:
        asm.parse(source)
        bytecode = asm.assemble()
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(bytecode)
            print(f"Assembled {len(bytecode)} bytes -> {args.output} ({args.target})")
        else:
            print(bytecode.hex())


if __name__ == "__main__":
    main()
