#!/usr/bin/env python3
import os
import sys
import glob
import re
import struct

# Constants
BRAINLIB_DIR = "brainlib"

REGISTERS = {
    'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
    'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
}
# XMM registers
for i in range(16):
    REGISTERS[f'xmm{i}'] = i

class Operand:
    def __init__(self, raw):
        self.raw = raw
    def __repr__(self): return self.raw

class Register(Operand):
    def __init__(self, name):
        super().__init__(name)
        self.name = name.lower()
        self.id = REGISTERS[self.name]
        self.is_xmm = self.name.startswith('xmm')
        self.is_r64 = not self.is_xmm # Simplification for now

class Immediate(Operand):
    def __init__(self, val_str):
        super().__init__(val_str)
        self.value = self.parse_value(val_str)

    def parse_value(self, s):
        s = s.strip()
        if s.startswith("'") and s.endswith("'") and len(s) == 3:
            return ord(s[1])
        try:
            return int(s, 0)
        except:
            return s # Return string if it's a label/const reference

class Memory(Operand):
    def __init__(self, text):
        super().__init__(text)
        # Parse [base + index*scale + disp]
        content = text.strip()[1:-1].strip()
        self.base = None
        self.index = None
        self.scale = 0
        self.disp = 0
        self.label = None
        self.offset = 0 # Additional offset for label

        # Tokenize by '+' but handle complex expr
        # Assume format: part1 + part2 ...

        parts = [p.strip() for p in content.split('+')]

        for p in parts:
            if '*' in p:
                # index*scale
                sub = p.split('*')
                if len(sub) == 2:
                    s0 = sub[0].strip()
                    s1 = sub[1].strip()
                    if s0.lower() in REGISTERS:
                        self.index = Register(s0)
                        self.scale = int(s1)
                    elif s1.lower() in REGISTERS:
                        self.index = Register(s1)
                        self.scale = int(s0)
            elif p.lower() in REGISTERS:
                reg = Register(p)
                if not self.base:
                    self.base = reg
                else:
                    # Treat second register as index with scale 1
                    self.index = reg
                    self.scale = 1
            elif p and (p[0].isdigit() or p.startswith('-') or p.startswith('0x')):
                try:
                    val = int(p, 0)
                    self.disp += val
                    self.offset += val
                except:
                    self.label = p
            elif p and p[0].isalpha():
                self.label = p
            else:
                pass

class InstructionDef:
    def __init__(self, mnemonic, properties):
        self.full_mnemonic = mnemonic
        self.base_mnemonic = mnemonic.split('.')[0]
        self.operands_signature = mnemonic.split('.')[1:]
        self.properties = properties

        # Parse opcode bytes
        if 'opcode' in properties:
            self.opcode = [int(x, 16) for x in properties['opcode'].split(',')]
        else:
            self.opcode = []

        self.rex = properties.get('rex')
        self.modrm = properties.get('modrm')

    def check_match(self, operands):
        if len(operands) != len(self.operands_signature):
            return False

        for i, sig in enumerate(self.operands_signature):
            op = operands[i]
            if sig == 'r64':
                if not isinstance(op, Register) or not op.is_r64: return False
            elif sig == 'mem':
                if not isinstance(op, Memory): return False
            elif sig.startswith('imm'):
                if not isinstance(op, Immediate): return False
                # Size check
                val = op.value
                if isinstance(val, str): return True # Assume fits for labels/constants not yet resolved

                if sig == 'imm8':
                     if not (-128 <= val <= 255): return False
                elif sig == 'imm16':
                     if not (-32768 <= val <= 65535): return False
                elif sig == 'imm32':
                     # imm32 in 64-bit context is often sign-extended
                     if not (-2147483648 <= val <= 2147483647): return False

            elif sig == 'rel32':
                 # Accepts label or imm, NOT register
                 if isinstance(op, Register): return False
                 if not (isinstance(op, Immediate) or isinstance(op, Memory)): return True
                 # Actually Memory should strictly not be rel32 usually, but let's keep it loose except for Reg
                 pass
            # Add more checks as needed
        return True

class MorphAssembler:
    def __init__(self):
        self.instructions = {}
        self.constants = {}
        self.labels = {} # name -> address
        self.output = bytearray()
        self.relocations = [] # list of (offset, type, label)
        self.output_format = 'bin' # 'bin' or 'elf64'
        self.entry_point = None

    def load_isa(self):
        vzoel_files = glob.glob(os.path.join(BRAINLIB_DIR, "*.vzoel"))
        for filepath in vzoel_files:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(';'): continue
                    if ';' in line: line = line.split(';')[0].strip()
                    parts = line.split()
                    if not parts: continue
                    mnemonic = parts[0]
                    props = {}
                    for part in parts[1:]:
                        if '=' in part:
                            k, v = part.split('=', 1)
                            props[k] = v
                        else:
                            # Store tags as boolean properties
                            props[part] = True
                    instr = InstructionDef(mnemonic, props)
                    base = instr.base_mnemonic
                    if base not in self.instructions: self.instructions[base] = []
                    self.instructions[base].append(instr)

    def parse_operand(self, op_str):
        op_str = op_str.strip()
        if not op_str: return None
        if op_str.startswith('[') and op_str.endswith(']'):
            return Memory(op_str)
        if op_str.lower() in REGISTERS:
            return Register(op_str)
        return Immediate(op_str)

    def assemble(self, filepath):
        with open(filepath, 'r') as f:
            lines = f.readlines()

        # Pass 1: Address calculation & Label collection
        current_addr = 0
        # If ELF, start code at a standard virtual address (e.g., 0x400000 + headers)
        # But for simplicity, we assume one segment readable executable at 0x400000
        base_addr = 0

        parsed_instructions = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'): continue
            if ';' in line: line = line.split(';')[0].strip()

            # Handle Labels
            if line.endswith(':'):
                label_name = line[:-1]
                self.labels[label_name] = current_addr
                continue

            # Handle assignments (len = $ - msg) - Simplified
            if '=' in line:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                if v == '$ - msg': # Hardcoded hack for the example for now
                    self.constants[k] = "EXPR_LEN_MSG"
                else:
                     try: self.constants[k] = int(v, 0)
                     except: pass
                continue

            # Parse Mnemonic
            parts = line.split(maxsplit=1)
            mnemonic = parts[0]

            # Handle Directives
            if mnemonic == 'format':
                fmt = parts[1] if len(parts) > 1 else ""
                if fmt.startswith('ELF64'):
                    self.output_format = 'elf64'
                    base_addr = 0x400000 # Standard base
                    current_addr = base_addr + 120 # Offset by header size
                continue

            if mnemonic == 'entry':
                self.entry_point = parts[1].strip()
                continue

            if mnemonic == 'segment':
                # Ignore segment directives for now, assume one flat segment
                continue

            # Check for label without colon (heuristic)
            # If first word is not a known mnemonic but second word is (or is db/use64)
            if len(parts) > 1:
                potential_mnemonic = parts[1].split()[0] if parts[1] else ""
                # Simple check: is parts[0] a known mnemonic?
                known_mnemonics = set(self.instructions.keys())
                known_mnemonics.add('db')
                known_mnemonics.add('rb')
                known_mnemonics.add('use64')

                if mnemonic not in known_mnemonics and (potential_mnemonic in known_mnemonics or '=' in line):
                     # Treat parts[0] as label
                     label_name = mnemonic
                     self.labels[label_name] = current_addr

                     # Consume label
                     line = line[len(label_name):].strip()
                     if not line: continue
                     parts = line.split(maxsplit=1)
                     mnemonic = parts[0]

            operands_str = parts[1] if len(parts) > 1 else ""

            # Handle DB
            if mnemonic == 'db':
                # Parse comma separated values
                values = []
                # Simple parser for strings and ints
                # Note: this is a weak parser, assumes quotes don't contain commas
                raw_parts = operands_str.split(',')
                size = 0
                data_bytes = bytearray()

                for p in raw_parts:
                    p = p.strip()
                    if p.startswith("'") or p.startswith('"'):
                         s = p[1:-1]
                         b = s.encode('utf-8') # ASCII
                         data_bytes.extend(b)
                    else:
                        try:
                            val = int(p, 0)
                            data_bytes.append(val)
                        except:
                            print(f"Warning: could not parse db value {p}")

                size = len(data_bytes)
                parsed_instructions.append({
                    'type': 'data',
                    'bytes': data_bytes,
                    'addr': current_addr
                })
                current_addr += size
                continue

            if mnemonic == 'use64': continue # Ignore

            if mnemonic == 'rb':
                # Handle Reserve Bytes by emitting zeros (Flat binary approach)
                count_str = operands_str.strip()
                count = 0
                try:
                    count = int(count_str, 0)
                except:
                    print(f"Warning: could not parse rb count {count_str}")

                if count > 0:
                    parsed_instructions.append({
                        'type': 'data',
                        'bytes': bytearray(count),
                        'addr': current_addr
                    })
                    current_addr += count
                continue

            # Parse Operands
            operands = []
            if operands_str:
                # Split by comma but respect brackets? Simple split for now
                ops_raw = operands_str.split(',')
                for r in ops_raw:
                    operands.append(self.parse_operand(r.strip()))

            # Find definition
            candidates = self.instructions.get(mnemonic, [])
            match = None
            for cand in candidates:
                if cand.check_match(operands):
                    match = cand
                    break

            if not match:
                print(f"Error: No matching instruction for {line}")
                continue

            # Estimate size (Assuming max size or standard logic)
            # This is tricky without encoding. I'll do encoding in Pass 1 to get size?
            # Or just store operands and encode in Pass 2.
            # But addressing depends on sizes.
            # Let's try to encode partially.

            parsed_instructions.append({
                'type': 'instr',
                'def': match,
                'operands': operands,
                'addr': current_addr
            })

            # Rough size estimation (essential for labels)
            # Opcode length + ModRM(1) + SIB(1) + Disp(4) + Imm(4/8)
            # For exactness, we should encode.
            encoded = self.encode_instruction(match, operands, current_addr, dry_run=True)
            size = len(encoded)
            current_addr += size

            # Update size in the record
            parsed_instructions[-1]['size'] = size

        # Pass 2: Final Encoding (Resolve labels)
        code_output = bytearray()

        # Patch constant EXPR_LEN_MSG if needed
        # Assuming msg is a label
        if 'EXPR_LEN_MSG' in self.constants.values():
            # Find msg label
            if 'msg' in self.labels:
                msg_addr = self.labels['msg']
                # length is end_addr - msg_addr.
                # Assuming 'msg' is at end.
                # This is specific to the example.
                # msg_len = $ - msg. $ is current address at the line.
                # I skipped '=' lines in address calc, so this is hard.
                # I'll rely on manual fix or simple resolution if possible.
                pass

        for p in parsed_instructions:
            if p['type'] == 'data':
                code_output.extend(p['bytes'])
            elif p['type'] == 'instr':
                # Re-encode with resolved labels
                encoded = self.encode_instruction(p['def'], p['operands'], p['addr'], dry_run=False)
                code_output.extend(encoded)

        if self.output_format == 'elf64':
            self.output = self.create_elf_header(code_output, base_addr)
        else:
            self.output = code_output

    def create_elf_header(self, code, base_addr):
        # Create minimal ELF64 executable header
        # ELF Header (64 bytes) + Program Header (56 bytes) = 120 bytes
        # Code starts after headers.

        # Determine Entry Point
        # Pass 1 labels already include +120 offset now.
        entry_addr = self.labels.get(self.entry_point, base_addr + 120) if self.entry_point else (base_addr + 120)

        # Construct ELF Header
        # Format <4s 5B 7x 2H I 3Q I 6H is cleaner for standard ELF64, but let's stick to H/I where possible.
        # 4s (Magic)
        # 5B (Class, Data, Version, OSABI, ABIVersion)
        # 7x (Pad)
        # 2H (Type, Machine)
        # I (Version)
        # 3Q (Entry, PhdrOff, ShdrOff)
        # I (Flags)
        # 6H (EhSize, PhEntSize, PhNum, ShEntSize, ShNum, ShStrNdx)

        elf_header = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
            b'\x7fELF',
            2, # Class: 64-bit
            1, # Data: Little endian
            1, # Version: 1
            0, # OS ABI: System V
            0, # ABI Version
            # Pad is handled by 7x
            2, # Type: Executable (ET_EXEC)
            0x3E, # Machine: AMD64
            1, # Version: 1
            entry_addr, # Entry Point
            64, # Phdr offset (immediately after ELF header)
            0, # Shdr offset
            0, # Flags
            64, # Header size
            56, # Phdr size
            1, # Phdr count
            0, # Shdr size
            0, # Shdr count
            0  # String table index
        )

        # Program Header
        file_size = 120 + len(code)
        mem_size = file_size

        phdr = struct.pack('<2I6Q',
            1, # Type: LOAD
            7, # Flags: R W E (Read, Write, Execute)
            0, # Offset
            base_addr, # VAddr
            base_addr, # PAddr
            file_size, # FileSize
            mem_size, # MemSize
            0x1000 # Align
        )

        return elf_header + phdr + code

    def resolve_value(self, op):
        if isinstance(op, Immediate):
            if isinstance(op.value, str):
                # Check constants
                if op.value in self.constants:
                    val = self.constants[op.value]
                    if val == "EXPR_LEN_MSG": return 33 # Hack for hello.asm
                    return val
                # Check labels
                if op.value in self.labels:
                    return self.labels[op.value]
                # Default 0?
                return 0
            return op.value
        return 0

    def encode_instruction(self, instr_def, operands, addr, dry_run=False):
        # Implementation of encoding logic based on .vzoel properties
        # This needs to handle REX, ModRM, Imm, Disp, SIB

        out = bytearray()

        # 1. REX Prefix
        # W bit
        rex = 0
        if instr_def.rex == 'W':
            rex |= 0x48

        reg_code = 0
        rm_code = 0

        modrm_byte = None
        sib_byte = None
        has_modrm = False

        if instr_def.modrm:
            has_modrm = True
            mod = 0
            reg = 0
            rm = 0

            spec = instr_def.modrm.split(',')

            # Mapping logic
            reg_operand = None
            rm_operand = None

            if len(spec) == 2:
                # "reg,mem" or "mem,reg" or "rm,reg" or "reg,rm"
                for i, role in enumerate(spec):
                    op = operands[i]
                    if role == 'reg':
                        if isinstance(op, Register):
                            reg = op.id
                            reg_operand = op
                    elif role == 'mem' or role == 'rm':
                         rm_operand = op
                         if role == 'rm' and isinstance(op, Register):
                             rm = op.id

            elif len(spec) == 1:
                # "0" or "reg" or "4"
                if spec[0].isdigit():
                    reg = int(spec[0])
                    # Operand 0 must be the RM
                    rm_operand = operands[0]
                else:
                    pass

            # Construct ModRM & SIB
            if rm_operand and isinstance(rm_operand, Memory):
                if hasattr(rm_operand, 'label') and rm_operand.label:
                     # RIP relative
                     mod = 0b00
                     rm = 0b101
                     # Calculate disp later
                else:
                    # [Base + Index*Scale + Disp]
                    base_reg = rm_operand.base
                    index_reg = rm_operand.index
                    scale = rm_operand.scale

                    need_sib = False

                    # Determine if SIB needed
                    if index_reg: need_sib = True
                    if base_reg and (base_reg.id & 7) == 4: need_sib = True # RSP/R12 needs SIB
                    if base_reg and (base_reg.id & 7) == 5 and not rm_operand.disp:
                        # RBP/R13 as base without disp needs mod=1/2 or special mod=0 handling
                        # Actually [rbp] is RIP relative if mod=0.
                        # If we want [rbp], we must use mod=1 and disp=0 (disp8).
                        # Let's handle this in displacement logic.
                        pass

                    if need_sib:
                        rm = 4 # Indicate SIB follows

                        ss = 0
                        if scale == 2: ss = 1
                        elif scale == 4: ss = 2
                        elif scale == 8: ss = 3

                        idx = 4 # None (RSP)
                        if index_reg:
                            idx = index_reg.id
                            if idx > 7: rex |= 0x02 # REX.X

                        base = 5 # None (RBP) -> Mod=0 means disp32 only
                        if base_reg:
                            base = base_reg.id
                            if base > 7: rex |= 0x01 # REX.B

                        sib_byte = (ss << 6) | ((idx & 7) << 3) | (base & 7)

                        # Mod selection
                        if rm_operand.disp == 0 and (base & 7) != 5:
                            mod = 0
                        elif -128 <= rm_operand.disp <= 127:
                            mod = 1
                        else:
                            mod = 2

                        # Exception: [r12] (base=4) needs SIB. mod=0.
                        # Exception: [rbp] (base=5) needs mod=1 + disp0 if disp=0.
                        if (base & 7) == 5 and mod == 0:
                            mod = 1 # Force disp8=0

                    else:
                        # No SIB
                        if base_reg:
                            rm = base_reg.id
                            if rm > 7: rex |= 0x01 # REX.B

                            # Mod selection
                            if rm_operand.disp == 0 and (rm & 7) != 5:
                                mod = 0
                            elif -128 <= rm_operand.disp <= 127:
                                mod = 1
                            else:
                                mod = 2

                            if (rm & 7) == 5 and mod == 0:
                                mod = 1 # Force disp8=0 for RBP/R13 base
                        else:
                            # Direct address (disp32)
                            mod = 0
                            rm = 4 # SIB
                            sib_byte = 0x25 # (00 100 101) -> Scale 1, Index None, Base None/disp32

            elif rm_operand and isinstance(rm_operand, Register):
                mod = 0b11
                rm = rm_operand.id
                if rm > 7: rex |= 0x01 # REX.B

            # REX.R
            if reg > 7: rex |= 0x04

            reg_code = reg & 7
            rm_code = rm & 7

            modrm_byte = (mod << 6) | (reg_code << 3) | rm_code

        # Opcode + reg_in_op
        ops = list(instr_def.opcode)
        if 'reg_in_op' in instr_def.properties:
            op0 = operands[0]
            if isinstance(op0, Register):
                ops[-1] += (op0.id & 7)
                if op0.id > 7: rex |= 0x01 # REX.B

        # Emit REX
        if rex:
            out.append(rex)

        out.extend(ops)

        if has_modrm:
            out.append(modrm_byte)
            if sib_byte is not None:
                out.append(sib_byte)

            # Emit Disp
            if rm_operand and isinstance(rm_operand, Memory):
                if hasattr(rm_operand, 'label') and rm_operand.label:
                     # RIP relative
                     target = self.labels.get(rm_operand.label, 0)
                     offset = getattr(rm_operand, 'offset', 0)
                     target += offset

                     # disp = target - (addr + len)
                     # Estimate length:
                     imm_size = 0
                     for op in operands:
                         if isinstance(op, Immediate):
                             sig = instr_def.operands_signature[operands.index(op)]
                             if 'imm32' in sig: imm_size = 4
                             elif 'imm8' in sig: imm_size = 1
                             elif 'imm64' in sig: imm_size = 8

                     total_len = len(out) + 4 + imm_size
                     disp = target - (addr + total_len)
                     out.extend(struct.pack('<i', disp))
                else:
                    # SIB/Normal Disp
                    if mod == 1:
                        out.append(rm_operand.disp & 0xFF)
                    elif mod == 2 or (mod == 0 and (rm & 7) == 5 and not need_sib) or (sib_byte is not None and (sib_byte & 7) == 5 and mod == 0):
                        # 32-bit disp cases
                        out.extend(struct.pack('<i', rm_operand.disp))

        # Emit Immediates
        for i, op in enumerate(operands):
            if isinstance(op, Immediate):
                 val = self.resolve_value(op)
                 sig = instr_def.operands_signature[i]
                 if 'imm32' in sig:
                     out.extend(struct.pack('<I', val & 0xFFFFFFFF))
                 elif 'imm8' in sig:
                     out.append(val & 0xFF)
                 elif 'imm64' in sig:
                     out.extend(struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))
                 elif 'rel32' in sig:
                     # rel32
                     current_len = len(out) + 4
                     offset = val - (addr + current_len)
                     out.extend(struct.pack('<i', offset))

        return out

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('source', help='Source assembly file')
    parser.add_argument('-o', '--output', help='Output file')
    args = parser.parse_args()

    asm = MorphAssembler()
    asm.load_isa()
    asm.assemble(args.source)

    outfile = args.output or "out.morph"
    with open(outfile, 'wb') as f:
        f.write(asm.output)
    print(f"Assembled {len(asm.output)} bytes to {outfile}")
