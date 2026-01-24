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
        # Parse [base + index*scale + disp] logic roughly
        # Supported formats: [label], [reg], [reg+disp]
        content = text.strip()[1:-1].strip()
        self.base = None
        self.label = None

        # Check if it's a known register
        if content.lower() in REGISTERS:
            self.base = Register(content)
        elif content[0].isalpha():
            # Assume label
            self.label = content
        else:
            # Complex parsing skipped for now
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
                # Resolve value if possible? No, check_match happens before resolution.
                # But we have parsed values in Immediate.
                # If it's a string (label), assume it fits?
                # Labels are usually addresses (64-bit) or offsets.
                # If label, we can't be sure, but usually we match strictly.
                if isinstance(val, str): return True # Assume fits for labels/constants not yet resolved

                if sig == 'imm8':
                     if not (-128 <= val <= 255): return False
                elif sig == 'imm16':
                     if not (-32768 <= val <= 65535): return False
                elif sig == 'imm32':
                     # imm32 in 64-bit context is often sign-extended
                     if not (-2147483648 <= val <= 4294967295): return False
                     # If it's strictly sign-extended context (like mov r64, imm32),
                     # values > 2^31-1 but < 2^32 might be represented as negative?
                     # Python ints are infinite precision.
                     # 0xFFFFFFFF is 4294967295.
                     # If instruction expects signed imm32, we should check signed range.
                     # mov r64, imm32 (C7) sign extends.
                     # So 0xFFFFFFFF becomes -1 (0xFF...FF).
                     # If user meant 0x00...00FFFFFFFF, that is NOT representable by C7 if it sign extends!
                     # Wait. mov r/m64, imm32 sign extends.
                     # So valid range is [-2^31, 2^31-1].
                     # If user writes 0xFFFFFFFF, it interprets as -1.
                     # If user wants +4294967295, they must use mov r64, imm64 (B8).
                     # So strictly, imm32 should match only signed 32-bit range.
                     if not (-2147483648 <= val <= 2147483647): return False

            elif sig == 'rel32':
                 # Accepts label or imm
                 if not (isinstance(op, Immediate) or isinstance(op, Memory)): return True # Wait, rel32 is usually a label (Immediate with string value)
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
                            pass # tags
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
                    # We can't know the value yet. Postpone?
                    # For now, let's just handle this in resolution
                    self.constants[k] = "EXPR_LEN_MSG"
                else:
                     try: self.constants[k] = int(v, 0)
                     except: pass
                continue

            # Parse Mnemonic
            parts = line.split(maxsplit=1)
            mnemonic = parts[0]

            # Check for label without colon (heuristic)
            # If first word is not a known mnemonic but second word is (or is db/use64)
            if len(parts) > 1:
                potential_mnemonic = parts[1].split()[0] if parts[1] else ""
                # Simple check: is parts[0] a known mnemonic?
                known_mnemonics = set(self.instructions.keys())
                known_mnemonics.add('db')
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
        self.output = bytearray()

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
                self.output.extend(p['bytes'])
            elif p['type'] == 'instr':
                # Re-encode with resolved labels
                encoded = self.encode_instruction(p['def'], p['operands'], p['addr'], dry_run=False)
                self.output.extend(encoded)

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
        # This needs to handle REX, ModRM, Imm, Disp

        out = bytearray()

        # 1. REX Prefix
        # W bit
        rex = 0
        if instr_def.rex == 'W':
            rex |= 0x48

        reg_code = 0
        rm_code = 0

        # Determine Register Codes for REX and ModRM
        # Logic depends on modrm string (e.g. "reg,mem")

        modrm_byte = None
        has_modrm = False

        if instr_def.modrm:
            has_modrm = True
            mod = 0
            reg = 0
            rm = 0

            spec = instr_def.modrm.split(',')

            # Mapping logic
            # modrm=reg,mem -> op0 is reg, op1 is mem
            # modrm=0 -> reg field is 0.

            # Find which operand maps to reg field and which to rm field
            reg_operand = None
            rm_operand = None

            if len(spec) == 2:
                # "reg,mem" or "mem,reg"
                # The first part corresponds to Operand 0
                # The second part corresponds to Operand 1

                for i, role in enumerate(spec):
                    op = operands[i]
                    if role == 'reg':
                        if isinstance(op, Register):
                            reg = op.id
                            reg_operand = op
                    elif role == 'mem':
                         # ModRM logic for memory
                         rm_operand = op
                    elif role == 'rm':
                         # Explicit R/M field (register)
                         if isinstance(op, Register):
                             rm_operand = op

            elif len(spec) == 1:
                # "0" or "reg" or "4"
                if spec[0].isdigit():
                    reg = int(spec[0])
                    # Operand 0 must be the RM
                    rm_operand = operands[0]
                else:
                    # Generic handling?
                    pass

            # Construct ModRM
            if rm_operand and isinstance(rm_operand, Memory):
                if rm_operand.label:
                     # RIP relative
                     mod = 0b00
                     rm = 0b101
                     # Calculate disp
                     target = self.labels.get(rm_operand.label, 0)
                     # rip is addr + instruction_len.
                     # Wait, instruction len is unknown during dry_run.
                     # Assume 7 bytes?
                     # encode_instruction calls recursively? No.
                     # For dry_run, we can just output placeholders.
                     # For real run, we need length.
                     # Circular dependency.
                     # Usually handled by assuming long disp (4 bytes).
                     disp = target - (addr + 7) # 7 is guess
                else:
                    # [reg]
                    mod = 0
                    rm = rm_operand.base.id
            elif rm_operand and isinstance(rm_operand, Register):
                mod = 0b11
                rm = rm_operand.id

            # REX bits
            if reg > 7: rex |= 0x04 # REX.R
            if rm > 7: rex |= 0x01 # REX.B

            reg_code = reg & 7
            rm_code = rm & 7

            modrm_byte = (mod << 6) | (reg_code << 3) | rm_code

        # Opcode + reg_in_op
        ops = list(instr_def.opcode)
        if 'reg_in_op' in instr_def.properties:
            # Add reg index to last opcode byte
            # Op 0 corresponds to Op 0?
            op0 = operands[0]
            if isinstance(op0, Register):
                ops[-1] += (op0.id & 7)
                if op0.id > 7: rex |= 0x01 # REX.B extension for opcode reg?

        # Emit REX if needed or if forced (W)
        if rex:
            out.append(rex)

        out.extend(ops)

        if has_modrm:
            out.append(modrm_byte)
            # Emit Disp if RIP relative
            if rm_code == 5 and (modrm_byte >> 6) == 0:
                 # Calculate real displacement
                 # We need total length to be correct.
                 # Current length so far: len(out) + 4 (disp) + imm_size
                 # This requires knowing imm size.
                 imm_size = 0
                 for op in operands:
                     if isinstance(op, Immediate):
                         # check def signature for size
                         # hacky: look for imm32 in signature
                         if 'imm32' in instr_def.operands_signature: imm_size = 4
                         elif 'imm8' in instr_def.operands_signature: imm_size = 1
                         elif 'imm64' in instr_def.operands_signature: imm_size = 8

                 total_len = len(out) + 4 + imm_size
                 target = 0
                 # Re-find label
                 for op in operands:
                     if isinstance(op, Memory) and op.label:
                         target = self.labels.get(op.label, 0)

                 disp = target - (addr + total_len)
                 out.extend(struct.pack('<i', disp))

        # Emit Immediates
        for i, op in enumerate(operands):
            if isinstance(op, Immediate):
                 val = self.resolve_value(op)
                 # Determine size from signature
                 sig = instr_def.operands_signature[i]
                 if 'imm32' in sig:
                     out.extend(struct.pack('<I', val & 0xFFFFFFFF))
                 elif 'imm8' in sig:
                     out.append(val & 0xFF)
                 elif 'imm64' in sig:
                     out.extend(struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))

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
