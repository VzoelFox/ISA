#!/usr/bin/env python3
import os
import sys
import glob
import re
import struct

# Constants
BRAINLIB_DIR = "brainlib"

REGISTERS = {
    # 64-bit
    'rax': (0, 64), 'rcx': (1, 64), 'rdx': (2, 64), 'rbx': (3, 64), 'rsp': (4, 64), 'rbp': (5, 64), 'rsi': (6, 64), 'rdi': (7, 64),
    'r8': (8, 64), 'r9': (9, 64), 'r10': (10, 64), 'r11': (11, 64), 'r12': (12, 64), 'r13': (13, 64), 'r14': (14, 64), 'r15': (15, 64),
    # 32-bit
    'eax': (0, 32), 'ecx': (1, 32), 'edx': (2, 32), 'ebx': (3, 32), 'esp': (4, 32), 'ebp': (5, 32), 'esi': (6, 32), 'edi': (7, 32),
    'r8d': (8, 32), 'r9d': (9, 32), 'r10d': (10, 32), 'r11d': (11, 32), 'r12d': (12, 32), 'r13d': (13, 32), 'r14d': (14, 32), 'r15d': (15, 32),
    # 16-bit
    'ax': (0, 16), 'cx': (1, 16), 'dx': (2, 16), 'bx': (3, 16), 'sp': (4, 16), 'bp': (5, 16), 'si': (6, 16), 'di': (7, 16),
    'r8w': (8, 16), 'r9w': (9, 16), 'r10w': (10, 16), 'r11w': (11, 16), 'r12w': (12, 16), 'r13w': (13, 16), 'r14w': (14, 16), 'r15w': (15, 16),
    # 8-bit (Low)
    'al': (0, 8), 'cl': (1, 8), 'dl': (2, 8), 'bl': (3, 8), 'spl': (4, 8), 'bpl': (5, 8), 'sil': (6, 8), 'dil': (7, 8),
    'r8b': (8, 8), 'r9b': (9, 8), 'r10b': (10, 8), 'r11b': (11, 8), 'r12b': (12, 8), 'r13b': (13, 8), 'r14b': (14, 8), 'r15b': (15, 8),
    # 8-bit (High) - Not supporting AH/CH/DH/BH for simplicity/modern use
}
# XMM registers
for i in range(16):
    REGISTERS[f'xmm{i}'] = (i, 128)

class Operand:
    def __init__(self, raw):
        self.raw = raw
    def __repr__(self): return self.raw

class Register(Operand):
    def __init__(self, name):
        super().__init__(name)
        self.name = name.lower()
        if self.name in REGISTERS:
            self.id, self.width = REGISTERS[self.name]
            self.is_xmm = self.width == 128
        else:
            # Fallback
            self.id = 0
            self.width = 64
            self.is_xmm = False

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
        # Also handle size prefix: "byte [rax]", "qword ptr [rax]"

        # Check prefixes
        self.width_prefix = None # 8, 16, 32, 64

        clean_text = text.strip()

        # Simple heuristic for prefix
        if ' ' in clean_text and '[' in clean_text:
            # might have prefix
            pre_bracket = clean_text.split('[')[0].lower()
            if 'byte' in pre_bracket: self.width_prefix = 8
            elif 'word' in pre_bracket and 'dword' not in pre_bracket and 'qword' not in pre_bracket: self.width_prefix = 16
            elif 'dword' in pre_bracket: self.width_prefix = 32
            elif 'qword' in pre_bracket: self.width_prefix = 64

            # Extract content inside brackets
            start = clean_text.find('[')
            end = clean_text.rfind(']')
            if start != -1 and end != -1:
                content = clean_text[start+1:end].strip()
            else:
                content = clean_text
        elif clean_text.startswith('[') and clean_text.endswith(']'):
            content = clean_text[1:-1].strip()
        else:
            content = clean_text

        self.base = None
        self.index = None
        self.scale = 0
        self.disp = 0
        self.label = None
        self.offset = 0

        parts = [p.strip() for p in content.split('+')]

        for p in parts:
            if '*' in p:
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
                if not isinstance(op, Register) or op.width != 64: return False
            elif sig == 'r32':
                if not isinstance(op, Register) or op.width != 32: return False
            elif sig == 'r16':
                if not isinstance(op, Register) or op.width != 16: return False
            elif sig == 'r8':
                if not isinstance(op, Register) or op.width != 8: return False
            elif sig == 'mem':
                if not isinstance(op, Memory): return False
            elif sig.startswith('imm'):
                if not isinstance(op, Immediate): return False
                val = op.value
                if isinstance(val, str): return True

                if sig == 'imm8':
                     if not (-128 <= val <= 255): return False
                elif sig == 'imm16':
                     if not (-32768 <= val <= 65535): return False
                elif sig == 'imm32':
                     if not (-2147483648 <= val <= 4294967295): return False # Allow unsigned 32
            elif sig == 'rel32':
                 if isinstance(op, Register): return False
                 pass
        return True

class MorphAssembler:
    def __init__(self):
        self.instructions = {}
        self.constants = {}
        self.labels = {}
        self.output = bytearray()
        self.relocations = []
        self.output_format = 'bin'
        self.entry_point = None
        self.parsed_instructions = []
        self.current_addr = 0
        self.base_addr = 0

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
                            props[part] = True
                    instr = InstructionDef(mnemonic, props)
                    base = instr.base_mnemonic
                    if base not in self.instructions: self.instructions[base] = []
                    self.instructions[base].append(instr)

    def parse_operand(self, op_str):
        op_str = op_str.strip()
        if not op_str: return None

        if (op_str.startswith("'") and op_str.endswith("'")) or \
           (op_str.startswith('"') and op_str.endswith('"')):
            return Immediate(op_str)

        if '[' in op_str or 'byte' in op_str.lower() or 'ptr' in op_str.lower():
            return Memory(op_str)
        if op_str.lower() in REGISTERS:
            return Register(op_str)
        return Immediate(op_str)

    def process_file(self, filepath):
        # Resolve path
        if not os.path.exists(filepath):
            # Try relative to tools/ or root
            if os.path.exists(os.path.join("tools", filepath)):
                filepath = os.path.join("tools", filepath)
            elif os.path.exists(os.path.join("brainlib", filepath)):
                filepath = os.path.join("brainlib", filepath)

        with open(filepath, 'r') as f:
            lines = f.readlines()

        # Keep track of file path for includes relative to it?
        # For simplicity, all includes are relative to CWD or known dirs

        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'): continue
            if ';' in line: line = line.split(';')[0].strip()

            if line.endswith(':'):
                label_name = line[:-1]
                self.labels[label_name] = self.current_addr
                continue

            if '=' in line:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                if v == '$ - msg':
                    self.constants[k] = "EXPR_LEN_MSG"
                else:
                     try: self.constants[k] = int(v, 0)
                     except: pass
                continue

            parts = line.split(maxsplit=1)
            mnemonic = parts[0]

            if mnemonic == 'format':
                fmt = parts[1] if len(parts) > 1 else ""
                if fmt.startswith('ELF64'):
                    self.output_format = 'elf64'
                    self.base_addr = 0x400000
                    self.current_addr = self.base_addr + 120
                continue

            if mnemonic == 'entry':
                self.entry_point = parts[1].strip()
                continue

            if mnemonic == 'include':
                # Recursive parsing
                inc_path = parts[1].strip()
                if inc_path.startswith("'") or inc_path.startswith('"'):
                    inc_path = inc_path[1:-1]

                # Check relative to current file's dir?
                # The prompt said include '../brainlib/vzoel_table.fox'
                # So it's relative.
                base_dir = os.path.dirname(filepath)
                full_inc_path = os.path.join(base_dir, inc_path)

                print(f"Including {full_inc_path}")
                self.process_file(full_inc_path)
                continue

            if mnemonic == 'segment':
                continue

            # Heuristic for label without colon (like in FASM: 'start:')
            # But here we handle 'label instr'
            if len(parts) > 1:
                potential_mnemonic = parts[1].split()[0] if parts[1] else ""
                known_mnemonics = set(self.instructions.keys())
                known_mnemonics.update(['db', 'dw', 'dd', 'dq', 'rb', 'use64'])

                if mnemonic not in known_mnemonics and (potential_mnemonic in known_mnemonics or '=' in line):
                     label_name = mnemonic
                     if label_name.endswith(':'): label_name = label_name[:-1]
                     self.labels[label_name] = self.current_addr
                     line = line[len(label_name)+ (1 if mnemonic.endswith(':') else 0):].strip()
                     if not line: continue
                     parts = line.split(maxsplit=1)
                     mnemonic = parts[0]

            operands_str = parts[1] if len(parts) > 1 else ""

            if mnemonic in ['db', 'dw', 'dd', 'dq']:
                raw_parts = operands_str.split(',')
                width = {'db': 1, 'dw': 2, 'dd': 4, 'dq': 8}[mnemonic]
                pack_fmt = {'db': 'B', 'dw': '<H', 'dd': '<I', 'dq': '<Q'}[mnemonic]

                current_bytes = bytearray()

                for p in raw_parts:
                    p = p.strip()
                    if not p: continue

                    is_str = p.startswith("'") or p.startswith('"')
                    is_int = False
                    val = 0

                    if is_str:
                         s = p[1:-1]
                         b = s.encode('utf-8')
                         if mnemonic == 'db':
                             current_bytes.extend(b)
                         else:
                             # For dw/dd/dq with string, maybe packed? Ignore for now or error.
                             pass
                         continue

                    try:
                        val = int(p, 0)
                        is_int = True
                    except:
                        is_int = False

                    if is_int:
                        if width == 1: current_bytes.append(val & 0xFF)
                        else: current_bytes.extend(struct.pack(pack_fmt, val & ((1<<(width*8))-1)))
                    else:
                        # It is a label/symbol reference
                        # Flush current bytes first
                        if len(current_bytes) > 0:
                            self.parsed_instructions.append({
                                'type': 'data',
                                'bytes': current_bytes,
                                'addr': self.current_addr
                            })
                            self.current_addr += len(current_bytes)
                            current_bytes = bytearray()

                        # Add data reference
                        self.parsed_instructions.append({
                            'type': 'data_ref',
                            'label': p,
                            'width': width,
                            'addr': self.current_addr
                        })
                        self.current_addr += width

                # Flush remaining
                if len(current_bytes) > 0:
                    self.parsed_instructions.append({
                        'type': 'data',
                        'bytes': current_bytes,
                        'addr': self.current_addr
                    })
                    self.current_addr += len(current_bytes)
                continue

            if mnemonic == 'use64': continue

            if mnemonic == 'rb':
                count_str = operands_str.strip()
                count = 0
                try:
                    count = int(count_str, 0)
                except:
                    print(f"Warning: could not parse rb count {count_str}")

                if count > 0:
                    self.parsed_instructions.append({
                        'type': 'data',
                        'bytes': bytearray(count),
                        'addr': self.current_addr
                    })
                    self.current_addr += count
                continue

            if mnemonic == 'align':
                try:
                    align_val = int(operands_str.strip(), 0)
                    if align_val > 0:
                        rem = self.current_addr % align_val
                        if rem > 0:
                            pad = align_val - rem
                            self.parsed_instructions.append({
                                'type': 'data',
                                'bytes': bytearray(pad), # Zeros
                                'addr': self.current_addr
                            })
                            self.current_addr += pad
                except:
                    print(f"Warning: invalid align value {operands_str}")
                continue

            # Handle Prefixes
            if mnemonic in ['rep', 'repe', 'repz', 'repne', 'repnz', 'lock']:
                prefix_map = {'rep': 0xF3, 'repe': 0xF3, 'repz': 0xF3,
                              'repne': 0xF2, 'repnz': 0xF2, 'lock': 0xF0}
                val = prefix_map[mnemonic]
                self.parsed_instructions.append({
                    'type': 'data',
                    'bytes': bytearray([val]),
                    'addr': self.current_addr
                })
                self.current_addr += 1

                # Parse remainder as new instruction
                if operands_str:
                    line = operands_str
                    parts = line.split(maxsplit=1)
                    mnemonic = parts[0]
                    operands_str = parts[1] if len(parts) > 1 else ""
                else:
                    continue

            operands = []
            if operands_str:
                ops_raw = self.split_operands(operands_str)
                for r in ops_raw:
                    operands.append(self.parse_operand(r))

            candidates = self.instructions.get(mnemonic, [])
            match = None
            for cand in candidates:
                if cand.check_match(operands):
                    match = cand
                    break

            if not match:
                # Fallback: Try with 8-bit/32-bit signature logic or error
                print(f"Error: No matching instruction for {line}")
                continue

            self.parsed_instructions.append({
                'type': 'instr',
                'def': match,
                'operands': operands,
                'addr': self.current_addr
            })

            encoded = self.encode_instruction(match, operands, self.current_addr, dry_run=True)
            size = len(encoded)
            self.parsed_instructions[-1]['size'] = size
            self.current_addr += size

    def assemble(self, filepath):
        # Pass 1
        self.process_file(filepath)

        # Pass 2
        code_output = bytearray()

        # Patch constant EXPR_LEN_MSG hack
        if 'EXPR_LEN_MSG' in self.constants.values():
             pass

        for p in self.parsed_instructions:
            if p['type'] == 'data':
                code_output.extend(p['bytes'])
            elif p['type'] == 'data_ref':
                val = self.labels.get(p['label'], 0)
                pack_fmt = {1: 'B', 2: '<H', 4: '<I', 8: '<Q'}[p['width']]
                code_output.extend(struct.pack(pack_fmt, val & ((1<<(p['width']*8))-1)))
            elif p['type'] == 'instr':
                encoded = self.encode_instruction(p['def'], p['operands'], p['addr'], dry_run=False)
                code_output.extend(encoded)

        if self.output_format == 'elf64':
            self.output = self.create_elf_header(code_output, self.base_addr)
        else:
            self.output = code_output

    def split_operands(self, s):
        res = []
        current = []
        in_quote = False
        quote_char = None

        for c in s:
            if in_quote:
                current.append(c)
                if c == quote_char:
                    in_quote = False
                    quote_char = None
            else:
                if c == '"' or c == "'":
                    in_quote = True
                    quote_char = c
                    current.append(c)
                elif c == ',':
                    res.append("".join(current).strip())
                    current = []
                else:
                    current.append(c)
        if current:
            res.append("".join(current).strip())
        return res

    def create_elf_header(self, code, base_addr):
        entry_addr = self.labels.get(self.entry_point, base_addr + 120) if self.entry_point else (base_addr + 120)
        elf_header = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH',
            b'\x7fELF', 2, 1, 1, 0, 0, 2, 0x3E, 1,
            entry_addr, 64, 0, 0, 64, 56, 1, 0, 0, 0
        )
        file_size = 120 + len(code)
        mem_size = file_size
        phdr = struct.pack('<2I6Q',
            1, 7, 0, base_addr, base_addr, file_size, mem_size, 0x1000
        )
        return elf_header + phdr + code

    def resolve_value(self, op):
        if isinstance(op, Immediate):
            if isinstance(op.value, str):
                if op.value in self.constants:
                    val = self.constants[op.value]
                    if val == "EXPR_LEN_MSG": return 33
                    return val
                if op.value in self.labels:
                    return self.labels[op.value]
                return 0
            return op.value
        return 0

    def encode_instruction(self, instr_def, operands, addr, dry_run=False):
        out = bytearray()
        rex = 0
        if instr_def.rex == 'W': rex |= 0x48

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
            reg_operand = None
            rm_operand = None

            if len(spec) == 2:
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
                if spec[0].isdigit():
                    reg = int(spec[0])
                    rm_operand = operands[0]
                else:
                    pass

            if rm_operand and isinstance(rm_operand, Memory):
                if hasattr(rm_operand, 'label') and rm_operand.label:
                     mod = 0b00
                     rm = 0b101
                else:
                    base_reg = rm_operand.base
                    index_reg = rm_operand.index
                    scale = rm_operand.scale
                    need_sib = False
                    if index_reg: need_sib = True
                    if base_reg and (base_reg.id & 7) == 4: need_sib = True

                    if need_sib:
                        rm = 4
                        ss = {1:0, 2:1, 4:2, 8:3}.get(scale, 0)
                        idx = 4
                        if index_reg:
                            idx = index_reg.id
                            if idx > 7: rex |= 0x02
                        base = 5
                        if base_reg:
                            base = base_reg.id
                            if base > 7: rex |= 0x01
                        sib_byte = (ss << 6) | ((idx & 7) << 3) | (base & 7)

                        if rm_operand.disp == 0 and (base & 7) != 5: mod = 0
                        elif -128 <= rm_operand.disp <= 127: mod = 1
                        else: mod = 2
                        if (base & 7) == 5 and mod == 0: mod = 1
                    else:
                        if base_reg:
                            rm = base_reg.id
                            if rm > 7: rex |= 0x01
                            if rm_operand.disp == 0 and (rm & 7) != 5: mod = 0
                            elif -128 <= rm_operand.disp <= 127: mod = 1
                            else: mod = 2
                            if (rm & 7) == 5 and mod == 0: mod = 1
                        else:
                            mod = 0
                            rm = 4
                            sib_byte = 0x25

            elif rm_operand and isinstance(rm_operand, Register):
                mod = 0b11
                rm = rm_operand.id
                if rm > 7: rex |= 0x01

            if reg > 7: rex |= 0x04
            reg_code = reg & 7
            rm_code = rm & 7
            modrm_byte = (mod << 6) | (reg_code << 3) | rm_code

        ops = list(instr_def.opcode)
        if 'reg_in_op' in instr_def.properties:
            op0 = operands[0]
            if isinstance(op0, Register):
                ops[-1] += (op0.id & 7)
                if op0.id > 7: rex |= 0x01

        if rex: out.append(rex)
        out.extend(ops)

        if has_modrm:
            is_label = False
            if rm_operand and isinstance(rm_operand, Memory) and hasattr(rm_operand, 'label') and rm_operand.label:
                is_label = True

            if not is_label:
                out.append(modrm_byte)
                if sib_byte is not None:
                    out.append(sib_byte)

            if rm_operand and isinstance(rm_operand, Memory):
                if hasattr(rm_operand, 'label') and rm_operand.label:
                     target = self.labels.get(rm_operand.label, 0)
                     offset = getattr(rm_operand, 'offset', 0)
                     target += offset

                     if rm_operand.index:
                         # Cannot use RIP relative with Index. Use Absolute SIB.
                         # Mod=00, RM=4 (SIB), Base=5 (None) -> Disp32
                         mod = 0
                         rm = 4

                         ss = {1:0, 2:1, 4:2, 8:3}.get(rm_operand.scale, 0)
                         idx = rm_operand.index.id
                         if idx > 7: rex |= 0x02
                         base = 5

                         sib_byte = (ss << 6) | ((idx & 7) << 3) | (base & 7)

                         # Re-construct ModRM since we changed strategy
                         if reg > 7: rex |= 0x04
                         reg_code = reg & 7
                         modrm_byte = (mod << 6) | (reg_code << 3) | rm

                         out.append(modrm_byte)
                         out.append(sib_byte)
                         out.extend(struct.pack('<I', target & 0xFFFFFFFF))

                     else:
                         # RIP relative
                         mod = 0b00
                         rm = 0b101

                         if reg > 7: rex |= 0x04
                         reg_code = reg & 7
                         modrm_byte = (mod << 6) | (reg_code << 3) | (rm & 7)
                         out.append(modrm_byte)

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
                    if sib_byte is not None: out.append(sib_byte)

                    if mod == 1:
                        out.append(rm_operand.disp & 0xFF)
                    elif mod == 2 or (mod == 0 and (rm & 7) == 5 and not need_sib) or (sib_byte is not None and (sib_byte & 7) == 5 and mod == 0):
                        out.extend(struct.pack('<i', rm_operand.disp))

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
