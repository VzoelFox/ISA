# Technical Debt & Self-Hosting Status

Saat ini, `tools/asm.fox` berfungsi sebagai **seed assembler** yang mampu melakukan encoding instruksi dasar, namun **belum siap** untuk self-hosting penuh.

## Status Self-Hosting
- **Current:** Mampu mengkompilasi urutan instruksi linear, operand sederhana (register rendah, immediate), dan kontrol alur dasar (label & jump relative).
- **Target:** Mampu mengkompilasi source code `tools/asm.fox` itu sendiri.

## Hutang Teknis (Technical Debt)

### 1. Lexer & Parser (Prioritas Tinggi)
- **Directive Support:** Tidak mendukung direktif FASM standar seperti `format ELF64`, `entry`, `segment`, `rb`, `db`, `include`. Saat ini assembler hanya membaca token dan menganggapnya sebagai mnemonic instruksi.
- **Data Definitions:** Tidak bisa menghandle definisi data seperti `msg_usage db "..."` atau `rb`.

### 2. Instruction Encoder (Prioritas Menengah)
- **Register Support:** Hanya mendukung register `rax` - `rdi` (0-7). Register `r8` - `r15` belum didukung di `parse_register`.
- **Memory Operands:** Tidak mendukung operand memori dengan kurung siku `[rax]`. Seluruh logika saat ini mengasumsikan Register Direct addressing (ModRM Mod=11).
- **SIB Byte:** Tidak ada dukungan untuk Scale-Index-Base byte, yang diperlukan untuk addressing kompleks.

### 3. Error Handling & Safety
- **Bounds Checking:** Output buffer fix 1MB tanpa pengecekan batas (`output_ptr` bisa overflow).
- **Strict Syntax:** Pengecekan koma antar operand masih longgar/opsional di beberapa tempat.

### 4. TODOs & Stubs dalam Kode
- `tools/asm.fox`:
  - `TODO: Handle flags (REX.W, RegInOp)` - Flag ini dibaca tapi belum digunakan sepenuhnya untuk logic REX prefix.
  - `TODO: Check if it is comma` - Validasi token pemisah.
  - `parse_int`: Validasi digit masih TODO.
