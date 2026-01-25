# Technical Debt & Self-Hosting Status

Saat ini, `tools/asm.fox` berfungsi sebagai **seed assembler** yang mampu melakukan encoding instruksi dasar dan menengah, kontrol alur, addressing memori lengkap (Direct, SIB untuk Stack, Displacement).

## Status Self-Hosting
- **Current:** Mampu mengkompilasi urutan instruksi linear, operand sederhana & memori (termasuk displacement), register r8-r15, kontrol alur (label & jump relative), definisi data (`db`, `rb`).
- **Target:** Mampu mengkompilasi source code `tools/asm.fox` itu sendiri.

## Hutang Teknis (Technical Debt)

### 1. Lexer & Parser (Prioritas Menengah)
- **Complex Directives:** Direktif kompleks seperti makro atau struktur `segment` yang detail belum didukung penuh (hanya parsing dasar untuk skip token).
- **String Parsing:** Lexer string masih primitif (tidak support escape characters, space dalam string mungkin bermasalah dengan tokenizer saat ini).

### 2. Instruction Encoder (Prioritas Rendah)
- **Full SIB Support:** SIB byte saat ini support base RSP/R12. Belum support parsing custom index/scale (misal `[rax + rbx*4]`).

### 3. Error Handling & Safety
- **Bounds Checking:** Output buffer fix 1MB tanpa pengecekan batas (`output_ptr` bisa overflow).
- **Strict Syntax:** Pengecekan koma antar operand masih longgar/opsional di beberapa tempat.

### 4. TODOs & Stubs dalam Kode
- `tools/asm.fox`:
  - `parse_int`: Validasi digit dan support hex/octal masih belum ada.
