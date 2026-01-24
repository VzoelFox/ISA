# Morph

A self-hosting x86-64 assembly environment.

## Quick Start

### 1. Build the Loader
Use the bootstrap Python assembler to build the native loader.

```bash
python3 tools/morph-asm.py loader/loader.fox -o loader/fox-loader-v2
chmod +x loader/fox-loader-v2
```

### 2. Assemble a Program
Assemble an example program into a raw `.morph` binary.

```bash
python3 tools/morph-asm.py examples/hello.asm -o examples/hello.morph
```

### 3. Run
Use the loader to execute the binary.

```bash
./loader/fox-loader-v2 examples/hello.morph
```

## Structure

-   `brainlib/`: Instruction Set Architecture (ISA) definitions.
-   `loader/`: Source code for the Morph loader (`loader.fox`).
-   `tools/`: Assembler tools (`morph-asm.py` and WIP `asm.fox`).
-   `examples/`: Example assembly programs.

## Development

To work on the native assembler (`tools/asm.fox`):

```bash
python3 tools/gen_isa_table.py  # Regenerate ISA tables
python3 tools/morph-asm.py tools/asm.fox -o tools/morph-asm
```
