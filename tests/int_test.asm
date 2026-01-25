format ELF64 executable
entry start

segment readable writeable

start:
    ; Test Decimal
    mov rax, 123

    ; Test Negative
    mov rbx, -456

    ; Test Hexadecimal (0x format)
    mov rcx, 0xA1

    ; Test Hexadecimal (0x format with lowercase)
    mov rdx, 0xff

    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall
