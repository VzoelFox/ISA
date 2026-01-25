format ELF64 executable
entry start

segment readable writeable

start:
    ; Test String with space
    db "Hello World"
    db 0

    ; Test String with quotes
    db 'String with single quotes'
    db 0

    mov rax, 60
    xor rdi, rdi
    syscall
