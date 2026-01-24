use64

; Header VZOELFOX (8 bytes)
db 'VZOELFOX'

; Platform ID / Reserved (8 bytes) to match Loader offset 16
db 1, 0, 0, 0, 0, 0, 0, 0

; Code start
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    lea rsi, [msg]      ; RIP-relative addressing works because we are raw binary
    mov rdx, msg_len
    syscall

    ret                 ; Return to loader (since we used CALL in loader)

msg db "Hello from .morph native binary!", 10
msg_len = $ - msg
