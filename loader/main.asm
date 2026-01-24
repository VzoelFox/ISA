format ELF64 executable 3
entry start

segment readable executable

start:
    ; Check command line arguments
    pop rcx             ; argc
    cmp rcx, 2
    jl usage            ; If argc < 2, show usage

    pop rdi             ; argv[0] (program name)
    pop rdi             ; argv[1] (target file path)
    mov [filename], rdi

    ; Open file
    mov rax, 2          ; sys_open
    mov rdi, [filename]
    mov rsi, 0          ; O_RDONLY
    mov rdx, 0
    syscall

    cmp rax, 0
    jl error_open
    mov [fd], rax

    ; Get file size (fstat)
    mov rax, 5          ; sys_fstat
    mov rdi, [fd]
    lea rsi, [stat_buf]
    syscall

    cmp rax, 0
    jl error_read

    mov rax, qword [stat_buf + 48] ; st_size is at offset 48 in 'struct stat' on Linux x86_64
    mov [filesize], rax

    ; Mmap memory (PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS)
    mov rax, 9          ; sys_mmap
    mov rdi, 0          ; addr = NULL
    mov rsi, [filesize] ; len
    mov rdx, 7          ; prot = RWX (Read=1, Write=2, Exec=4)
    mov r10, 34         ; flags = MAP_PRIVATE (2) | MAP_ANONYMOUS (32)
    mov r8, -1          ; fd = -1
    mov r9, 0           ; offset = 0
    syscall

    cmp rax, -1
    je error_mmap
    mov [mem_addr], rax

    ; Read file content into memory
    mov rax, 0          ; sys_read
    mov rdi, [fd]
    mov rsi, [mem_addr]
    mov rdx, [filesize]
    syscall

    cmp rax, 0
    jl error_read

    ; Close file
    mov rax, 3          ; sys_close
    mov rdi, [fd]
    syscall

    ; Verify Magic Header "VZOELFOX"
    mov rsi, [mem_addr]
    mov rax, [rsi]      ; Load first 8 bytes
    mov rbx, 0x584F464C454F5A56 ; "VZOELFOX" in little-endian
    cmp rax, rbx
    jne error_magic

    ; Calculate Entry Point (Skip Header 8 bytes + Platform ID 1 byte? Let's assume header is strictly just magic for now + platform info)
    ; User said: "header binary VZOELFOX (8byte)" and "loader hanya membaca platform header diawal"
    ; Let's assume structure: [8 bytes MAGIC] [Platform Data...] [Code...]
    ; For now, let's jump to offset 16 (8 magic + 8 reserved/platform) to be safe, or just 8.
    ; Let's print a message first.

    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_run]
    mov rdx, msg_run_len
    syscall

    ; Jump to code
    ; IMPORTANT: The file contains RAW code.
    ; We skip the header (let's say 16 bytes to allow for platform ID extensions).

    mov rax, [mem_addr]
    add rax, 16         ; Skip 16 bytes header
    call rax            ; Transfer control

    ; Exit loader
    mov rax, 60         ; sys_exit
    xor rdi, rdi
    syscall

usage:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_usage]
    mov rdx, msg_usage_len
    syscall
    jmp exit_err

error_open:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_err_open]
    mov rdx, msg_err_open_len
    syscall
    jmp exit_err

error_magic:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_err_magic]
    mov rdx, msg_err_magic_len
    syscall
    jmp exit_err

error_mmap:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_err_mmap]
    mov rdx, msg_err_mmap_len
    syscall
    jmp exit_err

error_read:
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_err_read]
    mov rdx, msg_err_read_len
    syscall
    jmp exit_err

exit_err:
    mov rax, 60
    mov rdi, 1
    syscall

segment readable writable

fd dq 0
filename dq 0
filesize dq 0
mem_addr dq 0

stat_buf rb 144 ; struct stat buffer

msg_usage db "Usage: ./fox-loader <file.morph>", 10
msg_usage_len = $ - msg_usage

msg_run db "[FoxLoader] Header verified. Executing payload...", 10
msg_run_len = $ - msg_run

msg_err_open db "Error: Could not open file.", 10
msg_err_open_len = $ - msg_err_open

msg_err_read db "Error: Could not read file.", 10
msg_err_read_len = $ - msg_err_read

msg_err_mmap db "Error: mmap failed.", 10
msg_err_mmap_len = $ - msg_err_mmap

msg_err_magic db "Error: Invalid VZOELFOX header!", 10
msg_err_magic_len = $ - msg_err_magic
