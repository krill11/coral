[org 0x7c00]
[bits 16]

; Clear the screen
mov ah, 0x00
mov al, 0x03
int 0x10

; Print welcome message
mov si, welcome_msg
call print_string

; Load kernel
mov ah, 0x02    ; BIOS read sector function
mov al, 15      ; Number of sectors to read
mov ch, 0       ; Cylinder number
mov cl, 2       ; Sector number (1 is boot sector)
mov dh, 0       ; Head number
mov dl, 0x80    ; Drive number (0x80 for first hard disk)
mov bx, 0x1000  ; Load to this address
int 0x13        ; BIOS interrupt
jc disk_error   ; Jump if error (carry flag set)

; Jump to kernel
jmp 0x1000

disk_error:
    mov si, disk_error_msg
    call print_string
    jmp $

print_string:
    mov ah, 0x0e    ; BIOS teletype output
.loop:
    lodsb           ; Load next character
    or al, al       ; Check if character is 0 (end of string)
    jz .done        ; If zero, we're done
    int 0x10        ; Print character
    jmp .loop       ; Repeat for next character
.done:
    ret

welcome_msg db 'Welcome to CoralOS!', 0x0D, 0x0A, 0
disk_error_msg db 'Error loading kernel!', 0x0D, 0x0A, 0

times 510-($-$$) db 0   ; Pad with zeros
dw 0xaa55              ; Boot signature 