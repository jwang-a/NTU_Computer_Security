from pwn import *
import binascii

###Utils
def pad(s):
    p = 16 - len(s) % 16
    return s + bytes([p] * p)

def submit(msg1,msg2):
    r.sendlineafter('(hex):',msg1)
    r.sendlineafter('(hex):',msg2)

###Start Exploit
## CBC-MAC in this problem is same as appending block of \x00 after padding msg
## MAC(m1||pad||0*16||m2[0]^MAC1||m2[1:]) == 
## MAC(m2||pad||0*16||m2[0]^MAC2||m2[1:])

r = remote('csie.ctf.tw',10136)
r.sendlineafter('[1~3]: ','2')

# Generate original blocks
msg1 = b'a'*16
msg2 = b'b'*16

# Get MAC of original blocks
submit(binascii.hexlify(msg1).decode('utf-8'),binascii.hexlify(msg2).decode('utf-8'))
mac = r.recvuntil('\n\n').strip().decode('utf-8').split(': ')[1].split(' != ')

# Generate hacked blocks with same MAC
msg3 = binascii.hexlify(pad(msg1)+b'\x00'*16).decode('utf-8')+hex(int(binascii.hexlify(msg2),16)^int(mac[0],16))[2:].rjust(32,'0')
msg4 = binascii.hexlify(pad(msg2)+b'\x00'*16).decode('utf-8')+hex(int(binascii.hexlify(msg2),16)^int(mac[1],16))[2:].rjust(32,'0')

# Get flag
submit(msg3,msg4)
r.interactive()
