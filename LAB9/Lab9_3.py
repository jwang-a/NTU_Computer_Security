from pwn import *
import binascii
import MD5_gen  ##Self modified tool

###Utils
def register(usr):
    r.sendlineafter('[>] ','register')
    r.sendlineafter('(hex): ',usr)
    token = r.recvuntil('\n\n').strip().split(b': ')[1]
    iv = token[:32]
    aes = token[32:]
    return iv,aes

def login(usr):
    r.sendlineafter('[>] ','login')
    r.sendlineafter('Token: ',usr)
    r.interactive()


###Start Exploit
## Tips: MD5 is merkle-damgard, so if H(A) = H(B), H(A||C) = H(B||C)
## Tips: MD5 collision for arbitrary IV can be cracked within minutes
##       Meaning that a prefix of N*(block_size) can be set beforehand'
## Tips: A,B,C,D of md5 != digest, since a padding scheme is present in digest
## Tips: CTR mode encryption is plain XOR if IV is leaked
## Additional : Padding of md5 is interesting >>
##              Step1 : a single bit 1 is added
##              Step2 : bit 0s are added until bit_len(msg)%512=448
##              Step3 : bit_len(orig_msg)%2^64 in small endian style is appended

r = remote('csie.ctf.tw',10136)
r.sendlineafter('[1~3]: ','3')

prefix = b'Crypto is fun'.ljust(64,b'\x00')
## Prefix md5 state 0x48ae556f 0x726bcb6f 0xcdab3441 0xdd31074a
B = MD5_gen.MD5(prefix)
print(B.get_state())

## Find md5 collision with md5-tunneling
usr1 = '6F9C5091DF7A8D00FDC70C0553E0460D1622214BFC3D20CDC98EE7883B878F2ED56C3405099CF4625FE26A72534F2913AE7C7214EDD57A608AAB34EAE1FC8B67BA7B13B269FFF5E5A4E22F6D6FB37FFDD1936EC59B53CC0C24C9E586CC963DDD45683BBC9F9007A68669DD298C64761DCED0D9B37BA20B5166BCB8DD65919C89'

usr2 = '6F9C5091DF7A8D00FDC70C0553E0460D162221CBFC3D20CDC98EE7883B878F2ED56C3405099CF4625FE26A7253CF2913AE7C7214EDD57A608AAB346AE1FC8B67BA7B13B269FFF5E5A4E22F6D6FB37FFDD1936E459B53CC0C24C9E586CC963DDD45683BBC9F9007A68669DD298CE4751DCED0D9B37BA20B5166BCB85D65919C89'

## Pad usr1/usr2 with pad of prefix
usr1 = '00'*51+usr1
usr2 = '00'*51+usr2

## Generate aes of usr2
iv, aes= register(usr1)
aes2 = hex(int(aes[:358],16)^int(usr1,16)^int(usr2,16))[2:].rjust(358,'0').encode('utf-8')+aes[358:]

## get flag
token2 = iv+aes2
login(token2)
