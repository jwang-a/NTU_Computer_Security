from pwn import *
import binascii

###Utils
def login(usr,pwd):
    r.sendlineafter('[>]','l')
    r.sendlineafter(': ',usr)
    r.sendlineafter(': ',pwd)
    token = r.recvuntil('\n\n').strip().decode('utf-8').split(': ')[1].split('\n')[0]
    print(len(token))
    return token

def verify(token,vc):
    r.sendlineafter('[>]','v')
    r.sendlineafter(': ',token)
    r.sendlineafter(': ',vc)
    r.interactive()


###Start exploint
## This solution utilizes msgpack format
## The packed message for this usr and password would be
##   b'\x83\xa3usr\xa5aaaaa\xa3pwd\xbcaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xa2vc\xda\x00(' + [40 bytes of vc]
##   notice that b'\xa2vc\xda' is located at the end of the third block
##   by setting b'\xda' to b'\xa0', we can set the length of vc to 0
##   this can be done by messing with the last byte of the previous(second) block
##   cropping the rest of the message results in a valid packed data with vc=''

r = remote('csie.ctf.tw',10138)

## set payload to let b'\xa2vc\xda' be at the end of a specific block
## length os usr is set such that a corrupted second block would not affect validity of packed data
usr = b'a'*5
pwd = b'a'*28

## get token
token = login(usr,pwd)

## crop token to leave only the first three blocks
token2 = bytes.fromhex(token)[:48]

## alter last byte of second block to set b'\xda' to b'\xa0'
token2 = list(token2)
token2[31] = token2[31]^0xda^0xa0
token2 = binascii.hexlify(bytes(token2))

## get flag
vc = ''
verify(token2,vc)
