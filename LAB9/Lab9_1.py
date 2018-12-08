from pwn import *
import binascii

###Utils
def register(usr):
    r.sendlineafter('[>] ','register')
    r.sendlineafter('Username: ',usr)
    token = r.recvuntil('\n\n').strip().split(b' ')[2]
    return token

def login(token):
    r.sendlineafter('[>] ','login')
    r.sendlineafter('Token: ',token)
    r.interactive()


###Start Exploit
##Copy and paste
r = remote('csie.ctf.tw',10136)
r.sendlineafter('[1~3]: ','1')

##Get Token1 Block1
# Block1 'usr=aaaaa&admin='
# Block2 'N...P...        '
token1 = register('a'*5)

##Get Token2 Block2
# Block1 'usr=aaaaaaaaaaaa'
# Block2 'Yaaaaaaaaaaaaaaa'
# Block3 '&admin=N...P... '
# Notice the need to push &admin to next block because of assertion in problem
token2 = register('a'*12+'Y'+'a'*15)

##Get Token3 Block2
# Block1 'usr=aaaa&admin=N'
# Block2 '...P...         '
token3 = register('a'*4)

##Payload = T1B1 + T2B1 + T3B2
payload = token1[:32]+token2[32:64]+token3[32:64]

##Get flag
login(payload)
