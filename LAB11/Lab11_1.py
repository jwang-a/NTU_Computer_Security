from hashlib import sha256
from Crypto.PublicKey import DSA
from Crypto.Util.number import *
from pwn import *
import binascii

def get_key():
    sig = r.recvuntil('[>]').strip().decode('utf-8').split('\n')
    P = int(sig[0].split(': ')[1])
    Q = int(sig[1].split(': ')[1])
    G = int(sig[2].split(': ')[1])
    Y = int(sig[3].split(': ')[1])
    return P,Q,G,Y

def sign(msg):
    r.sendlineafter('Command: ','sign')
    r.sendlineafter('Message: ',hex(msg)[2:])
    sig = r.recvuntil('\n\n').strip().decode('utf-8').split('\n')
    R = int(sig[0].split(': ')[1])
    S = int(sig[1].split(': ')[1])
    return R,S

def verify(R,S):
    r.sendlineafter('Command: ','flag')
    r.sendlineafter('r: ',str(R))
    r.sendlineafter('s: ',str(S))
    r.interactive()

def digest(s):
    return sha256(long_to_bytes(s)).digest()

def gcd(a,b):
    while a!=0:
        a,b = b%a,a
    return b

def findModReverse(a,m):
    if gcd(a,m)!=1:
        return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3!=0:
        q = u3//v3
        v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
    return u1%m

r = remote('csie.ctf.tw',10142)

P,Q,G,Y = get_key()
MSG = b'GIMME THE FLAG !!!!!!!'
MSG = int.from_bytes(MSG, 'little') % Q
msg = (Q-1)//2
R,S = sign(msg)
K = Q-1
X = ((S*K-bytes_to_long(digest(msg)))*findModReverse(R,Q))%Q
#l stands for leak
msg_l = (MSG+msg)%(Q-1)
R_l,S_l = sign(msg_l)
K_l_inv = (findModReverse(bytes_to_long(digest(msg_l))+X*R_l,Q)*S_l)%Q
K_l = findModReverse(K_l_inv,Q)
K_f = K_l*findModReverse(K,Q)
K_f_inv = findModReverse(K_f,Q)
R_f = pow(G,K_f,P)%Q
S_f = K_f_inv*(bytes_to_long(digest(MSG))+X*R_f)%Q
verify(R_f,S_f)


###Reference
#  https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
#  https://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/
#  https://rdist.root.org/2009/05/17/the-debian-pgp-disaster-that-almost-was/
