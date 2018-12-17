from Crypto.Util.number import *
from pwn import *

def info():
    r.sendlineafter('> ','1')
    nums = r.recvuntil('\n=').decode('utf-8').split('\n')
    c = int(nums[0].split(' = ')[1])
    e = int(nums[1].split(' = ')[1])
    n = int(nums[2].split(' = ')[1])
    return c,e,n

def decrypt(c):
    r.sendlineafter('> ','2')
    r.sendline(c)
    result = r.recvuntil('\n=').decode('utf-8').split('\n')[0].split(' = ')[1]
    return result

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

def findPow(a,m):
    i = 0
    while a>0:
        i+=1
        a//=m
    return i

def search(c,e,n,b_known):
    inv = findModReverse(b_known,n)
    M = 0
    sub = 0
    upbnd = findPow(n,b_known)
    for i in range(upbnd):
        result = int(decrypt(str(c*pow(inv,i*e,n))))
        result = (result-sub)%b_known
        M += result*pow(b_known,i)
        sub = ((sub+result)*inv)%n
        print('M',M)
    return M


###Start Exploit
## Main idea : LSB oracle
## different from the other version, this oracle can query multibytes at once

r = remote('csie.ctf.tw',10140)

c,e,n = info()
m = search(c,e,n,16)
print(long_to_bytes(m))
