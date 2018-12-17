from Crypto.Util.number import *
from pwn import *

###Utils
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

def search(c,e,n,high,low=0):
    ptr = (high+low)//2
    cnt = 0
    i = 1
    while True:
        print('H',high)
        print('L',low)
        result = int(decrypt(str(c*pow(2,i*e,n))))%2
        if result==0:
            high = ptr
        elif result==1:
            low = ptr
        if high==low:
            return ptr
        elif high<low:
            print('err')
            return ptr
        i+=1
        cnt+=1
        if cnt>255:
            global r
            r.close()
            r = remote('csie.ctf.tw',10140)
            cnt = 0
            c,e,n = info()
            nhigh = n
            nlow = 0
            i = 1
            while True:
                mid = (nhigh+nlow)//2
                if mid>=high:
                    nhigh = mid
                elif mid<low:
                    nlow = mid
                else:
                    break
                i+=1
            high = nhigh
            low = nlow
        ptr = (high+low)//2


###Start Exploit
## Main idea : LSB oracle
## Though the oracle quota is limited, m remains the same
## Which means we can carry the result across different encryptions
## This gives us the choice to perform simple LSB oracle attack
## Tip in this problem is to realize new bounds are to be reduced by comparing to previous bounds


r = remote('csie.ctf.tw',10140)

c,e,n = info()
m = search(c,e,n,n)
print(long_to_bytes(m))
