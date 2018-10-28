from pwn import *

r = remote("csie.ctf.tw",10123)
r.recvline()
r.recvline()
r.recvline()
for i in range(100):
	r.recvline()
	a = r.recvline()
	a = a.split(b' ')[:-1]
	num = ' '.join(list(map(str,sorted([int(i) for i in a]))))
	r.send(num+'\n')
r.recvline()
a = r.recvline()
print(a)
