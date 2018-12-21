from pwn import *
import numpy as np

def get_clue():
    clue = r.recvuntil('\n\n').strip().decode('utf-8').split('\n')[1]
    return clue

def send_ans(answer):
    r.sendlineafter('state? ',str(answer))
    r.interactive()

def gen_status():
    a = []
    a.append([])
    for i in range(64):
        a[0].append(i)
    a.append([])
    for i in range(13):
        a[1].append('')
    for i in range(51):
        a[1].append(i)
    for i in range(2):
        a.append([])
    for i in range(57):
        for j in range(2):
            a[2+j].append(a[j][i+7])
    for i in range(7):
        for j in range(2):
            a[2+j].append('')
    for i in range(4):
        a.append([])
    for i in range(17):
        for j in range(4):
            a[4+j].append('')
    for i in range(17,64):
        for j in range(4):
            a[4+j].append(a[j][i-17])
    status = [[[0 for j in range(64)] for i in range(64)] for r in range(201)]
    for i in range(64):
        status[0][i][i] = 1
    for r in range(1,201):
        for i in range(64):
            for j in range(8):
                if a[j][i]!='':
                    for k in range(64):
                        status[r][i][k]^=status[r-1][a[j][i]][k]
    LSB_status = []
    for i in range(1,201):
        LSB_status.append(status[i][0])
    FIN_status = []
    for i in range(64):
        FIN_status.append(status[200][i])
    return LSB_status,FIN_status

def Clean(vectors,clue):
    cleaned = []
    result = []
    length = len(clue)
    for i in range(length):
        if clue[i]!='.':
            cleaned.append(np.array(vectors[i]))
            result.append(int(clue[i]))
    return cleaned,result

def Gaussian_eliminate(S,result):
    used = [0 for i in range(len(S))]
    basis = []
    basis_y = []
    for i in range(64):
        base = -1
        for j,row in enumerate(S):
            if row[i]==1 and used[j]==0:
                base = j
                used[j] = 1
                break
        for j,row in enumerate(S):
            if row[i]==1 and j!=base:
                S[j] = (S[base]+S[j])%2
                result[j] = (result[base]+result[j])%2
        basis.append(S[base])
        basis_y.append(result[base])
    return basis,basis_y

def Calc_ans(basis,M,basis_y):
    M = np.array(M)
    answer = [0 for i in range(64)]
    for i,row in enumerate(M):
        for j in range(64):
            if row[j]==1:
                row = (row+basis[j])%2
                answer[i]^=basis_y[j]
    return answer

###Start exploit
#  Simple Gaussian elimination problem

LSB_status,FIN_status = gen_status()
r = remote('csie.ctf.tw',10143)
clue = get_clue()
cleaned,result = Clean(LSB_status,clue)
basis,basis_y=Gaussian_eliminate(cleaned,result)
answer = Calc_ans(basis,FIN_status,basis_y)
print(answer)
answer = int(''.join(list(map(str,answer[::-1]))),2)
send_ans(answer)
