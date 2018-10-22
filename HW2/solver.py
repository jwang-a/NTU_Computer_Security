import string

code =open('bf').read()
stack = [0 for i in range(len(code))]
sptr = 0
precon_pair = [0 for i in range(len(code))]
for i in range(len(code)):
    if code[i]=='[':
        stack[sptr] = i
        sptr+=1
    if code[i]==']':
        sptr-=1
        precon_pair[i] = stack[sptr]
        precon_pair[stack[sptr]] = i

can = string.printable
flag = []
for T in range(37):
    flag.append(' ')
    for C in range(len(can)):
        flag[T] = can[C]
        sccnt = 0
        offest = 0
        execptr=0
        arry=[0]
        ptr=0
        fin = 0
        while execptr<len(code):
            char = code[execptr]
            if char=='+':
                arry[ptr]+=1
                if arry[ptr]>255:
                    arry[ptr]=0
            if char=='-':
                arry[ptr]-=1
                if arry[ptr]<0:
                    arry[ptr]=255
            if char=='>':
                ptr+=1
                if ptr==len(arry):
                    arry.append(0)
            if char=='<':
                ptr-=1
            if char=='[':
                if arry[ptr]==0:
                    execptr = precon_pair[execptr]
            if char==']':
                execptr = precon_pair[execptr]-1
            if char==',':
                if sccnt==T+1:
                    if arry[0]==1:
                        fin = 1
                    break
                inp=ord(flag[sccnt])
                arry[ptr]=inp
                sccnt+=1
            if char=='.':
                print(chr(arry[ptr]),end='')
            execptr+=1
        if execptr==len(code):
            print(''.join(flag))
            exit()
        if fin==1:
            print(flag[T])
            break
