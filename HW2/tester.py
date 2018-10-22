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

sccnt = 0
offest = 0
execptr=0
arry=[0]
ptr=0
flag = open('tinput').read()
while execptr<len(code):
        char = code[execptr]
        if char=='+':
            arry[ptr]+=1
            if arry[ptr]>255:
                arry[ptr]=255
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
                '''
                if sccnt>=0:
                    print('[[[[[[['+str(execptr))
                    for i in range(len(arry)):
                        print('('+chr(arry[i])+','+str(arry[i])+')',end='')
                    print('')
                    print('')
                '''
        if char==']':
            execptr = precon_pair[execptr]-1
        if char==',':
            print(',,,,,,,')
            for i in range(len(arry)):
                print('('+chr(arry[i])+','+str(arry[i])+')',end='')
            print('')
            #inp=ord(input()[0])
            inp=ord(flag[sccnt])
            arry[ptr]=inp
            sccnt+=1
            '''
            for i in range(len(arry)):
                print('('+chr(arry[i])+','+str(arry[i])+')',end='')
            print('')
            print('')
            '''
        if char=='.':
            print(chr(arry[ptr]),end='')
            '''
            print('.......')
            for i in range(len(arry)):
                print('('+chr(arry[i])+','+str(arry[i])+')',end='')
            print('')
            print('')
            '''
        execptr+=1
