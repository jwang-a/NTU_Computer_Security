import gmpy2


###Utils
def gcd(a,b):
    while a!=0:
        a,b = b%a,a
    return b

def pollard(n):
    a = 2
    b = 2
    while True:
        a = pow(a,b,n)
        d = gcd(a-1,n)
        if 1<d<n:
            return d
        b+=1

def fermat_sieve(n,a,rounds):
    valid = n%20
    Val = [0,1,4,5,9,16]
    Cand = []
    for i in range(len(Val)):
        if (Val[i]-valid)%20 in Val:
            Cand.append(Val[i])
    b = 0
    for i in range(rounds):
        a_2 = a**2
        if a_2%20 in Cand:
            b_2 = a_2-n
            b = math.sqrt(b_2)
            if b//1==b:
                b = int(b)
                return a-b,a+b
        a_min_b = int(a-b)
        a+=1
    return -1,a_min_b

def findModReverse(a,m):
    if gcd(a,m)!=1:
        return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3!=0:
        q = u3//v3
        v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
    return u1%m


def tonelli_shanks(n,p):
    n%=p
    if p%4!=1:
        return None
    if pow(n,(p-1)//2,p)!=1:
        return None
    S = 0
    Q = p-1
    while Q%2==0:
        Q//=2
        S+=1
    for i in range(1,p):
        if pow(i,(p-1)//2,p)==p-1:
            z = i
            break
    M = S
    c = pow(z,Q,p)
    t = pow(n,Q,p)
    R = pow(n,(Q+1)//2,p)
    while True:
        if t==0:
            print('!')
            exit()
            return 0
        if t==1:
            return R
        i = 1
        t_cpy = t
        while True:
            t_cpy = pow(t_cpy,2,p)
            if t_cpy==1:
                break
            i+=1
        b = pow(c,pow(2,M-i-1),p)
        M = i
        c = pow(b,2,p)
        t = (t*pow(b,2,p))%p
        R = (R*b)%p


def rabin_dec(c,p,q):
    n = p*q
    if p%4==3:
        m_p = (c**((p+1)//4))%p
    else:
        m_p = tonelli_shanks(c,p)
    if q%4==3:
        m_q = (c**((q+1)//4))%q
    else:
        m_q = tonelli_shanks(c,q)
    y_p = findModReverse(p,q)
    y_q = findModReverse(q,p)
    m1 = (y_p*p*m_q+y_q*q*m_p)%n
    m2 = n-m1
    m3 = (y_p*p*m_q-y_q*q*m_p)%n
    m4 = n-m3
    return [m1,m2,m3,m4]


###Start Exploit
## Refer to references, too complicated to explain

n,e,c = json.loads(open('data','r').read())
p = pollard(n)
q1_q2 = n//p
q1_q2_3 = q1_q2*3
q1_base = gmpy2.isqrt_rem(q1_q2_3)[0]
q1, q2 = fermat_sieve(q1_q2_3,q1_base,10000)
q1//=3
phi = (p-1)*(q1-1)*(q2-1)
d = findModReverse(e//4,phi)

m_4_n = pow(c,d,n)
m_4_q1q2 = m_4_n%(q1*q2)
m_2 = rabin_dec(m_4_q1q2,q1,q2)
for i in range(4):
    m = rabin_dec(m_2[i],q1,q2)
    for j in range(4):
        print(long_to_bytes(m[j]))


'''
REF:
https://www.nku.edu/~christensen/Mathematical%20attack%20on%20RSA.pdf
http://www.math.columbia.edu/~goldfeld/PollardAttack.pdf
https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
https://en.wikipedia.org/wiki/Rabin_cryptosystem
https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
'''
