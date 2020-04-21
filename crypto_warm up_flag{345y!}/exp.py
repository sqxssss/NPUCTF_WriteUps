from Crypto.Util.number import *
from gmpy2 import *

cipher = 169169912654178
a = 128509160179202
b = 518818742414340
c = 358553002064450

n = gcd(a**2 - b,a**3 - c)

for i in range(2,iroot(n, 2)[0]):
    while n % i == 0:
        if i < 2**20:
            n//=i
        else:
            p, q = i, n//i
            break

tmp = {}
base = pow(2, iroot(n, 2)[0], n)
now = base
for i in range(1, iroot(n, 2)[0]):
    tmp[now] = i
    now = (now * base) % n 

now = a

for i in range(iroot(n, 2)[0]):
    if now in tmp:
        e = tmp[now] * iroot(n, 2)[0] - i
        # print(e)
        d = invert(e,(p-1)*(q-1))
        print(long_to_bytes(pow(cipher, d, n)))
    now = now * 2 % n


