### 认清形势，建立信心

#### [题目考点]

* DLP求解
* CRT

#### [题目文件]

[Click Here to Download](http://0xdktb.top/2020/04/19/WriteUp-NPUCTF-Crypto/warm_up_683484967e8895fa6ba3db693e607491.zip.zip)

#### [题解分析]

**Encryption**

```python
p = getPrime(25)
e = # Hidden
q = getPrime(25)
n = p * q
m = bytes_to_long(flag.strip(b"npuctf{").strip(b"}"))

c = pow(m, e, n)
print(c)
print(pow(2, e, n))
print(pow(4, e, n))
print(pow(8, e, n))
```

**Decryption**

$n|GCD(c_1^{2}-c_2,c_1^{3}-c_3)$，n易知

$e\in(0,n)$，即$size(e)\leq 50$，多种方法都能求解该数量级的DLP问题

这里采用BSGS，但直接对n用BSGS还是能到$O(2^{25})$，因此对p, q分别BSGS再CRT即可

本题的$m\%n$有多种情况，逐一判断即可

#### [exp]

```python
#!/usr/bin/env sage

from Crypto.Util.number import *

c1 = 128509160179202
c2 = 518818742414340
c3 = 358553002064450
n = GCD(c1**2-c2, c1**3-c3)
n.factor() # 2 * 18195301 * 28977097
```

```python
n //= 2
p = 18195301
q = 28977097

def bsgs(g, y, p):
    res = []
    m = int(ceil(sqrt(p - 1)))
    S = {pow(g, j, p):j for j in range(m)}
    gs = pow(g, p - 1 - m, p)
    for i in range(m):
        if y in S:
            res.append(i * m + S[y])
        y = y * gs % p
    return res

c1_p = c1 % p
c1_q = c1 % q
e_1 = bsgs(2, c1_p, p)
e_2 = bsgs(2, c1_q, q)
phi = (p - 1) * (q - 1)
e_n = [] # e % n
for e_p in e_1:
    for e_q in e_2:
        try:
            e_n.append(crt([e_p, e_q], [p - 1, q - 1])) # e % phi
        except:
            pass
more_e_n = []
for e in e_n:
    i = (n - e) // phi
    more_e_n += [e + j * phi for j in range(1, i + 1)]
e_n += more_e_n

d_n = [inverse(e, phi) for e in e_n]

m_n = set()
c = 169169912654178
for d in d_n:
    m_n.add(pow(c, d, n))
m_n = list(m_n)

for m in m_n:
    print(b'npuctf{' + long_to_bytes(m) + b'}')
```

#### [More]

签到题...结果没注意加密源码里m的strip，以为$m>>n$，所以其实已经解出来了还楞了好久...

### Mersenne_twister

#### [题目考点]

* MT逆算法

#### [题目文件]

[Click Here to Download](http://0xdktb.top/2020/04/19/WriteUp-NPUCTF-Crypto/Mersenne_twister.zip)

#### [题解分析]

**Encryption**

```python
assert len(flag) == 26
assert flag[:7] == 'npuctf{'
assert flag[-1] == '}'
...
def encrypt(key , plain):
    tmp = md5(plain).digest()
    return hexlify(XOR(tmp , key))
...
flag = flag.encode()
random = mt73991(seed)
f = open('./cipher.txt' , 'wb')
for i in flag:
    key = b''.join([random.getramdanbits() for _ in range(4)])
    cipher = encrypt(key , chr(i).encode())
    f.write(cipher)
```

**Decryption**

kpa逆encrypt函数，可得`mt_output[0]~mt_output[27],mt_output[100]~mt_output[103]`

```python
def Next(self , tmp):
    tmp ^= (tmp >> 11)
    tmp ^= (tmp << 7) & 0x9ddf4680
    tmp ^= (tmp << 15) & 0xefc65400
    tmp ^= (tmp >> 18) & 0x34adf670
    return tmp
```

从mt_output[i]恢复出state[i]

```python
def __init__(self , seed):
    self.state = [seed] + [0] * 232
    self.flag = 0
    self.srand()
    self.generate()
    
def srand(self):
    for i in range(232):
        self.state[i+1] = 1812433253 * (self.state[i] ^ (self.state[i] >> 27)) - i
        self.state[i+1] &= 0xffffffff

def generate(self):
    for i in range(233):
        y = (self.state[i] & 0x80000000) | (self.state[(i+1)%233] & 0x7fffffff)
        temp = y >> 1
        temp ^= self.state[(i + 130) % 233]
        if y & 1:
            temp ^= 0x9908f23f
        self.state[i] = temp
```

但这里得到的state是generate一轮后的state，所以要逆出至少一个old_state

发现`state[103]`和`state[0]`已知，且与`old_state[103]`和`old_state[104]`存在等式关系（`old_state[104]`能用`state[103]`表示）

![](Snipaste_2020-04-20_00-22-17.png)

但s104可能存在两种可能(In [26])，因此在In [28]中进行一次判断，本题中为唯一解

得到s104后逆srand函数即可得到seed

(`&=0xffffffff`等价于`%=0x100000000`，因此`(state[i+1]+i)*inverse(1812433253, 0x100000000)`即可得到`(self.state[i] ^ (self.state[i] >> 27))`，进而得到`state[i]`

#### [exp]

```python
# In[1]:
from hashlib import md5
from binascii import hexlify, unhexlify
from Crypto.Util.number import *

# In[2]:
cipher = unhexlify(open("cipher.txt", "rb").read())

# In[3]:
XOR = lambda s1 ,s2 : bytes([x1 ^ x2 for x1 ,x2 in zip(s1 , s2)])

# In[4]:
prefix_mt_output = []
prefix = b'npuctf{'
j = 0
for i in prefix:
    tmp = md5(chr(i).encode()).digest()
    randnum = XOR(tmp, cipher[16 * j : 16 * (j + 1)])
    for k in range(4):
        prefix_mt_output.append(bytes_to_long(randnum[4 * k : 4 * (k + 1)]))
    j += 1

# In[5]:
suffix_mt_output = [] #output[100]~output[103]
suffix = b'}'
tmp = md5(suffix).digest()
randnum = XOR(tmp, cipher[16 * 25 : 16 * 26])
for i in range(4):
    suffix_mt_output.append(bytes_to_long(randnum[4 * i : 4 * (i + 1)]))

# In[6]:
def unBitshiftLeftXor(value, shift, mask):
    i = 0
    res = 0
    while i * shift < 32:
        partMask = (0xffffffff >> (32 - shift)) << (shift * i)
        part = value & partMask
        value ^= (part << shift) & mask
        res |= part
        i += 1
    return res

def unBitshiftRightXor(value, shift, mask):
    i = 0
    res = 0
    while i * shift < 32:
        partMask = ((0xffffffff << (32 - shift)) & 0xffffffff) >> (shift * i)
        part = value & partMask
        value ^= (part >> shift) & mask
        res |= part
        i += 1
    return res

def recoverState(value):
    value = unBitshiftRightXor(value, 18, 0x34adf670)
    value = unBitshiftLeftXor(value, 15, 0xefc65400)
    value = unBitshiftLeftXor(value, 7, 0x9ddf4680)
    value = unBitshiftRightXor(value, 11, 0xffffffff)
    return value

# In[7]:
prefix_state = []
for value in prefix_mt_output:
    prefix_state.append(recoverState(value))
suffix_state = [] #state[100]~state[103]
for value in suffix_mt_output:
    suffix_state.append(recoverState(value))

# In[22]:
cur = suffix_state[-1] #state[103]

# In[23]:
cur ^= prefix_state[0]

# In[24]:
if size(cur) > 31: #最高比特一定要是0
    print("old_state[104] & 1 == 1")
    cur ^= 0x9908f23f #奇数
else:
    print("old_state[104] & 1 == 0") #偶数

# In[25]:
cur <<= 1 #偶数末尾比特=0

# In[26]:
s104_1 = cur & 0x7fffffff
s104_2 = s104_1 | 0x80000000

# In[27]:
coef = inverse(1812433253, 0x100000000)
def inv_srand(value, i):
    value &= 0xffffffff
    value += i
    value *= coef
    value = unBitshiftRightXor(value, 27, 0xffffffff)
    return value

# In[28]:
if inv_srand(s104_1, 103) & 0x80000000 == cur & 0x80000000:
    if inv_srand(s104_2, 103) & 0x80000000 == cur & 0x80000000:
        print("two cases found")
    else:
        s104 = s104_1
else:
    s104 = s104_2

# In[29]:
cur = s104
for i in range(103, -1, -1):
    cur = inv_srand(cur, i)
seed = cur

# In[30]:
class mt73991:
    def __init__(self , seed):
        self.state = [seed] + [0] * 232
        self.flag = 0
        self.srand()
        self.generate()
    def srand(self):
        for i in range(232):
            self.state[i+1] = 1812433253 * (self.state[i] ^ (self.state[i] >> 27)) - i
            self.state[i+1] &= 0xffffffff


    def generate(self):
        for i in range(233):
            y = (self.state[i] & 0x80000000) | (self.state[(i+1)%233] & 0x7fffffff)
            temp = y >> 1
            temp ^= self.state[(i + 130) % 233]
            if y & 1:
                temp ^= 0x9908f23f
            self.state[i] = temp
    def getramdanbits(self):
        if self.flag == 233:
            self.generate()
            self.flag = 0
        bits = self.Next(self.state[self.flag]).to_bytes(4 , 'big')
        self.flag += 1
        return bits
        
    def Next(self , tmp):
        tmp ^= (tmp >> 11)
        tmp ^= (tmp << 7) & 0x9ddf4680
        tmp ^= (tmp << 15) & 0xefc65400
        tmp ^= (tmp >> 18) & 0x34adf670
        return tmp

# In[31]:
random = mt73991(seed)

# In[32]:
pt = b''
for i in range(26):
    key = b''.join([random.getramdanbits() for _ in range(4)])
    pt += XOR(key, cipher[16 * i : 16 * (i + 1)])

# In[33]:
import string
str_set = string.printable.encode()
md5_set = []
for i in str_set:
    md5_set.append(md5(chr(i).encode()).digest())

# In[34]:
flag = ''
for i in range(26):
    idx = md5_set.index(pt[16 * i:16 * (i + 1)])
    flag += chr(str_set[idx])
flag
```

#### [More]

解`old_state[103]`那里采用z3解方程失败（原因是Int类型不支持位运算，但BitVec('s103', 32)又是在$GF(2^{32})$上的元，基础运算定义不一致，求解结果错误）

因此采用了手动解方程的办法，后续如果知道有轮子再补

### 共模攻击

#### [题目考点]

* 共模攻击
* 有限域开根
* CopperSmith

#### [题目文件]

[Click Here to Download](http://0xdktb.top/2020/04/19/WriteUp-NPUCTF-Crypto/ezrsa_c799462e82d9c969f1d28a373733e6f1.zip.zip)

#### [题解分析]

hint.py

```python
m = bytes_to_long(hint)
p = getPrime(256)
c = pow(m, 256, p)
print(p)
...
# c可以通过真·共模求出来
```

256非素数，懒得自己写有限域开根高效算法了...sage直接来

![](Snipaste_2020-04-21_21-49-44.png)

再回到task.py

```python
p, q = getPrime(512), getPrime(512)
n = p * q
e1, e2 = p, q
c1, c2 = pow(m, e1, n), pow(m, e2, n)

print(n)
print(c1)
print(c2)
```

hint给出m比特长度上界，联想到coppersmith，再可行性分析如下：

$c1\equiv m^{p}\equiv m(mod\ p),c2\equiv m^{q}\equiv m(mod\ q)$

$\therefore n|(c1-m)(c2-m)$

上界分析$\frac{1}{2}n^{\frac{1^{2}}{2}}\approx 2^{511}$，而上面hint已经给了size(m)<400，所以可行性分析通过

![](Snipaste_2020-04-21_21-58-34.png)

#### [exp]

没完整的- -按上面的截图手动测就好

#### [More]

coin师傅还是强啊quq

### EzRSA

#### [题目考点]

* 已知(e, n, d)恢复(p, q)
* Rabin解密

#### [题目文件]

[Click Here to Download](http://0xdktb.top/2020/04/19/WriteUp-NPUCTF-Crypto/difficultrsa.py)

#### [题解分析]

题目给出`n`，`lcm(p-1,q-1)`，`c`，`e`，测试发现`GCD(e, lcm) == 2`

因此令`d=inverse(e//2,lcm)`，则$m^{2}\equiv c^{d}(mod\ n)$

但非有限域下的二次根求解难度在m足够大的时候几乎不可行，于是思路转向分解n

比赛的时候发现`size(lcm) == 2045`，也就是说`GCD(p-1,q-1)`极小，爆破小素数组合即可，发现GCD为8

成功分解N，求解Rabin即可（当然，这是非预期...shallow师傅后来提了一下才反应过来，这道题考察的点实际上是已知(e, n, d)来分解n）

关于已知(e, n, d)分解N，我在之前的博客也提到过[http://0xdktb.top/2020/02/28/Summary-of-Crypto-in-CTF-RSA/#rsa---given-e-d-n](http://0xdktb.top/2020/02/28/Summary-of-Crypto-in-CTF-RSA/#rsa---given-e-d-n)

#### [exp]

```python
from Crypto.Util.number import *
from gmpy2 import next_prime, gcd
import sympy

lcm = 
e = 
assert(GCD(lcm, e) == 2)
n = 
d = inverse(e // 2, lcm)
m2 = pow(c, d, n) # m^2

def Factorize(n, e, d):
    g = 2
    while True:
        k = e * d - 1
        while not k & 1:
            k //= 2
            p = int(gcd(pow(g, k, n) - 1, n)) % n
            if p > 1:
                return (p, n // p)
        g = int(next_prime(g))
        
(p, q) = Factorize(n, e // 2, d)

# 下面求解Rabin是用sage手动测的，如果想合成完整脚本的话请用求解Rabin的脚本(多种可能要进行筛选)
m_p = sympy.nthroot_mod(m2, 2, p)
m_q = sympy.nthroot_mod(m2, 2, q)
m = crt([m_p, m_q], [p, q])
long_to_bytes(m)

# b'NPUCTF{diff1cult_rsa_1s_e@sy}'
```

### EzLCG

#### [出题手记]

[Click Here to Download](http://0xdktb.top/2020/04/19/WriteUp-NPUCTF-Crypto/EzLCG.pdf)

### EzSPN

#### [出题手记]

[Click Here to Download](http://0xdktb.top/2020/04/19/WriteUp-NPUCTF-Crypto/EzSPN.pdf)