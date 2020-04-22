

<table> <tr> <td bgcolor=red>

昵称：test1357

联系方式：qq1156935631

或者校内邮箱：xiangweijiang@mail.nwpu.edu.cn 

</td> </tr> </table>

额额额额额。。。我就是个小白，第一次搞ctf，也不知道为什么就有我名字了

Misc：

打不开的图片

下载下来后发现文件名是zip

那就解压

得到what's_this，用winhex打开

发现是张png图片，然后发现宽度有问题。

利用crc校验码修复图片宽度

```python
import struct
import binascii
import os

fi = open('what's_this.png', 'rb').read()

# 12-15字节代表固定的文件头数据块的标示，16-19字节代表宽度，20-23字节代表高度，24-28字节分别代表
# Bit depth、ColorType、Compression method、Filter method、Interlace method
# 29-32字节为CRC校验和

for i in range(10000):  # 宽度0-9999搜索
    data = fi[12:16] + struct.pack('>I', i) + fi[
                                              20:29]  # pack函数将int转为bytes,>表示大端00 00 00 02,I表示4字节无符号int;<表示小端 02 00 00 00
    crc = binascii.crc32(data) & 0xffffffff  # byte的大小为8bits而int的大小为32bits,转换时进行与运算避免补码问题0x932f8a6b
    if crc == struct.unpack('>I', fi[29:33])[0] & 0xffffffff:  # 解开为无符号整数
        print(i)
```

得到宽度439

在winhex中修改，然后得到可以打开的图片。

给了一串字符MZWGCZ33OV2HC3D5，本来还以为是flag。。。。

(而且33后面的那个也太像零了吧。。。。。。)

结果并不是，那就继续解。。。。

由于那个太像0了，我查的发现好像base32里没有0。。。。。。。。。

一直用base64解。。。解不出来，

后来觉得可能那个是O我就用base32解，然后得到flag{utql}

