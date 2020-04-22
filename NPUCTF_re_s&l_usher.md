---
title: NPUCTF
categories:
- competition
tags: 
- reverse
- CTF
---

# are-you-a-fan

[这题不会做,参考了其他师傅的做的](https://www.wootec.top/2020/04/21/Ha1cyon-CTF-%E8%8A%9C%E6%B9%96WP/)

获得了新知识[base64隐写](https://www.jianshu.com/p/48fe4dd3e5ce)

```c
#include <stdio.h>
#include <string.h>

int TableFind(char ch);

int main()
{
	char flag[100]={0};
	int temp=0;
	int digit=0;
	char line[][100]={"55y85YmN6YeN5aSN55qE6aOO5pmvLG==",
					"5riQ5riQ5qih57OK5LqG57qm5a6aLO==",
					"5pif56m65LiL5rWB5rWq55qE5L2gLH==",
					"5LuN54S256eY5a+G55qE6Led56a7LA==",
					"5rip5bqm5raI5aSx55qE556s6Ze0LH==",
					"5peg5rOV6Kem5pG455qE5piO5aSpLF==",
					"5rKh5pyJ5byV5Yqb55qE5LiW55WMLG==",
					"5rKh5pyJ6ISa5Y2w55qE5YWJ5bm0LD==",
					"6L+Y5Zyo562J552A5L2g5Ye6546wLH==",
					"5pel5pel5aSc5aSc6Ieq6L2s55qE6KGM5pifLE==",
					"5Yiw5aSE6YGu5ruh5Yir5Lq655qE6IOM5b2xLG==",
					"6K6p6aOO5ZC55pWj5re35Lmx55qE5ZG85ZC4LG==",
					"5b+r5b+r5riF6YaSfn==",
					"6Z2Z6Z2Z54Wn5Lqu5Y6f5p2l55qE6Ieq5bexLL==",
					"5aSp56m65rSS5ruh5b+954S255qE5YWJ5piOLE==",
					"55y85Lit5Y+q6KaB57ua54OC55qE5aSp6ZmFLG==",
					"5YaN6aOe6KGMIW==",
					"5oiR5YuH5pWi5Zyw5oqs6LW35aS0LM==",
					"55yL552A6Iyr6Iyr55qE5a6H5a6ZLH==",
					"5aSa5bCR5pyq55+l55qE5pif55CDLJ==",
					"5pyJ5rKh5pyJ6YCa5ZCR5pyq5p2l6Lev5Y+jLD==",
					"5Lqy54ix55qE5LyZ5Ly0LB==",
					"6K6p5oiR5Lus5LiA6LW354K554eDLG==",
					"5YuH5rCU5ZKM5L+h5b+1LO==",
					"5Zyo6YGl6L+c55qE5aSp6L65LG==",
					"6ZO25rKz6L6557yYLH==",
					"5pyJ5LiA54mH56We5aWH55qE5b2p6Jm55rW3LC==",
					"5ZKM5oiR5LiA6LW35YaS6ZmpLB==",
					"6aOe5ZCR5Y+m5LiA5Liq5LiW55WMLC==",
					"5Zyo6YGl6L+c55qE5aSp6L65LB==",
					"6ZO25rKz6L6557yYLC==",
					"5pyJ5LiA54mH56We5aWH55qE5b2p6Jm55rW3LB==",
					"5ZKM5oiR5LiA6LW35YaS6ZmpLH==",
					"6aOe5ZCR5Y+m5LiA5Liq5LiW55WMLN==",
					"c3VwZXIgbWFnaWMgd29ybGR+fg==",};
	int t=0;
	for(int i=0;i<=35;i++)
	{
		int len=strlen(line[i]);
		if(line[i][len-1]!='=')
			continue;
		else if (line[i][len-2]!='=')
		{
			digit+=2;
			temp=(temp<<2)+(TableFind(line[i][len-2])&0x3);
		}
		else
		{
			digit+=4;
			temp=(temp<<4)+(TableFind(line[i][len-3])&0xF);
		}
		if(digit==8)
		{
			digit=0;
			flag[t++]=(char)temp;
		}
		else if(digit>8)
		{
			digit=2;
			flag[t++]=(char)(temp>>2);
			temp&=0x3;
		}
	}
	printf("%s",flag);
}

int TableFind(char ch)
{
	char table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int len=strlen(table);
	for(int i=0;i<len;i++)
		if(ch==table[i])
			return i;
}
```

# BYBY_OBFUS

简单题目,听说可以直接动调balabala,无所谓啦反正也挺简单的

丢入IDA,算了不放原来的F5代码了,直接放精简后的代码,里面的F0X12345都是比较简单的

```c
#include <stdio.h>

int main()
{
	int key[]={0,0x1E79,0x1E79,0x2135,0x170D,0x1F41,0x1901,0x2CED,0x11F9,0x2649,0x2581,0x2DB5,0x14B5,0x25E5,0x2A31,0x30D5,0};
	int temp[100]={0};
	int table[]={2,3,4,5};
	char input[100]={0};
	int count=0;
	scanf("%s", input);//len=15
	for ( int j = 1; j <= 15; ++j )
	{
	    temp[j] = input[j-1] - table[(j-1) % 4];
		temp[j] ^= table[(j-1) % 4];
		temp[j] *= 10;
	}
	for ( int k = 1; k <= 15; ++k )
	{
	    if ( temp[k] == (key[k]-1) / 10 )
	      ++count;
	}
	if ( count == 15 )
	    puts("\nPASS");
}
```

exp很容易写出

```c
#include <stdio.h>

int main()
{
	int key[]={0,0x1E79,0x1E79,0x2135,0x170D,0x1F41,0x1901,0x2CED,0x11F9,0x2649,0x2581,0x2DB5,0x14B5,0x25E5,0x2A31,0x30D5,0};
	int temp[100]={0};
	int table[]={2,3,4,5};
	char flag[100]={0};
	for ( int k = 1; k <= 15; ++k )
	    temp[k] = (key[k]-1) / 100;
	for(int j=15;j>=1;j--)
	{
		temp[j] ^= table[(j-1) % 4];
	    flag[j-1] = table[(j-1) % 4] + temp[j];
	}
	printf("%s",flag);
}
```

# maze

这个题看名字就知道是迷宫型

看F5就知道有49个格子,然后再分析一下就可以知道 h左 j上 l右 k下

然后就可以弄一个记事本打7*7个X然后能走的地方就O走到最右下角就成功

这个主要是他不是一次性提交走的位置,而是一个一个的键入的,如果是一次性输入完的话,要动调去看对了没有就比较麻烦

# RXencode

F5的代码十分清晰,很容易看出输入经过base64换表后与key比较

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void decode(char* str);

int main()
{
	char key[]={0x9E,0x9B,0x9C,0xB5,0xFE,0x70,0xD3,0x0F,0xB2,0xD1,0x4F,0x9C,0x02,0x7F,0xAB,0xDE,0x59,0x65,0x63,0xE7,0x40,0x9D,0xCD,0xFA,0x00};
	//ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234{}789+/=
	decode(key);
	return 0; 
} 

void decode(char* str)
{
	int temp=strlen(str)*4/3;
	char* tempt=(char*)malloc(temp);
	memset(tempt,0,temp);
	for(int i=0,j=0;j<temp;i+=3,j+=4)
	{
		tempt[j]=(str[i]>>2)&0x3F;
		tempt[j+1]=((str[i]&3)<<4)|((str[i+1]>>4)&0xF);
		tempt[j+2]=((str[i+1]&0xF)<<2)|((str[i+2]>>6)&3);
		tempt[j+3]=str[i+2]&0x3F;
	}
	char table[67]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234{}789+/=";
	char flag[100]={0};
	for(int i=0;i<temp;i++)
	{
		flag[i]=table[tempt[i]];
	}
	printf("%s",flag);
	free(tempt);
	return; 
}
```

# EAZYOBFU2

这个题目呢,源码级混淆

在源码里塞了2000个没用的操作输入的函数,然后在其中的某一个函数中添加了有用的代码

然而怎么就能够知道这2000个函数没有用呢,并且怎么知道是哪一个函数有用呢

出题人:我不知道

一个比较好的方法是用angr(我并不会用,没学py

```c
#include <stdio.h>

int main()
{
	int keys[100]={0x21,0x3F,0xA3,0xE9,0x8F};
	unsigned char cmps[30]={0x6E,0x10,0xEC,0x13,0xC1,0xCB,0xF0,0x2D,0xC6,0x32,0xFD,0x86,0xEE,0xCB,0x89,0x92,0x3C,0x46,0x49,0x71,0x62,0x57};
	for(int i=1;i<22;i++)
	{
		cmps[i]=(cmps[i]<<3)|(cmps[i]>>5);
		cmps[i]-=((keys[i%6]>>6)^(keys[(i-1)%6]<<4)&0xFE);
		cmps[i]=(cmps[i]^i)-i;
	}
	printf("%s",cmps);
}
```

[引个流](https://usher2008.github.io/)

