---
title: Reversing a Playstation X Application?
date: 2023-12-27T00:00:00Z
draft: false
description: RE from WGMY 2023
tocOpen: false
---

# WGMY 2024 -- RmRf

> "What happened to my system? It has been working perfectly for more than 20 years."

We are given a zip that contains a **bin** and **cue** file. If we run strings, we see that it points to a playstation/PSX program.

I extracted the **ISO** file by running `binwalk --extract rmrf.bin`. From the **ISO** file, we can extract the playstation **EXE** by using **unar**.

```cs
rmrf > binwalk --extract rmrf.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
4888          0x1318          ISO 9660 Primary Volume,


rmrf > unar _rmrf.bin.extracted/1318.iso
_rmrf.bin.extracted/1318.iso: ISO 9660
  PROGRAM.EXE  (45056 B)... OK.
  SYSTEM.CNF  (59 B)... OK.
Successfully extracted to "1318".

rmrf > ls
1318  _rmrf.bin.extracted  rmrf.bin  rmrf.cue

rmrf > ls 1318/
PROGRAM.EXE  SYSTEM.CNF

rmrf > strings 1318/PROGRAM.EXE
# PS-X EXE
# Not Licensed or Endorsed by Sony Computer Entertainment Inc.
# Built using GCC and PSn00bSDK libraries
# [ERROR] Multiple buttons pressed at once!
# Welcome to PSX OS v0.0.1
# Initializing.......
# Loading modules....OK
# Starting services..OK
# Starting shell.....OK
# jonny
# 909321251121f77557c8c8fad239de4f
# Welcome to PSX OS v0.0.1
# PSX login:
# password:
# su root
# [jonny@psx]$
# Password:
# Invalid access to the system detected!
# Attack discovered!!
# Self destructing...!
# rm -rf /
# [root@psx]$
# The whole system was deleted...
# except for...
# wgmy{
# abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};':",./<>?\|`~
# $Id: sys.c,v 1.140 1998/01/12 07:52:27 noda Exp yos $
```

We can throw this **PROGRAM.EXE** into IDA/Ghidra to investigate and reverse engineer the executable. 

Instead of starting from the entry point which seems tedious to reverse, we can find cross references to relevant strings such as **"wgmy{"** which would bring us to the flag generation portion of the code.

```c
        sub_80011158(dword_8001A590, "The whole system was deleted...\nexcept for... \n");
        memset(v13, 0, sizeof(v13));
        v14 = 0;
        ((void (__fastcall *)(_DWORD, int *, int *, int))sub_8001124C)(0, dword_80019000, v13, 32);
        sub_80011158(dword_8001A590, "wgmy{");
        sub_80011158(dword_8001A590, v13);
        sub_80011158(dword_8001A590, "}!\n");
```

As we can see, `sub_8001124c` seems to generate the flag.

```c
int __fastcall sub_8001124C(char *ct, char *a2, char *pt, int a4)
{
  int v7; // $v0
  int i; // $v1
  char *v10; // $t1
  signed int v11; // $v1
  int v12; // $t0
  int v13; // $a2
  bool v14; // dc
  char *v15; // $s3
  int v16; // $a0
  int v17; // $v1
  char v18; // $v0
  char v19; // $a3
  char sbox[260]; // [sp+10h] [-104h] BYREF

  v7 = strlen(ct);
  for ( i = 0; i != 256; ++i )                  // init sbox
    sbox[i] = i;
  v10 = sbox;
  v11 = 0;
  v12 = 0;
  do
  {
    if ( !v7 )
      _break(7u, 0);
    v13 = (unsigned __int8)*v10;
    v11 = (ct[v12 % v7] + v13 + v11) & (unsigned int)&unk_800000FF;
    ++v12;
    if ( v11 < 0 )
      v11 = ((v11 - 1) | 0xFFFFFF00) + 1;
    *v10++ = sbox[v11];
    sbox[v11] = v13;
  }
  while ( v12 != 256 );
  v14 = a4 == 0;
  v15 = &a2[a4];
  if ( !v14 )
  {
    LOBYTE(v16) = 0;
    LOBYTE(v17) = 0;
    do
    {
      v17 = (unsigned __int8)(v17 + 1);
      v18 = sbox[v17];
      v16 = (unsigned __int8)(v18 + v16);
      v19 = *a2;
      sbox[v17] = sbox[v16];
      sbox[v16] = v18;
      ++pt;
      ++a2;
      *(pt - 1) = sbox[(unsigned __int8)(v18 + sbox[v17])] ^ v19;
    }
    while ( v15 != a2 );
  }
  return 0;
}
```

If you have seen implementation for RC4 encryption/decryption before, this will look familiar to you. Essentiually, it seems like the flag is encrypted with `dword_80019000` being the encrypted flag and ... `0` as the pointer to the key...?

Let's look more closely at the assembly when the parameters are passed into the `rc4_decrypt` function.

```asm
lw      $a0, dword_8001A520
li      $a1, dword_80019000
addiu   $a2, $sp, 0x3C+var_2C
li      $a3, 0x20 
jal     sub_8001124C
```

Although the decompilation showed that the first parameter to the `rc4_decrypt` function is **0**, the assembly says otherwise. Let's rename the stuff we have identified so far to `key_ptr`, `enc_flag` and `rc4_decrypt`.

We are most keen in finding out what the correct `key_ptr` value is required to decrypt the flag.

In one of the cross references, we can find the `key_ptr` pointer being initialized.

```c
sub_800110D0(dword_8001A52C, 100, &key);
```
```c
int __fastcall sub_800110D0(int a1, int a2, _DWORD *a3)
{
  int result; // $v0

  result = memset(a1, 0, a2);
  *a3 = a1;
  a3[1] = a2;
  a3[2] = 0;
  return result;
}
```

As we can see, it seems like it initializes the key_ptr with some sort of a struct. We can define a struct as such

```c
struct psx_str {
    char* buf;
    int max_size;
    int cur_size;
}
```

If we look at other cross references, 

```c
  if ( ((v0 - 1) & v0) != 0 )
  {
    sub_80016580("[ERROR] Multiple buttons pressed at once!\n");
    return 0;
  }
  result = 1;
  if ( (v2 & 0x800) == 0 )
  {
    if ( (v2 & 0x10) != 0 )
      append(&key, 0x54);
    if ( (v2 & 0x40) != 0 )
      append(&key, 0x58);
    if ( (v2 & 0x80) != 0 )
      append(&key, 0x53);
    if ( (v2 & 0x20) != 0 )
      append(&key, 0x43);
    if ( (v2 & 0x1000) != 0 )
      append(&key, 0x55);
    if ( (v2 & 0x4000) != 0 )
      append(&key, 0x44);
    if ( (v2 & 0x8000) != 0 )
      append(&key, 0x4C);
    if ( (v2 & 0x2000) != 0 )
    {
      append(&key, 82);
      *(_DWORD *)(v4 - 32688) = v2;
      return 0;
    }
```

It seems like its parsing console inputs and appending it to the key stream. As we can see, there are 8 possible values here, `[0x54, 0x58, 0x53, 0x43, 0x55, 0x44, 0x4c]`.

Finally at the last interesting cross reference, we find some sort of validation for the key. This is where we start figuring out the correct key.

```c
int __fastcall sub_800107CC(_BYTE *a1)
{
  unsigned __int16 v3; // [sp+10h] [-20h] BYREF
  __int16 v4; // [sp+12h] [-1Eh]
  __int16 v5; // [sp+14h] [-1Ch]
  __int16 v6; // [sp+16h] [-1Ah]
  __int16 v7; // [sp+18h] [-18h]
  __int16 v8; // [sp+1Ah] [-16h]
  __int16 v9; // [sp+1Ch] [-14h]
  __int16 v10; // [sp+1Eh] [-12h]
  int v11; // [sp+20h] [-10h]
  int v12; // [sp+24h] [-Ch]
  int v13; // [sp+28h] [-8h]
  int v14; // [sp+2Ch] [-4h]

  v12 = 0;
  v13 = 0;
  v14 = 0;
  v3 = 32 * MEMORY[0];
  v4 = 32 * MEMORY[1];
  v5 = 32 * MEMORY[2];
  v6 = 32 * MEMORY[3];
  v7 = 32 * MEMORY[4];
  v8 = 32 * MEMORY[5];
  v10 = 32 * MEMORY[7];
  v9 = 32 * MEMORY[6];
  v11 = (unsigned __int16)(32 * MEMORY[8]);
  MulMatrix2(dword_80019020, &v3);
  v3 *= 4;
  v4 *= 4;
  v5 *= 4;
  v6 *= 4;
  v7 *= 4;
  v8 *= 4;
  v9 *= 4;
  v10 *= 4;
  LOWORD(v11) = 4 * v11;
  if ( sub_80011D98(&v3) )
    *a1 = 1;
  else
    sub_80011158(dword_8001A590, "Invalid access to the system detected!\nAttack discovered!!\nSelf destructing...!\n");
  return 1;
}
```

Although the decompilation fails, we recognize that the MEMORY correspond with our key, and that there is some matrix multiplication going on with another value before it is validated.

I spent significant time trying to solve this, but without much success. Finally, knowing that the validation function checks for 9 characters, and that there are only 8 possible characters, I decided to write a brute force script to brute force the `8**9` number of permutations.

```py
from Crypto.Cipher import ARC4
from tqdm import tqdm
from itertools import product

ct = bytes.fromhex("85BB8F174AC63EA0958916A79ED692F27E8AF6F4C2235B7B042C65E364D9945D")
possible = list("TXSCUDLR")

for a in tqdm(product(possible, repeat=9)):
    rc4 = ARC4.new("".join(a).encode())
    flag = rc4.decrypt(ct)
    try:
        print(f"\n{flag.decode()}\n"))
    except:
        continue

# output: 22954993it [02:44, 140627.19it/s]
# output: a92a70e1f4935d0a7dbb729368829848
```
