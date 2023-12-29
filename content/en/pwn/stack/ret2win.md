---
title: Return2Win Technique
date: 0006-01-01T00:00:07Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---

## Prologue

**Recap:**

> RIP is the instruction pointer which is a 64-bit register that holds the memory address of the instruction to be executed next.

> Stack grows downwards. Newly popped data will be at lower addresses.
Simply put, a stack is a tower but upside down :p

> Each function has its own stack layout, denominated by rbp (base pointer) and rsp (stack pointer).

<br>

In order to understand how to ret2win, we have to learn more about what the stack layout as well as what happens behind the scenes when functions are called.

Let's consider this C program;

```c
#include <stdio.h>

int win() {
  printf("you can't call me ;)")
}

int vuln() {
    char name[10];

    gets(&name);
    return 0;
}

int main() {
    vuln();
    return 0;
}

```

When `vuln()` is called, we know that it calls `printf()` and returns to `main()`.

However, how does the program go back to main afterwards?

How does the program know where it was at in `main()` before the call?

Well before, `vuln()` is actually called, our `RIP` containing the address of the next instruction in `main()` will be saved on the stack.

This is known as the return address as when `vuln()` returns, the stack for the current function _(denominated by rbp and rsp)_ will be 'demolished', program will pop the return address from the stack.

When vuln is called, our `main()` stack layout will be saved, and a new stack will be 'created' for the `vuln()` function, even though it may not use the stack at all!

As you can see, we will save our `RBP`, then our `RIP`, before building our `vuln()` stack, if we need one at all.

![image](/pwn/images/x64_frame_nonleaf.png)

<br>

## Return 2 Win Theory

Since we know that our return address is actually saved on the stack and that `vuln()` will return to the return address, which **should** be at `main()`.

However, can we call `win()`, even though `win()` was not called at all in this entire program?

Consider our stack layout and the following terminating instructions of a function:

```asm
0x555555555153 <vuln+30>                  leave
0x555555555154 <vuln+31>                  ret <0x555555555163; main+14>
 ↓
0x555555555163 <main+14>                  mov    eax, 0


```

| :------------- |
|      ...       |
| :------------- |
| return address |
| :------------- |
|   saved rbp    | <- rbp
| :------------- |
|    name[10]    | <- rsp
| :------------- |


As shown above, when a function ends, it calls `leave` which 'destroys' the current stack frame of the function and restores our `main()` stack frame. We are left with;

| :------------- |
|      ...       |
| :------------- |
| return address | <- rsp
| :------------- |

And when `ret` aka `return` is called, the return address **or** `saved rip` is restored into the `rip`.

The `rip` will now be at `<main+14>` which was the next instruction after `vuln()` was called from `main()`.

If we could possibly overwrite the return address, we could possibly make our program return to any function we want.

Let's try it out!

<br>

## Exploiting our C program

```c
// gcc -no-pie win.c -o win
#include <stdio.h>

int win() {
  printf("you can't call me ;)")
}

int vuln() {
    char name[10];

    gets(&name);
    return 0;
}

int main() {
    vuln();
    return 0;
}

```

We will compile this without **PIE**.

`gets()` may seem unfamiliar to you, but let's look at it's documentation.

> The C library function char *gets(char *str) reads a line from stdin and stores it into the string pointed to by str. It stops when either the newline character is read or when the end-of-file is reached, whichever comes first.

Wow! This means that we have an unlimited input size, up till a newline character.

This gives us a buffer overflow, and we will try to overwrite the return address to call `win()`.

Let's first find `win()` function. We can do that in `GDB` or with `nm` which is a handy tool to list a program symbols.

```
➜ nm win | grep win
0000000000401132 T win
```

As we can see, our win is at `0x401132`.

Now let's calculate our offset. We will firstly calculate our offset with our theory. Consider the stack at the point of our input.

| :------------- |
|      ...       |
| :------------- |
| return address |
| :------------- |
|   saved rbp    |  <- rbp |
| :------------- |
|    name[10]    |  <- rsp |
| :------------- |

If we do `file win` or `checksec win`, we can see that it is a 64-bit binary.

This means that our addresses are stored as `64/8 = 8` bytes.

This means `saved rbp` is 8 bytes.

In order to overflow name and reach return address, we have to fill up a buffer of `10 (name) + 8 (rbp) = 18` bytes.

Hence our offset is 18.

Alternatively, we can send a de brujin sequence and see where our program tries to return to in gdb.

When sending `1111222233334444555566667777888899990000` as an input, our program segfaults as there is our return address is overwritten with random values that probably do not exist in the program.

```
► 0x401164 <vuln+31>    ret    <0x3737363636363535> # aka 77666655
```

As we recall, integers are stored in little-endian in a binary, this is the same for addresses. Hence, the address it tries to return to is in reverse order.

With some simple math, we can calculate our offset.

``4*4 + 2 = 18``

Putting all the pieces together, we can craft our exploit script.

```py
from pwn import * # import pwntools library

p = process('./win') # start porcess

WINADDRESS = 0x401132 # win address

p.sendline(b"A"*18 + p64(WINADDRESS)) # send input to process, with address in 64-bit little endian
p.interactive() # control process manually
```

Try it out and it should print `"You can't call me!"`.

<br>

---

## Practices

_coming soon..._

<br><br>

---

<div style="text-align: right"> <a href="/pwn/rop/whatisrop">Chapter 5: Introduction to Return Oriented Programming (ROP)</a> </div>
