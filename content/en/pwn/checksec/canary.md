---
title: Stack Canary
date: 0007-01-01T00:00:08Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---


## Stack Canary

> Stack Canaries are a secret value placed on the stack which changes every time the program is started. Prior to a function return, the stack canary is checked and if it appears to be modified, the program exits immediately.

It is also **important** to note that canaries always have a null byte.

Let's consider our previously written C program.

Assuming we made a mistake when coding our program, we do not limit our input, which means that nasty nasty things could happen if we write more than what our `name[10]` can hold!

```c
#include <stdio.h>

int main() {
    char name[10];

    puts("What is your name?");
    scanf("%s", &name);
    printf("Hello %s", &name);
    return 0;
}
```

Let's compile this with ``gcc -fstack-protector hello.c``.

Let's try to input more than what `name[10]` could hold.

![image](/pwn/images/canary.png)

As you can see, our program aborts immediately without even echoing our input.

This is because when we exceed our 10 bytes of buffer in `name`, we have overwritten the canary and failed the check.

## Let's Delve deeper

Let's try to send an input that does not overflow name and see what our stack looks like in GDB.

```
00:0000│ rsp 0x7fffffffe5e0
01:0008│     0x7fffffffe5e8
02:0010│     0x7fffffffe5f0 ◂— 0x7475706e69796d /* 'myinput' */
03:0018│     0x7fffffffe5f8 ◂— 0x4a8dccd5c1ee0600 # this is the canary
04:0020│ rbp 0x7fffffffe600
```

As you can see, my input is stored on my stack, right before the canary. If I send a normal input that does not exceed my buffer, the canary is unchanged and will pass the check later on in the program.

Let me now overflow `name[10]` and see what the stack looks like in GDB.

```
00:0000│ rsp 0x7fffffffe5e0
01:0008│     0x7fffffffe5e8
02:0010│     0x7fffffffe5f0 ◂— 'aaaaaaaaaaaaaaaa'
03:0018│     0x7fffffffe5f8 ◂— 'aaaaaaaa' # canary was here
04:0020│ rbp 0x7fffffffe600
```

Our canary is gone! When our program checks the canary later, it will no longer be there and it will abort.

That is the **stack canary**.

<br><br>

---

<div style="text-align: right"> <a href="/pwn/checksec/aslr_pie">Next Page: Address Randomization</a> </div>
