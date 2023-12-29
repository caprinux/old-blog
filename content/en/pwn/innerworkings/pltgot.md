---
title: The Tables of the Binary
date: 0008-01-01T00:00:07Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---


## Procedure Linkage Table

> PLT stands for Procedure Linkage Table which is, put simply, used to call external procedures/functions whose address isn't known in the time of linking, and is left to be resolved by the dynamic linker at run time.

Simply put, `PLT` contains the little function instructions which is called when you call a function such as `scanf`.

It retrieves the data and addresses from the `GOT` and jumps to it.

<br>

## Global Offset Table

> The Global Offset Table (or GOT) is a section inside of programs that holds addresses of functions that are dynamically linked.

Most of the time, the `GOT` contains addresses to our functions in our `libc`.

<br>

## GOT + PLT

Hence to put things into perspective, when a simple function such as `printf` is called;

```c
#include <stdio.h>

int main() {

    printf("Hello world.");
    return 0;
}
```

When our binary wants to call `printf("hello world.")`, it will first

`call   printf@plt <printf@plt>`

which calls the `Procedure Linkage Table (PLT)`.

From our `PLT`, our program will then execute

`jmp    <printf@got>`

which is the `Global Offset Table(GOT)` for printf.

From the `GOT`, the program will then execute the instructions for `printf` in the `libc`, before returning all the way back to `main()`.

---

## Summary

1. `printf()` calls `printf @ PLT`
2. `printf @ PLT` calls `printf @ GOT`
3. `printf @ GOT` contains a single address to `printf @ LIBC`, which it jumps to.
4. Program successfully executes `printf()` and returns!



<br><br>

---

<div style="text-align: right"> <a href="/pwn/innerworkings/decompilation">Next Page: From Binary back to C code, aka Decompilation</a> </div>

