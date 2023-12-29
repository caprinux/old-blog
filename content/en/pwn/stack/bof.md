---
title: Stack Buffer Overflow 
date: 0006-01-01T00:00:09Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---

Finally! We are getting started on the real stuff 😏

If you have followed along this series so far, congratulations on coming thus far!

You have only just started on your road to becoming a pwn god and I hope you enjoy your journey :)

## Buffer Overflow Concept

Consider the following program.

```c
// gcc secret.c -o secret
#include <stdio.h>

int main() {

    char secret[20] = "you cant touch me";
    char name[10];

    puts("What is your name?");
    scanf("%s", &name);
    printf("Hello %s\n", &name);
    puts(&secret);
    return 0;
}
```

The program contains a variable `secret[20]`, which contains `you cant touch me`.

Nowhere in this program writes into this variable which means that we should not be able to modify the variable.

However, are we really not able to do so?

This program takes in an input **(with no size limit)** into a variable `name[10]`, with size limit of 10 bytes.

What would happen if we just continue to input more characters, and if we are not stopped by a canary?

We could possible overwrite other stuff. Let's have a look at our stack layout.

![image](/pwn/images/stackstructure2.jpg)

If we exceed `name[10]`, we will then write into `secret[20]` and more.

Let's test it out!

![image](/pwn/images/i touched secret.jpg)

We managed to overwrite `secret` with whatever we want, even though there is no function allowing us to write to `secret`.

That is the essence of buffer overflow.

**Overwriting things to use the program in ways it was not intended to be used.**

<br>

## Automating a BOF with pwntools

However, what if our buffer is like 50 bytes, does that mean we have to type out all 50 bytes?

We can use PwnTools - a python module built specifically for pwning.

```py
from pwn import *

p = process('./secret') # run the process
p.sendline("A"*10 + "i_touched_secret!") # send an input to the process
p.interactive() # go back to manually running the program
```

## Let's put this into action.

We will try 2 **Buffer Overflow** practices now.

Source code will **not** be provided, this is a good chance for you to practice your decompilation as well.

If you do not know how to decompile a binary, check out [From Binary back to C code, aka Decompilation](/pwn/innerworkings/decompilation).

#### WhiteHacks 2021 - Puddi Puddi

> Why have a MEGA 🍮 when you can have a GIGA 🍮?
>
> Attached: [puddi.zip](/pwn/files/puddi.zip)
>
> Objective is to print flag.txt through the binary

Solution can be found [here](/pwn/stack/bofsolutions#whitehacks-2021---puddi-puddi).

#### dCTF 2021 - Pinch Me

> This should be easy!
>
> Attached: [pinch_me](/pwn/files/pinch_me)
>
> Objective is to obtain a shell through the binary

Solution can be found [here](/pwn/stack/bofsolutions#dctf-2021---pinch-me).

<br><br>

---

_credits goes to the respective challenge creators for making the challenges._

_i do not OWN either of the 2 ctf challenges put up above. if you are the owner of the challenge and you would like me to take down your challenge, please email me and i will take it down asap._

<br><br>

---

<div style="text-align: right"> <a href="/pwn/stack/ret2win">Next Page: Return 2 Win Technique</a> </div>
