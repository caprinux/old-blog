---
title: no eXecute (NX)
date: 0007-01-01T00:00:09Z
draft: false
description: nil
toc: false
---

## New Concepts Covered
- Check Binary Security
- No eXecute

<br>

## Check Binary Security
---

You need PwnTools (`pip install pwntools`) OR Checksec Tool (``sudo apt-get install checksec``)

Simply run ``checksec <binary-name>`` in order to list the security in the binary.

For example,

![image](/pwn/images/checksec.png)

<br>

## No eXecute

> The No eXecute or the NX bit (also known as Data Execution Prevention or DEP) marks certain areas of the program as not executable, meaning that stored input or data cannot be executed as code.

This is important because NX differentiates **code** from **data**. It prevents the program from interpreting your **data** as **code** and executing it.

This is important because if someone can input data to be executed by the machine, they can ideally do malicious things such as obtaining a shell on a remote service.

Consider our previous C program

```c
#include <stdio.h>

int main() {
    char name[10];

    puts("What is your name?");
    scanf("%10s", &name);
    printf("Hello %s", &name);
    return 0;
}
```

All our little instructions and function calls here are stored in binary numbers when it is compiled, which allows the machine to read it.

However, our variable `name[10]` is also stored in binary form, a bunch of 1s and 0s.

So how does the program differentiate between my `name[10]` data and my `instructions`.

That is why NX is important because it tells the machine which data is **executable** and which is **not**.

We will explore this protection further in our ``shellcode`` chapter!

<br><br>

---

<div style="text-align: right"> <a href="/pwn/checksec/canary">Next Page: The Stack Canary</a> </div>
