---
title: The x86 Memory
date: 0008-01-01T00:00:05Z
draft: false
description: nil
toc: false
---

This will be a very brief explanation of how the memory works in a program.

This is how the memory layout looks like in a program:

![image](/pwn/images/Program_memory_layout.pdf.jpg)

Let's get straight to our example

<br>

## Example

Consider the following program:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char data[1000] = "Hi I go to the .data section of the memory because I am a global variable with a defined value aka initialzed variables";

char bss[100];
int also_inside_bss;
// These 2 variables are in the bss section of the memory because they are global variables with no defined values aka uninitialised variables

void main() {

    char hello[100] = "Hi I go to the stack because I'm a variable initialized inside a function";
    char *heap;
    heap = malloc(100);
    strcpy(heap, "Hi I am in the heap because I have been malloc'ed");
}
```

And this is how it all comes together!

![image](/pwn/images/memory.png)

<br><br>

---

<div style="text-align: right"> <a href="/pwn/checksec/nx">Chapter 3: No eXecute (NX)</a> </div>
