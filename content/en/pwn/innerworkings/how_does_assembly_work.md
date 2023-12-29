---
title: How does Assembly work?
date: 0008-01-01T00:00:08Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---



## New concepts Covered
- Registers
- Stack
- Assembly Instructions
- Calling Conventions

---

Please watch this [video](https://www.youtube.com/watch?v=75gBFiFtAb8) on x86 Assembly, it's really amazing.
<br>

## Registers
---

> A register is a location within the processor that is able to store data, much like RAM. Unlike RAM however, accesses to registers are effectively instantaneous.

There are actually 17 registers in an `AMD64 architecture`, aka `64 bit`.

14 of which are general purpose registers:
`rax`, `rbx`, `rcx`, `rdx`, `rdi`, `rsi`, `r8`, `r9`, `r10`, `r11`, `r12`, `r13`, `r14`, `r15`

and 3 of which are reserved registers:
`rbp`, `rsp`, `rip`.

`rbp` : 64-Bit Base Pointer

`rsp` : 64-Bit Stack Pointer

`rip` : 64-Bit Instruction Pointer

We will cover `rbp` and `rsp` when we talk about the **stack**,

`rip` when we cover assembly instructions!

Some of the general purpose registers also have some specific functions, which we will also talk about later in the chapter.

<br>

#### Sizing Conventions

Registers with prefix `r-` often has a size of 64-bits for 64-Bit binaries.

However, such registers can have different sized accesses for backwards compatibility.

For example, the `rax` is the full **64-bits** register, the `eax` is the **low 32-bits** of the `rax` register, `ax` is the **low 16-bits**, `al` is the **low 8-bits** and `ah` is the **high 8-bits** of `ax`.

![image](/pwn/images/assemblyregister1.png)

![image](/pwn/images/assemblyregister2.png)

<br>

## The Stack
---
As convenient as registers are, they are insufficient in holding large-data.

Then the question is, where are our data and variables stored at???

**Stack.**

> In x86, the stack is simply an area in RAM that was chosen to be the stack - there is no special hardware to store stack contents. The esp/rsp register holds the address in memory where the bottom of the stack resides.

Think of the **stack** as a **tower**:

![image](/pwn/images/towerstack.png)

When we want to add a new block, we add it on top, and when we want to remove a block, we remove from the top. _if you remove from the bottom the whole tower will topple!!_

This is exactly same as the stack.

When we add a block on top, we use a `push` instruction.

When we remove a block from the top, we use a `pop` instruction.

![image](/pwn/images/stackstructure.jpg)

In our stack, these blocks holds a size based on the data it stores.

_i.e. if we declare a variable `name[10]`, a block size 10 will be pushed onto the stack._

<br>

## Assembly Instructions
---

If you have not watched this [x86 Assembly video](https://www.youtube.com/watch?v=75gBFiFtAb8) yet, please do go watch now.

<br>

>  An assembly language is a low-level programming language designed for a specific type of processor.

If you are compiling a C program, it is compiled from C to assembly code which can then be interpreted by the machine.

However, we could also write assembly directly. However, how do we call functions that `read` and `write` without our `LIBC functions`?

This is where **syscall** comes in.

> A system call is a request made by a program to the operating system. It allows an application to access functions and commands from the operating system's API.

`Syscall` takes in a few arguments from **specific registers**, and executes it.

Look at this [syscall table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) which shows the types of functions available and the arguments taken in.

<br>

Consider the following program which is written in assembly, which we will try to interpret.

```asm
.global _start
_start:
.intel_syntax noprefix

        push rbp
        mov rbp, rsp
        sub rsp, 50

        mov rax, 0
        mov rdi, 0
        mov rsi, rsp
        mov rdx, 10
        syscall

        mov rax, 1
        mov rdi, 1
        mov rsi, rsp
        mov rdx, 10
        syscall

        mov    rax, 60
        mov    rdi, 0
        syscall

```

```asm
.global _start
_start:
.intel_syntax noprefix
```

This chunk just initializes the assembly code so that it can be compiled.

```asm
push rbp
mov rbp, rsp
sub rsp, 50
```

This sets the base pointer, moves the stack pointer to it, and subtract stack pointer by 50.

Now we have a stack of 50 bytes, with `rbp` and `rsp` denominating the 2 ends.

```asm
mov rax, 0
mov rdi, 0
mov rsi, rsp
mov rdx, 10
syscall
```

This sets the following registers:

`rax`: 0        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; _system call index (read)_

`rdi`: 0        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; _file descriptor (0=input, 1=output, 2=error)_

`rsi`: rsp      &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; _buffer (aka location of input/output)_

`rdx`: 10       &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; _count (aka size of input/output)_

If we refer to our **syscall table**, we see the significance of each register as shown above.

We can see that the `syscall` reads an input of size 10 at our stack pointer.

This means our input will be on the stack.

```asm
mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 10
syscall
```

This sets the following registers:

`rax`: 1&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_system call index (write)_

`rdi`: 1&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_file descriptor (0=input, 1=output, 2=error)_

`rsi`: rsp&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_buffer (aka location of input/output)_

`rdx`: 10&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_count (aka size of input/output)_

In this chunk, we can see that our `syscall` write to our output 10 bytes of whatever is at RSP.
<br>

In short, the program runs `read(STDIN, rsp, 10)`

Hence, putting all the pieces together, we see that it echoes our input!

Compile with ``gcc -nostdlib -static <asm file name>``

![image](/pwn/images/assemblyprogram1.png)

<br>

## Calling Conventions
---

Now we have seen how assembly instructions work with syscall, what about assembly instructions after being compiled from a C program?

Consider the same C program we wrote in the previous ``How does C Programming work`` tutorial.

```c
#include <stdio.h>

int main() {
    char name[10];
    int somevalue = 10;

    puts("What is your name?");
    scanf("%10s", &name);
    printf("Hello %s", &name);
    return somevalue;
}
```

How does assembly parse arguments into functions such as `scanf`?

Well, for 64-bit binaries, function arguments are first passed in certain registers:

  1. `RDI`
  2. `RSI`
  3. `RDX`
  4. `RCX`
  5. `R8`
  6. `R9`

then any leftover arguments are taken from the stack.

Hence, `%10s` will be parsed into RDI, and `&name` will be parsed into RSI.

As the function ends, it attempts to return `somevalue` to the caller function.

This return value goes into rax.
<br><br>

---

<div style="text-align: right"> <a href="/pwn/innerworkings/pltgot">Next Page: The Tables of the Binary (GOT/PLT)</a> </div>

