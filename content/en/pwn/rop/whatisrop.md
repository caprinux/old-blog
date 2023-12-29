---
title: Return Oriented Programming
date: 0005-01-01T00:00:09Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---

> Return Oriented Programming (or ROP) is the idea of chaining together small snippets of assembly with stack control to cause the program to do more complex things.

As we saw in Buffer Overflows, having stack control can be very powerful since it allows us to overwrite saved instruction pointers to control the flow of the program and call programs that was never called in the function.

However, some functions may require arguments that we have to pass, whilst sometimes we may not even have a `win()` or a `give_shell()` function at all.

This is where ROP comes in. ROP allows us to piece together bits and pieces of instructions to do many many things and get even stronger control over our program as a whole.

In this chapter, we will cover many of these powerful techniques.

<br><br>

---

<div style="text-align: right"> <a href="/pwn/rop/ropgadgets">Next Page: ROP Gadgets</a> </div>


