---
title: Binary Randomization (ASLR/PIE)
date: 0007-01-01T00:00:07Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---


## ASLR

> Address Space Layout Randomization (or ASLR) is the randomization of the place in memory where the program, shared libraries, the stack, and the heap are.

What this means basically is that every single time you rerun the binary, your functions, stack and heap addresses will have different addresses each time.

However, the only thing that stays constant is the offsets between each address.

Hence, if you are able to calculate the `ASLR base address` during that run of the binary, you can possibly calculate all addresses easily.

<br>

## PIE

> PIE, like the ASLR, randomizes the base address but in this case it is from the binary itself. This makes it difficult for us to use gadgets or functions of the binary.

PIE is almost identical to ASLR. Except **more hardcore**.

**Everything**, **every single address**, will be randomized which means everything will have different addresses during each run of the binary.

Likewise, offsets between each address will still remain the same.

If you are able to calculate the `PIE base address` during that run of the binary, you can possible calculate all addresses easily.

<br><br>

---

<div style="text-align: right"> <a href="/pwn/checksec/relro">Next Page: Relocation Read-Only (RELRO)</a> </div>
