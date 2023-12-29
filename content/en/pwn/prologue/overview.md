---
title: README
date: 0009-01-01T00:00:01Z
draft: false
description: Pwn for Fun and Profit is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on The Art of Pwn.
toc: false
---

_Pwn for Fun and Profit_ is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on `The Art of Pwn`.

I wrote this tutorial to provide people with the things I hope I knew / was told when I first started off on my pwn journey.

I hope that you enjoy this tutorial as much as I enjoyed writing it, and that it was useful to you.

<br>

- **Prologue**
  1. [What is Pwn?](/pwn/prologue/what_is_pwn)

- **The ELF Executable**
  1. [The C Program](/pwn/innerworkings/how_does_c_programming_work)
  2. [Assembly and the Stack](/pwn/innerworkings/how_does_assembly_work)
  3. [The Tables of the Binary](/pwn/innerworkings/pltgot)
  4. [Binary Decompilation](/pwn/innerworkings/decompilation)
  5. [The x86 Memory](/pwn/innerworkings/memory)


- **Securities of a Binary**
  1. [no eXecute (NX)](/pwn/checksec/nx)
  2. [Stack Canary](/pwn/checksec/canary)
  3. [Binary Randomization (ASLR/PIE)](/pwn/checksec/aslr_pie)
  4. [Relocation Read-Only (RELRO)](/pwn/checksec/relro)

- **Breaking The Stack**
  1. [Buffer Overflow](/pwn/stack/bof)
        * [WhiteHacks 2021 - Puddi Puddi](/pwn/stack/bof#whitehacks-2021---puddi-puddi)
        * [dCTF 2021 - Pinch_Me](/pwn/stack/bof#dctf-2021---pinch-me) _(dynamic analysis, little-endian)_
  2. [Return 2 Win](/pwn/stack/ret2win)

- **Return Oriented Programming**
  1. [What is Return Oriented Programming?](/pwn/rop/whatisrop)
  2. [ROP Gadgets](/pwn/rop/ropgadgets)
  3. [Return 2 Libc: The Concept](/pwn/rop/ret2libc1)
  4. [Return 2 Libc: Execution](/pwn/rop/ret2libc2)


<br>

---

<br>

## Additional Resources

* [Good Reads](https://tinyurl.com/infosecgrail)
  * Hacking: The Art of Exploitation 2
  * Practical Binary Analysis
  * The Shellcoders Handbook 2nd Edition
  * Practical Reverse Engineering

* WarGames/CTFs
  * [PicoCTF](https://play.picoctf.org/practice )
  * [Narnia OverTheWire](https://overthewire.org/wargames/narnia/)
  * [Pwnable KR](https://pwnable.kr/play.php )
  * [Pwnable TW](https://pwnable.tw/challenge/)

* Learning Resources
  * [CTF101](https://ctf101.org/)
  * [Nightmare](https://guyinatuxedo.github.io/00-intro/index.html)
  * [Live OverFlow](https://tinyurl.com/liveoverflowtutorial)
  * [Pwn College](https://pwn.college/) (lecture+practices)
  * [RPISEC](https://github.com/RPISEC/MBE) (lecture+practice)
  * [Principles of Pwning (PoP)](https://dystopia.sg/pwning/)

