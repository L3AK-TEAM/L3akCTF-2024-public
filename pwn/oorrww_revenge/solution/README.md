# oorrww_revenge


## tl;dr
- `pop rax; ret;` and `mov rdi, rax;` in `gifts()` to leak libc_addr
- `-` bypass canary check
- write orw chain on bss and stack pivot to there
- happy flag (don't forget the data processing :)
