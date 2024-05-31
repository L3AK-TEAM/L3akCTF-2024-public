#!/bin/bash

qemu-system-x86_64 \
    -m 100M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "console=ttyS0 kaslr oops=panic panic=1 pti=on quiet" \
    -cpu qemu64,+smep,+smap \
    -monitor /dev/null \
    -nographic \
    -no-reboot \

