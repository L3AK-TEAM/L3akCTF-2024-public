FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y qemu-system-x86 qemu-utils socat cpio gzip wget 

EXPOSE 1337

RUN useradd -d /home/ctf -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
RUN ulimit -c 0

WORKDIR /home/ctf

COPY bzImage ./bzImage
COPY run.sh ./run.sh
COPY rootfs.cpio ./rootfs.cpio

RUN chmod +x ./run.sh
RUN chmod 666 ./rootfs.cpio

USER ctf
CMD socat tcp-l:1337,reuseaddr,fork EXEC:"./run.sh",pty,stderr

