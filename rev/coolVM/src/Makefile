CC 	= /usr/bin/x86_64-linux-musl-gcc
CF 	= -fpie -fPIC -static -O3 -Wl,-z,relro
CO 	= coolVM_dist
CS 	= main_dist.c

all: dist

dist:
	$(CC) $(CF) -o $(CO) $(CS)
	strip $(CO)
	
clean: 
	rm $(CO)