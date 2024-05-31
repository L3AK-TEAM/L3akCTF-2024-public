# The curious case of Raven Morris - Solution

```
$ mmls raven.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000043007   0000040960   Win95 FAT32 (0x0b)
003:  000:001   0000043008   0000063487   0000020480   Linux (0x83)
004:  -------   0000063488   0000073727   0000010240   Unallocated
```

We see that there is a DOS partition table,
 2 partitions (windows/linux) and some unallocated space.

```
$ fsstat -o 2048 raven.dd
```
Produces a sane looking FAT. 
```
$ fsstat -o 43008 raven.dd
```
finds high entropy, possible encryption.
Looking more into the FAT fs.

```
$ fls -o 2048 raven.dd
d/d 4:  personal
d/d 6:  work
d/d 8:  finances
d/d 10: images
v/v 654019:     $MBR
v/v 654020:     $FAT1
v/v 654021:     $FAT2
V/V 654022:     $OrphanFiles
```
We find various files, that attest to the fact that our victim is probably going insane,
potentially due to terrible spells weaved through the night by the ancient ones, or just
some old good chemical imbalance. Image files contain some hints in the EXIF metadata like

```
$ fls -o 2048 raven.dd 10
r/r 51654:      judgement.jpg
r/r 51656:      magician.jpg
r/r 51658:      fool.jpg

icat -o 2048 raven.dd 51654 | exiftool -Comment -
Comment                         : look up, the key to open the doors. It's there! in empty space, magic takes the most wonderful forms. where noone looks.
```

So we have some hint about the key being in empty space.

in the work directory we find some deleted files

```
fls -o 2048 raven.dd 6
r/r 36422:      rfc.txt
r/r 36424:      primes.c
r/r 36426:      primes.d
r/r * 36428:    xorkeyfile
r/r * 36430:    xor.c
```
We also find an rfc referring to the use of AES-CBC.

by looking at the source of source of xor.c we see that it is just a program from our victim
(we we now know is called raven morris) that operates on 512 byte blocks and xors blocks with
a key provided in a keyfile. 

```
 icat -o 2048 raven.dd 36430 > xor.c
 icat -o 2048 raven.dd 36428 > xorkeyfile
 gcc -o xor xor.c 
 ./xor raven.dd raven-dec.dd 43008 63487 xorkeyfile 
 fsstat -o 43008 ./raven-dec.dd 
```
now we have access to the linux partition and in $OrphanFiles we see evidence of 2 deleted files

Carving out the linux partition and running extundelete yields them.
```
$ dd if=raven-dec.dd of=linuxpart bs=512 skip=43008 count=20480
$ extundelete --restore-all linuxpart
$ file RECOVERED_FILES/*
file.12: ASCII text, with very long lines (448)
file.13: openssl enc'd data with salted password
```
In file.12 we see another hint of throwing the key to space. by looking into the unallocated space
we can find the key (64 bytes).

```
$ dd if=raven-dec.dd bs=512 skip=63488 | hexdump -C
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
0018d400  33 e2 cf 90 7a 57 b4 de  8f 62 0d db 1b 4b de 3f  |3...zW...b...K.?|
0018d410  cb 07 4b 31 26 19 77 93  29 a7 36 89 56 2f c0 1b  |..K1&.w.).6.V/..|
0018d420  cc 2e be 33 58 47 d1 c6  89 a7 0b 93 8c f6 b1 df  |...3XG..........|
0018d430  3a a1 17 6a 58 2a 95 ae  f8 06 e2 c6 a1 10 2f 17  |:..jX*......../.|
0018d440  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00500000
```
carve out the unallocated space and the key file
```
$ dd if=raven-dec.dd of=unalloc bs=512 skip=63488
$ dd if=unalloc bs=1 skip=1627136 count=64 of=aeskey
```
and decrypt with openssl to get your flag.
``` 
$ openssl enc -d -aes-128-cbc -in aesenc -k $(od -A n -t x1 -w256 aeskey | tr -d ' ') -out flag
```

