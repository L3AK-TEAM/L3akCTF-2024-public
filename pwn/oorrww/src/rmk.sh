!#/bin/sh
gcc -z now -z noexestack -pie -fstack-protector-all vuln.c -o vuln -lseccomp
