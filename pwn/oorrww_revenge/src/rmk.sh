!#/bin/sh
gcc -z now -z noexestack -no-pie -fstack-protector vuln.c -o vuln -lseccomp