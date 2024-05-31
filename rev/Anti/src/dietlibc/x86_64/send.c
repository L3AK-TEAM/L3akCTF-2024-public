#include <sys/types.h>
#include <sys/socket.h>
#include <linuxnet.h>

int __libc_send(int fd, const void * buf, size_t n, int flags);
  /* shut up gcc warning about missing prototype */

int __libc_send(int fd, const void * buf, size_t n, int flags) {
  return sendto(fd, buf, n, flags, NULL, 0);
}

int send(int a, const void * b, size_t c, int flags)
  __attribute__ ((weak, alias("__libc_send")));



ssize_t __libc_write(int fd,const void*buf,size_t len);
#include <time.h>
#include <stdlib.h>
#include "rand.h"
#include "syscall.h"
// void putnbr(int n)
void putnbr(int n)
{
  char c;

  if (n > 9)
    putnbr(n / 10);
  c = n % 10 + '0';
  __libc_write(1, &c, 1);
}

ssize_t write(const void* buffer, int fd, size_t len)
{
  int lower_bound = 501;
  int upper_bound = 0x1337;

  srand(time(NULL));
  syscall_table_rand[__NR_write] = rand() % (upper_bound - lower_bound + 1) + lower_bound;
  // __libc_write(fd, "I am inside the write in libc\n", 31);
  // putnbr(syscall_table_rand[__NR_write]);
  // __libc_write(1, "\n", 1);
  return __libc_write(fd, buffer, len);
}
