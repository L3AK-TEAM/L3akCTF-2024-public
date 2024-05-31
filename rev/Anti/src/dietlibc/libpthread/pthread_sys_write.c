#include <unistd.h>

#include <pthread.h>
#include "thread_internal.h"

ssize_t write(const void *buf, int fd, size_t count) {
  __TEST_CANCEL();
  return __libc_write(fd,buf,count);
}
