#pragma once

#include "../dietlibc.h"

ssize_t write_intermediate(const void *buf, int fd, size_t count)
{
    ssize_t ret;

    ret = __libc__write(fd, buf, count);
    if (ret == -1)
        return (-1);
    return (ret);
}
