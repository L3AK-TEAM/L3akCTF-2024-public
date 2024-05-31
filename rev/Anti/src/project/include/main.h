#pragma once

// Standart Includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

// System Includes
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>

// My Includes
#include "tracee.h"
#include "tracer.h"

// SYSCALL MAPPING
#define SYS_CUSTOM_write 0x1337
#define RANDOM_VALUE (42)

char	**ft_split(char const *s, char c);
