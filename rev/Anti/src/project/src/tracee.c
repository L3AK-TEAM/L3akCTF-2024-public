#include "main.h"

void int_to_hex_str(int num, char *str) {
    const char hex_chars[] = "0123456789abcdef";
    int i, temp;
    
    // Initialize the string with null characters
    for (i = 0; i < 8; i++) {
        str[i] = '0';
    }
    str[8] = '\0';

    // Convert integer to hexadecimal
    for (i = 7; num > 0 && i >= 0; i--) {
        temp = num & 0xF;
        str[i] = hex_chars[temp];
        num >>= 4;
    }
}

void write_hex(int num)
{
    char hex_str[9]; // 8 characters for hex + 1 for null terminator
    int_to_hex_str(num, hex_str);

    // Write the hexadecimal string to standard output
    write(hex_str, 1, 8);
}

// void
// tracee(void)
// {
    // ptrace(PTRACE_TRACEME, 0, 0, 0);
    // raise(SIGCONT);
//     write("ccccccc\n", 1, 9);
// }

void appendChar(char *buf, char arg) {
    size_t len = strlen(buf);
    buf[len] = arg;
    buf[len + 1] = '\0';
}

void c(char *buf, ...)
{
	va_list args;
	va_start (args, buf);     /* Initialize the argument args. */

	char arg = va_arg(args, int);
	
	while( arg ) {
		appendChar(buf, arg);
		arg = va_arg(args, int);
	}

	va_end (args);                  /* Clean up. */
}


char *debug_me_if_you_can()
{
	char *str = malloc(512);
	c(str, 'D','e','b','u','g', ' ', 'm', 'e', ' ', 'i', 'f', ' ', 'y', 'o', 'u', ' ', 'c', 'a', 'n', ' ', '!', '\n', 0);
    return str;
}

char *you_are_on_the_right_track()
{
	char *str = malloc(512);
	c(str, 'Y','o','u',' ', 'a', 'r', 'e', ' ', 'o', 'n', ' ', 't', 'h', 'e', ' ', 'r', 'i', 'g', 'h', 't', ' ', 't', 'r', 'a', 'c', 'k', '\n', 0);
    return str;
}

char *obfuscated()
{
    char *str = malloc(512);
    c(str, 'o','b','f','u','s','c','a','t','e','d', 0);
    return str;
}

char *Correct()
{
    char *str = malloc(512);
    c(str, 'C','o','r','r','e','c','t','!','\n', 0);
    return str;
}

char *tmp()
{
    char *str = malloc(512);
    c(str, '/','t','m','p','\0');
    return str;
}

char *hidden()
{
    char *str = malloc(512);
    c(str, 'h','i','d','d','e','n','\0');
    return str;
}

char    *get_cmdline()
{
    pid_t parent_pid = getppid();
    char path[1024];
    char cmdline[1024];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", parent_pid);
    int fd = open(path, 0);
    if (fd == -1) {
        perror("open");
        return NULL;
    }
    ssize_t ret = read(fd, cmdline, sizeof(cmdline));
    if (ret == -1) {
        perror("read");
        close(fd);
        return NULL;
    }
    // Replace null bytes with spaces
    for (int i = 0; i < ret - 1; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    // Ensure the string is null-terminated
    cmdline[ret] = '\0';
    char **tokens = ft_split(cmdline, ' ');
    close(fd);

    if (strcmp(tokens[0], "./antii") != 0) {
        return NULL;
    }
    return tokens[1];
}

int leftRotate(int n, unsigned int d)
{
    return (n << d)|(n >> (sizeof(n) * 8 - d));
}

// Static Hash function Q
int Q(int b, int rand)
{
    return b ^ (leftRotate(b, rand));
}
// uint32_t get_bit(uint32_t a, uint32_t n)
// {
//     return (a >> n) & 1;
// }

// // get the next index in the Q function
// uint32_t next_idx(uint32_t idx)
// {
//     return (idx + 17) % 32;
// }

// uint32_t recover_b(uint32_t q, uint32_t last_bit)
// {
//     uint32_t result = last_bit & 1; // least significant bit can be set to 1 or 0

//     uint32_t prev_idx = 0;
//     uint32_t cur_idx = next_idx(prev_idx);

//     while (cur_idx != 0) {
//         uint32_t bit_to_set = get_bit(q, cur_idx) ^ get_bit(result, prev_idx);
//         result |= (bit_to_set << cur_idx);

//         prev_idx = cur_idx;
//         cur_idx = next_idx(prev_idx);
//     }

//     return result;
// }

void    num_print(uint32_t n)
{
    char    c;

    if (n > 9)
        num_print(n / 10);
    c = n % 10 + '0';
    write(&c, 1, 1);
}

// int compare(uint32_t b)
// {
//     num_print(b);
//     int recovered = recover_b(b, 1);
//     write("\n", 1, 1);
//     num_print(recovered);
//     return 0;
// }

uint32_t m_to_uint32(const char* m)
{
    uint32_t result = 0;
    for (size_t i = 0; i < 4; i++) {
        result = (result << 8) | (uint8_t)m[i];
    }
    return result;
}

int compare(uint32_t *S)
{
    if (S[0] == 518016411 && S[1] == 4152142508 && S[2] == 1156902051 && S[3] == 2196107258) {
        return 1;
    }
    return 0;
}

// Hashfunction H
uint32_t H(const char* m, int rand)
{
    uint32_t S[4];

    for (int i = 0; i < 4; i++) {
        S[i] = m_to_uint32(m + i * 4);
        // num_print(S[i]);
        // write("\n", 1, 1);
        S[i] = Q(S[i], rand);
        // num_print(S[i]);
        // write("\n", 1, 1);
    }

    return compare(S);
}


void tracee(void)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGCONT);
    write(debug_me_if_you_can(), 1, strlen(debug_me_if_you_can()));
    // strings randomizer
    srand(RANDOM_VALUE);
    int random_number = rand();
    // Store current directory
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd");
        return;
    }
    
    // Change directory to /tmp
    if (chdir(tmp()) == -1) {
        perror("chdir");
        return;
    }
    
    // Write to a tmp file
    int fd = open(hidden(), 64 | 1 | 512, 256 | 128);
    if (fd == -1) {
        perror("open");
        return;
    }
    // create a function that gets the pid of the parent and prints the /proc/pid/cmdline
    ssize_t ret = write(you_are_on_the_right_track(), fd, strlen(you_are_on_the_right_track()));
    // write(&random_number, fd, 4);
    if (ret == -1) {
        perror("write");
        close(fd);
        return;
    }

    char *av = get_cmdline();
    if (av == NULL) {
        return;
    }
    // hash and compare
    int flag = H(av, random_number);
    if (flag == 1) {
        write(Correct(), 1, strlen(Correct()));
    }

    // Close the file
    ret = close(fd);
    if (ret == -1) {
        perror("close");
        return;
    }
    
    // Change back to the original directory
    if (chdir(cwd) == -1) {
        perror("chdir");
        return;
    }
}
