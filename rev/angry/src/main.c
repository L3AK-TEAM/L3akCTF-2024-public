#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

// L3AK{angr_4_l1f3_d0nt_do_iT_m4nU4lly}
// 0123456789012345678901234567890123456789
// [0x4c, 0x33, 0x41, 0x4b, 0x7b, 0x61, 0x6e, 0x67, 0x72, 0x5f, 0x34, 0x5f, 0x6c, 0x31, 0x66, 0x33, 0x5f, 0x64, 0x30, 0x6e, 0x74, 0x5f, 0x64, 0x6f, 0x5f, 0x69, 0x54, 0x5f, 0x6d, 0x34, 0x6e, 0x55, 0x34, 0x6c, 0x6c, 0x79, 0x7d]

int get_5f()
{
    int a = 5;
    a *= 10;
    a--;
    a += 25;
    a *= 2;
    a >>= 2;
    return (a ^ 122);
}

int get_len()
{
    return (222/(2 + 2 + 2));
}



int more_checks(char *input)
{
    // check these indexes : 8,9,23,29
    // printf("%c %c %c %c\n", input[8], input[9], input[23], input[29]);
    if (input[8] == 0x72 && input[9] == 0x5f && input[23] == 444 >> 2 && input[29] == 0x34)
    {
        if ((input[10] & ~0x30) < 10)
            return (true);
    }
    return (false);
}

// create a function that checks the input letter by letter
int compare(char *input)
{
    if (strlen(input) == get_len())
        if (input[5] * input[15] - input[7] == 4844)
            if (input[6] == 0x6e && (-input[7] * -input[7] == 10609) && (input[8] ^ 0xde == 172))
                if ((input[9] ^ 0xad == 242) && (input[10] << 2 == 208) && input[11] == 0x5f)
                    if (input[12] == 0x6c && (input[13] ^ input[0] ^ input[1] ^ input[2] ^ input[3] == 68) && (input[14] + input[15] + input[16] + input[17] == 348))
                        if ((input[15] ^ input[1] ^ input[2] == 65) && (input[16] + input[21] - input[25] == 85) && (input[17] - input[32] + input[33] == 156))
                            if (input[18] == 0x30 && input[19] == 0x6e && input[20] == 0x74)
                                if (((input[21] ^ input[17]) == 59) && input[22] == 0x64 && (input[23] ^ 3 + input[21] == 13))
                                    if (input[24] == 0x5f && (input[25] - input[5] == 8) && (2 * input[26] - 2^10 == 172))
                                        if (input[27] == 0x5f && (input[28] + input[21] - input[25] == 99) && (input[29] ^ input[31] + input[28] == 246))
                                            if (input[30] == 0x6e && (input[31] ^ input[13] == 100) && (input[34] + input[31] == 193) && (input[32] + input[33] == 160))
                                                if (input[33] == 0x6c && (input[33] - input[1] == 57) && input[34] == 0x6c && input[35] == 0x79 && input[36] == 0x7d)
                                                    return (true);
    return (false);
}

void chomp(char *s)
{
    while (*s && *s != '\n' && *s != '\r')
        s++;
    *s = 0;
}

void get_string(char *buf, char *prompt, int length)
{
    printf("%s", prompt);
    fgets(buf, length, stdin);
    chomp(buf);
}

int main(void)
{
    char* name = (char*) malloc(sizeof(char));

    // printer("So you made it to the second round huh ?!");
    // printer("But don't think this is gonna be as easy as the previous one ;)");
    // printer("I am not gonna give you the flag on plaintext now :))))");
    get_string(name, "Give me a password : ", 40);
    if (compare(name))
    {
        if (more_checks(name))
            printf("Congratulations !\n");
        else
            printf("Bruh : (\n");
    }
    else
        printf("Bruh : (\n");
    return (0);
}