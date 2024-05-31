#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

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

char *flag()
{
    char *str = malloc(512);
    c(str, 'L','3','A','K','{','b','4','b','y','_','s','T','3','P','s','}', 0);
    return str;
}

int main(int argc, char **argv)
{
    char *str = flag();
    if (argv[1] && !strcmp(argv[1], str))
        printf("Correct!\n");
    else
        printf("Wrong!\n");
    return 0;
}
