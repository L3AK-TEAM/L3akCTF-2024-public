#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file;
    char filename[] = "flag.txt";

    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char c;
    while ((c = fgetc(file)) != EOF) {
        putchar(c);
    }

    fclose(file);
    return 0;
}