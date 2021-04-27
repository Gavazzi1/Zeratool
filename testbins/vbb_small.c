#include <stdio.h>
#include <stdlib.h>

int go() {
    char buffer[64];

    FILE *f = fopen("file.txt", "r");
    if (f == NULL) {
        printf("fopen failed\n");
        return 1;
    }
    unsigned char games = 0;
    unsigned short len = 0;
    fseek(f, 0, SEEK_SET);
    fread(&games, 1, 1, f);
    while (games > 0) {
        fread(&len, 1, 2, f);
        fread(buffer, 1, len, f);
        buffer[len] = 0;
        --games;
    }

    return 0;
}


int main() {
    return go();
}
