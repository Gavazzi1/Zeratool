#include <stdio.h>
#include <stdlib.h>

int go() {
    char buffer[1024];

    FILE *f = fopen("file.txt", "r");
    if (f == NULL) {
        printf("fopen failed\n");
        return 1;
    }
    int games = 0;
    int len = 0;
    fseek(f, 0, SEEK_SET);
    fread(&games, 1, 4, f);
    printf("games = %d\n", games);
    while (games > 0) {
        fread(&len, 1, 4, f);
        printf("len = %d\n", len);
        size_t val = len;
        printf("val = %zu\n", val);
        fread(buffer, 1, len, f);
        buffer[len] = 0;
        --games;
    }

    return 0;
}


int main() {
    return go();
}
