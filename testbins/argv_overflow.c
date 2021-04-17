#include <string.h>
#include <stdio.h>

void go(char* arg) {
    char buf[32];
    strcpy(buf, arg);
    printf("%s\n", buf);
    return;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    go(argv[1]);
    return 0;
}



