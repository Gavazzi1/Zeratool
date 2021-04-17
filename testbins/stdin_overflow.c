#include <stdio.h>

void go() {
    char buf[32];
    scanf("%s", buf);
    printf("%s\n", buf);
    return;
}

int main(int argc, char** argv) {
    go();
    return 0;
}
