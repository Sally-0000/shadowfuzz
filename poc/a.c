#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main() {
    char buf[0x20];
    puts("Hello, World!");
    read(0, buf, 0x40);
    return 0;
}