#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
    volatile uint32_t acc = 0;
    char buf[4] = {0};
    int rounds = 256;

    if (read(STDIN_FILENO, buf, sizeof(buf)) > 0 && buf[0] == 'L') {
        rounds = 512;
    }

    for (int i = 0; i < rounds; i++) {
        acc += (uint32_t)i;
    }

    if (acc == 0xffffffffU) {
        puts("unreachable");
    }
    return 0;
}
