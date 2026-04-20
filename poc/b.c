#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
    char buf[64] = {0};
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);

    if (n <= 0) {
        return 0;
    }

    if (buf[0] == 'A') {
        puts("level 1");
        if (buf[1] == 'B') {
            puts("level 2");
            if (buf[2] == 'C') {
                puts("level 3");
                if (buf[3] == 'D') {
                    puts("boom");
                    raise(SIGABRT);
                }
            }
        }
    }

    return 0;
}
