#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
    char buf[64] = {0};
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);

    if (n <= 0) {
        return 0;
    }

    buf[strcspn(buf, "\r\n")] = '\0';

    if (strcmp(buf, "OpenSesame42!") == 0) {
        raise(SIGABRT);
    }

    return 0;
}
