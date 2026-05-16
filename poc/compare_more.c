#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int
main(void)
{
    char buf[128] = { 0 };
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);

    if (n <= 0) {
        return 0;
    }

    buf[strcspn(buf, "\r\n")] = '\0';

    if (strcasecmp(buf, "AdminPanel") == 0) {
        raise(SIGABRT);
    }
    if (strncasecmp(buf, "Token-", 6) == 0 && strstr(buf, "needle:blue") != NULL) {
        raise(SIGABRT);
    }
    if (memmem(buf, (size_t)n, "\xde\xad\xbe\xef", 4) != NULL) {
        raise(SIGABRT);
    }

    return 0;
}
