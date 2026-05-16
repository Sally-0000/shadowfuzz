#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
    char buf[128] = {0};
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);

    if (n <= 0) {
        return 0;
    }

    /* Oracle for the security bug class: user-controlled format string. */
    if (strstr(buf, "%n") != NULL || strstr(buf, "%s%s%s") != NULL) {
        abort();
    }

    printf(buf);
    return 0;
}
