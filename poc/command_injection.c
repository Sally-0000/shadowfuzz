#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
has_shell_metachar(const char *s)
{
    return strpbrk(s, ";&|`$<>") != NULL;
}

int
main(void)
{
    char user[128] = {0};
    char command[256];
    ssize_t n = read(STDIN_FILENO, user, sizeof(user) - 1);

    if (n <= 0) {
        return 0;
    }

    user[strcspn(user, "\r\n")] = '\0';
    snprintf(command, sizeof(command), "lookup-user --name '%s'", user);

    /* Safe oracle: detect command injection input without executing a shell. */
    if (has_shell_metachar(user)) {
        abort();
    }

    return command[0] == '\0';
}
