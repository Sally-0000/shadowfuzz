#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
    char user[96] = {0};
    char command[192];
    ssize_t n = read(STDIN_FILENO, user, sizeof(user) - 1);

    if (n <= 0) {
        return 0;
    }

    user[strcspn(user, "\r\n")] = '\0';
    snprintf(command, sizeof(command), "true %s", user);
    return system(command);
}
