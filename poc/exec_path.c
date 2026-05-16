#include <string.h>
#include <unistd.h>

int
main(void)
{
    char path[128] = {0};
    char *const argv[] = {path, NULL};
    ssize_t n = read(STDIN_FILENO, path, sizeof(path) - 1);

    if (n <= 0) {
        return 0;
    }

    path[strcspn(path, "\r\n")] = '\0';
    execv(path, argv);
    return 0;
}
