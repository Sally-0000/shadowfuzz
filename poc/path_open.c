#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
    char path[128] = {0};
    ssize_t n = read(STDIN_FILENO, path, sizeof(path) - 1);
    int fd;

    if (n <= 0) {
        return 0;
    }

    path[strcspn(path, "\r\n")] = '\0';
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
    }

    return 0;
}
