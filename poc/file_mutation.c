#include <fcntl.h>
#include <unistd.h>

int
main(void)
{
    char input[16] = { 0 };
    ssize_t n = read(STDIN_FILENO, input, sizeof(input) - 1);

    if (n <= 0) {
        return 0;
    }

    if (input[0] == 'D') {
        unlink("shadowfuzz-delete-target");
        return 0;
    }

    if (input[0] == 'T') {
        int fd = open("shadowfuzz-overwrite-target", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            close(fd);
        }
        return 0;
    }

    return 0;
}
