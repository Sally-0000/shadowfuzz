#include <fcntl.h>
#include <unistd.h>

int main(void) {
    char input[8] = { 0 };
    ssize_t n = read(STDIN_FILENO, input, sizeof(input) - 1);
    const char *path = "regular.txt";
    int fd;

    if (n > 0 && input[0] == 'S') {
        path = ".aws/credentials";
    } else if (n > 0 && input[0] == 'K') {
        path = ".kube/config";
    } else if (n > 0 && input[0] == 'I') {
        path = ".ssh/id_ed25519";
    }

    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
    }
    return 0;
}
