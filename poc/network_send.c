#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int
main(void)
{
    char input[16] = { 0 };
    int fds[2] = { -1, -1 };
    const char *payload = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    ssize_t n = read(STDIN_FILENO, input, sizeof(input) - 1);

    if (n > 0 && input[0] == 'M') {
        payload = "GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return 0;
    }

    send(fds[0], payload, strlen(payload), 0);
    close(fds[0]);
    close(fds[1]);
    return 0;
}
