#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int
main(void)
{
    char input[16] = { 0 };
    ssize_t n = read(STDIN_FILENO, input, sizeof(input) - 1);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);

    if (n > 0 && input[0] == 'R') {
        inet_pton(AF_INET, "203.0.113.1", &addr.sin_addr);
    } else {
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    }

    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return 0;
}
