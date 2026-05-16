#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
    char input[8] = { 0 };
    ssize_t n = read(STDIN_FILENO, input, sizeof(input) - 1);
    const char *value;

    if (n > 0 && input[0] == 'S') {
        value = getenv("AWS_SECRET_ACCESS_KEY");
    } else if (n > 0 && input[0] == 'T') {
        value = getenv("API_TOKEN");
    } else {
        value = getenv("PATH");
    }

    return value == NULL ? 0 : 0;
}
