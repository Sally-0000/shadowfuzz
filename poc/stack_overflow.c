#include <unistd.h>

static void
vuln(void)
{
    char buf[16];

    read(STDIN_FILENO, buf, 128);
}

int
main(void)
{
    vuln();
    return 0;
}
