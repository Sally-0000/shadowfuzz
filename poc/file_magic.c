#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    unsigned char buf[32] = {0};
    FILE *fp;
    size_t n;

    if (argc < 2) {
        return 0;
    }

    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        return 0;
    }

    n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    if (n >= 12 && memcmp(buf, "SHDW", 4) == 0) {
        if (buf[4] == 0x01 && buf[5] == 0x23) {
            if (memcmp(buf + 6, "FUZZ", 4) == 0) {
                if (buf[10] == 0x7f && buf[11] == 0xff) {
                    abort();
                }
            }
        }
    }

    return 0;
}
