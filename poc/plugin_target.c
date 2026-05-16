#include <stdint.h>
#include <stdlib.h>

int
plugin_init(void)
{
    return 0;
}

int
plugin_process(const uint8_t *data, size_t size)
{
    if (size >= 4 && data[0] == 'P' && data[1] == 'L' && data[2] == 'G' &&
        data[3] == '!') {
        abort();
    }

    return 0;
}

void
plugin_fini(void)
{
}
