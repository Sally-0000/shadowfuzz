#include <stdint.h>
#include <stdlib.h>

int
target_entry(const uint8_t *data, size_t size)
{
    if (size >= 4 && data[0] == 'S' && data[1] == 'O' && data[2] == '!' &&
        data[3] == '!') {
        abort();
    }

    return 0;
}
