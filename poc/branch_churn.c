#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static uint32_t
mix_round(uint32_t value, uint32_t i, unsigned char mode)
{
    if (((value ^ i ^ mode) & 1U) != 0) {
        value = value * 33U + i;
    } else {
        value = (value >> 1) ^ (i * 17U);
    }

    if (((value + mode) & 7U) == 3U) {
        value ^= 0x9e3779b9U;
    } else if ((value & 15U) == 9U) {
        value += 0x7f4a7c15U;
    } else {
        value ^= value << 5;
    }

    return value;
}

int
main(void)
{
    unsigned char input[8] = { 0 };
    uint32_t state = 0x12345678U;
    uint32_t rounds = 50000;
    ssize_t n = read(STDIN_FILENO, input, sizeof(input));

    if (n > 0 && input[0] == 'L') {
        rounds = 100000;
    }

    for (uint32_t i = 0; i < rounds; i++) {
        state = mix_round(state, i, input[0]);
    }

    if (state == 0xffffffffU) {
        puts("unreachable");
    }
    return 0;
}
