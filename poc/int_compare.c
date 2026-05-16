#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
static __attribute__((noinline)) int
cmp_mem_imm_u32(const uint32_t *value)
{
    unsigned char equal = 0;

    __asm__ volatile("cmpl $0x2147434d, %[mem]\n\t"
                     "sete %[equal]\n\t"
                     : [equal] "=qm"(equal)
                     : [mem] "m"(*value)
                     : "cc");
    return equal;
}

static __attribute__((noinline)) int
cmp_reg_reg_u32(uint32_t observed, uint32_t expected)
{
    unsigned char equal = 0;

    __asm__ volatile("cmp %[expected], %[observed]\n\t"
                     "sete %[equal]\n\t"
                     : [equal] "=qm"(equal)
                     : [observed] "r"(observed), [expected] "r"(expected)
                     : "cc");
    return equal;
}
#else
static __attribute__((noinline)) int
cmp_mem_imm_u32(const uint32_t *value)
{
    return *value == 0x2147434dU;
}

static __attribute__((noinline)) int
cmp_reg_reg_u32(uint32_t observed, uint32_t expected)
{
    return observed == expected;
}
#endif

int
main(void)
{
    unsigned char buf[12] = { 0 };
    uint32_t magic32 = 0;
    uint32_t reg_magic = 0;
    uint16_t magic16 = 0;
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

    if (n >= 4) {
        memcpy(&magic32, buf, sizeof(magic32));
        if (cmp_mem_imm_u32(&magic32)) {
            raise(SIGABRT);
        }
    }

    if (n >= 6) {
        memcpy(&magic16, buf + 4, sizeof(magic16));
        if (magic16 == 0x5a59U) {
            raise(SIGABRT);
        }
    }

    if (n >= 10) {
        memcpy(&reg_magic, buf + 6, sizeof(reg_magic));
        if (cmp_reg_reg_u32(reg_magic, 0x52474552U)) {
            raise(SIGABRT);
        }
    }

    return 0;
}
