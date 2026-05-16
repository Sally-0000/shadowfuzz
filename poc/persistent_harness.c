#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int
read_exact_fd(int fd, void *buf, size_t count)
{
    unsigned char *p = (unsigned char *)buf;
    size_t total = 0;

    while (total < count) {
        ssize_t rc = read(fd, p + total, count - total);

        if (rc == 0) {
            return 0;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total += (size_t)rc;
    }
    return 1;
}

static int
write_all_fd(int fd, const void *buf, size_t count)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t total = 0;

    while (total < count) {
        ssize_t rc = write(fd, p + total, count - total);

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total += (size_t)rc;
    }
    return 0;
}

static int
process_one(const unsigned char *data, size_t size)
{
    volatile uint32_t score = 0;

    if (size > 0 && data[0] == 'P') {
        score++;
    }
    if (size > 1 && data[1] == 'E') {
        score++;
    }
    if (size > 2 && data[2] == 'R') {
        score++;
    }
    if (size > 3 && data[3] == 'S') {
        return SIGABRT;
    }
    return score >= 3 ? 1 : 0;
}

static uint32_t
status_to_wait_status(int status)
{
    if (status == SIGABRT) {
        return (uint32_t)SIGABRT;
    }
    return (uint32_t)((status & 0xff) << 8);
}

static int
run_persistent_loop(int input_fd, int output_fd)
{
    unsigned char *buf = NULL;
    size_t capacity = 0;

    while (1) {
        uint32_t size = 0;
        uint32_t status = 0;
        int rc = read_exact_fd(input_fd, &size, sizeof(size));

        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            free(buf);
            return 1;
        }
        if (size > capacity) {
            unsigned char *new_buf = realloc(buf, size == 0 ? 1 : size);

            if (new_buf == NULL) {
                free(buf);
                return 1;
            }
            buf = new_buf;
            capacity = size;
        }
        if (size > 0 && read_exact_fd(input_fd, buf, size) != 1) {
            free(buf);
            return 1;
        }

        raise(SIGUSR1);
        status = status_to_wait_status(process_one(buf, size));
        raise(SIGUSR2);
        if (write_all_fd(output_fd, &status, sizeof(status)) != 0) {
            free(buf);
            return 1;
        }
    }

    free(buf);
    return 0;
}

int
main(void)
{
    const char *input_fd_env = getenv("SHADOWFUZZ_PERSISTENT_IN_FD");
    const char *output_fd_env = getenv("SHADOWFUZZ_PERSISTENT_OUT_FD");

    if (input_fd_env != NULL && output_fd_env != NULL) {
        return run_persistent_loop(atoi(input_fd_env), atoi(output_fd_env));
    }

    {
        unsigned char buf[16];
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        int status;

        if (n < 0) {
            return 1;
        }
        status = process_one(buf, (size_t)n);
        if (status == SIGABRT) {
            raise(SIGABRT);
        }
        return status;
    }
}
