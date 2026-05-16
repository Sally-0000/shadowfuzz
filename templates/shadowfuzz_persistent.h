#ifndef SHADOWFUZZ_PERSISTENT_H
#define SHADOWFUZZ_PERSISTENT_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

typedef int (*shadowfuzz_persistent_cb_t)(const uint8_t *data, size_t size,
                                          void *user_data);

static int
shadowfuzz_read_exact(int fd, void *buf, size_t count)
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
shadowfuzz_write_all(int fd, const void *buf, size_t count)
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

static uint32_t
shadowfuzz_exit_code_to_wait_status(int exit_code)
{
    return (uint32_t)((exit_code & 0xff) << 8);
}

static int
shadowfuzz_maybe_run_persistent(shadowfuzz_persistent_cb_t callback, void *user_data)
{
    const char *input_fd_env = getenv("SHADOWFUZZ_PERSISTENT_IN_FD");
    const char *output_fd_env = getenv("SHADOWFUZZ_PERSISTENT_OUT_FD");
    int input_fd;
    int output_fd;
    uint8_t *buffer = NULL;
    size_t capacity = 0;

    if (input_fd_env == NULL || output_fd_env == NULL) {
        return -1;
    }

    input_fd = atoi(input_fd_env);
    output_fd = atoi(output_fd_env);

    while (1) {
        uint32_t size = 0;
        uint32_t status;
        int callback_status;
        int rc = shadowfuzz_read_exact(input_fd, &size, sizeof(size));

        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            perror("persistent read size");
            free(buffer);
            return 2;
        }
        if (size > capacity) {
            uint8_t *new_buffer = realloc(buffer, size == 0 ? 1 : size);

            if (new_buffer == NULL) {
                perror("persistent realloc");
                free(buffer);
                return 2;
            }
            buffer = new_buffer;
            capacity = size;
        }
        if (size > 0 && shadowfuzz_read_exact(input_fd, buffer, size) != 1) {
            perror("persistent read data");
            free(buffer);
            return 2;
        }

        raise(SIGUSR1);
        callback_status = callback(buffer, size, user_data);
        raise(SIGUSR2);

        status = shadowfuzz_exit_code_to_wait_status(callback_status);
        if (shadowfuzz_write_all(output_fd, &status, sizeof(status)) != 0) {
            perror("persistent write status");
            free(buffer);
            return 2;
        }
    }

    free(buffer);
    return 0;
}

#endif
