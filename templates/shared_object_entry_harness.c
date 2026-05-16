#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "shadowfuzz_persistent.h"

typedef int (*target_entry_t)(const uint8_t *data, size_t size);

static int
call_target_entry(const uint8_t *data, size_t size, void *user_data)
{
    target_entry_t entry = (target_entry_t)user_data;

    return entry(data, size);
}

int
main(int argc, char **argv)
{
    const char *library_path;
    const char *symbol_name;
    void *handle;
    target_entry_t entry;
    uint8_t buffer[65536];
    ssize_t nread;
    char *error;
    int persistent_rc;

    if (argc != 3) {
        fprintf(stderr, "usage: %s /path/to/library.so entry_symbol\n", argv[0]);
        return 2;
    }

    library_path = argv[1];
    symbol_name = argv[2];

    handle = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    dlerror();
    entry = (target_entry_t)dlsym(handle, symbol_name);
    error = dlerror();
    if (error != NULL || entry == NULL) {
        fprintf(stderr, "dlsym failed: %s\n", error != NULL ? error : symbol_name);
        dlclose(handle);
        return 2;
    }

    persistent_rc = shadowfuzz_maybe_run_persistent(call_target_entry, (void *)entry);
    if (persistent_rc >= 0) {
        dlclose(handle);
        return persistent_rc;
    }

    nread = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (nread < 0) {
        perror("read");
        dlclose(handle);
        return 2;
    }

    (void)entry(buffer, (size_t)nread);
    dlclose(handle);
    return 0;
}
