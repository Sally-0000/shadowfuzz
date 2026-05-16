#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "shadowfuzz_persistent.h"

typedef int (*plugin_init_t)(void);
typedef int (*plugin_process_t)(const uint8_t *data, size_t size);
typedef void (*plugin_fini_t)(void);

static int
call_plugin_process(const uint8_t *data, size_t size, void *user_data)
{
    plugin_process_t plugin_process = (plugin_process_t)user_data;

    return plugin_process(data, size);
}

int
main(int argc, char **argv)
{
    void *handle;
    plugin_init_t plugin_init;
    plugin_process_t plugin_process;
    plugin_fini_t plugin_fini;
    uint8_t buffer[65536];
    ssize_t nread;
    int persistent_rc;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/plugin.so\n", argv[0]);
        return 2;
    }

    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    plugin_init = (plugin_init_t)dlsym(handle, "plugin_init");
    plugin_process = (plugin_process_t)dlsym(handle, "plugin_process");
    plugin_fini = (plugin_fini_t)dlsym(handle, "plugin_fini");
    if (plugin_process == NULL) {
        fprintf(stderr, "missing required symbol: plugin_process\n");
        dlclose(handle);
        return 2;
    }

    if (plugin_init != NULL && plugin_init() != 0) {
        dlclose(handle);
        return 2;
    }

    persistent_rc =
        shadowfuzz_maybe_run_persistent(call_plugin_process, (void *)plugin_process);
    if (persistent_rc >= 0) {
        if (plugin_fini != NULL) {
            plugin_fini();
        }
        dlclose(handle);
        return persistent_rc;
    }

    nread = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (nread < 0) {
        perror("read");
        if (plugin_fini != NULL) {
            plugin_fini();
        }
        dlclose(handle);
        return 2;
    }

    (void)plugin_process(buffer, (size_t)nread);

    if (plugin_fini != NULL) {
        plugin_fini();
    }
    dlclose(handle);
    return 0;
}
