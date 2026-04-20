#include "dr_api.h"
#include "drmgr.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNIX
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#endif

#define DEFAULT_MAP_SIZE (1U << 16)
static byte *coverage_map;
static uint32_t coverage_map_size = DEFAULT_MAP_SIZE;
static bool coverage_map_from_shm;
static file_t bitmap_output = INVALID_FILE;
static int tls_index = -1;
static void *log_mutex;
static bool filter_main_module_only = true;
static bool instrument_all_modules;
static bool quiet_logs;
static app_pc main_module_start;
static app_pc main_module_end;
static char target_module_name[256];

static uint32_t
hash_u64(uint64_t value)
{
    uint64_t x = value;
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return (uint32_t)x;
}

static uint32_t
stable_location_id(app_pc pc)
{
    module_data_t *module = dr_lookup_module(pc);
    uint64_t module_hash = 0;
    uint64_t rel = (uint64_t)(ptr_uint_t)pc;
    uint32_t loc;

    if (module != NULL) {
        rel = (uint64_t)(pc - module->start);
        if (module->full_path != NULL) {
            const char *p = module->full_path;
            while (*p != '\0') {
                module_hash = (module_hash * 131) + (unsigned char)(*p);
                p++;
            }
        } else {
            module_hash = (uint64_t)(ptr_uint_t)module->start;
        }
        dr_free_module_data(module);
    }

    loc = hash_u64((module_hash << 1) ^ rel);
    return loc & (coverage_map_size - 1);
}

static const char *
get_env(const char *name)
{
    return getenv(name);
}

static uint32_t
parse_u32_env(const char *name, uint32_t default_value)
{
    const char *value = get_env(name);
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || value[0] == '\0') {
        return default_value;
    }

    parsed = strtoul(value, &end, 0);
    if (end == value || *end != '\0' || parsed == 0 || parsed > UINT32_MAX) {
        return default_value;
    }

    return (uint32_t)parsed;
}

static void
log_message(const char *message)
{
    if (quiet_logs) {
        return;
    }
    dr_mutex_lock(log_mutex);
    dr_fprintf(STDERR, "shadowcov: %s\n", message);
    dr_mutex_unlock(log_mutex);
}

static void
log_error(const char *message)
{
    dr_mutex_lock(log_mutex);
    dr_fprintf(STDERR, "shadowcov: error: %s\n", message);
    dr_mutex_unlock(log_mutex);
}

static const char *
base_name(const char *path)
{
    const char *last_slash;

    if (path == NULL) {
        return NULL;
    }

    last_slash = strrchr(path, '/');
    return last_slash == NULL ? path : last_slash + 1;
}

static void
copy_string(char *dst, size_t dst_size, const char *src)
{
    size_t len;

    if (dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    len = strlen(src);
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void
open_bitmap_output(void)
{
    const char *path = get_env("SHADOWCOV_BITMAP_OUT");

    if (path == NULL || path[0] == '\0') {
        path = "coverage.map";
    }

    bitmap_output = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    if (bitmap_output == INVALID_FILE) {
        log_error("failed to open bitmap output file");
    }
}

static bool
map_coverage_from_afl_shm(void)
{
#ifdef UNIX
    const char *shm_id_str = get_env("__AFL_SHM_ID");
    int shm_id;
    void *shm_ptr;

    if (shm_id_str == NULL || shm_id_str[0] == '\0') {
        shm_id_str = get_env("AFL_SHM_ID");
    }
    if (shm_id_str == NULL || shm_id_str[0] == '\0') {
        return false;
    }

    shm_id = (int)strtol(shm_id_str, NULL, 10);
    if (shm_id <= 0) {
        log_error("invalid AFL_SHM_ID");
        return false;
    }

    shm_ptr = shmat(shm_id, NULL, 0);
    if (shm_ptr == (void *)-1) {
        log_error("failed to attach AFL shared memory");
        return false;
    }

    coverage_map = (byte *)shm_ptr;
    coverage_map_from_shm = true;
    log_message("attached to AFL shared memory");
    return true;
#else
    return false;
#endif
}

static void
allocate_local_coverage_map(void)
{
    coverage_map = dr_global_alloc(coverage_map_size);
    memset(coverage_map, 0, coverage_map_size);
    log_message("using local in-process coverage map");
}

static void
configure_module_filter(void)
{
    const char *instrument_modules = get_env("SHADOWCOV_INSTRUMENT_MODULES");
    const char *target_module = get_env("SHADOWCOV_TARGET_MODULE");
    module_data_t *main_module;

    if (instrument_modules != NULL && strcmp(instrument_modules, "all") == 0) {
        instrument_all_modules = true;
        filter_main_module_only = false;
        log_message("instrumenting all modules");
        return;
    }

    if (target_module != NULL && target_module[0] != '\0') {
        copy_string(target_module_name, sizeof(target_module_name), target_module);
        filter_main_module_only = false;
        if (!quiet_logs) {
            dr_mutex_lock(log_mutex);
            dr_fprintf(STDERR, "shadowcov: filtering to module name '%s'\n", target_module_name);
            dr_mutex_unlock(log_mutex);
        }
        return;
    }

    main_module = dr_get_main_module();
    if (main_module == NULL) {
        log_error("failed to resolve main module; falling back to all modules");
        instrument_all_modules = true;
        filter_main_module_only = false;
        return;
    }

    main_module_start = main_module->start;
    main_module_end = main_module->end;
    copy_string(target_module_name, sizeof(target_module_name),
                base_name(main_module->full_path));
    dr_free_module_data(main_module);

    if (!quiet_logs) {
        dr_mutex_lock(log_mutex);
        dr_fprintf(STDERR, "shadowcov: filtering to main module '%s'\n", target_module_name);
        dr_mutex_unlock(log_mutex);
    }
}

static bool
should_instrument_pc(app_pc pc)
{
    module_data_t *module;
    bool allowed = false;

    if (instrument_all_modules) {
        return true;
    }

    if (filter_main_module_only) {
        return pc >= main_module_start && pc < main_module_end;
    }

    module = dr_lookup_module(pc);
    if (module == NULL) {
        return false;
    }

    if (module->full_path != NULL && base_name(module->full_path) != NULL &&
        strcmp(base_name(module->full_path), target_module_name) == 0) {
        allowed = true;
    } else if (dr_module_preferred_name(module) != NULL &&
               strcmp(dr_module_preferred_name(module), target_module_name) == 0) {
        allowed = true;
    }

    dr_free_module_data(module);
    return allowed;
}

static void
event_thread_init(void *drcontext)
{
    uint16_t *prev_loc;

    prev_loc = dr_thread_alloc(drcontext, sizeof(*prev_loc));
    *prev_loc = 0;
    drmgr_set_tls_field(drcontext, tls_index, prev_loc);
}

static void
event_thread_exit(void *drcontext)
{
    void *prev_loc = drmgr_get_tls_field(drcontext, tls_index);
    if (prev_loc != NULL) {
        dr_thread_free(drcontext, prev_loc, sizeof(uint16_t));
    }
}

static void
record_edge(uint32_t cur_loc)
{
    void *drcontext = dr_get_current_drcontext();
    uint16_t *prev_loc = drmgr_get_tls_field(drcontext, tls_index);
    uint32_t edge_idx = cur_loc ^ *prev_loc;

    coverage_map[edge_idx % coverage_map_size]++;
    *prev_loc = (uint16_t)(cur_loc >> 1);
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, instr_t *where,
                  bool for_trace, bool translating, void *user_data)
{
    app_pc start_pc;
    uint32_t cur_loc;

    (void)for_trace;
    (void)user_data;

    if (translating || coverage_map == NULL) {
        return DR_EMIT_DEFAULT;
    }

    start_pc = dr_fragment_app_pc(tag);
    if (start_pc == NULL) {
        return DR_EMIT_DEFAULT;
    }
    if (!should_instrument_pc(start_pc)) {
        return DR_EMIT_DEFAULT;
    }

    cur_loc = stable_location_id(start_pc);
    dr_insert_clean_call(drcontext, bb, where, (void *)record_edge, false, 1,
                         OPND_CREATE_INT32((int)cur_loc));
    return DR_EMIT_DEFAULT;
}

static void
flush_bitmap_to_file(void)
{
    ssize_t written;

    if (bitmap_output == INVALID_FILE || coverage_map == NULL) {
        return;
    }

    written = dr_write_file(bitmap_output, coverage_map, coverage_map_size);
    if (written < 0 || (size_t)written != coverage_map_size) {
        log_error("failed to flush coverage bitmap");
    }
}

static void
event_exit(void)
{
    flush_bitmap_to_file();

    if (bitmap_output != INVALID_FILE) {
        dr_close_file(bitmap_output);
    }

    if (coverage_map != NULL && !coverage_map_from_shm) {
        dr_global_free(coverage_map, coverage_map_size);
    }

#ifdef UNIX
    if (coverage_map_from_shm && coverage_map != NULL) {
        shmdt(coverage_map);
    }
#endif

    drmgr_unregister_tls_field(tls_index);
    drmgr_exit();
    dr_mutex_destroy(log_mutex);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("shadowfuzz standalone coverage engine", "https://github.com/");

    if (!drmgr_init()) {
        DR_ASSERT(false);
        return;
    }

    log_mutex = dr_mutex_create();
    quiet_logs = get_env("SHADOWCOV_QUIET") != NULL;
    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    coverage_map_size = parse_u32_env("SHADOWCOV_MAP_SIZE", DEFAULT_MAP_SIZE);
    if ((coverage_map_size & (coverage_map_size - 1)) != 0) {
        coverage_map_size = DEFAULT_MAP_SIZE;
        log_message("SHADOWCOV_MAP_SIZE is not a power of two, falling back to 65536");
    }

    if (!map_coverage_from_afl_shm()) {
        allocate_local_coverage_map();
        open_bitmap_output();
    }
    configure_module_filter();

    dr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_basic_block, NULL);

    dr_log(NULL, DR_LOG_ALL, 1, "shadowcov initialized\n");
}
