#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drwrap.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNIX
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#define DEFAULT_MAP_SIZE (1U << 16)
#define MAX_NGRAM_SIZE 8
#define MAX_NETWORK_PAYLOAD_SCAN 512

typedef struct thread_cov_state_t {
    uint32_t prev_loc;
    uint32_t history[MAX_NGRAM_SIZE];
} thread_cov_state_t;

static byte *coverage_map;
static uint32_t coverage_map_size = DEFAULT_MAP_SIZE;
static uint32_t ngram_size = 1;
static bool coverage_map_from_shm;
static bool disable_neverzero;
static bool enable_hitcount_buckets;
static bool enable_inline_coverage;
static bool enable_persistent_reset_hook;
static bool persistent_coverage_enabled = true;
static file_t bitmap_output = INVALID_FILE;
static int tls_index = -1;
static void *log_mutex;
static bool filter_main_module_only = true;
static bool instrument_all_modules;
static bool quiet_logs;
static bool abort_on_dangerous_api;
static bool abort_on_credential_file;
static bool abort_on_file_mutation;
static bool abort_on_path_traversal;
static bool abort_on_exec;
static bool abort_on_env_access;
static bool abort_on_network;
static bool trace_cmp;
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
rotl32(uint32_t value, uint32_t shift)
{
    shift &= 31;
    if (shift == 0) {
        return value;
    }
    return (value << shift) | (value >> (32 - shift));
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

static uint32_t
parse_ngram_size(void)
{
    uint32_t value = parse_u32_env("SHADOWCOV_NGRAM_SIZE", 1);

    if (value == 1 || value == 2 || value == 4 || value == 8) {
        return value;
    }

    return 1;
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

static void
log_string_event(const char *label, const char *value)
{
    if (quiet_logs) {
        return;
    }
    dr_mutex_lock(log_mutex);
    dr_fprintf(STDERR, "shadowcov: %s '%s'\n", label, value);
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

static bool
copy_app_string(char *dst, size_t dst_size, const char *src)
{
    size_t idx;

    if (dst_size == 0) {
        return false;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return false;
    }

    for (idx = 0; idx + 1 < dst_size; idx++) {
        char ch = '\0';
        size_t bytes_read = 0;

        if (!dr_safe_read(src + idx, sizeof(ch), &ch, &bytes_read) ||
            bytes_read != sizeof(ch)) {
            dst[idx] = '\0';
            return false;
        }
        dst[idx] = ch;
        if (ch == '\0') {
            return true;
        }
    }

    dst[dst_size - 1] = '\0';
    return true;
}

static bool
has_shell_metachar(const char *s)
{
    while (s != NULL && *s != '\0') {
        if (strchr(";&|`$<>", *s) != NULL) {
            return true;
        }
        s++;
    }
    return false;
}

static bool
token_list_contains_prefix(const char *tokens, const char *value)
{
    const char *cursor;

    if (tokens == NULL || tokens[0] == '\0' || value == NULL) {
        return false;
    }

    cursor = tokens;
    while (*cursor != '\0') {
        const char *end = cursor;
        size_t len;

        while (*end != '\0' && *end != ',' && *end != ':') {
            end++;
        }

        len = (size_t)(end - cursor);
        if (len > 0 && strncmp(value, cursor, len) == 0) {
            return true;
        }

        cursor = *end == '\0' ? end : end + 1;
    }

    return false;
}

static bool
token_list_contains_substring(const char *tokens, const char *value)
{
    const char *cursor;

    if (tokens == NULL || tokens[0] == '\0' || value == NULL) {
        return false;
    }

    cursor = tokens;
    while (*cursor != '\0') {
        const char *end = cursor;
        char token[128];
        size_t len;

        while (*end != '\0' && *end != ',' && *end != ':') {
            end++;
        }

        len = (size_t)(end - cursor);
        if (len > 0 && len < sizeof(token)) {
            memcpy(token, cursor, len);
            token[len] = '\0';
            if (strstr(value, token) != NULL) {
                return true;
            }
        }

        cursor = *end == '\0' ? end : end + 1;
    }

    return false;
}

static bool
token_list_contains_exact(const char *tokens, const char *value)
{
    const char *cursor;

    if (tokens == NULL || tokens[0] == '\0' || value == NULL) {
        return false;
    }

    cursor = tokens;
    while (*cursor != '\0') {
        const char *end = cursor;
        size_t len;

        while (*end != '\0' && *end != ',' && *end != ':') {
            end++;
        }

        len = (size_t)(end - cursor);
        if (strlen(value) == len && strncmp(value, cursor, len) == 0) {
            return true;
        }

        cursor = *end == '\0' ? end : end + 1;
    }

    return false;
}

static bool
path_is_allowlisted(const char *path)
{
    return token_list_contains_prefix(get_env("SHADOWCOV_PATH_ALLOWLIST"), path);
}

static bool
env_name_is_allowlisted(const char *name)
{
    return token_list_contains_exact(get_env("SHADOWCOV_ENV_ALLOWLIST"), name);
}

static bool
has_sensitive_env_name(const char *name)
{
    char lower_name[256];
    size_t idx;

    if (name == NULL || name[0] == '\0') {
        return false;
    }

    for (idx = 0; idx + 1 < sizeof(lower_name) && name[idx] != '\0'; idx++) {
        lower_name[idx] =
            name[idx] >= 'A' && name[idx] <= 'Z' ? (char)(name[idx] - 'A' + 'a')
                                                 : name[idx];
    }
    lower_name[idx] = '\0';

    return strstr(lower_name, "password") != NULL ||
        strstr(lower_name, "passwd") != NULL ||
        strstr(lower_name, "secret") != NULL ||
        strstr(lower_name, "token") != NULL ||
        strstr(lower_name, "apikey") != NULL ||
        strstr(lower_name, "api_key") != NULL ||
        strstr(lower_name, "private_key") != NULL ||
        strstr(lower_name, "credential") != NULL ||
        strstr(lower_name, "aws_access_key") != NULL ||
        strstr(lower_name, "aws_secret_access_key") != NULL;
}

static bool
has_path_traversal_pattern(const char *s)
{
    if (s == NULL || s[0] == '\0') {
        return false;
    }

    if (s[0] == '/') {
        return true;
    }

    return strstr(s, "../") != NULL || strstr(s, "..\\") != NULL ||
        strcmp(s, "..") == 0 || strncmp(s, "../", 3) == 0 ||
        strncmp(s, "..\\", 3) == 0;
}

static bool
has_credential_path_pattern(const char *path)
{
    char lower_path[512];
    const char *name;
    size_t idx;

    if (path == NULL || path[0] == '\0') {
        return false;
    }

    for (idx = 0; idx + 1 < sizeof(lower_path) && path[idx] != '\0'; idx++) {
        lower_path[idx] =
            path[idx] >= 'A' && path[idx] <= 'Z' ? (char)(path[idx] - 'A' + 'a')
                                                 : path[idx];
    }
    lower_path[idx] = '\0';
    name = base_name(lower_path);

    return strstr(lower_path, ".aws/credentials") != NULL ||
        strstr(lower_path, ".kube/config") != NULL ||
        strstr(lower_path, "/kubeconfig") != NULL ||
        strstr(lower_path, "/.netrc") != NULL ||
        strstr(lower_path, "/id_rsa") != NULL ||
        strstr(lower_path, "/id_dsa") != NULL ||
        strstr(lower_path, "/id_ecdsa") != NULL ||
        strstr(lower_path, "/id_ed25519") != NULL ||
        strstr(lower_path, "client_secret") != NULL ||
        (name != NULL &&
         (strcmp(name, "credentials") == 0 || strcmp(name, ".netrc") == 0 ||
          strcmp(name, "kubeconfig") == 0 || strcmp(name, "id_rsa") == 0 ||
          strcmp(name, "id_dsa") == 0 || strcmp(name, "id_ecdsa") == 0 ||
          strcmp(name, "id_ed25519") == 0));
}

static bool
has_file_mutation_flags(int flags)
{
#ifdef UNIX
    return (flags & O_CREAT) != 0 || (flags & O_TRUNC) != 0 ||
        (flags & O_APPEND) != 0 || (flags & O_WRONLY) != 0 ||
        (flags & O_RDWR) != 0;
#else
    (void)flags;
    return false;
#endif
}

static bool
has_file_mutation_mode(const char *mode)
{
    if (mode == NULL || mode[0] == '\0') {
        return false;
    }

    return strchr(mode, 'w') != NULL || strchr(mode, 'a') != NULL ||
        strchr(mode, 'x') != NULL || strchr(mode, '+') != NULL;
}

static bool
has_exec_suspicious_pattern(const char *s)
{
    if (s == NULL || s[0] == '\0') {
        return false;
    }

    return strchr(s, '/') != NULL || strchr(s, '\\') != NULL ||
        strstr(s, "..") != NULL || has_shell_metachar(s);
}

static bool
exec_path_is_allowed(const char *path)
{
    const char *allowlist = get_env("SHADOWCOV_EXEC_ALLOWLIST");
    const char *name = base_name(path);
    const char *cursor;

    if (allowlist == NULL || allowlist[0] == '\0' || name == NULL || name[0] == '\0') {
        return false;
    }

    cursor = allowlist;
    while (*cursor != '\0') {
        const char *end = cursor;
        size_t len;

        while (*end != '\0' && *end != ',' && *end != ':') {
            end++;
        }

        len = (size_t)(end - cursor);
        if (strlen(name) == len && strncmp(name, cursor, len) == 0) {
            return true;
        }

        cursor = *end == '\0' ? end : end + 1;
    }

    return false;
}

static char
ascii_lower(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch - 'A' + 'a');
    }
    return ch;
}

static bool
ascii_starts_with_ci(const char *s, const char *prefix)
{
    while (*prefix != '\0') {
        if (ascii_lower(*s) != ascii_lower(*prefix)) {
            return false;
        }
        s++;
        prefix++;
    }
    return true;
}

static const char *
ascii_strstr_ci(const char *haystack, const char *needle)
{
    size_t needle_len = strlen(needle);

    if (needle_len == 0) {
        return haystack;
    }

    while (*haystack != '\0') {
        size_t idx;
        for (idx = 0; idx < needle_len; idx++) {
            if (haystack[idx] == '\0' ||
                ascii_lower(haystack[idx]) != ascii_lower(needle[idx])) {
                break;
            }
        }
        if (idx == needle_len) {
            return haystack;
        }
        haystack++;
    }

    return NULL;
}

static bool
host_is_loopback_or_local(const char *host, size_t host_len)
{
    if (host == NULL || host_len == 0) {
        return true;
    }

    if (host_len == 9 && strncmp(host, "localhost", host_len) == 0) {
        return true;
    }
    if (host_len >= 4 && strncmp(host, "127.", 4) == 0) {
        return true;
    }
    if (host_len == 3 && strncmp(host, "::1", host_len) == 0) {
        return true;
    }
    if (host_len == 5 && strncmp(host, "[::1]", host_len) == 0) {
        return true;
    }

    return false;
}

static bool
host_token_is_non_loopback(const char *host)
{
    const char *end = host;

    while (*host == ' ' || *host == '\t') {
        host++;
    }
    end = host;
    while (*end != '\0' && *end != '\r' && *end != '\n' && *end != '/' &&
           *end != ':' && *end != ' ' && *end != '\t') {
        end++;
    }

    return !host_is_loopback_or_local(host, (size_t)(end - host));
}

static bool
has_non_loopback_http_host(const char *payload)
{
    const char *host_header = ascii_strstr_ci(payload, "\nhost:");
    const char *url;

    if (ascii_starts_with_ci(payload, "host:")) {
        host_header = payload - 1;
    }
    if (host_header != NULL && host_token_is_non_loopback(host_header + 6)) {
        return true;
    }

    url = ascii_strstr_ci(payload, "http://");
    if (url != NULL && host_token_is_non_loopback(url + 7)) {
        return true;
    }

    url = ascii_strstr_ci(payload, "https://");
    return url != NULL && host_token_is_non_loopback(url + 8);
}

static bool
has_suspicious_network_payload(const byte *app_buf, size_t len)
{
    char payload[MAX_NETWORK_PAYLOAD_SCAN + 1];
    size_t bytes_to_read;
    size_t bytes_read = 0;

    if (app_buf == NULL || len == 0) {
        return false;
    }

    bytes_to_read = len < MAX_NETWORK_PAYLOAD_SCAN ? len : MAX_NETWORK_PAYLOAD_SCAN;
    if (!dr_safe_read(app_buf, bytes_to_read, payload, &bytes_read) || bytes_read == 0) {
        return false;
    }

    payload[bytes_read] = '\0';
    if (token_list_contains_substring(get_env("SHADOWCOV_NETWORK_ALLOWLIST"), payload)) {
        return false;
    }
    return ascii_strstr_ci(payload, "169.254.169.254") != NULL ||
        ascii_strstr_ci(payload, "metadata.google.internal") != NULL ||
        ascii_strstr_ci(payload, "metadata-flavor:") != NULL ||
        has_non_loopback_http_host(payload);
}

static bool
sockaddr_to_string(const struct sockaddr *addr, socklen_t addr_len, char *dst,
                   size_t dst_size)
{
#ifdef UNIX
    sa_family_t family;
    size_t bytes_read = 0;

    if (addr == NULL || dst == NULL || dst_size == 0) {
        return false;
    }
    dst[0] = '\0';

    if (addr_len < sizeof(family) ||
        !dr_safe_read(&addr->sa_family, sizeof(family), &family, &bytes_read) ||
        bytes_read != sizeof(family)) {
        return false;
    }

    if (family == AF_INET) {
        struct sockaddr_in in_addr;

        if (addr_len < sizeof(in_addr)) {
            return false;
        }
        if (!dr_safe_read(addr, sizeof(in_addr), &in_addr, &bytes_read) ||
            bytes_read != sizeof(in_addr)) {
            return false;
        }
        return inet_ntop(AF_INET, &in_addr.sin_addr, dst, (socklen_t)dst_size) != NULL;
    }

    if (family == AF_INET6) {
        struct sockaddr_in6 in6_addr;

        if (addr_len < sizeof(in6_addr)) {
            return false;
        }
        if (!dr_safe_read(addr, sizeof(in6_addr), &in6_addr, &bytes_read) ||
            bytes_read != sizeof(in6_addr)) {
            return false;
        }
        return inet_ntop(AF_INET6, &in6_addr.sin6_addr, dst, (socklen_t)dst_size) != NULL;
    }
#else
    (void)addr;
    (void)addr_len;
    (void)dst;
    (void)dst_size;
#endif
    return false;
}

static bool
sockaddr_is_allowlisted(const struct sockaddr *addr, socklen_t addr_len)
{
    char value[INET6_ADDRSTRLEN];

    if (!sockaddr_to_string(addr, addr_len, value, sizeof(value))) {
        return false;
    }
    return token_list_contains_prefix(get_env("SHADOWCOV_NETWORK_ALLOWLIST"), value);
}

static bool
is_loopback_sockaddr(const struct sockaddr *addr, socklen_t addr_len)
{
#ifdef UNIX
    sa_family_t family;
    size_t bytes_read = 0;

    if (addr == NULL) {
        return true;
    }

    if (addr_len < sizeof(family) ||
        !dr_safe_read(&addr->sa_family, sizeof(family), &family, &bytes_read) ||
        bytes_read != sizeof(family)) {
        return true;
    }

    if (family == AF_INET) {
        struct sockaddr_in in_addr;
        uint32_t host_order;

        if (addr_len < sizeof(in_addr)) {
            return true;
        }
        if (!dr_safe_read(addr, sizeof(in_addr), &in_addr, &bytes_read) ||
            bytes_read != sizeof(in_addr)) {
            return true;
        }

        host_order = ntohl(in_addr.sin_addr.s_addr);
        return (host_order & 0xff000000U) == 0x7f000000U;
    }

    if (family == AF_INET6) {
        struct sockaddr_in6 in6_addr;
        const byte *bytes;
        size_t idx;

        if (addr_len < sizeof(in6_addr)) {
            return true;
        }
        if (!dr_safe_read(addr, sizeof(in6_addr), &in6_addr, &bytes_read) ||
            bytes_read != sizeof(in6_addr)) {
            return true;
        }

        bytes = (const byte *)&in6_addr.sin6_addr;
        for (idx = 0; idx < 15; idx++) {
            if (bytes[idx] != 0) {
                return false;
            }
        }
        return bytes[15] == 1;
    }
#endif

    return true;
}

static void
increment_counter(byte *counter)
{
    if (enable_hitcount_buckets) {
        if (*counter == 0) {
            *counter = 1;
        } else if (*counter == 1) {
            *counter = 2;
        } else if (*counter == 2) {
            *counter = 4;
        } else if (*counter < 8) {
            *counter = 8;
        } else if (*counter < 16) {
            *counter = 16;
        } else if (*counter < 32) {
            *counter = 32;
        } else if (*counter < 128) {
            *counter = 128;
        }
        return;
    }

    (*counter)++;
    if (!disable_neverzero && *counter == 0) {
        *counter = 1;
    }
}

static bool
insert_inline_counter_update(void *drcontext, instrlist_t *bb, instr_t *where,
                             uint32_t cur_loc)
{
#if defined(X86)
    reg_id_t state_reg;
    reg_id_t tmp_reg;
    reg_id_t hist_reg;
    reg_id_t state_reg32;
    reg_id_t tmp_reg32;
    reg_id_t hist_reg32;
    instr_t *skip_zero_fix;
    instr_t *not_zero;
    instr_t *not_one;
    instr_t *not_two;
    instr_t *ge_eight;
    instr_t *ge_sixteen;
    instr_t *ge_thirty_two;
    instr_t *bucket_done;
    uint32_t i;

    if (ngram_size > MAX_NGRAM_SIZE) {
        return false;
    }

    if (drreg_reserve_register(drcontext, bb, where, NULL, &state_reg) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, where, NULL, &tmp_reg) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, where, NULL, &hist_reg) != DRREG_SUCCESS ||
        drreg_reserve_aflags(drcontext, bb, where) != DRREG_SUCCESS) {
        return false;
    }

    state_reg32 = reg_resize_to_opsz(state_reg, OPSZ_4);
    tmp_reg32 = reg_resize_to_opsz(tmp_reg, OPSZ_4);
    hist_reg32 = reg_resize_to_opsz(hist_reg, OPSZ_4);

    if (!drmgr_insert_read_tls_field(drcontext, tls_index, bb, where, state_reg)) {
        return false;
    }

    instrlist_meta_preinsert(
        bb, where,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(tmp_reg32),
                            OPND_CREATE_MEM32(state_reg,
                                              offsetof(thread_cov_state_t, prev_loc))));
    instrlist_meta_preinsert(
        bb, where,
        INSTR_CREATE_xor(drcontext, opnd_create_reg(tmp_reg32), OPND_CREATE_INT32(cur_loc)));
    for (i = 1; i < ngram_size; i++) {
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_ld(
                drcontext, opnd_create_reg(hist_reg32),
                OPND_CREATE_MEM32(state_reg,
                                  offsetof(thread_cov_state_t, history) +
                                      ((int)i - 1) * (int)sizeof(uint32_t))));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_rol(drcontext, opnd_create_reg(hist_reg32),
                             OPND_CREATE_INT8((char)(i * 7))));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_xor(drcontext, opnd_create_reg(tmp_reg32),
                             opnd_create_reg(hist_reg32)));
    }
    instrlist_meta_preinsert(
        bb, where,
        INSTR_CREATE_and(drcontext, opnd_create_reg(tmp_reg32),
                         OPND_CREATE_INT32((int)(coverage_map_size - 1))));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)coverage_map,
                                     opnd_create_reg(state_reg), bb, where, NULL, NULL);

    if (enable_hitcount_buckets) {
        not_zero = INSTR_CREATE_label(drcontext);
        not_one = INSTR_CREATE_label(drcontext);
        not_two = INSTR_CREATE_label(drcontext);
        ge_eight = INSTR_CREATE_label(drcontext);
        ge_sixteen = INSTR_CREATE_label(drcontext);
        ge_thirty_two = INSTR_CREATE_label(drcontext);
        bucket_done = INSTR_CREATE_label(drcontext);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(0)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_instr(not_zero)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(1)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jmp(drcontext, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(bb, where, not_zero);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(1)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_instr(not_one)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(2)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jmp(drcontext, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(bb, where, not_one);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(2)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_instr(not_two)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(4)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jmp(drcontext, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(bb, where, not_two);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(8)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jcc(drcontext, OP_jae, opnd_create_instr(ge_eight)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(8)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jmp(drcontext, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(bb, where, ge_eight);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(16)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_jcc(drcontext, OP_jae, opnd_create_instr(ge_sixteen)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(16)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jmp(drcontext, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(bb, where, ge_sixteen);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(32)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_jcc(drcontext, OP_jae, opnd_create_instr(ge_thirty_two)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(32)));
        instrlist_meta_preinsert(
            bb, where, INSTR_CREATE_jmp(drcontext, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(bb, where, ge_thirty_two);

        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                             OPND_CREATE_INT8(127)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_jcc(drcontext, OP_ja, opnd_create_instr(bucket_done)));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(drcontext,
                                opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                OPND_CREATE_INT8(-128)));
        instrlist_meta_preinsert(bb, where, bucket_done);
    } else {
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_inc(drcontext,
                             opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1)));
        if (!disable_neverzero) {
            skip_zero_fix = INSTR_CREATE_label(drcontext);
            instrlist_meta_preinsert(
                bb, where,
                INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(skip_zero_fix)));
            instrlist_meta_preinsert(
                bb, where,
                INSTR_CREATE_mov_st(drcontext,
                                    opnd_create_base_disp(state_reg, tmp_reg, 1, 0, OPSZ_1),
                                    OPND_CREATE_INT8(1)));
            instrlist_meta_preinsert(bb, where, skip_zero_fix);
        }
    }

    drmgr_insert_read_tls_field(drcontext, tls_index, bb, where, state_reg);
    for (i = MAX_NGRAM_SIZE - 1; i > 0; i--) {
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_ld(
                drcontext, opnd_create_reg(hist_reg32),
                OPND_CREATE_MEM32(state_reg,
                                  offsetof(thread_cov_state_t, history) +
                                      ((int)i - 1) * (int)sizeof(uint32_t))));
        instrlist_meta_preinsert(
            bb, where,
            INSTR_CREATE_mov_st(
                drcontext,
                OPND_CREATE_MEM32(state_reg,
                                  offsetof(thread_cov_state_t, history) +
                                      (int)i * (int)sizeof(uint32_t)),
                opnd_create_reg(hist_reg32)));
    }
    instrlist_meta_preinsert(
        bb, where,
        INSTR_CREATE_mov_st(drcontext,
                            OPND_CREATE_MEM32(state_reg,
                                              offsetof(thread_cov_state_t, history)),
                            OPND_CREATE_INT32((int)cur_loc)));
    instrlist_meta_preinsert(
        bb, where,
        INSTR_CREATE_mov_st(drcontext,
                            OPND_CREATE_MEM32(state_reg,
                                              offsetof(thread_cov_state_t, prev_loc)),
                            OPND_CREATE_INT32((int)(cur_loc >> 1))));

    if (drreg_unreserve_aflags(drcontext, bb, where) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, where, hist_reg) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, where, tmp_reg) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, where, state_reg) != DRREG_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)drcontext;
    (void)bb;
    (void)where;
    (void)cur_loc;
    return false;
#endif
}

static void
bump_synthetic_coverage(uint64_t tag, uint32_t progress)
{
    uint32_t idx;

    if (coverage_map == NULL || coverage_map_size == 0) {
        return;
    }
    if (enable_persistent_reset_hook && !persistent_coverage_enabled) {
        return;
    }

    idx = hash_u64(tag ^ ((uint64_t)progress * 0x9e3779b97f4a7c15ULL));
    increment_counter(&coverage_map[idx & (coverage_map_size - 1)]);
}

static uint32_t
matching_prefix_len(const byte *a, const byte *b, uint32_t max_len, bool stop_at_nul)
{
    uint32_t idx;

    if (a == NULL || b == NULL) {
        return 0;
    }

    for (idx = 0; idx < max_len; idx++) {
        byte av = 0;
        byte bv = 0;
        size_t bytes_read = 0;

        if (!dr_safe_read(a + idx, sizeof(av), &av, &bytes_read) ||
            bytes_read != sizeof(av)) {
            break;
        }
        if (!dr_safe_read(b + idx, sizeof(bv), &bv, &bytes_read) ||
            bytes_read != sizeof(bv)) {
            break;
        }
        if (av != bv) {
            break;
        }
        if (stop_at_nul && av == '\0') {
            idx++;
            break;
        }
    }

    return idx;
}

static uint32_t
matching_prefix_len_ci(const byte *a, const byte *b, uint32_t max_len, bool stop_at_nul)
{
    uint32_t idx;

    if (a == NULL || b == NULL) {
        return 0;
    }

    for (idx = 0; idx < max_len; idx++) {
        byte av = 0;
        byte bv = 0;
        size_t bytes_read = 0;

        if (!dr_safe_read(a + idx, sizeof(av), &av, &bytes_read) ||
            bytes_read != sizeof(av)) {
            break;
        }
        if (!dr_safe_read(b + idx, sizeof(bv), &bv, &bytes_read) ||
            bytes_read != sizeof(bv)) {
            break;
        }
        if ((byte)ascii_lower((char)av) != (byte)ascii_lower((char)bv)) {
            break;
        }
        if (stop_at_nul && av == '\0') {
            idx++;
            break;
        }
    }

    return idx;
}

static uint32_t
best_substring_prefix_len(const byte *haystack, uint32_t haystack_len, const byte *needle,
                          uint32_t needle_len, bool stop_at_nul)
{
    uint32_t best = 0;
    uint32_t idx;

    if (haystack == NULL || needle == NULL || haystack_len == 0 || needle_len == 0) {
        return 0;
    }

    if (haystack_len > 128) {
        haystack_len = 128;
    }
    if (needle_len > 64) {
        needle_len = 64;
    }

    for (idx = 0; idx < haystack_len; idx++) {
        uint32_t available = haystack_len - idx;
        uint32_t max_len = available < needle_len ? available : needle_len;
        uint32_t matched;

        if (max_len == 0) {
            break;
        }

        matched = matching_prefix_len(haystack + idx, needle, max_len, stop_at_nul);
        if (matched > best) {
            best = matched;
        }
        if (best >= needle_len) {
            break;
        }
    }

    return best;
}

static uint32_t
safe_string_scan_len(const byte *value, uint32_t max_len)
{
    uint32_t len;

    if (value == NULL) {
        return 0;
    }

    for (len = 0; len < max_len; len++) {
        byte ch = 0;
        size_t bytes_read = 0;

        if (!dr_safe_read(value + len, sizeof(ch), &ch, &bytes_read) ||
            bytes_read != sizeof(ch) || ch == '\0') {
            break;
        }
    }

    return len;
}

static void
trace_cmp_progress(const char *api_name, uint32_t prefix_len)
{
    uint32_t idx;
    uint64_t tag = 0xcbf29ce484222325ULL;
    const char *p = api_name;

    if (prefix_len == 0) {
        return;
    }

    while (p != NULL && *p != '\0') {
        tag ^= (unsigned char)*p;
        tag *= 0x100000001b3ULL;
        p++;
    }

    for (idx = 1; idx <= prefix_len; idx++) {
        bump_synthetic_coverage(tag, idx);
    }
}

static void
trace_int_cmp_progress(uint64_t tag, uint64_t observed, uint64_t expected, uint32_t width)
{
    uint32_t idx;
    uint32_t matched = 0;

    if (width == 0 || width > 8) {
        return;
    }

    for (idx = 0; idx < width; idx++) {
        uint8_t observed_byte = (uint8_t)((observed >> (idx * 8)) & 0xffU);
        uint8_t expected_byte = (uint8_t)((expected >> (idx * 8)) & 0xffU);

        if (observed_byte != expected_byte) {
            break;
        }
        matched++;
    }

    for (idx = 1; idx <= matched; idx++) {
        bump_synthetic_coverage(tag, idx);
    }
}

static void
strcmp_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *a = (const byte *)drwrap_get_arg(wrapcxt, 0);
    const byte *b = (const byte *)drwrap_get_arg(wrapcxt, 1);
    uint32_t prefix_len = matching_prefix_len(a, b, 64, true);

    trace_cmp_progress(api_name, prefix_len);
}

static void
strncmp_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *a = (const byte *)drwrap_get_arg(wrapcxt, 0);
    const byte *b = (const byte *)drwrap_get_arg(wrapcxt, 1);
    uint32_t n = (uint32_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);

    if (n > 64) {
        n = 64;
    }
    trace_cmp_progress(api_name, matching_prefix_len(a, b, n, true));
}

static void
memcmp_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *a = (const byte *)drwrap_get_arg(wrapcxt, 0);
    const byte *b = (const byte *)drwrap_get_arg(wrapcxt, 1);
    uint32_t n = (uint32_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);

    if (n > 64) {
        n = 64;
    }
    trace_cmp_progress(api_name, matching_prefix_len(a, b, n, false));
}

static void
strcasecmp_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *a = (const byte *)drwrap_get_arg(wrapcxt, 0);
    const byte *b = (const byte *)drwrap_get_arg(wrapcxt, 1);

    trace_cmp_progress(api_name, matching_prefix_len_ci(a, b, 64, true));
}

static void
strncasecmp_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *a = (const byte *)drwrap_get_arg(wrapcxt, 0);
    const byte *b = (const byte *)drwrap_get_arg(wrapcxt, 1);
    uint32_t n = (uint32_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);

    if (n > 64) {
        n = 64;
    }
    trace_cmp_progress(api_name, matching_prefix_len_ci(a, b, n, true));
}

static void
strstr_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *haystack = (const byte *)drwrap_get_arg(wrapcxt, 0);
    const byte *needle = (const byte *)drwrap_get_arg(wrapcxt, 1);
    uint32_t haystack_len = safe_string_scan_len(haystack, 128);
    uint32_t needle_len = safe_string_scan_len(needle, 64);

    trace_cmp_progress(api_name,
                       best_substring_prefix_len(haystack, haystack_len, needle,
                                                 needle_len, true));
}

static void
memmem_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *haystack = (const byte *)drwrap_get_arg(wrapcxt, 0);
    uint32_t haystack_len = (uint32_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 1);
    const byte *needle = (const byte *)drwrap_get_arg(wrapcxt, 2);
    uint32_t needle_len = (uint32_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 3);

    trace_cmp_progress(api_name,
                       best_substring_prefix_len(haystack, haystack_len, needle,
                                                 needle_len, false));
}

static void
abort_target_for_oracle(void)
{
#ifdef UNIX
    kill(getpid(), SIGABRT);
#else
    dr_exit_process(128 + 6);
#endif
}

static void
dangerous_string_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 0);
    char value[512];

    if (!copy_app_string(value, sizeof(value), app_arg)) {
        return;
    }

    if (has_shell_metachar(value)) {
        log_string_event(api_name, value);
        abort_target_for_oracle();
    }
}

static void
path_arg0_check(const char *api_name, const char *app_arg, bool mutation)
{
    char value[512];

    if (!copy_app_string(value, sizeof(value), app_arg)) {
        return;
    }

    if (path_is_allowlisted(value)) {
        return;
    }

    if ((abort_on_credential_file && has_credential_path_pattern(value)) ||
        (abort_on_path_traversal && has_path_traversal_pattern(value)) ||
        (abort_on_file_mutation && mutation)) {
        log_string_event(api_name, value);
        abort_target_for_oracle();
    }
}

static void
open_arg0_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 0);
    int flags = (int)(ptr_int_t)drwrap_get_arg(wrapcxt, 1);

    path_arg0_check(api_name, app_arg, has_file_mutation_flags(flags));
}

static void
openat_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 1);
    int flags = (int)(ptr_int_t)drwrap_get_arg(wrapcxt, 2);

    path_arg0_check(api_name, app_arg, has_file_mutation_flags(flags));
}

static void
fopen_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 0);
    const char *mode_arg = (const char *)drwrap_get_arg(wrapcxt, 1);
    char mode[16];
    bool mutation = false;

    if (copy_app_string(mode, sizeof(mode), mode_arg)) {
        mutation = has_file_mutation_mode(mode);
    }

    path_arg0_check(api_name, app_arg, mutation);
}

static void
file_arg0_mutation_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 0);

    path_arg0_check(api_name, app_arg, true);
}

static void
file_arg1_mutation_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 1);

    path_arg0_check(api_name, app_arg, true);
}

static void
rename_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *old_arg = (const char *)drwrap_get_arg(wrapcxt, 0);
    const char *new_arg = (const char *)drwrap_get_arg(wrapcxt, 1);

    path_arg0_check(api_name, old_arg, true);
    path_arg0_check(api_name, new_arg, true);
}

static void
renameat_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *old_arg = (const char *)drwrap_get_arg(wrapcxt, 1);
    const char *new_arg = (const char *)drwrap_get_arg(wrapcxt, 3);

    path_arg0_check(api_name, old_arg, true);
    path_arg0_check(api_name, new_arg, true);
}

static void
exec_path_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 0);
    char value[512];

    if (!copy_app_string(value, sizeof(value), app_arg)) {
        return;
    }

    if (has_exec_suspicious_pattern(value) && !exec_path_is_allowed(value)) {
        log_string_event(api_name, value);
        abort_target_for_oracle();
    }
}

static void
env_access_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const char *app_arg = (const char *)drwrap_get_arg(wrapcxt, 0);
    char value[256];

    if (!copy_app_string(value, sizeof(value), app_arg)) {
        return;
    }

    if (has_sensitive_env_name(value) && !env_name_is_allowlisted(value)) {
        log_string_event(api_name, value);
        abort_target_for_oracle();
    }
}

static void
connect_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const struct sockaddr *addr = (const struct sockaddr *)drwrap_get_arg(wrapcxt, 1);
    socklen_t addr_len = (socklen_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);

    if (!is_loopback_sockaddr(addr, addr_len) &&
        !sockaddr_is_allowlisted(addr, addr_len)) {
        log_string_event(api_name, "non-loopback address");
        abort_target_for_oracle();
    }
}

static void
send_api_pre(void *wrapcxt, void **user_data)
{
    const char *api_name = (const char *)*user_data;
    const byte *buf = (const byte *)drwrap_get_arg(wrapcxt, 1);
    size_t len = (size_t)(ptr_uint_t)drwrap_get_arg(wrapcxt, 2);

    if (has_suspicious_network_payload(buf, len)) {
        log_string_event(api_name, "suspicious outbound payload");
        abort_target_for_oracle();
    }
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
#ifdef UNIX
    if (abort_on_network && sysnum == SYS_connect) {
        const struct sockaddr *addr =
            (const struct sockaddr *)dr_syscall_get_param(drcontext, 1);
        socklen_t addr_len = (socklen_t)dr_syscall_get_param(drcontext, 2);

        if (!is_loopback_sockaddr(addr, addr_len) &&
            !sockaddr_is_allowlisted(addr, addr_len)) {
            log_string_event("connect", "non-loopback address");
            abort_target_for_oracle();
        }
    }
    if (abort_on_network && sysnum == SYS_sendto) {
        const byte *buf = (const byte *)dr_syscall_get_param(drcontext, 1);
        size_t len = (size_t)dr_syscall_get_param(drcontext, 2);

        if (has_suspicious_network_payload(buf, len)) {
            log_string_event("sendto", "suspicious outbound payload");
            abort_target_for_oracle();
        }
    }
    if (abort_on_file_mutation || abort_on_credential_file) {
#ifdef SYS_open
        if (sysnum == SYS_open) {
            const char *path = (const char *)dr_syscall_get_param(drcontext, 0);
            int flags = (int)dr_syscall_get_param(drcontext, 1);

            path_arg0_check("open", path, has_file_mutation_flags(flags));
        }
#endif
#ifdef SYS_openat
        if (sysnum == SYS_openat) {
            const char *path = (const char *)dr_syscall_get_param(drcontext, 1);
            int flags = (int)dr_syscall_get_param(drcontext, 2);

            path_arg0_check("openat", path, has_file_mutation_flags(flags));
        }
#endif
#ifdef SYS_creat
        if (sysnum == SYS_creat) {
            const char *path = (const char *)dr_syscall_get_param(drcontext, 0);

            path_arg0_check("creat", path, true);
        }
#endif
#ifdef SYS_unlink
        if (sysnum == SYS_unlink) {
            const char *path = (const char *)dr_syscall_get_param(drcontext, 0);

            path_arg0_check("unlink", path, true);
        }
#endif
#ifdef SYS_unlinkat
        if (sysnum == SYS_unlinkat) {
            const char *path = (const char *)dr_syscall_get_param(drcontext, 1);

            path_arg0_check("unlinkat", path, true);
        }
#endif
#ifdef SYS_rename
        if (sysnum == SYS_rename) {
            const char *old_path = (const char *)dr_syscall_get_param(drcontext, 0);
            const char *new_path = (const char *)dr_syscall_get_param(drcontext, 1);

            path_arg0_check("rename", old_path, true);
            path_arg0_check("rename", new_path, true);
        }
#endif
#ifdef SYS_renameat
        if (sysnum == SYS_renameat) {
            const char *old_path = (const char *)dr_syscall_get_param(drcontext, 1);
            const char *new_path = (const char *)dr_syscall_get_param(drcontext, 3);

            path_arg0_check("renameat", old_path, true);
            path_arg0_check("renameat", new_path, true);
        }
#endif
#ifdef SYS_renameat2
        if (sysnum == SYS_renameat2) {
            const char *old_path = (const char *)dr_syscall_get_param(drcontext, 1);
            const char *new_path = (const char *)dr_syscall_get_param(drcontext, 3);

            path_arg0_check("renameat2", old_path, true);
            path_arg0_check("renameat2", new_path, true);
        }
#endif
    }
#else
    (void)drcontext;
    (void)sysnum;
#endif
    return true;
}

static void
try_wrap_api(const module_data_t *module, const char *symbol,
             void (*pre_func_cb)(void *wrapcxt, void **user_data))
{
    app_pc target = (app_pc)dr_get_proc_address(module->handle, symbol);

    if (target == NULL) {
        return;
    }
    if (drwrap_is_wrapped(target, pre_func_cb, NULL)) {
        return;
    }

    if (drwrap_wrap_ex(target, pre_func_cb, NULL, (void *)symbol,
                       DRWRAP_CALLCONV_DEFAULT)) {
        if (!quiet_logs) {
            dr_mutex_lock(log_mutex);
            dr_fprintf(STDERR, "shadowcov: wrapped dangerous API %s @" PFX "\n",
                       symbol, target);
            dr_mutex_unlock(log_mutex);
        }
    }
}

static void
event_module_load(void *drcontext, const module_data_t *module, bool loaded)
{
    (void)drcontext;
    (void)loaded;

    if (!abort_on_dangerous_api && !abort_on_credential_file &&
        !abort_on_path_traversal &&
        !abort_on_file_mutation && !abort_on_exec && !abort_on_env_access &&
        !abort_on_network && !trace_cmp) {
        return;
    }

    if (abort_on_dangerous_api) {
        try_wrap_api(module, "system", dangerous_string_api_pre);
        try_wrap_api(module, "popen", dangerous_string_api_pre);
    }

    if (abort_on_credential_file || abort_on_path_traversal ||
        abort_on_file_mutation) {
        try_wrap_api(module, "open", open_arg0_api_pre);
        try_wrap_api(module, "open64", open_arg0_api_pre);
        try_wrap_api(module, "openat", openat_api_pre);
        try_wrap_api(module, "openat64", openat_api_pre);
        try_wrap_api(module, "fopen", fopen_api_pre);
        try_wrap_api(module, "fopen64", fopen_api_pre);
    }

    if (abort_on_file_mutation) {
        try_wrap_api(module, "creat", file_arg0_mutation_api_pre);
        try_wrap_api(module, "creat64", file_arg0_mutation_api_pre);
        try_wrap_api(module, "unlink", file_arg0_mutation_api_pre);
        try_wrap_api(module, "unlinkat", file_arg1_mutation_api_pre);
        try_wrap_api(module, "remove", file_arg0_mutation_api_pre);
        try_wrap_api(module, "rename", rename_api_pre);
        try_wrap_api(module, "renameat", renameat_api_pre);
        try_wrap_api(module, "renameat2", renameat_api_pre);
    }

    if (abort_on_exec) {
        try_wrap_api(module, "execl", exec_path_api_pre);
        try_wrap_api(module, "execlp", exec_path_api_pre);
        try_wrap_api(module, "execle", exec_path_api_pre);
        try_wrap_api(module, "execv", exec_path_api_pre);
        try_wrap_api(module, "execvp", exec_path_api_pre);
        try_wrap_api(module, "execvpe", exec_path_api_pre);
        try_wrap_api(module, "execve", exec_path_api_pre);
    }

    if (abort_on_env_access) {
        try_wrap_api(module, "getenv", env_access_api_pre);
        try_wrap_api(module, "secure_getenv", env_access_api_pre);
        try_wrap_api(module, "__secure_getenv", env_access_api_pre);
    }

    if (abort_on_network) {
        try_wrap_api(module, "connect", connect_api_pre);
        try_wrap_api(module, "send", send_api_pre);
        try_wrap_api(module, "sendto", send_api_pre);
    }

    if (trace_cmp) {
        try_wrap_api(module, "strcmp", strcmp_pre);
        try_wrap_api(module, "strncmp", strncmp_pre);
        try_wrap_api(module, "memcmp", memcmp_pre);
        try_wrap_api(module, "strcasecmp", strcasecmp_pre);
        try_wrap_api(module, "strncasecmp", strncasecmp_pre);
        try_wrap_api(module, "strstr", strstr_pre);
        try_wrap_api(module, "memmem", memmem_pre);
    }
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
    char *end = NULL;
    long parsed;
    int shm_id;
    void *shm_ptr;

    if (shm_id_str == NULL || shm_id_str[0] == '\0') {
        shm_id_str = get_env("AFL_SHM_ID");
    }
    if (shm_id_str == NULL || shm_id_str[0] == '\0') {
        return false;
    }

    parsed = strtol(shm_id_str, &end, 10);
    if (end == shm_id_str || *end != '\0' || parsed < 0) {
        log_error("invalid AFL_SHM_ID");
        return false;
    }
    shm_id = (int)parsed;

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

static bool
opnd_get_immediate_value(opnd_t opnd, int64_t *value)
{
    if (opnd_is_immed_int(opnd)) {
        *value = (int64_t)opnd_get_immed_int(opnd);
        return true;
    }
    if (opnd_is_immed_int64(opnd)) {
        *value = (int64_t)opnd_get_immed_int64(opnd);
        return true;
    }
    return false;
}

static uint32_t
opnd_fixed_size_bytes(opnd_t opnd)
{
    uint size = opnd_size_in_bytes(opnd_get_size(opnd));

    if (size == 1 || size == 2 || size == 4 || size == 8) {
        return (uint32_t)size;
    }
    return 0;
}

static reg_id_t
reg_for_width(reg_id_t reg, uint32_t width)
{
    if (width == 1) {
        return reg_resize_to_opsz(reg, OPSZ_1);
    }
    if (width == 2) {
        return reg_resize_to_opsz(reg, OPSZ_2);
    }
    if (width == 4) {
        return reg_resize_to_opsz(reg, OPSZ_4);
    }
    return reg_resize_to_opsz(reg, OPSZ_8);
}

static bool
insert_int_cmp_clean_call(void *drcontext, instrlist_t *bb, instr_t *where, uint64_t tag,
                          opnd_t observed, opnd_t expected, uint32_t width)
{
#if defined(X86)
    reg_id_t scratch = DR_REG_NULL;
    opnd_t observed_arg = observed;

    if (opnd_is_memory_reference(observed) || width < 8) {
        if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch) !=
            DRREG_SUCCESS) {
            return false;
        }
        instrlist_meta_preinsert(bb, where,
                                 INSTR_CREATE_xor(drcontext, opnd_create_reg(scratch),
                                                  opnd_create_reg(scratch)));
        observed_arg = opnd_create_reg(scratch);
        instrlist_meta_preinsert(bb, where,
                                 INSTR_CREATE_mov_ld(
                                     drcontext, opnd_create_reg(reg_for_width(scratch, width)),
                                     observed));
    }

    dr_insert_clean_call(drcontext, bb, where, (void *)trace_int_cmp_progress, false, 4,
                         OPND_CREATE_INT64((int64)tag), observed_arg, expected,
                         OPND_CREATE_INT32((int)width));

    if (scratch != DR_REG_NULL &&
        drreg_unreserve_register(drcontext, bb, where, scratch) != DRREG_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)drcontext;
    (void)bb;
    (void)where;
    (void)tag;
    (void)observed;
    (void)expected;
    (void)width;
    return false;
#endif
}

static bool
insert_int_cmp_reg_reg_clean_call(void *drcontext, instrlist_t *bb, instr_t *where,
                                  uint64_t tag, opnd_t observed, opnd_t expected,
                                  uint32_t width)
{
#if defined(X86)
    reg_id_t observed_scratch;
    reg_id_t expected_scratch;
    opnd_t observed_arg;
    opnd_t expected_arg;

    if (drreg_reserve_register(drcontext, bb, where, NULL, &observed_scratch) !=
        DRREG_SUCCESS) {
        return false;
    }
    if (drreg_reserve_register(drcontext, bb, where, NULL, &expected_scratch) !=
        DRREG_SUCCESS) {
        (void)drreg_unreserve_register(drcontext, bb, where, observed_scratch);
        return false;
    }

    observed_arg = opnd_create_reg(reg_for_width(observed_scratch, width));
    expected_arg = opnd_create_reg(reg_for_width(expected_scratch, width));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_xor(drcontext, opnd_create_reg(observed_scratch),
                                              opnd_create_reg(observed_scratch)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_xor(drcontext, opnd_create_reg(expected_scratch),
                                              opnd_create_reg(expected_scratch)));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext, observed_arg, observed));
    instrlist_meta_preinsert(bb, where,
                             INSTR_CREATE_mov_ld(drcontext, expected_arg, expected));
    observed_arg = opnd_create_reg(observed_scratch);
    expected_arg = opnd_create_reg(expected_scratch);

    dr_insert_clean_call(drcontext, bb, where, (void *)trace_int_cmp_progress, false, 4,
                         OPND_CREATE_INT64((int64)tag), observed_arg, expected_arg,
                         OPND_CREATE_INT32((int)width));

    if (drreg_unreserve_register(drcontext, bb, where, expected_scratch) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, where, observed_scratch) !=
            DRREG_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)drcontext;
    (void)bb;
    (void)where;
    (void)tag;
    (void)observed;
    (void)expected;
    (void)width;
    return false;
#endif
}

static void
maybe_insert_int_cmp_trace(void *drcontext, instrlist_t *bb, instr_t *where)
{
#if defined(X86)
    int opcode;
    opnd_t src0;
    opnd_t src1;
    opnd_t observed;
    opnd_t expected;
    int64_t immediate_value = 0;
    uint32_t width;
    app_pc pc;
    uint64_t tag;

    if (!trace_cmp || !instr_is_app(where) || instr_num_srcs(where) < 2) {
        return;
    }

    opcode = instr_get_opcode(where);
    if (opcode != OP_cmp) {
        return;
    }

    src0 = instr_get_src(where, 0);
    src1 = instr_get_src(where, 1);
    pc = instr_get_app_pc(where);
    if (pc == NULL) {
        return;
    }

    if (opnd_get_immediate_value(src0, &immediate_value) &&
        (opnd_is_reg(src1) || opnd_is_memory_reference(src1))) {
        observed = src1;
        if (immediate_value >= -255 && immediate_value <= 255) {
            return;
        }
        width = opnd_fixed_size_bytes(observed);
        if (width == 0) {
            return;
        }
        tag = 0x9e3779b97f4a7c15ULL ^ (uint64_t)stable_location_id(pc) ^
            ((uint64_t)(uint32_t)immediate_value << 17);
        (void)insert_int_cmp_clean_call(
            drcontext, bb, where, tag, observed,
            OPND_CREATE_INT64((int64)immediate_value), width);
        return;
    }

    if (opnd_get_immediate_value(src1, &immediate_value) &&
        (opnd_is_reg(src0) || opnd_is_memory_reference(src0))) {
        observed = src0;
        if (immediate_value >= -255 && immediate_value <= 255) {
            return;
        }
        width = opnd_fixed_size_bytes(observed);
        if (width == 0) {
            return;
        }
        tag = 0x9e3779b97f4a7c15ULL ^ (uint64_t)stable_location_id(pc) ^
            ((uint64_t)(uint32_t)immediate_value << 17);
        (void)insert_int_cmp_clean_call(
            drcontext, bb, where, tag, observed,
            OPND_CREATE_INT64((int64)immediate_value), width);
        return;
    }

    if (!opnd_is_reg(src0) || !opnd_is_reg(src1)) {
        return;
    }

    observed = src0;
    expected = src1;
    width = opnd_fixed_size_bytes(observed);
    if (width == 0 || width != opnd_fixed_size_bytes(expected)) {
        return;
    }

    tag = 0x517cc1b727220a95ULL ^ (uint64_t)stable_location_id(pc) ^
        ((uint64_t)width << 41);
    (void)insert_int_cmp_reg_reg_clean_call(drcontext, bb, where, tag, observed, expected,
                                            width);
#else
    (void)drcontext;
    (void)bb;
    (void)where;
#endif
}

static void
event_thread_init(void *drcontext)
{
    thread_cov_state_t *state;

    state = dr_thread_alloc(drcontext, sizeof(*state));
    memset(state, 0, sizeof(*state));
    drmgr_set_tls_field(drcontext, tls_index, state);
}

static void
event_thread_exit(void *drcontext)
{
    void *state = drmgr_get_tls_field(drcontext, tls_index);
    if (state != NULL) {
        dr_thread_free(drcontext, state, sizeof(thread_cov_state_t));
    }
}

static void
record_edge(uint32_t cur_loc)
{
    void *drcontext = dr_get_current_drcontext();
    thread_cov_state_t *state = drmgr_get_tls_field(drcontext, tls_index);
    uint32_t edge_idx;
    uint32_t i;

    if (state == NULL ||
        (enable_persistent_reset_hook && !persistent_coverage_enabled)) {
        return;
    }

    edge_idx = cur_loc ^ state->prev_loc;
    for (i = 1; i < ngram_size; i++) {
        edge_idx ^= rotl32(state->history[i - 1], i * 7);
    }

    increment_counter(&coverage_map[edge_idx & (coverage_map_size - 1)]);

    for (i = MAX_NGRAM_SIZE - 1; i > 0; i--) {
        state->history[i] = state->history[i - 1];
    }
    state->history[0] = cur_loc;
    state->prev_loc = cur_loc >> 1;
}

static void
reset_persistent_iteration_state(void *drcontext)
{
    thread_cov_state_t *state = drmgr_get_tls_field(drcontext, tls_index);

    if (state != NULL) {
        memset(state, 0, sizeof(*state));
    }
    if (coverage_map != NULL && coverage_map_size > 0) {
        memset(coverage_map, 0, coverage_map_size);
    }
}

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
#ifdef UNIX
    if (!enable_persistent_reset_hook || siginfo == NULL) {
        return DR_SIGNAL_DELIVER;
    }
    if (siginfo->sig == SIGUSR1) {
        reset_persistent_iteration_state(drcontext);
        persistent_coverage_enabled = true;
        return DR_SIGNAL_SUPPRESS;
    }
    if (siginfo->sig == SIGUSR2) {
        persistent_coverage_enabled = false;
        return DR_SIGNAL_SUPPRESS;
    }
#else
    (void)drcontext;
    (void)siginfo;
#endif
    return DR_SIGNAL_DELIVER;
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

    maybe_insert_int_cmp_trace(drcontext, bb, where);

    cur_loc = stable_location_id(start_pc);
    if (enable_inline_coverage && !enable_persistent_reset_hook &&
        insert_inline_counter_update(drcontext, bb, where, cur_loc)) {
        return DR_EMIT_DEFAULT;
    }

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

    drmgr_unregister_module_load_event(event_module_load);
    drmgr_unregister_pre_syscall_event(event_pre_syscall);
    if (enable_persistent_reset_hook) {
        drmgr_unregister_signal_event(event_signal);
    }
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_unregister_bb_insertion_event(event_basic_block);
    drmgr_unregister_tls_field(tls_index);
    drwrap_exit();
    drreg_exit();
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
    {
        drreg_options_t ops = { sizeof(ops), 4, false };
        if (drreg_init(&ops) != DRREG_SUCCESS) {
            DR_ASSERT(false);
            return;
        }
    }

    log_mutex = dr_mutex_create();
    quiet_logs = get_env("SHADOWCOV_QUIET") != NULL;
    abort_on_dangerous_api = get_env("SHADOWCOV_ABORT_ON_DANGEROUS_API") != NULL;
    abort_on_credential_file =
        get_env("SHADOWCOV_ABORT_ON_CREDENTIAL_FILE") != NULL;
    abort_on_file_mutation = get_env("SHADOWCOV_ABORT_ON_FILE_MUTATION") != NULL;
    abort_on_path_traversal = get_env("SHADOWCOV_ABORT_ON_PATH_TRAVERSAL") != NULL;
    abort_on_exec = get_env("SHADOWCOV_ABORT_ON_EXEC") != NULL;
    abort_on_env_access = get_env("SHADOWCOV_ABORT_ON_ENV_ACCESS") != NULL;
    abort_on_network = get_env("SHADOWCOV_ABORT_ON_NETWORK") != NULL;
    trace_cmp = get_env("SHADOWCOV_TRACE_CMP") != NULL;
    disable_neverzero = get_env("SHADOWCOV_DISABLE_NEVERZERO") != NULL;
    enable_hitcount_buckets = get_env("SHADOWCOV_HITCOUNT_BUCKETS") != NULL;
    enable_inline_coverage = get_env("SHADOWCOV_INLINE_COVERAGE") != NULL;
    enable_persistent_reset_hook = get_env("SHADOWCOV_PERSISTENT_RESET_HOOK") != NULL;
    persistent_coverage_enabled = !enable_persistent_reset_hook;
    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);
    if (!drwrap_init()) {
        DR_ASSERT(false);
        return;
    }

    coverage_map_size = parse_u32_env("SHADOWCOV_MAP_SIZE", DEFAULT_MAP_SIZE);
    if ((coverage_map_size & (coverage_map_size - 1)) != 0) {
        coverage_map_size = DEFAULT_MAP_SIZE;
        log_message("SHADOWCOV_MAP_SIZE is not a power of two, falling back to 65536");
    }
    ngram_size = parse_ngram_size();

    if (!map_coverage_from_afl_shm()) {
        allocate_local_coverage_map();
        open_bitmap_output();
    }
    configure_module_filter();

    dr_register_exit_event(event_exit);
    if (enable_persistent_reset_hook) {
        drmgr_register_signal_event(event_signal);
    }
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_basic_block, NULL);

    dr_log(NULL, DR_LOG_ALL, 1, "shadowcov initialized\n");
}
