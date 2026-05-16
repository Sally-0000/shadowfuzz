#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define AFL_FORKSRV_FD 198
#define PERSISTENT_IN_FD 200
#define PERSISTENT_OUT_FD 201
#define DEFAULT_MAP_SIZE (1U << 16)
#define POLICY_MAX_INCLUDE_DEPTH 8

static bool verbose_logs;

typedef struct shadowfuzz_options_t {
    bool check_only;
    bool abort_on_dangerous_api;
    bool abort_on_credential_file;
    bool abort_on_exec;
    bool abort_on_env_access;
    bool abort_on_file_mutation;
    bool abort_on_network;
    bool abort_on_path_traversal;
    bool hitcount_buckets;
    bool instrument_all_modules;
    bool inline_coverage;
    bool persistent;
    bool quiet_shadowcov;
    bool trace_cmp;
    int target_arg_index;
    const char *bitmap_out;
    const char *policy_file;
    const char *map_size;
    const char *ngram_size;
    const char *exec_allowlist;
    const char *env_allowlist;
    const char *network_allowlist;
    const char *path_allowlist;
    const char *target_module;
} shadowfuzz_options_t;

static void
usage(FILE *stream)
{
    fprintf(stream,
            "Usage:\n"
            "  shadowfuzz-dbi [options] /path/to/target [target args...]\n"
            "\n"
            "Options:\n"
            "  --check                 Validate runtime paths and target, then exit\n"
            "  --map-size N            Set SHADOWCOV_MAP_SIZE for this run\n"
            "  --ngram N               Set SHADOWCOV_NGRAM_SIZE to 1, 2, 4, or 8\n"
            "  --bitmap-out PATH       Set SHADOWCOV_BITMAP_OUT for this run\n"
            "  --policy-file PATH      Load target policy defaults; may be repeated\n"
            "  --target-module NAME    Set SHADOWCOV_TARGET_MODULE for this run\n"
            "  --instrument-all        Set SHADOWCOV_INSTRUMENT_MODULES=all\n"
            "  --abort-on-dangerous-api\n"
            "                          Abort when shadowcov sees dangerous API usage\n"
            "  --abort-on-credential-file\n"
            "                          Abort when file APIs touch likely credential paths\n"
            "  --abort-on-exec         Abort when shadowcov sees suspicious exec* path\n"
            "  --abort-on-env-access   Abort when getenv reads sensitive names\n"
            "  --abort-on-file-mutation\n"
            "                          Abort on delete, rename, create, truncate, or write-open\n"
            "  --abort-on-network      Abort on unsafe connect/send network activity\n"
            "  --exec-allowlist LIST   Allow comma/colon-separated exec basenames\n"
            "  --env-allowlist LIST    Allow comma/colon-separated env var names\n"
            "  --network-allowlist LIST\n"
            "                          Allow comma/colon-separated network tokens\n"
            "  --path-allowlist LIST   Allow comma/colon-separated path prefixes\n"
            "  --abort-on-path-traversal\n"
            "                          Abort when shadowcov sees unsafe file paths\n"
            "  --hitcount-buckets      Use AFL-style bucketed coverage counters\n"
            "  --inline-coverage       Use inline edge counter updates when supported\n"
            "  --persistent            Experimental: use the shadowfuzz persistent harness protocol\n"
            "  --trace-cmp            Enable shadowcov strcmp/strncmp/memcmp feedback\n"
            "  --quiet-shadowcov       Set SHADOWCOV_QUIET=1 for this run\n"
            "\n"
            "Environment:\n"
            "  SHADOWFUZZ_DRRUN_PATH   Override drrun path\n"
            "  SHADOWFUZZ_CLIENT_PATH  Override shadowcov client path\n"
            "  SHADOWFUZZ_VERBOSE      Print executor debug logs when set\n"
            "  SHADOWCOV_ABORT_ON_DANGEROUS_API\n"
            "                       Abort on suspicious system/popen/execve calls\n"
            "  SHADOWCOV_ABORT_ON_CREDENTIAL_FILE\n"
            "                       Abort on likely credential file paths\n"
            "  SHADOWCOV_ABORT_ON_EXEC\n"
            "                       Abort on suspicious exec* calls\n"
            "  SHADOWCOV_ABORT_ON_ENV_ACCESS\n"
            "                       Abort on sensitive getenv/secure_getenv names\n"
            "  SHADOWCOV_ABORT_ON_FILE_MUTATION\n"
            "                       Abort on destructive file mutation APIs\n"
            "  SHADOWCOV_ABORT_ON_NETWORK\n"
            "                       Abort on non-loopback connect() and suspicious send payloads\n"
            "  SHADOWCOV_EXEC_ALLOWLIST\n"
            "                       Comma/colon-separated allowed exec basenames\n"
            "  SHADOWCOV_ENV_ALLOWLIST\n"
            "                       Comma/colon-separated allowed env var names\n"
            "  SHADOWCOV_NETWORK_ALLOWLIST\n"
            "                       Comma/colon-separated allowed IPs or payload tokens\n"
            "  SHADOWCOV_PATH_ALLOWLIST\n"
            "                       Comma/colon-separated allowed path prefixes\n"
            "  SHADOWCOV_ABORT_ON_PATH_TRAVERSAL\n"
            "                       Abort on suspicious open/openat/fopen paths\n"
            "  SHADOWCOV_TRACE_CMP  Enable strcmp/strncmp/memcmp progress feedback\n"
            "  SHADOWCOV_HITCOUNT_BUCKETS\n"
            "                       Use AFL-style bucketed coverage counters\n"
            "  SHADOWCOV_INLINE_COVERAGE\n"
            "                       Use inline edge counter updates when supported\n"
            "  SHADOWCOV_NGRAM_SIZE Coverage context size: 1, 2, 4, or 8\n"
            "  SHADOWCOV_MAP_SIZE   Coverage bitmap size (default: 65536)\n"
            "  SHADOWCOV_QUIET      Suppress shadowcov informational logs\n"
            "\n"
            "This is a minimal AFL++ forkserver-compatible executor.\n");
}

static bool
path_exists(const char *path)
{
    return path != NULL && access(path, F_OK) == 0;
}

static bool
path_is_executable(const char *path)
{
    return path != NULL && access(path, X_OK) == 0;
}

static const char *
get_env(const char *name)
{
    return getenv(name);
}

static char *
trim_ascii(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        s++;
    }
    end = s + strlen(s);
    while (end > s &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
            end[-1] == '\n')) {
        end--;
    }
    *end = '\0';
    return s;
}

static bool
parse_policy_bool(const char *value, bool *out)
{
    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 || strcmp(value, "on") == 0) {
        *out = true;
        return true;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
        strcmp(value, "no") == 0 || strcmp(value, "off") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static int
normalize_policy_key(char *dst, size_t dst_size, const char *section, const char *key,
                     const char *path, unsigned line_no)
{
    int written;

    if (section[0] == '\0') {
        written = snprintf(dst, dst_size, "%s", key);
    } else if (strcmp(section, "oracles") == 0) {
        if (strncmp(key, "abort_on_", 9) == 0) {
            written = snprintf(dst, dst_size, "%s", key);
        } else {
            written = snprintf(dst, dst_size, "abort_on_%s", key);
        }
    } else if (strcmp(section, "allowlists") == 0) {
        written = snprintf(dst, dst_size, "%s_allowlist", key);
    } else if (strcmp(section, "coverage") == 0) {
        written = snprintf(dst, dst_size, "%s", key);
    } else if (strcmp(section, "target") == 0) {
        if (strcmp(key, "module") == 0) {
            written = snprintf(dst, dst_size, "target_module");
        } else {
            written = snprintf(dst, dst_size, "%s", key);
        }
    } else {
        fprintf(stderr, "shadowfuzz-dbi: unknown policy section %s:%u: [%s]\n",
                path, line_no, section);
        return -1;
    }

    if (written <= 0 || (size_t)written >= dst_size) {
        fprintf(stderr, "shadowfuzz-dbi: policy key too long %s:%u\n", path,
                line_no);
        return -1;
    }
    return 0;
}

static bool
valid_policy_ngram(const char *value)
{
    return strcmp(value, "1") == 0 || strcmp(value, "2") == 0 ||
        strcmp(value, "4") == 0 || strcmp(value, "8") == 0;
}

static int apply_policy_file_internal(shadowfuzz_options_t *options,
                                      const char *path, unsigned depth);

static int
apply_policy_entry(shadowfuzz_options_t *options, const char *section, const char *key,
                   const char *value, const char *path, unsigned line_no)
{
    char normalized_key[96];
    bool parsed_bool;
    char *owned_value = NULL;

    if (normalize_policy_key(normalized_key, sizeof(normalized_key), section, key, path,
                             line_no) != 0) {
        return -1;
    }

    if (strcmp(normalized_key, "abort_on_dangerous_api") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_dangerous_api)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "abort_on_credential_file") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_credential_file)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "abort_on_exec") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_exec)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "abort_on_env_access") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_env_access)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "abort_on_file_mutation") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_file_mutation)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "abort_on_network") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_network)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "abort_on_path_traversal") == 0) {
        if (!parse_policy_bool(value, &options->abort_on_path_traversal)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "trace_cmp") == 0) {
        if (!parse_policy_bool(value, &options->trace_cmp)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "hitcount_buckets") == 0) {
        if (!parse_policy_bool(value, &options->hitcount_buckets)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "inline_coverage") == 0) {
        if (!parse_policy_bool(value, &options->inline_coverage)) {
            goto invalid_bool;
        }
    } else if (strcmp(normalized_key, "exec_allowlist") == 0 ||
               strcmp(normalized_key, "env_allowlist") == 0 ||
               strcmp(normalized_key, "network_allowlist") == 0 ||
               strcmp(normalized_key, "path_allowlist") == 0 ||
               strcmp(normalized_key, "ngram") == 0 ||
               strcmp(normalized_key, "target_module") == 0) {
        if (value[0] == '\0') {
            fprintf(stderr, "shadowfuzz-dbi: empty value in policy %s:%u: %s\n",
                    path, line_no, key);
            return -1;
        }
        if (strcmp(normalized_key, "ngram") == 0 && !valid_policy_ngram(value)) {
            fprintf(stderr,
                    "shadowfuzz-dbi: invalid ngram in policy %s:%u: %s\n",
                    path, line_no, value);
            return -1;
        }
        owned_value = strdup(value);
        if (owned_value == NULL) {
            fprintf(stderr, "shadowfuzz-dbi: failed to allocate policy value\n");
            return -1;
        }
        if (strcmp(normalized_key, "exec_allowlist") == 0) {
            options->exec_allowlist = owned_value;
        } else if (strcmp(normalized_key, "env_allowlist") == 0) {
            options->env_allowlist = owned_value;
        } else if (strcmp(normalized_key, "network_allowlist") == 0) {
            options->network_allowlist = owned_value;
        } else if (strcmp(normalized_key, "path_allowlist") == 0) {
            options->path_allowlist = owned_value;
        } else if (strcmp(normalized_key, "ngram") == 0) {
            options->ngram_size = owned_value;
        } else {
            options->target_module = owned_value;
        }
    } else {
        fprintf(stderr, "shadowfuzz-dbi: unknown policy key %s:%u: %s\n", path,
                line_no, key);
        return -1;
    }

    return 0;

invalid_bool:
    fprintf(stderr, "shadowfuzz-dbi: invalid boolean in policy %s:%u: %s=%s\n",
            path, line_no, key, value);
    return -1;
}

static int
policy_dirname(char *dst, size_t dst_size, const char *path)
{
    const char *slash = strrchr(path, '/');

    if (slash == NULL) {
        return snprintf(dst, dst_size, ".") < (int)dst_size ? 0 : -1;
    }
    if (slash == path) {
        return snprintf(dst, dst_size, "/") < (int)dst_size ? 0 : -1;
    }
    return snprintf(dst, dst_size, "%.*s", (int)(slash - path), path) <
            (int)dst_size
        ? 0
        : -1;
}

static int
resolve_policy_include(char *dst, size_t dst_size, const char *policy_path,
                       const char *include_path)
{
    char dir[PATH_MAX];

    if (include_path[0] == '/') {
        return snprintf(dst, dst_size, "%s", include_path) < (int)dst_size ? 0
                                                                           : -1;
    }
    if (policy_dirname(dir, sizeof(dir), policy_path) != 0) {
        return -1;
    }
    return snprintf(dst, dst_size, "%s/%s", dir, include_path) < (int)dst_size ? 0
                                                                               : -1;
}

static int
apply_policy_file_internal(shadowfuzz_options_t *options, const char *path,
                           unsigned depth)
{
    FILE *file;
    char line[1024];
    char current_section[32] = "";
    unsigned line_no = 0;

    if (depth > POLICY_MAX_INCLUDE_DEPTH) {
        fprintf(stderr, "shadowfuzz-dbi: policy include depth exceeded at %s\n",
                path);
        return -1;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "shadowfuzz-dbi: failed to open policy file %s: %s\n", path,
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *entry;
        char *equals;
        char *comment;
        char *key;
        char *value;
        size_t entry_len;

        line_no++;
        entry_len = strlen(line);
        if (entry_len > 0 && line[entry_len - 1] != '\n' && !feof(file)) {
            fprintf(stderr, "shadowfuzz-dbi: policy line too long %s:%u\n", path,
                    line_no);
            fclose(file);
            return -1;
        }
        entry = trim_ascii(line);
        if (entry[0] == '\0' || entry[0] == '#') {
            continue;
        }
        comment = strchr(entry, '#');
        if (comment != NULL) {
            *comment = '\0';
            entry = trim_ascii(entry);
        }
        if (entry[0] == '[') {
            size_t len = strlen(entry);
            if (len < 3 || entry[len - 1] != ']') {
                fprintf(stderr, "shadowfuzz-dbi: invalid policy section %s:%u\n",
                        path, line_no);
                fclose(file);
                return -1;
            }
            entry[len - 1] = '\0';
            entry = trim_ascii(entry + 1);
            if (strcmp(entry, "oracles") != 0 &&
                strcmp(entry, "allowlists") != 0 &&
                strcmp(entry, "coverage") != 0 && strcmp(entry, "target") != 0) {
                fprintf(stderr,
                        "shadowfuzz-dbi: unknown policy section %s:%u: [%s]\n",
                        path, line_no, entry);
                fclose(file);
                return -1;
            }
            if (snprintf(current_section, sizeof(current_section), "%s", entry) >=
                (int)sizeof(current_section)) {
                fprintf(stderr, "shadowfuzz-dbi: policy section too long %s:%u\n",
                        path, line_no);
                fclose(file);
                return -1;
            }
            continue;
        }
        equals = strchr(entry, '=');
        if (equals == NULL) {
            fprintf(stderr, "shadowfuzz-dbi: invalid policy line %s:%u\n", path,
                    line_no);
            fclose(file);
            return -1;
        }
        *equals = '\0';
        key = trim_ascii(entry);
        value = trim_ascii(equals + 1);
        if (key[0] == '\0') {
            fprintf(stderr, "shadowfuzz-dbi: empty policy key %s:%u\n", path,
                    line_no);
            fclose(file);
            return -1;
        }
        if (current_section[0] == '\0' && strcmp(key, "include") == 0) {
            char include_path[PATH_MAX];
            if (value[0] == '\0') {
                fprintf(stderr,
                        "shadowfuzz-dbi: empty include path in policy %s:%u\n",
                        path, line_no);
                fclose(file);
                return -1;
            }
            if (resolve_policy_include(include_path, sizeof(include_path), path,
                                       value) != 0) {
                fprintf(stderr,
                        "shadowfuzz-dbi: policy include path too long %s:%u\n",
                        path, line_no);
                fclose(file);
                return -1;
            }
            if (apply_policy_file_internal(options, include_path, depth + 1) != 0) {
                fclose(file);
                return -1;
            }
            continue;
        }
        if (apply_policy_entry(options, current_section, key, value, path, line_no) !=
            0) {
            fclose(file);
            return -1;
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "shadowfuzz-dbi: failed reading policy file %s\n", path);
        fclose(file);
        return -1;
    }
    fclose(file);
    options->policy_file = path;
    return 0;
}

static int
apply_policy_file(shadowfuzz_options_t *options, const char *path)
{
    return apply_policy_file_internal(options, path, 0);
}

static void
log_message(const char *message)
{
    if (!verbose_logs) {
        return;
    }
    fprintf(stderr, "shadowfuzz-dbi: %s\n", message);
}

static void
log_path(const char *label, const char *path)
{
    if (!verbose_logs) {
        return;
    }
    fprintf(stderr, "shadowfuzz-dbi: %s%s\n", label, path);
}

static void
log_wait_status(int status)
{
    if (!verbose_logs) {
        return;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 127 || exit_code == 1) {
            fprintf(stderr, "shadowfuzz-dbi: child exited with launcher/exec failure code=%d\n",
                    exit_code);
        } else {
            fprintf(stderr, "shadowfuzz-dbi: child exited normally code=%d\n", exit_code);
        }
        return;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        fprintf(stderr, "shadowfuzz-dbi: child terminated by signal=%d", sig);
#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            fprintf(stderr, " core_dump=1");
        }
#endif
        fputc('\n', stderr);
        return;
    }

    fprintf(stderr, "shadowfuzz-dbi: child returned raw wait status=%d\n", status);
}

static int
status_to_exit_code(int status)
{
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

static int
make_absolute(char *dst, size_t dst_size, const char *base_dir, const char *suffix)
{
    int written = snprintf(dst, dst_size, "%s/%s", base_dir, suffix);
    return written > 0 && (size_t)written < dst_size ? 0 : -1;
}

static int
resolve_repo_root(char *root_dir, size_t root_size, const char *argv0)
{
    char exe_path[PATH_MAX];
    ssize_t len;
    char *slash;

    len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) {
        if (realpath(argv0, exe_path) == NULL) {
            return -1;
        }
    } else {
        exe_path[len] = '\0';
    }

    slash = strrchr(exe_path, '/');
    if (slash == NULL) {
        return -1;
    }
    *slash = '\0';

    if (snprintf(root_dir, root_size, "%s", exe_path) >= (int)root_size) {
        return -1;
    }
    slash = strrchr(root_dir, '/');
    if (slash != NULL && strcmp(slash + 1, "build") == 0) {
        *slash = '\0';
    }
    return 0;
}

static int
parse_options(int argc, char **argv, shadowfuzz_options_t *options)
{
    int idx = 1;

    memset(options, 0, sizeof(*options));

    if (argc < 2) {
        usage(stderr);
        return 1;
    }

    while (idx < argc) {
        if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--help") == 0) {
            usage(stdout);
            return 0;
        }
        if (strcmp(argv[idx], "--check") == 0) {
            options->check_only = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--policy-file") == 0) {
            if (idx + 1 >= argc) {
                usage(stderr);
                return 1;
            }
            if (apply_policy_file(options, argv[idx + 1]) != 0) {
                return 1;
            }
            idx += 2;
            continue;
        }
        if (strcmp(argv[idx], "--instrument-all") == 0) {
            options->instrument_all_modules = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-dangerous-api") == 0) {
            options->abort_on_dangerous_api = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-credential-file") == 0) {
            options->abort_on_credential_file = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-exec") == 0) {
            options->abort_on_exec = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-env-access") == 0) {
            options->abort_on_env_access = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-file-mutation") == 0) {
            options->abort_on_file_mutation = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-network") == 0) {
            options->abort_on_network = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--abort-on-path-traversal") == 0) {
            options->abort_on_path_traversal = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--hitcount-buckets") == 0) {
            options->hitcount_buckets = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--inline-coverage") == 0) {
            options->inline_coverage = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--persistent") == 0) {
            options->persistent = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--trace-cmp") == 0) {
            options->trace_cmp = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--quiet-shadowcov") == 0) {
            options->quiet_shadowcov = true;
            idx++;
            continue;
        }
        if (strcmp(argv[idx], "--map-size") == 0 || strcmp(argv[idx], "--ngram") == 0 ||
            strcmp(argv[idx], "--exec-allowlist") == 0 ||
            strcmp(argv[idx], "--env-allowlist") == 0 ||
            strcmp(argv[idx], "--network-allowlist") == 0 ||
            strcmp(argv[idx], "--path-allowlist") == 0 ||
            strcmp(argv[idx], "--bitmap-out") == 0 ||
            strcmp(argv[idx], "--target-module") == 0) {
            if (idx + 1 >= argc) {
                usage(stderr);
                return 1;
            }
            if (strcmp(argv[idx], "--map-size") == 0) {
                options->map_size = argv[idx + 1];
            } else if (strcmp(argv[idx], "--ngram") == 0) {
                options->ngram_size = argv[idx + 1];
            } else if (strcmp(argv[idx], "--exec-allowlist") == 0) {
                options->exec_allowlist = argv[idx + 1];
            } else if (strcmp(argv[idx], "--env-allowlist") == 0) {
                options->env_allowlist = argv[idx + 1];
            } else if (strcmp(argv[idx], "--network-allowlist") == 0) {
                options->network_allowlist = argv[idx + 1];
            } else if (strcmp(argv[idx], "--path-allowlist") == 0) {
                options->path_allowlist = argv[idx + 1];
            } else if (strcmp(argv[idx], "--bitmap-out") == 0) {
                options->bitmap_out = argv[idx + 1];
            } else {
                options->target_module = argv[idx + 1];
            }
            idx += 2;
            continue;
        }
        break;
    }

    options->target_arg_index = idx;

    if (argc <= options->target_arg_index) {
        usage(stderr);
        return 1;
    }

    return -1;
}

static int
resolve_runtime_paths(char *root_dir, size_t root_dir_size, char *drrun_path,
                      size_t drrun_path_size, char *client_path, size_t client_path_size,
                      const char *argv0)
{
    const char *drrun_override;
    const char *client_override;

    if (resolve_repo_root(root_dir, root_dir_size, argv0) != 0) {
        fprintf(stderr, "shadowfuzz-dbi: failed to resolve repository root\n");
        return -1;
    }

    drrun_override = get_env("SHADOWFUZZ_DRRUN_PATH");
    client_override = get_env("SHADOWFUZZ_CLIENT_PATH");

    if (drrun_override != NULL && drrun_override[0] != '\0') {
        if (snprintf(drrun_path, drrun_path_size, "%s", drrun_override) >=
            (int)drrun_path_size) {
            fprintf(stderr, "shadowfuzz-dbi: SHADOWFUZZ_DRRUN_PATH is too long\n");
            return -1;
        }
    } else if (make_absolute(drrun_path, drrun_path_size, root_dir,
                             "third_party/DynamoRIO-Linux-11.3.0-1/bin64/drrun") != 0) {
        fprintf(stderr, "shadowfuzz-dbi: failed to build drrun path\n");
        return -1;
    }

    if (client_override != NULL && client_override[0] != '\0') {
        if (snprintf(client_path, client_path_size, "%s", client_override) >=
            (int)client_path_size) {
            fprintf(stderr, "shadowfuzz-dbi: SHADOWFUZZ_CLIENT_PATH is too long\n");
            return -1;
        }
    } else if (make_absolute(client_path, client_path_size, root_dir,
                             "build/libshadowcov.so") != 0) {
        fprintf(stderr, "shadowfuzz-dbi: failed to build client path\n");
        return -1;
    }

    return 0;
}

static int
run_preflight_checks(const char *drrun_path, const char *client_path, const char *target_path)
{
    if (!path_exists(drrun_path)) {
        fprintf(stderr, "shadowfuzz-dbi: missing drrun at %s\n", drrun_path);
        return -1;
    }
    if (!path_exists(client_path)) {
        fprintf(stderr, "shadowfuzz-dbi: missing client at %s\n", client_path);
        return -1;
    }
    if (!path_exists(target_path)) {
        fprintf(stderr, "shadowfuzz-dbi: target not found: %s\n", target_path);
        return -1;
    }
    if (!path_is_executable(target_path)) {
        fprintf(stderr, "shadowfuzz-dbi: target is not executable: %s\n", target_path);
        return -1;
    }
    return 0;
}

static void
apply_shadowcov_options(const shadowfuzz_options_t *options, char *map_size_buf,
                        size_t map_size_buf_size)
{
    if (options->quiet_shadowcov) {
        setenv("SHADOWCOV_QUIET", "1", 1);
    } else if (getenv("SHADOWCOV_QUIET") == NULL) {
        setenv("SHADOWCOV_QUIET", "1", 0);
    }

    if (options->map_size != NULL) {
        setenv("SHADOWCOV_MAP_SIZE", options->map_size, 1);
    } else if (getenv("SHADOWCOV_MAP_SIZE") == NULL) {
        snprintf(map_size_buf, map_size_buf_size, "%u", DEFAULT_MAP_SIZE);
        setenv("SHADOWCOV_MAP_SIZE", map_size_buf, 0);
    }

    if (options->ngram_size != NULL) {
        setenv("SHADOWCOV_NGRAM_SIZE", options->ngram_size, 1);
    }
    if (options->bitmap_out != NULL) {
        setenv("SHADOWCOV_BITMAP_OUT", options->bitmap_out, 1);
    }
    if (options->target_module != NULL) {
        setenv("SHADOWCOV_TARGET_MODULE", options->target_module, 1);
    }
    if (options->instrument_all_modules) {
        setenv("SHADOWCOV_INSTRUMENT_MODULES", "all", 1);
    }
    if (options->abort_on_dangerous_api) {
        setenv("SHADOWCOV_ABORT_ON_DANGEROUS_API", "1", 1);
    }
    if (options->abort_on_credential_file) {
        setenv("SHADOWCOV_ABORT_ON_CREDENTIAL_FILE", "1", 1);
    }
    if (options->abort_on_exec) {
        setenv("SHADOWCOV_ABORT_ON_EXEC", "1", 1);
    }
    if (options->abort_on_env_access) {
        setenv("SHADOWCOV_ABORT_ON_ENV_ACCESS", "1", 1);
    }
    if (options->abort_on_file_mutation) {
        setenv("SHADOWCOV_ABORT_ON_FILE_MUTATION", "1", 1);
    }
    if (options->abort_on_network) {
        setenv("SHADOWCOV_ABORT_ON_NETWORK", "1", 1);
    }
    if (options->exec_allowlist != NULL) {
        setenv("SHADOWCOV_EXEC_ALLOWLIST", options->exec_allowlist, 1);
    }
    if (options->env_allowlist != NULL) {
        setenv("SHADOWCOV_ENV_ALLOWLIST", options->env_allowlist, 1);
    }
    if (options->network_allowlist != NULL) {
        setenv("SHADOWCOV_NETWORK_ALLOWLIST", options->network_allowlist, 1);
    }
    if (options->path_allowlist != NULL) {
        setenv("SHADOWCOV_PATH_ALLOWLIST", options->path_allowlist, 1);
    }
    if (options->abort_on_path_traversal) {
        setenv("SHADOWCOV_ABORT_ON_PATH_TRAVERSAL", "1", 1);
    }
    if (options->trace_cmp) {
        setenv("SHADOWCOV_TRACE_CMP", "1", 1);
    }
    if (options->hitcount_buckets) {
        setenv("SHADOWCOV_HITCOUNT_BUCKETS", "1", 1);
    }
    if (options->inline_coverage) {
        setenv("SHADOWCOV_INLINE_COVERAGE", "1", 1);
    }
    if (options->persistent) {
        setenv("SHADOWCOV_PERSISTENT_RESET_HOOK", "1", 1);
    }

    if (getenv("__AFL_SHM_ID") != NULL && getenv("AFL_SHM_ID") == NULL) {
        setenv("AFL_SHM_ID", getenv("__AFL_SHM_ID"), 0);
    }
    if (verbose_logs) {
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_MAP_SIZE=%s\n",
                get_env("SHADOWCOV_MAP_SIZE") != NULL ? get_env("SHADOWCOV_MAP_SIZE")
                                                      : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_NGRAM_SIZE=%s\n",
                get_env("SHADOWCOV_NGRAM_SIZE") != NULL ? get_env("SHADOWCOV_NGRAM_SIZE")
                                                        : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_BITMAP_OUT=%s\n",
                get_env("SHADOWCOV_BITMAP_OUT") != NULL ? get_env("SHADOWCOV_BITMAP_OUT")
                                                        : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_TARGET_MODULE=%s\n",
                get_env("SHADOWCOV_TARGET_MODULE") != NULL ? get_env("SHADOWCOV_TARGET_MODULE")
                                                           : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_INSTRUMENT_MODULES=%s\n",
                get_env("SHADOWCOV_INSTRUMENT_MODULES") != NULL
                    ? get_env("SHADOWCOV_INSTRUMENT_MODULES")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_QUIET=%s\n",
                get_env("SHADOWCOV_QUIET") != NULL ? get_env("SHADOWCOV_QUIET")
                                                   : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: policy_file=%s\n",
                options->policy_file != NULL ? options->policy_file : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_DANGEROUS_API=%s\n",
                get_env("SHADOWCOV_ABORT_ON_DANGEROUS_API") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_DANGEROUS_API")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_CREDENTIAL_FILE=%s\n",
                get_env("SHADOWCOV_ABORT_ON_CREDENTIAL_FILE") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_CREDENTIAL_FILE")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_EXEC=%s\n",
                get_env("SHADOWCOV_ABORT_ON_EXEC") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_EXEC")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_ENV_ACCESS=%s\n",
                get_env("SHADOWCOV_ABORT_ON_ENV_ACCESS") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_ENV_ACCESS")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_FILE_MUTATION=%s\n",
                get_env("SHADOWCOV_ABORT_ON_FILE_MUTATION") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_FILE_MUTATION")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_NETWORK=%s\n",
                get_env("SHADOWCOV_ABORT_ON_NETWORK") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_NETWORK")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_EXEC_ALLOWLIST=%s\n",
                get_env("SHADOWCOV_EXEC_ALLOWLIST") != NULL
                    ? get_env("SHADOWCOV_EXEC_ALLOWLIST")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ENV_ALLOWLIST=%s\n",
                get_env("SHADOWCOV_ENV_ALLOWLIST") != NULL
                    ? get_env("SHADOWCOV_ENV_ALLOWLIST")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_NETWORK_ALLOWLIST=%s\n",
                get_env("SHADOWCOV_NETWORK_ALLOWLIST") != NULL
                    ? get_env("SHADOWCOV_NETWORK_ALLOWLIST")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_PATH_ALLOWLIST=%s\n",
                get_env("SHADOWCOV_PATH_ALLOWLIST") != NULL
                    ? get_env("SHADOWCOV_PATH_ALLOWLIST")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_ABORT_ON_PATH_TRAVERSAL=%s\n",
                get_env("SHADOWCOV_ABORT_ON_PATH_TRAVERSAL") != NULL
                    ? get_env("SHADOWCOV_ABORT_ON_PATH_TRAVERSAL")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_TRACE_CMP=%s\n",
                get_env("SHADOWCOV_TRACE_CMP") != NULL ? get_env("SHADOWCOV_TRACE_CMP")
                                                       : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_HITCOUNT_BUCKETS=%s\n",
                get_env("SHADOWCOV_HITCOUNT_BUCKETS") != NULL
                    ? get_env("SHADOWCOV_HITCOUNT_BUCKETS")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: SHADOWCOV_INLINE_COVERAGE=%s\n",
                get_env("SHADOWCOV_INLINE_COVERAGE") != NULL
                    ? get_env("SHADOWCOV_INLINE_COVERAGE")
                    : "<unset>");
        fprintf(stderr, "shadowfuzz-dbi: AFL_SHM_ID=%s\n",
                get_env("AFL_SHM_ID") != NULL ? get_env("AFL_SHM_ID") : "<unset>");
    }
}

static int
write_all(int fd, const void *buf, size_t count)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t written = 0;

    while (written < count) {
        ssize_t rc = write(fd, p + written, count - written);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        written += (size_t)rc;
    }
    return 0;
}

static int
read_exact(int fd, void *buf, size_t count)
{
    unsigned char *p = (unsigned char *)buf;
    size_t read_total = 0;

    while (read_total < count) {
        ssize_t rc = read(fd, p + read_total, count - read_total);
        if (rc == 0) {
            return 0;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        read_total += (size_t)rc;
    }
    return 1;
}

static int
read_current_testcase(unsigned char **data_out, uint32_t *size_out)
{
    unsigned char *data = NULL;
    size_t size = 0;
    size_t capacity = 4096;

    if (lseek(STDIN_FILENO, 0, SEEK_SET) < 0 && errno != ESPIPE) {
        perror("lseek(stdin)");
        return -1;
    }

    data = malloc(capacity);
    if (data == NULL) {
        perror("malloc");
        return -1;
    }

    while (1) {
        ssize_t rc;

        if (size == capacity) {
            unsigned char *new_data;

            if (capacity > UINT32_MAX / 2U) {
                fprintf(stderr, "shadowfuzz-dbi: testcase is too large for persistent protocol\n");
                free(data);
                return -1;
            }
            capacity *= 2;
            new_data = realloc(data, capacity);
            if (new_data == NULL) {
                perror("realloc");
                free(data);
                return -1;
            }
            data = new_data;
        }

        rc = read(STDIN_FILENO, data + size, capacity - size);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read(stdin)");
            free(data);
            return -1;
        }
        size += (size_t)rc;
        if (size > UINT32_MAX) {
            fprintf(stderr, "shadowfuzz-dbi: testcase is too large for persistent protocol\n");
            free(data);
            return -1;
        }
    }

    *data_out = data;
    *size_out = (uint32_t)size;
    return 0;
}

static int
spawn_target(char **exec_argv)
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        execv(exec_argv[0], exec_argv);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return status;
}

static void
close_forkserver_fds(void)
{
    close(AFL_FORKSRV_FD);
    close(AFL_FORKSRV_FD + 1);
}

static void
exec_target(char **exec_argv, bool close_afl_fds)
{
    if (close_afl_fds) {
        close_forkserver_fds();
    }
    execv(exec_argv[0], exec_argv);
}

static int
run_target_once(char **exec_argv, bool close_afl_fds, pid_t *child_pid_out)
{
    pid_t child_pid;
    int status;

    child_pid = fork();
    if (child_pid < 0) {
        return -1;
    }

    if (child_pid == 0) {
        exec_target(exec_argv, close_afl_fds);
        _exit(127);
    }

    if (child_pid_out != NULL) {
        *child_pid_out = child_pid;
    }

    if (waitpid(child_pid, &status, 0) < 0) {
        return -1;
    }

    return status;
}

static pid_t
start_target(char **exec_argv, bool close_afl_fds)
{
    pid_t child_pid;

    child_pid = fork();
    if (child_pid < 0) {
        return -1;
    }

    if (child_pid == 0) {
        exec_target(exec_argv, close_afl_fds);
        _exit(127);
    }

    return child_pid;
}

static int
run_direct_mode(char **exec_argv)
{
    int status;

    /* Direct-run mode still uses the same child execution path as forkserver mode
     * so that status handling stays consistent between the two entry points.
     */
    log_message("starting direct execution path");
    status = run_target_once(exec_argv, false, NULL);
    if (status < 0) {
        perror("fork/wait");
        return 1;
    }

    log_wait_status(status);
    return status_to_exit_code(status);
}

static int
run_forkserver_mode(int ctl_fd, int st_fd, char **exec_argv)
{
    uint32_t handshake = 0;
    char pid_msg[64];

    /* This is intentionally the minimal AFL-compatible loop: handshake once,
     * run one child per command, and report pid + wait status back upstream.
     */
    log_message("starting AFL forkserver-compatible path");
    if (write_all(st_fd, &handshake, sizeof(handshake)) != 0) {
        perror("forkserver handshake");
        return 1;
    }

    while (1) {
        uint32_t command = 0;
        pid_t child_pid;
        int status;
        int rc;

        rc = read_exact(ctl_fd, &command, sizeof(command));
        if (rc <= 0) {
            break;
        }

        if (lseek(STDIN_FILENO, 0, SEEK_SET) < 0) {
            if (errno != ESPIPE) {
                perror("lseek(stdin)");
                return 1;
            }
        }

        child_pid = start_target(exec_argv, true);
        if (child_pid < 0) {
            perror("fork");
            return 1;
        }

        if (verbose_logs) {
            snprintf(pid_msg, sizeof(pid_msg), "spawned child pid=%ld", (long)child_pid);
            log_message(pid_msg);
        }

        if (write_all(st_fd, &child_pid, sizeof(child_pid)) != 0) {
            perror("write child pid");
            kill(child_pid, SIGKILL);
            return 1;
        }

        if (waitpid(child_pid, &status, 0) < 0) {
            perror("waitpid");
            return 1;
        }

        log_wait_status(status);

        if (write_all(st_fd, &status, sizeof(status)) != 0) {
            perror("write child status");
            return 1;
        }
    }

    return 0;
}

typedef struct persistent_child_t {
    pid_t pid;
    int input_fd;
    int output_fd;
} persistent_child_t;

static void
close_persistent_child(persistent_child_t *child)
{
    if (child->input_fd >= 0) {
        close(child->input_fd);
        child->input_fd = -1;
    }
    if (child->output_fd >= 0) {
        close(child->output_fd);
        child->output_fd = -1;
    }
}

static int
start_persistent_child(char **exec_argv, persistent_child_t *child)
{
    int to_child[2];
    int from_child[2];
    pid_t pid;

    child->pid = -1;
    child->input_fd = -1;
    child->output_fd = -1;

    if (pipe(to_child) != 0) {
        perror("pipe");
        return -1;
    }
    if (pipe(from_child) != 0) {
        perror("pipe");
        close(to_child[0]);
        close(to_child[1]);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        close(to_child[0]);
        close(to_child[1]);
        close(from_child[0]);
        close(from_child[1]);
        return -1;
    }

    if (pid == 0) {
        char input_fd_buf[32];
        char output_fd_buf[32];
        int persistent_input_fd;
        int persistent_output_fd;

        close(to_child[1]);
        close(from_child[0]);

        persistent_input_fd = fcntl(to_child[0], F_DUPFD, PERSISTENT_IN_FD);
        persistent_output_fd = fcntl(from_child[1], F_DUPFD, PERSISTENT_OUT_FD);
        if (persistent_input_fd < 0 || persistent_output_fd < 0) {
            _exit(127);
        }
        close(to_child[0]);
        close(from_child[1]);

        snprintf(input_fd_buf, sizeof(input_fd_buf), "%d", persistent_input_fd);
        snprintf(output_fd_buf, sizeof(output_fd_buf), "%d", persistent_output_fd);
        setenv("SHADOWFUZZ_PERSISTENT_IN_FD", input_fd_buf, 1);
        setenv("SHADOWFUZZ_PERSISTENT_OUT_FD", output_fd_buf, 1);
        close_forkserver_fds();
        execv(exec_argv[0], exec_argv);
        _exit(127);
    }

    close(to_child[0]);
    close(from_child[1]);
    child->pid = pid;
    child->input_fd = to_child[1];
    child->output_fd = from_child[0];
    return 0;
}

static int
send_persistent_testcase(persistent_child_t *child, const unsigned char *data,
                         uint32_t size)
{
    if (write_all(child->input_fd, &size, sizeof(size)) != 0) {
        return -1;
    }
    if (size > 0 && write_all(child->input_fd, data, size) != 0) {
        return -1;
    }
    return 0;
}

static int
read_persistent_status(persistent_child_t *child, int *status_out)
{
    uint32_t status = 0;
    int rc = read_exact(child->output_fd, &status, sizeof(status));

    if (rc <= 0) {
        return rc;
    }
    *status_out = (int)status;
    return 1;
}

static int
reap_persistent_child(persistent_child_t *child, int *status_out)
{
    int status = 0;

    close_persistent_child(child);
    if (child->pid <= 0) {
        return -1;
    }
    if (waitpid(child->pid, &status, 0) < 0) {
        return -1;
    }
    *status_out = status;
    child->pid = -1;
    return 0;
}

static int
run_persistent_forkserver_mode(int ctl_fd, int st_fd, char **exec_argv)
{
    uint32_t handshake = 0;
    persistent_child_t child = { -1, -1, -1 };

    log_message("starting AFL persistent harness path");
    if (write_all(st_fd, &handshake, sizeof(handshake)) != 0) {
        perror("forkserver handshake");
        return 1;
    }

    while (1) {
        uint32_t command = 0;
        unsigned char *testcase = NULL;
        uint32_t testcase_size = 0;
        int status = 0;
        int rc;

        rc = read_exact(ctl_fd, &command, sizeof(command));
        if (rc <= 0) {
            break;
        }

        if (child.pid <= 0 &&
            start_persistent_child(exec_argv, &child) != 0) {
            return 1;
        }

        if (write_all(st_fd, &child.pid, sizeof(child.pid)) != 0) {
            perror("write child pid");
            kill(child.pid, SIGKILL);
            (void)reap_persistent_child(&child, &status);
            return 1;
        }

        if (read_current_testcase(&testcase, &testcase_size) != 0) {
            kill(child.pid, SIGKILL);
            (void)reap_persistent_child(&child, &status);
            return 1;
        }

        if (send_persistent_testcase(&child, testcase, testcase_size) != 0 ||
            read_persistent_status(&child, &status) <= 0) {
            free(testcase);
            if (reap_persistent_child(&child, &status) != 0) {
                perror("waitpid");
                return 1;
            }
        } else {
            free(testcase);
        }

        log_wait_status(status);

        if (write_all(st_fd, &status, sizeof(status)) != 0) {
            perror("write child status");
            if (child.pid > 0) {
                kill(child.pid, SIGKILL);
                (void)reap_persistent_child(&child, &status);
            }
            return 1;
        }

        if (child.pid > 0 && WIFSIGNALED(status)) {
            /* Synthetic per-iteration crashes keep the persistent process alive.
             * Real process death is handled by the read/reap path above.
             */
            continue;
        }
    }

    if (child.pid > 0) {
        int status;

        close_persistent_child(&child);
        kill(child.pid, SIGTERM);
        (void)waitpid(child.pid, &status, 0);
    }

    return 0;
}

int
main(int argc, char **argv)
{
    shadowfuzz_options_t options;
    char root_dir[PATH_MAX];
    char drrun_path[PATH_MAX];
    char client_path[PATH_MAX];
    const char *target_path;
    char map_size_buf[32];
    char **exec_argv;
    int ctl_fd = AFL_FORKSRV_FD;
    int st_fd = AFL_FORKSRV_FD + 1;
    bool in_afl = false;
    int parse_rc;

    parse_rc = parse_options(argc, argv, &options);
    if (parse_rc >= 0) {
        return parse_rc;
    }

    target_path = argv[options.target_arg_index];
    verbose_logs = get_env("SHADOWFUZZ_VERBOSE") != NULL;

    if (resolve_runtime_paths(root_dir, sizeof(root_dir), drrun_path, sizeof(drrun_path),
                              client_path, sizeof(client_path), argv[0]) != 0) {
        return 1;
    }

    if (run_preflight_checks(drrun_path, client_path, target_path) != 0) {
        return 1;
    }
    log_path("using drrun ", drrun_path);
    log_path("using client ", client_path);
    log_path("using target ", target_path);

    if (options.check_only) {
        printf("shadowfuzz-dbi: check ok\n");
        return 0;
    }

    apply_shadowcov_options(&options, map_size_buf, sizeof(map_size_buf));

    exec_argv = calloc((size_t)(argc - options.target_arg_index + 5), sizeof(char *));
    if (exec_argv == NULL) {
        perror("calloc");
        return 1;
    }

    exec_argv[0] = drrun_path;
    exec_argv[1] = "-c";
    exec_argv[2] = client_path;
    exec_argv[3] = "--";
    for (int i = options.target_arg_index; i < argc; i++) {
        exec_argv[i - options.target_arg_index + 4] = argv[i];
    }

    if (fcntl(ctl_fd, F_GETFD) != -1 && fcntl(st_fd, F_GETFD) != -1) {
        in_afl = true;
    }

    if (!in_afl) {
        return run_direct_mode(exec_argv);
    }

    if (options.persistent) {
        return run_persistent_forkserver_mode(ctl_fd, st_fd, exec_argv);
    }

    return run_forkserver_mode(ctl_fd, st_fd, exec_argv);
}
