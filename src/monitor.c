#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "monitor.h"
#include "monitor.skel.h"

#define MAX_AGENTS 128
#define MAX_TLS_LINKS 8

struct agent_spec {
    __u32 pid;
    __u32 id;
};

struct tls_program_pair {
    const char *symbol;
    struct bpf_program *entry;
    struct bpf_program *exit;
};

static volatile sig_atomic_t exiting;
static bool json_output;
static bool capture_only;
static __u64 realtime_offset_ns;
static unsigned long long received_events;
static unsigned long long invalid_events;
static unsigned long long received_by_type[EVENT_TLS_WRITE + 1];

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

static int libbpf_log(enum libbpf_print_level level, const char *format,
                      va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static const char *event_name(__u32 type)
{
    switch (type) {
    case EVENT_FORK: return "fork";
    case EVENT_EXEC: return "exec";
    case EVENT_EXIT: return "exit";
    case EVENT_OPEN: return "openat";
    case EVENT_UNLINK: return "unlink";
    case EVENT_UNLINKAT: return "unlinkat";
    case EVENT_RMDIR: return "rmdir";
    case EVENT_CONNECT: return "connect";
    case EVENT_TLS_READ: return "tls_read";
    case EVENT_TLS_WRITE: return "tls_write";
    default: return "unknown";
    }
}

static void format_time(__u64 monotonic_ns, char *buffer, size_t size)
{
    __u64 realtime_ns = realtime_offset_ns + monotonic_ns;
    time_t seconds = realtime_ns / 1000000000ULL;
    struct tm tm_value;
    size_t length;

    gmtime_r(&seconds, &tm_value);
    length = strftime(buffer, size, "%Y-%m-%dT%H:%M:%S", &tm_value);
    if (length < size)
        snprintf(buffer + length, size - length, ".%03lluZ",
                 (unsigned long long)((realtime_ns / 1000000ULL) % 1000));
}

/* Preserve binary bytes as JSON code points. TLS UTF-8 is decoded after
 * reassembly in the analyzer, since one event can split a multibyte character. */
static void json_bytes(const char *value, size_t value_length, char *output,
                       size_t output_size)
{
    static const char hexadecimal[] = "0123456789abcdef";
    size_t input_index;
    size_t output_index = 0;

    if (!output_size)
        return;
    for (input_index = 0; input_index < value_length; input_index++) {
        unsigned char character = value[input_index];

        if (character == '"' || character == '\\') {
            if (output_index + 2 >= output_size)
                break;
            output[output_index++] = '\\';
            output[output_index++] = character;
        } else if (character == '\n' || character == '\r' || character == '\t') {
            if (output_index + 2 >= output_size)
                break;
            output[output_index++] = '\\';
            output[output_index++] =
                character == '\n' ? 'n' : (character == '\r' ? 'r' : 't');
        } else if (character >= 0x20 && character <= 0x7e) {
            if (output_index + 1 >= output_size)
                break;
            output[output_index++] = character;
        } else {
            if (output_index + 6 >= output_size)
                break;
            output[output_index++] = '\\';
            output[output_index++] = 'u';
            output[output_index++] = '0';
            output[output_index++] = '0';
            output[output_index++] = hexadecimal[character >> 4];
            output[output_index++] = hexadecimal[character & 0x0f];
        }
    }
    output[output_index] = '\0';
}

static int handle_event(void *context, void *data, size_t data_size)
{
    const struct event *event = data;
    char timestamp[64];
    char address[INET6_ADDRSTRLEN] = "";
    char escaped_object[EVENT_PATH_LEN * 6 + 1];
    char escaped_comm[TASK_COMM_LEN * 6 + 1];
    char escaped_data[EVENT_DATA_LEN * 6 + 1];
    __u32 payload_length;

    (void)context;
    if (data_size < EVENT_BASE_SIZE) {
        fprintf(stderr, "short ring-buffer event: %zu bytes\n", data_size);
        invalid_events++;
        return 0;
    }

    received_events++;
    if (event->type == 0 || event->type > EVENT_TLS_WRITE) {
        invalid_events++;
        return 0;
    }
    received_by_type[event->type]++;
    if (capture_only)
        return 0;
    format_time(event->timestamp_ns, timestamp, sizeof(timestamp));
    if (event->address_family == AF_INET)
        inet_ntop(AF_INET, event->address, address, sizeof(address));
    else if (event->address_family == AF_INET6)
        inet_ntop(AF_INET6, event->address, address, sizeof(address));

    payload_length = event->data_len > EVENT_DATA_LEN ? EVENT_DATA_LEN : event->data_len;
    if ((size_t)payload_length > data_size - EVENT_BASE_SIZE)
        payload_length = (__u32)(data_size - EVENT_BASE_SIZE);
    if (json_output) {
        json_bytes(event->object, strnlen(event->object, EVENT_PATH_LEN),
                   escaped_object, sizeof(escaped_object));
        json_bytes(event->comm, strnlen(event->comm, TASK_COMM_LEN),
                   escaped_comm, sizeof(escaped_comm));
        json_bytes(event->data, payload_length, escaped_data, sizeof(escaped_data));
        printf("{\"time\":\"%s\",\"timestamp_ns\":%llu,"
               "\"type\":\"%s\",\"agent_id\":%u,"
               "\"tgid\":%u,\"tid\":%u,\"ppid\":%u,"
               "\"uid\":%u,\"gid\":%u,\"comm\":\"%s\","
               "\"object\":\"%s\",\"child_pid\":%u,"
               "\"dirfd\":%d,\"flags\":%u,\"retval\":%lld,"
               "\"destination\":\"%s\",\"port\":%u,"
               "\"data_len\":%u,\"data_size\":%u,"
               "\"truncated\":%s,\"payload_encoding\":\"latin-1\","
               "\"payload\":\"%s\"}\n",
               timestamp, (unsigned long long)event->timestamp_ns,
               event_name(event->type), event->agent_id, event->tgid,
               event->tid, event->ppid, event->uid, event->gid,
               escaped_comm, escaped_object, event->child_pid, event->dirfd,
               event->flags, (long long)event->retval, address,
               event->destination_port, payload_length, event->data_size,
               (event->flags & EVENT_FLAG_TRUNCATED) ? "true" : "false",
               escaped_data);
    } else {
        printf("%-24s agent=%-5u pid=%-7u tid=%-7u %-9s comm=%-16s",
               timestamp, event->agent_id, event->tgid, event->tid,
               event_name(event->type), event->comm);
        if (event->type == EVENT_FORK)
            printf(" child=%u", event->child_pid);
        else if (event->type == EVENT_CONNECT)
            printf(" destination=%s:%u ret=%lld", address,
                   event->destination_port, (long long)event->retval);
        else if (event->type == EVENT_TLS_READ || event->type == EVENT_TLS_WRITE) {
            char preview[97];
            size_t preview_length = payload_length > 16 ? 16 : payload_length;

            json_bytes(event->data, preview_length, preview, sizeof(preview));
            printf(" bytes=%u/%u preview=\"%s\"", payload_length,
                   event->data_size, preview);
        } else if (event->object[0])
            printf(" object=%s ret=%lld", event->object,
                   (long long)event->retval);
        putchar('\n');
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --agent ID:PID [--agent ID:PID ...] [options]\n"
            "  --agent ID:PID  observe one root Agent; repeat for multiple Agents\n"
            "  --openssl PATH  libssl shared library used for TLS plaintext probes\n"
            "  --no-tls        disable optional OpenSSL uprobe attachment\n"
            "  --capture-only  consume and validate events without formatting output\n"
            "  --json          emit one JSON object per line\n",
            program);
}

static bool parse_u32(const char *text, __u32 *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno || !end || *end || parsed == 0 || parsed > UINT32_MAX)
        return false;
    *value = (__u32)parsed;
    return true;
}

static bool parse_agent(const char *text, struct agent_spec *agent)
{
    const char *separator = strchr(text, ':');
    char id_text[32];
    size_t id_length;

    if (!separator)
        return false;
    id_length = (size_t)(separator - text);
    if (!id_length || id_length >= sizeof(id_text))
        return false;
    memcpy(id_text, text, id_length);
    id_text[id_length] = '\0';
    return parse_u32(id_text, &agent->id) && parse_u32(separator + 1, &agent->pid);
}

static bool read_pid_namespace(__u32 pid, struct stat *info)
{
    char path[64];

    snprintf(path, sizeof(path), "/proc/%u/ns/pid", pid);
    return stat(path, info) == 0;
}

static void configure_pid_namespace(struct monitor_bpf *skeleton,
                                    const struct agent_spec *agents,
                                    size_t agent_count)
{
    struct stat info;
    struct stat other;
    size_t index;

    if (!agent_count || !read_pid_namespace(agents[0].pid, &info)) {
        fprintf(stderr,
                "warning: pid namespace is unresolved; agent lookup uses kernel pids\n");
        return;
    }
    for (index = 1; index < agent_count; index++) {
        if (!read_pid_namespace(agents[index].pid, &other) ||
            other.st_dev != info.st_dev || other.st_ino != info.st_ino) {
            fprintf(stderr,
                    "warning: Agent %u is outside Agent %u's pid namespace\n",
                    agents[index].id, agents[0].id);
        }
    }
    skeleton->rodata->pidns_dev = (__u64)info.st_dev;
    skeleton->rodata->pidns_ino = (__u64)info.st_ino;
}

static bool tracepoint_exists(const char *name)
{
    char path[256];

    snprintf(path, sizeof(path), "/sys/kernel/tracing/events/syscalls/%s", name);
    if (access(path, R_OK) == 0)
        return true;
    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/syscalls/%s", name);
    return access(path, R_OK) == 0;
}

static void configure_syscall_pair(struct bpf_program *enter_program,
                                   struct bpf_program *exit_program,
                                   const char *syscall_name)
{
    char enter_name[96];
    char exit_name[96];

    snprintf(enter_name, sizeof(enter_name), "sys_enter_%s", syscall_name);
    snprintf(exit_name, sizeof(exit_name), "sys_exit_%s", syscall_name);
    if (tracepoint_exists(enter_name) && tracepoint_exists(exit_name))
        return;

    fprintf(stderr, "warning: syscall tracepoints for %s are unavailable; disabling them\n",
            syscall_name);
    bpf_program__set_autoload(enter_program, false);
    bpf_program__set_autoload(exit_program, false);
}

static bool path_is_readable(const char *path)
{
    return path && path[0] == '/' && access(path, R_OK) == 0;
}

static bool discover_openssl(__u32 pid, char *output, size_t output_size)
{
    static const char *fallbacks[] = {
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib64/libssl.so.3",
    };
    char maps_path[64];
    char line[PATH_MAX + 256];
    FILE *stream;
    size_t index;

    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    stream = fopen(maps_path, "r");
    if (stream) {
        while (fgets(line, sizeof(line), stream)) {
            char *path = strchr(line, '/');
            char *newline;

            if (!path || !strstr(path, "libssl.so"))
                continue;
            newline = strchr(path, '\n');
            if (newline)
                *newline = '\0';
            if (!path_is_readable(path))
                continue;
            snprintf(output, output_size, "%s", path);
            fclose(stream);
            return true;
        }
        fclose(stream);
    }

    for (index = 0; index < sizeof(fallbacks) / sizeof(fallbacks[0]); index++) {
        if (path_is_readable(fallbacks[index])) {
            snprintf(output, output_size, "%s", fallbacks[index]);
            return true;
        }
    }
    return false;
}

static int attach_one_uprobe(struct bpf_program *program, const char *path,
                             const char *symbol, bool return_probe,
                             struct bpf_link **link_output)
{
    struct bpf_uprobe_opts options = {};
    struct bpf_link *link;
    long error;

    options.sz = sizeof(options);
    options.func_name = symbol;
    options.retprobe = return_probe;
    link = bpf_program__attach_uprobe_opts(program, -1, path, 0, &options);
    error = libbpf_get_error(link);
    if (error) {
        fprintf(stderr, "warning: cannot attach %s%s in %s: %s\n",
                symbol, return_probe ? " return probe" : " entry probe", path,
                strerror((int)-error));
        return (int)error;
    }
    *link_output = link;
    return 0;
}

static size_t attach_tls_probes(struct monitor_bpf *skeleton, const char *path,
                                struct bpf_link **links)
{
    struct tls_program_pair pairs[] = {
        {"SSL_read", skeleton->progs.handle_ssl_read_enter,
         skeleton->progs.handle_ssl_read_exit},
        {"SSL_write", skeleton->progs.handle_ssl_write_enter,
         skeleton->progs.handle_ssl_write_exit},
        {"SSL_read_ex", skeleton->progs.handle_ssl_read_ex_enter,
         skeleton->progs.handle_ssl_read_ex_exit},
        {"SSL_write_ex", skeleton->progs.handle_ssl_write_ex_enter,
         skeleton->progs.handle_ssl_write_ex_exit},
    };
    size_t link_count = 0;
    size_t index;

    for (index = 0; index < sizeof(pairs) / sizeof(pairs[0]); index++) {
        struct bpf_link *entry_link = NULL;
        struct bpf_link *exit_link = NULL;

        if (attach_one_uprobe(pairs[index].entry, path, pairs[index].symbol,
                              false, &entry_link) != 0)
            continue;
        if (attach_one_uprobe(pairs[index].exit, path, pairs[index].symbol,
                              true, &exit_link) != 0) {
            bpf_link__destroy(entry_link);
            continue;
        }
        links[link_count++] = entry_link;
        links[link_count++] = exit_link;
        fprintf(stderr, "attached OpenSSL plaintext probes: %s\n", pairs[index].symbol);
    }
    return link_count;
}

static void configure_tls_programs(struct monitor_bpf *skeleton, bool enabled)
{
    struct bpf_program *programs[] = {
        skeleton->progs.handle_ssl_read_enter,
        skeleton->progs.handle_ssl_read_exit,
        skeleton->progs.handle_ssl_write_enter,
        skeleton->progs.handle_ssl_write_exit,
        skeleton->progs.handle_ssl_read_ex_enter,
        skeleton->progs.handle_ssl_read_ex_exit,
        skeleton->progs.handle_ssl_write_ex_enter,
        skeleton->progs.handle_ssl_write_ex_exit,
    };
    size_t index;

    for (index = 0; index < sizeof(programs) / sizeof(programs[0]); index++) {
        if (enabled)
            bpf_program__set_autoattach(programs[index], false);
        else
            bpf_program__set_autoload(programs[index], false);
    }
}

static unsigned long long dropped_event_count(struct monitor_bpf *skeleton)
{
    int cpu_count = libbpf_num_possible_cpus();
    __u64 *values;
    __u32 key = 0;
    unsigned long long total = 0;
    int index;

    if (cpu_count <= 0)
        return 0;
    values = calloc((size_t)cpu_count, sizeof(*values));
    if (!values)
        return 0;
    if (bpf_map_lookup_elem(bpf_map__fd(skeleton->maps.dropped_events), &key,
                            values) == 0) {
        for (index = 0; index < cpu_count; index++)
            total += values[index];
    }
    free(values);
    return total;
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"agent", required_argument, 0, 'A'},
        {"openssl", required_argument, 0, 'o'},
        {"no-tls", no_argument, 0, 'n'},
        {"capture-only", no_argument, 0, 'c'},
        {"json", no_argument, 0, 'j'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };
    struct agent_spec agents[MAX_AGENTS];
    struct monitor_bpf *skeleton = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct bpf_link *tls_links[MAX_TLS_LINKS] = {};
    struct timespec realtime;
    struct timespec monotonic;
    struct rlimit memory_limit = {RLIM_INFINITY, RLIM_INFINITY};
    char openssl_path[PATH_MAX] = "";
    size_t agent_count = 0;
    size_t tls_link_count = 0;
    size_t index;
    bool tls_enabled = true;
    int option;
    int error = 0;

    while ((option = getopt_long(argc, argv, "A:o:ncjh", options, NULL)) != -1) {
        switch (option) {
        case 'A':
            if (agent_count >= MAX_AGENTS ||
                !parse_agent(optarg, &agents[agent_count])) {
                fprintf(stderr, "invalid --agent value '%s' (expected ID:PID)\n", optarg);
                return 2;
            }
            agent_count++;
            break;
        case 'o': snprintf(openssl_path, sizeof(openssl_path), "%s", optarg); break;
        case 'n': tls_enabled = false; break;
        case 'c': capture_only = true; break;
        case 'j': json_output = true; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }

    if (!agent_count) {
        usage(argv[0]);
        return 2;
    }
    for (index = 0; index < agent_count; index++) {
        size_t other;

        if (kill((pid_t)agents[index].pid, 0) != 0 && errno == ESRCH) {
            fprintf(stderr, "PID %u does not exist\n", agents[index].pid);
            return 1;
        }
        for (other = 0; other < index; other++) {
            if (agents[other].pid == agents[index].pid ||
                agents[other].id == agents[index].id) {
                fprintf(stderr, "duplicate Agent PID or id: %u:%u\n",
                        agents[index].id, agents[index].pid);
                return 2;
            }
        }
    }
    if (openssl_path[0] && !path_is_readable(openssl_path)) {
        fprintf(stderr, "OpenSSL library is not readable: %s\n", openssl_path);
        return 2;
    }
    if (tls_enabled && !openssl_path[0] &&
        !discover_openssl(agents[0].pid, openssl_path, sizeof(openssl_path))) {
        fprintf(stderr, "warning: libssl not found; TLS plaintext probes disabled\n");
        tls_enabled = false;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    clock_gettime(CLOCK_REALTIME, &realtime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    realtime_offset_ns =
        (__u64)realtime.tv_sec * 1000000000ULL + realtime.tv_nsec -
        ((__u64)monotonic.tv_sec * 1000000000ULL + monotonic.tv_nsec);

    libbpf_set_print(libbpf_log);
    if (setrlimit(RLIMIT_MEMLOCK, &memory_limit) != 0 && errno != EPERM)
        fprintf(stderr, "warning: cannot raise memlock limit: %s\n", strerror(errno));
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skeleton = monitor_bpf__open();
    if (!skeleton) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    configure_syscall_pair(skeleton->progs.handle_openat_enter,
                           skeleton->progs.handle_openat_exit, "openat");
    configure_syscall_pair(skeleton->progs.handle_unlink_enter,
                           skeleton->progs.handle_unlink_exit, "unlink");
    configure_syscall_pair(skeleton->progs.handle_unlinkat_enter,
                           skeleton->progs.handle_unlinkat_exit, "unlinkat");
    configure_syscall_pair(skeleton->progs.handle_rmdir_enter,
                           skeleton->progs.handle_rmdir_exit, "rmdir");
    configure_syscall_pair(skeleton->progs.handle_connect_enter,
                           skeleton->progs.handle_connect_exit, "connect");
    configure_tls_programs(skeleton, tls_enabled);
    configure_pid_namespace(skeleton, agents, agent_count);

    error = monitor_bpf__load(skeleton);
    if (error) {
        fprintf(stderr, "failed to load BPF programs: %d\n", error);
        goto cleanup;
    }

    for (index = 0; index < agent_count; index++) {
        if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.tracked_tgids),
                                &agents[index].pid, &agents[index].id,
                                BPF_ANY) != 0) {
            fprintf(stderr, "failed to register Agent %u PID %u: %s\n",
                    agents[index].id, agents[index].pid, strerror(errno));
            error = 1;
            goto cleanup;
        }
    }

    error = monitor_bpf__attach(skeleton);
    if (error) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", error);
        goto cleanup;
    }

    if (tls_enabled) {
        tls_link_count = attach_tls_probes(skeleton, openssl_path, tls_links);
        if (!tls_link_count)
            fprintf(stderr, "warning: no OpenSSL plaintext probes were attached\n");
        else
            fprintf(stderr, "OpenSSL plaintext capture source: %s\n", openssl_path);
    }

    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                                   handle_event, NULL, NULL);
    if (!ring_buffer) {
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        error = 1;
        goto cleanup;
    }

    fprintf(stderr, "monitoring %zu root Agent(s); Ctrl-C to stop\n", agent_count);
    for (index = 0; index < agent_count; index++)
        fprintf(stderr, "  Agent %u -> root PID %u\n", agents[index].id,
                agents[index].pid);
    while (!exiting) {
        error = ring_buffer__poll(ring_buffer, 250);
        if (error == -EINTR) {
            error = 0;
            continue;
        }
        if (error < 0) {
            fprintf(stderr, "ring-buffer polling failed: %d\n", error);
            break;
        }
    }
    if (exiting)
        error = 0;

cleanup:
    if (skeleton)
        fprintf(stderr,
                "collector stopped; received=%llu dropped=%llu invalid=%llu "
                "fork=%llu exec=%llu exit=%llu file=%llu connect=%llu tls=%llu\n",
                received_events, dropped_event_count(skeleton), invalid_events,
                received_by_type[EVENT_FORK], received_by_type[EVENT_EXEC],
                received_by_type[EVENT_EXIT],
                received_by_type[EVENT_OPEN] + received_by_type[EVENT_UNLINK] +
                    received_by_type[EVENT_UNLINKAT] + received_by_type[EVENT_RMDIR],
                received_by_type[EVENT_CONNECT],
                received_by_type[EVENT_TLS_READ] + received_by_type[EVENT_TLS_WRITE]);
    ring_buffer__free(ring_buffer);
    for (index = 0; index < tls_link_count; index++)
        bpf_link__destroy(tls_links[index]);
    monitor_bpf__destroy(skeleton);
    return error ? 1 : 0;
}
