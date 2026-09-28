#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "monitor.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u32);
} tracked_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct pending_file {
    __u32 type;
    __s32 dirfd;
    __u32 flags;
    char path[EVENT_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_file);
} pending_files SEC(".maps");

struct pending_connect {
    __u16 family;
    __u16 port;
    __u8 address[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_connect);
} pending_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

struct pending_tls {
    __u64 buffer;
    __u64 size_pointer;
    __u32 requested;
    __u8 direction;
    __u8 extended_api;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_tls);
} pending_tls_calls SEC(".maps");

static __always_inline __u32 current_agent_id(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 *agent_id = bpf_map_lookup_elem(&tracked_tgids, &tgid);

    return agent_id ? *agent_id : 0;
}

static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&dropped_events, &key);

    if (value)
        *value += 1;
}

static __always_inline void initialize_event(struct event *event, __u32 type,
                                             __u32 agent_id)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task;

    __builtin_memset(event, 0, EVENT_BASE_SIZE);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->agent_id = agent_id;
    event->tgid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->type = type;
    event->dirfd = -1;
    task = (struct task_struct *)bpf_get_current_task();
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline struct event *new_event(__u32 type, __u32 agent_id)
{
    struct event *event;

    event = bpf_ringbuf_reserve(&events, EVENT_BASE_SIZE, 0);
    if (!event) {
        count_drop();
        return 0;
    }
    initialize_event(event, type, agent_id);
    return event;
}

static __always_inline struct event *new_tls_event(__u32 type, __u32 agent_id)
{
    struct event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }
    initialize_event(event, type, agent_id);
    __builtin_memset(event->data, 0, sizeof(event->data));
    return event;
}

static __always_inline int remember_file(struct trace_event_raw_sys_enter *ctx,
                                         __u32 type, __s32 dirfd,
                                         const char *path, __u32 flags)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_file pending = {};

    (void)ctx;
    if (!current_agent_id())
        return 0;

    pending.type = type;
    pending.dirfd = dirfd;
    pending.flags = flags;
    bpf_probe_read_user_str(pending.path, sizeof(pending.path), path);
    bpf_map_update_elem(&pending_files, &key, &pending, BPF_ANY);
    return 0;
}

static __always_inline int submit_file_result(struct trace_event_raw_sys_exit *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_file *pending;
    struct event *event;
    __u32 agent_id;

    pending = bpf_map_lookup_elem(&pending_files, &key);
    if (!pending)
        return 0;

    agent_id = current_agent_id();
    if (!agent_id)
        goto cleanup;

    event = new_event(pending->type, agent_id);
    if (!event)
        goto cleanup;

    event->dirfd = pending->dirfd;
    event->flags = pending->flags;
    event->retval = ctx->ret;
    __builtin_memcpy(event->object, pending->path, sizeof(event->object));
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&pending_files, &key);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 child_pid = BPF_CORE_READ(ctx, child_pid);
    __u32 *agent_id;
    struct event *event;

    agent_id = bpf_map_lookup_elem(&tracked_tgids, &parent_tgid);
    if (!agent_id)
        return 0;

    bpf_map_update_elem(&tracked_tgids, &child_pid, agent_id, BPF_ANY);
    event = new_event(EVENT_FORK, *agent_id);
    if (!event)
        return 0;
    event->child_pid = child_pid;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 agent_id = current_agent_id();
    __u32 location;
    const char *filename;
    struct event *event;

    if (!agent_id)
        return 0;

    event = new_event(EVENT_EXEC, agent_id);
    if (!event)
        return 0;

    location = BPF_CORE_READ(ctx, __data_loc_filename);
    filename = (const char *)ctx + (location & 0xffff);
    bpf_probe_read_kernel_str(event->object, sizeof(event->object), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 agent_id = current_agent_id();
    struct event *event;

    (void)ctx;
    if (!agent_id)
        return 0;

    event = new_event(EVENT_EXIT, agent_id);
    if (event)
        bpf_ringbuf_submit(event, 0);

    if (tid == tgid)
        bpf_map_delete_elem(&tracked_tgids, &tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    return remember_file(ctx, EVENT_OPEN, (__s32)ctx->args[0],
                         (const char *)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    return submit_file_result(ctx);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
    return remember_file(ctx, EVENT_UNLINK, -1,
                         (const char *)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int handle_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
    return submit_file_result(ctx);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
    return remember_file(ctx, EVENT_UNLINKAT, (__s32)ctx->args[0],
                         (const char *)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int handle_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    return submit_file_result(ctx);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int handle_rmdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    return remember_file(ctx, EVENT_RMDIR, -1,
                         (const char *)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int handle_rmdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    return submit_file_result(ctx);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    const void *user_address = (const void *)ctx->args[1];
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_connect pending = {};
    struct sockaddr_in address4;
    struct sockaddr_in6 address6;

    if (!current_agent_id() || !user_address)
        return 0;

    if (bpf_probe_read_user(&pending.family, sizeof(pending.family),
                            user_address) < 0)
        return 0;

    if (pending.family == AF_INET) {
        if (bpf_probe_read_user(&address4, sizeof(address4), user_address) < 0)
            return 0;
        pending.port = bpf_ntohs(address4.sin_port);
        __builtin_memcpy(pending.address, &address4.sin_addr.s_addr, 4);
    } else if (pending.family == AF_INET6) {
        if (bpf_probe_read_user(&address6, sizeof(address6), user_address) < 0)
            return 0;
        pending.port = bpf_ntohs(address6.sin6_port);
        __builtin_memcpy(pending.address, &address6.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        return 0;
    }

    bpf_map_update_elem(&pending_connects, &key, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_connect *pending;
    struct event *event;
    __u32 agent_id;

    pending = bpf_map_lookup_elem(&pending_connects, &key);
    if (!pending)
        return 0;

    agent_id = current_agent_id();
    if (!agent_id)
        goto cleanup;

    event = new_event(EVENT_CONNECT, agent_id);
    if (!event)
        goto cleanup;

    event->retval = ctx->ret;
    event->address_family = pending->family;
    event->destination_port = pending->port;
    __builtin_memcpy(event->address, pending->address, sizeof(event->address));
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&pending_connects, &key);
    return 0;
}

static __always_inline int remember_tls(struct pt_regs *ctx, __u8 direction,
                                        __u8 extended_api)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_tls pending = {};

    if (!current_agent_id())
        return 0;

    pending.buffer = (__u64)PT_REGS_PARM2(ctx);
    pending.requested = (__u32)PT_REGS_PARM3(ctx);
    pending.direction = direction;
    pending.extended_api = extended_api;
    if (extended_api)
        pending.size_pointer = (__u64)PT_REGS_PARM4(ctx);
    if (!pending.buffer || !pending.requested)
        return 0;
    bpf_map_update_elem(&pending_tls_calls, &key, &pending, BPF_ANY);
    return 0;
}

static __always_inline int submit_tls(struct pt_regs *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_tls *pending;
    struct event *event;
    __u64 actual_size = 0;
    long result = PT_REGS_RC(ctx);
    __u32 capture_size;
    __u32 agent_id;

    pending = bpf_map_lookup_elem(&pending_tls_calls, &key);
    if (!pending)
        return 0;

    agent_id = current_agent_id();
    if (!agent_id)
        goto cleanup;

    if (pending->extended_api) {
        if (result != 1 || !pending->size_pointer)
            goto cleanup;
        if (bpf_probe_read_user(&actual_size, sizeof(actual_size),
                                (const void *)pending->size_pointer) < 0)
            goto cleanup;
    } else {
        if (result <= 0)
            goto cleanup;
        actual_size = (__u64)result;
    }
    if (actual_size > pending->requested)
        actual_size = pending->requested;
    if (!actual_size)
        goto cleanup;

    capture_size = actual_size > EVENT_DATA_LEN ? EVENT_DATA_LEN : actual_size;
    event = new_tls_event(
        pending->direction == 0 ? EVENT_TLS_READ : EVENT_TLS_WRITE, agent_id);
    if (!event)
        goto cleanup;

    event->data_size = actual_size > 0xffffffffULL ? 0xffffffffU : actual_size;
    event->data_len = capture_size;
    if (actual_size > EVENT_DATA_LEN)
        event->flags |= EVENT_FLAG_TRUNCATED;
    if (bpf_probe_read_user(event->data, capture_size,
                            (const void *)pending->buffer) < 0) {
        bpf_ringbuf_discard(event, 0);
        goto cleanup;
    }
    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&pending_tls_calls, &key);
    return 0;
}

SEC("uprobe")
int handle_ssl_read_enter(struct pt_regs *ctx)
{
    return remember_tls(ctx, 0, 0);
}

SEC("uretprobe")
int handle_ssl_read_exit(struct pt_regs *ctx)
{
    return submit_tls(ctx);
}

SEC("uprobe")
int handle_ssl_write_enter(struct pt_regs *ctx)
{
    return remember_tls(ctx, 1, 0);
}

SEC("uretprobe")
int handle_ssl_write_exit(struct pt_regs *ctx)
{
    return submit_tls(ctx);
}

SEC("uprobe")
int handle_ssl_read_ex_enter(struct pt_regs *ctx)
{
    return remember_tls(ctx, 0, 1);
}

SEC("uretprobe")
int handle_ssl_read_ex_exit(struct pt_regs *ctx)
{
    return submit_tls(ctx);
}

SEC("uprobe")
int handle_ssl_write_ex_enter(struct pt_regs *ctx)
{
    return remember_tls(ctx, 1, 1);
}

SEC("uretprobe")
int handle_ssl_write_ex_exit(struct pt_regs *ctx)
{
    return submit_tls(ctx);
}
