#ifndef AGENT_MONITOR_H
#define AGENT_MONITOR_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16
#define EVENT_PATH_LEN 256
#define EVENT_DATA_LEN 256

#define EVENT_FLAG_TRUNCATED (1U << 31)

enum event_type {
    EVENT_FORK = 1,
    EVENT_EXEC,
    EVENT_EXIT,
    EVENT_OPEN,
    EVENT_UNLINK,
    EVENT_UNLINKAT,
    EVENT_RMDIR,
    EVENT_CONNECT,
    EVENT_TLS_READ,
    EVENT_TLS_WRITE,
};

struct event {
    __u64 timestamp_ns;
    __u32 agent_id;
    __u32 tgid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 type;
    __u32 child_pid;
    __s32 dirfd;
    __u32 flags;
    __s64 retval;
    __u16 address_family;
    __u16 destination_port;
    __u32 data_len;
    __u32 data_size;
    __u8 address[16];
    char comm[TASK_COMM_LEN];
    char object[EVENT_PATH_LEN];
    char data[EVENT_DATA_LEN];
};

#define EVENT_BASE_SIZE __builtin_offsetof(struct event, data)

#endif
