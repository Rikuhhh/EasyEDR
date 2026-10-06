#include <linux/sched.h>
#include <linux/in.h>
#include <linux/socket.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char cmd[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(connect_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.cmd, sizeof(data.cmd));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

struct connect_data_t {
    u32 pid;
    u32 uid;
    u16 family;
    u16 dport;
    u32 daddr;
    char comm[16];
};

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct sockaddr_in address = {};
    struct connect_data_t data = {};

    bpf_probe_read_user(&address, sizeof(address), args->uservaddr);
    if (address.sin_family != AF_INET) {
        return 0;
    }

    u64 pid_uid = bpf_get_current_pid_tgid();
    data.pid = pid_uid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.family = address.sin_family;
    data.dport = bpf_ntohs(address.sin_port);
    data.daddr = bpf_ntohl(address.sin_addr.s_addr);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    connect_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

struct fork_data_t {
    u32 parent_pid;
    u32 child_pid;
    char parent_comm[16];
};

BPF_PERF_OUTPUT(fork_events);

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct fork_data_t data = {};

    data.parent_pid = args->parent_pid;
    data.child_pid = args->child_pid;

    bpf_get_current_comm(&data.parent_comm, sizeof(data.parent_comm));

    fork_events.perf_submit(args, &data, sizeof(data));
    return 0;
}