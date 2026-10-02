#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char cmd[16];
};

BPF_PERF_OUTPUT(events);

int hook_execve(struct pt_regs *ctx) {
    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.cmd, sizeof(data.cmd));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}