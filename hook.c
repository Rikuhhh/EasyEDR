// execve.c hook

#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    char filename[256];
};

