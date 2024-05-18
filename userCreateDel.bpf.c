#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char command[256];
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.command, sizeof(event.command), (void *)ctx->filename);

    if (strstr(event.command, "useradd") || strstr(event.command, "userdel")) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}