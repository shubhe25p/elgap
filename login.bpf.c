#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/utsname.h>

BPF_PERF_OUTPUT(events);

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    int success;
};

TRACEPOINT_PROBE(pam, pam_authenticate) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.success = args->retval == PAM_SUCCESS;
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}