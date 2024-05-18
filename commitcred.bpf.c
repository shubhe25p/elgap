#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
    u32 gid;
};

BPF_PERF_OUTPUT(events);

int trace_commit_creds(struct pt_regs *ctx, struct cred *new) {
    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = new->uid.val;
    data.gid = new->gid.val;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}