#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(processes, u32, struct data_t);

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.pid = pid;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    processes.update(&pid, &data);
    return 0;
}