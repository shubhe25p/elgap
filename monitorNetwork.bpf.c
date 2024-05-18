#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_PERF_OUTPUT(events);

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char saddr[INET6_ADDRSTRLEN];
    char daddr[INET6_ADDRSTRLEN];
    u16 sport;
    u16 dport;
};

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct inet_sock *inet = inet_sk(sk);
    
    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.saddr, sizeof(event.saddr), (void *)&inet->inet_saddr);
    bpf_probe_read_kernel_str(&event.daddr, sizeof(event.daddr), (void *)&inet->inet_daddr);
    event.sport = inet->inet_sport;
    event.dport = inet->inet_dport;

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}