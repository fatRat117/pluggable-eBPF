#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
    __uint(max_entries, 128);
} execve_events SEC(".maps");

struct execve_data {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct syscalls_sys_enter_execve_ctx *ctx) {
    struct execve_data data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(data.comm, sizeof(data.comm));
    
    // Try to read filename from the first argument
    if (ctx->filename) {
        bpf_probe_read_user_str(data.filename, sizeof(data.filename), 
                                (const char *)ctx->filename);
    }
    
    bpf_perf_event_output(ctx, &execve_events, BPF_F_CURRENT_CPU, 
                          &data, sizeof(data));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
