// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile u64 core_bitmap = 0;

enum {
    SCHED_SWITCH = 1,
    SCHED_EXEC = 2,
    SCHED_EXIT = 3,
    SOFTIRQ_ENTRY = 4,
    SOFTIRQ_EXIT = 5,
};

struct sched_message_t {
    u64 timestamp_ns;
    u32 event_type;
    u32 pid;
    u32 prev_pid;
    u32 next_pid;
    u32 softirq_vec;
    u32 cpu_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, char[TASK_COMM_LEN]);
} task_comms SEC(".maps");

static inline bool is_current_core_traced(void)
{
    return !core_bitmap || (core_bitmap & (1 << bpf_get_smp_processor_id()));
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    struct sched_message_t *e;

    if (!is_current_core_traced()) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = SCHED_SWITCH;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->prev_pid = ctx->prev_pid;
    e->next_pid = ctx->next_pid;
    e->event_type = SCHED_SWITCH;
    e->cpu_id = bpf_get_smp_processor_id();
    e->softirq_vec = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct sched_message_t *e;

    if (!is_current_core_traced()) {
        return 0;
    }


    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->timestamp_ns = bpf_ktime_get_tai_ns();
    e->event_type = SCHED_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->prev_pid = 0;
    e->next_pid = 0;
    e->cpu_id = bpf_get_smp_processor_id();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct sched_message_t *e;

    if (!is_current_core_traced()) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->timestamp_ns = bpf_ktime_get_tai_ns();
    e->event_type = SCHED_EXIT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->prev_pid = 0;
    e->next_pid = 0;
    e->cpu_id = bpf_get_smp_processor_id();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/irq/softirq_entry")
int handle_softirq_entry(struct trace_event_raw_softirq *ctx)
{
    struct sched_message_t *e;

    if (!is_current_core_traced()) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->timestamp_ns = bpf_ktime_get_tai_ns();
    e->event_type = SOFTIRQ_ENTRY;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->prev_pid = 0;
    e->next_pid = 0;
    e->softirq_vec = ctx->vec;
    e->cpu_id = bpf_get_smp_processor_id();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/irq/softirq_exit")
int handle_softirq_exit(struct trace_event_raw_softirq *ctx)
{
    struct sched_message_t *e;

    if (!is_current_core_traced()) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->timestamp_ns = bpf_ktime_get_tai_ns();
    e->event_type = SOFTIRQ_EXIT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->prev_pid = 0;
    e->next_pid = 0;
    e->softirq_vec = ctx->vec;
    e->event_type = SOFTIRQ_EXIT;
    e->cpu_id = bpf_get_smp_processor_id();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
