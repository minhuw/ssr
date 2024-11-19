// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

const volatile __u16 tgt_src_port = 0;
const volatile __u16 tgt_dst_port = 0;

#define SOL_TCP		6

#define TCP_CONGESTION		13

struct dctcp_message_t {
    u64 timestamp_ns;
    struct flow flow;
    u32 snd_cwnd;
    u32 ssthresh;
    u32 in_flight;
    u32 delivered;
    u32 delivered_ce;
    u32 srtt;
    u32 mdev;
    u32 snd_una;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32 * 1024 * 1024);
} events SEC(".maps");


SEC("fexit/tcp_ack")
int BPF_PROG(trace_tcp_cong_avoid, struct sock *sk) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

    if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
        return 0;
    }

    // Check if the inet_connection_sock or icsk_ca_ops is valid
    const char* cc_name = BPF_CORE_READ(icsk, icsk_ca_ops, name);
    if (bpf_strncmp(cc_name, 5, "dctcp") != 0)
        return 0;

    // Send data to user-space
    struct dctcp_message_t *event =
        bpf_ringbuf_reserve(&events, sizeof(struct dctcp_message_t), 0);

    if (!event)
        return 0;

    // Prepare event data
    event->timestamp_ns = bpf_ktime_get_tai_ns();

    event->flow.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->flow.comm, sizeof(event->flow.comm));
    event->flow.socket_cookie = bpf_get_socket_cookie(sk);

    event->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    event->ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    event->in_flight = BPF_CORE_READ(tp, packets_out);
    event->delivered = BPF_CORE_READ(tp, delivered);
    event->delivered_ce = BPF_CORE_READ(tp, delivered_ce);
    event->srtt = BPF_CORE_READ(tp, srtt_us) >> 3;
    event->mdev = BPF_CORE_READ(tp, mdev_us);
    event->snd_una = BPF_CORE_READ(tp, snd_una);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
