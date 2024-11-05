// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define SOL_TCP		6

#define TCP_CONGESTION		13

struct dctcp_message_t {
    u64 timestamp_ns;
    u64 socket_cookie;
    u32 snd_cwnd;
    u32 ssthresh;
    u32 in_flight; 
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} dctcp_events SEC(".maps");

// Attach fentry to `tcp_cong_avoid`
SEC("fentry/tcp_ack")
int BPF_PROG(trace_tcp_cong_avoid, struct sock *sk) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

    // Check if the inet_connection_sock or icsk_ca_ops is valid

    if (bpf_strncmp(BPF_CORE_READ(icsk, icsk_ca_ops, name), 5, "dctcp") != 0)
        return 0;

    // Send data to user-space
    struct dctcp_message_t *event =
        bpf_ringbuf_reserve(&dctcp_events, sizeof(struct dctcp_message_t), 0);

    if (!event)
        return 0;

    // Prepare event data
    event->socket_cookie = bpf_get_socket_cookie(sk);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    event->ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    event->in_flight = BPF_CORE_READ(tp, packets_out);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
