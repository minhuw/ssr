// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

const volatile __u16 tgt_src_port = 0;
const volatile __u16 tgt_dst_port = 0;

#define ETH_P_IP    0x0800      /* Internet Protocol packet */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    u64 timestamp_ns;
    struct flow flow;
    u32 seq;
    u32 ack;
    u32 len;
    u16 wnd;
    u8 direction;
    u8 flags;
};

SEC("cgroup_skb/egress")
int tcp_egress(struct __sk_buff *skb)
{
    struct event *e;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void*)(iph + 1) > data_end)
        return 1;
        
    if (iph->protocol != IPPROTO_TCP)
        return 1;

    struct tcphdr *th = (void*)(iph + 1);
    if ((void*)(th + 1) > data_end)
        return 1;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 1;
    }

    // Calculate header lengths
    u32 ip_hdr_len = iph->ihl * 4;    // IP header length in bytes
    u32 tcp_hdr_len = th->doff * 4;   // TCP header length in bytes
    
    // Calculate total IP packet length and payload length
    u32 total_len = bpf_ntohs(iph->tot_len);
    u32 payload_len = total_len - ip_hdr_len - tcp_hdr_len;

    e->timestamp_ns = bpf_ktime_get_ns();

    e->flow.pid = 0;
    e->flow.socket_cookie = bpf_get_socket_cookie(skb);

    e->seq = bpf_ntohl(th->seq);
    e->ack = bpf_ntohl(th->ack_seq);
    e->len = payload_len;
    e->wnd = bpf_ntohs(th->window);
    e->direction = 1;
    e->flags = ((th->fin) << 0) |
               ((th->syn) << 1) |
               ((th->rst) << 2) |
               ((th->psh) << 3) |
               ((th->ack) << 4) |
               ((th->urg) << 5) |
               ((th->ece) << 6) |
               ((th->cwr) << 7);

    bpf_ringbuf_submit(e, 0);

    return 1;
}


SEC("cgroup_skb/ingress")
int tcp_ingress(struct __sk_buff *skb)
{
    struct event *e;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void*)(iph + 1) > data_end)
        return 1;
        
    if (iph->protocol != IPPROTO_TCP)
        return 1;

    struct tcphdr *th = (void*)(iph + 1);
    if ((void*)(th + 1) > data_end)
        return 1;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 1;
    }

    // Calculate header lengths
    u32 ip_hdr_len = iph->ihl * 4;    // IP header length in bytes
    u32 tcp_hdr_len = th->doff * 4;   // TCP header length in bytes
    
    // Calculate total IP packet length and payload length
    u32 total_len = bpf_ntohs(iph->tot_len);
    u32 payload_len = total_len - ip_hdr_len - tcp_hdr_len;

    e->timestamp_ns = bpf_ktime_get_ns();

    e->flow.pid = 0;
    e->flow.socket_cookie = bpf_get_socket_cookie(skb);

    e->seq = bpf_ntohl(th->seq);
    e->ack = bpf_ntohl(th->ack_seq);
    e->len = payload_len;
    e->wnd = bpf_ntohs(th->window);
    e->direction = 0;
    e->flags = ((th->fin) << 0) |
               ((th->syn) << 1) |
               ((th->rst) << 2) |
               ((th->psh) << 3) |
               ((th->ack) << 4) |
               ((th->urg) << 5) |
               ((th->ece) << 6) |
               ((th->cwr) << 7);

    bpf_ringbuf_submit(e, 0);

    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";