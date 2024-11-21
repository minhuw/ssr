// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

const volatile __u16 tgt_src_port = 0;
const volatile __u16 tgt_dst_port = 0;

#define ETH_P_IP 0x0800 /* Internet Protocol packet */

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32 * 1024 * 1024);
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
int tcp_egress(struct __sk_buff *skb) {
  struct event *e;
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *iph = data;
  if ((void *)(iph + 1) > data_end)
    return 1;

  if (iph->protocol != IPPROTO_TCP)
    return 1;

  struct tcphdr *th = (void *)(iph + 1);
  if ((void *)(th + 1) > data_end)
    return 1;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 1;
  }

  // Calculate header lengths
  u32 ip_hdr_len = iph->ihl * 4;  // IP header length in bytes
  u32 tcp_hdr_len = th->doff * 4; // TCP header length in bytes

  // Calculate total IP packet length and payload length
  u32 total_len = bpf_ntohs(iph->tot_len);
  u32 payload_len = total_len - ip_hdr_len - tcp_hdr_len;

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = 0;
  e->flow.socket_cookie = bpf_get_socket_cookie(skb);

  e->seq = bpf_ntohl(th->seq);
  e->ack = bpf_ntohl(th->ack_seq);
  e->len = payload_len;
  e->wnd = bpf_ntohs(th->window);
  e->direction = 0;
  e->flags = ((th->fin) << 0) | ((th->syn) << 1) | ((th->rst) << 2) |
             ((th->psh) << 3) | ((th->ack) << 4) | ((th->urg) << 5) |
             ((th->ece) << 6) | ((th->cwr) << 7);

  bpf_ringbuf_submit(e, 0);

  return 1;
}

SEC("cgroup_skb/ingress")
int tcp_ingress(struct __sk_buff *skb) {
  struct event *e;
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *iph = data;
  if ((void *)(iph + 1) > data_end)
    return 1;

  if (iph->protocol != IPPROTO_TCP)
    return 1;

  struct tcphdr *th = (void *)(iph + 1);
  if ((void *)(th + 1) > data_end)
    return 1;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 1;
  }

  // Calculate header lengths
  u32 ip_hdr_len = iph->ihl * 4;  // IP header length in bytes
  u32 tcp_hdr_len = th->doff * 4; // TCP header length in bytes

  // Calculate total IP packet length and payload length
  u32 total_len = bpf_ntohs(iph->tot_len);
  u32 payload_len = total_len - ip_hdr_len - tcp_hdr_len;

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = 0;
  e->flow.socket_cookie = bpf_get_socket_cookie(skb);

  e->seq = bpf_ntohl(th->seq);
  e->ack = bpf_ntohl(th->ack_seq);
  e->len = payload_len;
  e->wnd = bpf_ntohs(th->window);
  e->direction = 1;
  e->flags = ((th->fin) << 0) | ((th->syn) << 1) | ((th->rst) << 2) |
             ((th->psh) << 3) | ((th->ack) << 4) | ((th->urg) << 5) |
             ((th->ece) << 6) | ((th->cwr) << 7);

  bpf_ringbuf_submit(e, 0);

  return 1;
}

SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) {
  struct event *e;
  struct tcphdr *th;
  // Get TCP header
  th = (struct tcphdr *)BPF_CORE_READ(skb, data);

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  // Calculate header lengths
  u32 tcp_hdr_len =
      BPF_CORE_READ_BITFIELD_PROBED(th, doff) * 4; // TCP header length in bytes
  u32 payload_len = BPF_CORE_READ(skb, len) - tcp_hdr_len;

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = 0;
  e->flow.socket_cookie = bpf_get_socket_cookie(sk);

  e->seq = bpf_ntohl(BPF_CORE_READ(th, seq));
  e->ack = bpf_ntohl(BPF_CORE_READ(th, ack_seq));

  e->len = payload_len;
  e->wnd = bpf_ntohs(BPF_CORE_READ(th, window));
  e->direction = 2;
  e->flags = ((BPF_CORE_READ_BITFIELD_PROBED(th, fin)) << 0) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, syn)) << 1) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, rst)) << 2) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, psh)) << 3) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ack)) << 4) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, urg)) << 5) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ece)) << 6) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, cwr)) << 7);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
  struct event *e;
  struct iphdr *iph;
  struct tcphdr *th;

  // Get TCP header
  th = (struct tcphdr *)BPF_CORE_READ(skb, data);

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  // Calculate header lengths
  u32 tcp_hdr_len =
      BPF_CORE_READ_BITFIELD_PROBED(th, doff) * 4; // TCP header length in bytes
  u32 payload_len = BPF_CORE_READ(skb, len) - tcp_hdr_len;

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = 0;
  e->flow.socket_cookie = bpf_get_socket_cookie(sk);

  e->seq = bpf_ntohl(BPF_CORE_READ(th, seq));
  e->ack = bpf_ntohl(BPF_CORE_READ(th, ack_seq));

  e->len = payload_len;
  e->wnd = bpf_ntohs(BPF_CORE_READ(th, window));
  e->direction = 3;
  e->flags = ((BPF_CORE_READ_BITFIELD_PROBED(th, fin)) << 0) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, syn)) << 1) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, rst)) << 2) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, psh)) << 3) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ack)) << 4) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, urg)) << 5) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ece)) << 6) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, cwr)) << 7);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fentry/tcp_ack")
int BPF_PROG(tcp_ack, struct sock *sk, const struct sk_buff *skb, int flag) {
  struct event *e;
  struct iphdr *iph;
  struct tcphdr *th;

  // Get TCP header
  th = (struct tcphdr *)BPF_CORE_READ(skb, data);

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  // Calculate header lengths
  u32 tcp_hdr_len =
      BPF_CORE_READ_BITFIELD_PROBED(th, doff) * 4; // TCP header length in bytes
  u32 payload_len = BPF_CORE_READ(skb, len) - tcp_hdr_len;

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = 0;
  e->flow.socket_cookie = bpf_get_socket_cookie(sk);

  e->seq = bpf_ntohl(BPF_CORE_READ(th, seq));
  e->ack = bpf_ntohl(BPF_CORE_READ(th, ack_seq));

  e->len = payload_len;
  e->wnd = bpf_ntohs(BPF_CORE_READ(th, window));
  e->direction = 4;
  e->flags = ((BPF_CORE_READ_BITFIELD_PROBED(th, fin)) << 0) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, syn)) << 1) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, rst)) << 2) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, psh)) << 3) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ack)) << 4) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, urg)) << 5) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ece)) << 6) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, cwr)) << 7);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fentry/tcp_add_backlog")
int BPF_PROG(tcp_add_backlog, struct sock *sk, struct sk_buff *skb,
             enum skb_drop_reason *reason) {
  struct event *e;
  struct iphdr *iph;
  struct tcphdr *th;

  // Get TCP header
  th = (struct tcphdr *)BPF_CORE_READ(skb, data);

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  // Calculate header lengths
  u32 tcp_hdr_len =
      BPF_CORE_READ_BITFIELD_PROBED(th, doff) * 4; // TCP header length in bytes
  u32 payload_len = BPF_CORE_READ(skb, len) - tcp_hdr_len;

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = 0;
  e->flow.socket_cookie = bpf_get_socket_cookie(sk);

  e->seq = bpf_ntohl(BPF_CORE_READ(th, seq));
  e->ack = bpf_ntohl(BPF_CORE_READ(th, ack_seq));

  e->len = payload_len;
  e->wnd = bpf_ntohs(BPF_CORE_READ(th, window));
  e->direction = 5;
  e->flags = ((BPF_CORE_READ_BITFIELD_PROBED(th, fin)) << 0) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, syn)) << 1) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, rst)) << 2) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, psh)) << 3) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ack)) << 4) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, urg)) << 5) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, ece)) << 6) |
             ((BPF_CORE_READ_BITFIELD_PROBED(th, cwr)) << 7);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";