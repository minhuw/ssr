// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

const volatile __u16 tgt_src_port = 0;
const volatile __u16 tgt_dst_port = 0;

enum {
  PACKET = 1,
  PACKET_DONE = 2,
  APP_SEND = 3,
  APP_SEND_DONE = 4,
  ACK = 5,
};

struct send_timeline_message_t {
  u64 timestamp_ns;
  struct flow flow;
  int event_type;
  u32 snd_nxt;
  u32 snd_una;
  u32 write_seq;
  u32 seq;
  u32 len;
};

static inline u32 sk_get_snd_nxt(struct sock *sk) {
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  return BPF_CORE_READ(tp, snd_nxt);
}

static inline u32 sk_get_snd_una(struct sock *sk) {
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  return BPF_CORE_READ(tp, snd_una);
}

static inline u32 sk_get_write_seq(struct sock *sk) {
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  return BPF_CORE_READ(tp, write_seq);
}

static inline u32 skb_get_seq(struct sk_buff *skb) {
  struct tcphdr *th = (struct tcphdr *)BPF_CORE_READ(skb, data);
  return bpf_ntohl(BPF_CORE_READ(th, seq));
}

static inline u32 skb_get_payload_len(struct sk_buff *skb) {
  struct tcphdr *th = (struct tcphdr *)BPF_CORE_READ(skb, data);
  u32 tcp_hdr_len = BPF_CORE_READ_BITFIELD_PROBED(th, doff) * 4;
  return BPF_CORE_READ(skb, len) - tcp_hdr_len;
}

static inline u32 sk_get_cookie(struct sock *sk) {
  return bpf_get_socket_cookie(sk);
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32 * 1024 * 1024);
} events SEC(".maps");

SEC("fentry/ip_queue_xmit")
int BPF_PROG(__tcp_transmit_skb_entry, struct sock *sk, struct sk_buff *skb,
             int clone_it, gfp_t gfp_mask, u32 rcv_nxt) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct send_timeline_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct send_timeline_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();
  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  e->flow.socket_cookie = sk_get_cookie(sk);
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));

  e->event_type = PACKET;
  e->snd_nxt = sk_get_snd_nxt(sk);
  e->snd_una = sk_get_snd_una(sk);
  e->write_seq = sk_get_write_seq(sk);
  e->seq = skb_get_seq(skb);
  e->len = skb_get_payload_len(skb);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fentry/tcp_sendmsg_locked")
int BPF_PROG(tcp_sendmsg_locked_entry, struct sock *sk, struct msghdr *msg,
             size_t size) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct send_timeline_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct send_timeline_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();
  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  e->flow.socket_cookie = sk_get_cookie(sk);
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));

  e->event_type = APP_SEND;
  e->snd_nxt = sk_get_snd_nxt(sk);
  e->snd_una = sk_get_snd_una(sk);
  e->write_seq = sk_get_write_seq(sk);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fexit/tcp_sendmsg_locked")
int BPF_PROG(tcp_sendmsg_locked_exit, struct sock *sk, struct msghdr *msg,
             size_t size) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct send_timeline_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct send_timeline_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();
  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  e->flow.socket_cookie = sk_get_cookie(sk);
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));

  e->event_type = APP_SEND_DONE;
  e->snd_nxt = sk_get_snd_nxt(sk);
  e->snd_una = sk_get_snd_una(sk);
  e->write_seq = sk_get_write_seq(sk);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fexit/tcp_ack")
int BPF_PROG(tcp_ack_exit, struct sock *sk, const struct sk_buff *skb,
             int flag) {
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }
  // Send data to user-space
  struct send_timeline_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct send_timeline_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();
  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  e->flow.socket_cookie = sk_get_cookie(sk);
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));

  e->event_type = ACK;
  e->snd_nxt = sk_get_snd_nxt(sk);
  e->snd_una = sk_get_snd_una(sk);
  e->write_seq = sk_get_write_seq(sk);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
