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
  PACEKT_DONE = 2,
  APP_RECV = 3,
  APP_RECV_END = 4,
  ACK_SENT = 5,
  PACKET_QUEUED = 6,
};

struct recvstory_message_t {
  u64 timestamp_ns;
  struct flow flow;
  int event_type;
  u32 rcv_nxt;
  u32 copied_seq;
  u32 seq;
  u32 len;
};

static inline u32 skb_get_seq(struct sk_buff *skb) {
  struct tcphdr *th = (struct tcphdr *)BPF_CORE_READ(skb, data);
  return bpf_ntohl(BPF_CORE_READ(th, seq));
}

static inline u32 skb_get_payload_len(struct sk_buff *skb) {
  struct tcphdr *th = (struct tcphdr *)BPF_CORE_READ(skb, data);
  u32 tcp_hdr_len = BPF_CORE_READ_BITFIELD_PROBED(th, doff) * 4;
  return BPF_CORE_READ(skb, len) - tcp_hdr_len;
}

static inline u32 sk_get_rcv_nxt(struct sock *sk) {
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  return BPF_CORE_READ(tp, rcv_nxt);
}

static inline u32 sk_get_copied_seq(struct sock *sk) {
  struct tcp_sock *tp = (struct tcp_sock *)sk;
  return BPF_CORE_READ(tp, copied_seq);
}

static inline u32 sk_get_cookie(struct sock *sk) {
  return bpf_get_socket_cookie(sk);
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32 * 1024 * 1024);
} events SEC(".maps");

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established_entry, struct sock *sk, struct sk_buff *skb) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct recvstory_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct recvstory_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();
  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  e->flow.socket_cookie = sk_get_cookie(sk);
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));

  e->event_type = PACKET;
  e->rcv_nxt = sk_get_rcv_nxt(sk);
  e->copied_seq = sk_get_copied_seq(sk);
  e->seq = skb_get_seq(skb);
  e->len = skb_get_payload_len(skb);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fexit/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established_exit, struct sock *sk, struct sk_buff *skb) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct recvstory_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct recvstory_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));
  e->flow.socket_cookie = sk_get_cookie(sk);

  e->event_type = PACEKT_DONE;
  e->rcv_nxt = sk_get_rcv_nxt(sk);
  e->copied_seq = sk_get_copied_seq(sk);
  e->seq = skb_get_seq(skb);
  e->len = skb_get_payload_len(skb);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len) {

  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

#if PRINTK_DEBUG
  bpf_printk("kprobe triggered at tcp_recvmsg, rcv_nxt: %u, "
             "copied_seq: %u, RecvQ: %d\n",
             rcv_nxt, copied_seq, rcv_nxt - copied_seq);
#endif

  struct recvstory_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct recvstory_message_t), 0);
  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));
  e->flow.socket_cookie = sk_get_cookie(sk);
  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->event_type = APP_RECV;
  e->rcv_nxt = sk_get_rcv_nxt(sk);
  e->copied_seq = sk_get_copied_seq(sk);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len) {

  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct recvstory_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct recvstory_message_t), 0);
  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));
  e->flow.socket_cookie = sk_get_cookie(sk);

  e->event_type = APP_RECV_END;
  e->rcv_nxt = sk_get_rcv_nxt(sk);
  e->copied_seq = sk_get_copied_seq(sk);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fexit/tcp_add_backlog")
int BPF_PROG(tcp_add_backlog_exit, struct sock *sk, struct sk_buff *skb,
             enum skb_drop_reason *reason, bool ret) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct recvstory_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct recvstory_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));
  e->flow.socket_cookie = sk_get_cookie(sk);

  e->event_type = PACKET_QUEUED;
  e->rcv_nxt = sk_get_rcv_nxt(sk);
  e->copied_seq = sk_get_copied_seq(sk);
  e->seq = skb_get_seq(skb);
  e->len = skb_get_payload_len(skb);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("fexit/__tcp_send_ack")
int BPF_PROG(__tcp_send_ack_exit, struct sock *sk, u32 rcv_nxt) {
  if (!filter_conn(sk, tgt_src_port, tgt_dst_port)) {
    return 0;
  }

  struct recvstory_message_t *e =
      bpf_ringbuf_reserve(&events, sizeof(struct recvstory_message_t), 0);

  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_tai_ns();

  e->flow.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->flow.comm, sizeof(e->flow.comm));
  e->flow.socket_cookie = sk_get_cookie(sk);

  e->event_type = ACK_SENT;
  e->rcv_nxt = sk_get_rcv_nxt(sk);
  e->copied_seq = sk_get_copied_seq(sk);
  e->seq = rcv_nxt;

  bpf_ringbuf_submit(e, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
