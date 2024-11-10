// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PRINTK_DEBUG 0

const volatile __u16 tgt_src_port = 0;
const volatile __u16 tgt_dst_port = 0;

struct five_tuple_t {
  __u32 saddr;   // Source IP address
  __u32 daddr;   // Destination IP address
  __u16 sport;   // Source port
  __u16 dport;   // Destination port
  __u8 protocol; // Protocol (e.g., IPPROTO_TCP)
};

enum {
  NEW_PACKET_EVENT = 1,
  NEW_PACEKT_DONE_EVENT = 2,
  APP_RECV_EVENT = 3,
  APP_RECV_DONE_EVENT = 4,
};

struct buffer_message_t {
  __u32 pid;
  char comm[16];
  __u32 rx_buffer;
  __u64 timestamp_ns;
  __u64 socket_cookie;
  int event_type;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

int filter_conn(struct sock *sk) {
  __u16 src_port = sk->__sk_common.skc_num;
  __u16 dst_port = sk->__sk_common.skc_dport;

  if (((src_port == tgt_src_port) || (tgt_src_port == 0)) &&
      ((dst_port == tgt_dst_port) || (tgt_dst_port == 0))) {
    return 1;
  }
  return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established_entry, struct sock *sk, struct sk_buff *skb) {
  if (!filter_conn(sk)) {
    return 0;
  }

  struct tcp_sock *tp = (struct tcp_sock *)sk;
  __u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
  __u32 copied_seq = BPF_CORE_READ(tp, copied_seq);
  __u64 cookie = bpf_get_socket_cookie(sk);

#if PRINTK_DEBUG
  bpf_printk("kprobe triggered at tcp_rcv_established, rcv_nxt: %u, "
             "copied_seq: %u, RecvQ: %d\n",
             rcv_nxt, copied_seq, rcv_nxt - copied_seq);
#endif

  struct buffer_message_t *data =
      bpf_ringbuf_reserve(&events, sizeof(struct buffer_message_t), 0);

  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->rx_buffer = rcv_nxt - copied_seq;
  data->timestamp_ns = bpf_ktime_get_ns();
  data->socket_cookie = cookie;
  data->event_type = NEW_PACKET_EVENT;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  bpf_ringbuf_submit(data, 0);

  return 0;
}

SEC("fexit/tcp_rcv_established")
int BPF_PROG(tcp_rcv_established_exit, struct sock *sk, struct sk_buff *skb) {
  if (!filter_conn(sk)) {
    return 0;
  }

  struct tcp_sock *tp = (struct tcp_sock *)sk;
  __u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
  __u32 copied_seq = BPF_CORE_READ(tp, copied_seq);
  __u64 cookie = bpf_get_socket_cookie(sk);

#if PRINTK_DEBUG
  bpf_printk("kprobe triggered at tcp_rcv_established, rcv_nxt: %u, "
             "copied_seq: %u, RecvQ: %d\n",
             rcv_nxt, copied_seq, rcv_nxt - copied_seq);
#endif

  struct buffer_message_t *data =
      bpf_ringbuf_reserve(&events, sizeof(struct buffer_message_t), 0);

  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->rx_buffer = rcv_nxt - copied_seq;
  data->timestamp_ns = bpf_ktime_get_ns();
  data->socket_cookie = cookie;
  data->event_type = NEW_PACEKT_DONE_EVENT;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  bpf_ringbuf_submit(data, 0);

  return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len) {

  if (!filter_conn(sk)) {
    return 0;
  }

  struct tcp_sock *tp = (struct tcp_sock *)sk;
  __u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
  __u32 copied_seq = BPF_CORE_READ(tp, copied_seq);
  __u64 cookie = bpf_get_socket_cookie(sk);

#if PRINTK_DEBUG
  bpf_printk("kprobe triggered at tcp_recvmsg, rcv_nxt: %u, "
             "copied_seq: %u, RecvQ: %d\n",
             rcv_nxt, copied_seq, rcv_nxt - copied_seq);
#endif

  struct buffer_message_t *data =
      bpf_ringbuf_reserve(&events, sizeof(struct buffer_message_t), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->rx_buffer = rcv_nxt - copied_seq;
  data->timestamp_ns = bpf_ktime_get_ns();
  data->socket_cookie = bpf_get_socket_cookie(sk);
  data->event_type = APP_RECV_EVENT;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  bpf_ringbuf_submit(data, 0);

  return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len) {

  if (!filter_conn(sk)) {
    return 0;
  }

  struct tcp_sock *tp = (struct tcp_sock *)sk;
  __u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
  __u32 copied_seq = BPF_CORE_READ(tp, copied_seq);
  __u64 cookie = bpf_get_socket_cookie(sk);

#if PRINTK_DEBUG
  bpf_printk("kprobe triggered at tcp_recvmsg, rcv_nxt: %u, "
             "copied_seq: %u, RecvQ: %d\n",
             rcv_nxt, copied_seq, rcv_nxt - copied_seq);
#endif

  struct buffer_message_t *data =
      bpf_ringbuf_reserve(&events, sizeof(struct buffer_message_t), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->rx_buffer = rcv_nxt - copied_seq;
  data->timestamp_ns = bpf_ktime_get_ns();
  data->socket_cookie = bpf_get_socket_cookie(sk);
  data->event_type = APP_RECV_DONE_EVENT;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  bpf_ringbuf_submit(data, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
