// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

struct sock_info {
  __u16 family;
  __u16 sport;
  __u16 dport;
  union {
    struct in_addr saddr;
    struct in6_addr saddr6;
  };
  union {
    struct in_addr daddr;
    struct in6_addr daddr6;
  };
};

struct event {
  __u64 cookie;
  struct sock_info info;
  __u8 event_type;
};

enum {
  EVENT_CONNECT = 1,
  EVENT_ACCEPT = 2,
  EVENT_CLOSE = 3,
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 32 * 1024 * 1024);
} events SEC(".maps");

SEC("sockops")
int socket_ops(struct bpf_sock_ops *skops) {
  struct event *e;
  __u8 event_type = 0;

  switch (skops->op) {
  case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    event_type = EVENT_CONNECT;
    break;
  case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    event_type = EVENT_ACCEPT;
    break;
  case BPF_SOCK_OPS_STATE_CB:
    if (skops->args[1] == BPF_TCP_CLOSE) {
      event_type = EVENT_CLOSE;
    }
    break;
  default:
    return 1;
  }

  if (!event_type)
    return 1;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 1;

  e->info.family = skops->family;

  if (e->info.family == AF_INET) {
    e->info.saddr.s_addr = skops->local_ip4;
    e->info.daddr.s_addr = skops->remote_ip4;
  } else if (e->info.family == AF_INET6) {
    bpf_probe_read_kernel(&e->info.saddr6, sizeof(skops->local_ip6),
                          &skops->local_ip6);
    bpf_probe_read_kernel(&e->info.daddr6, sizeof(skops->remote_ip6),
                          &skops->remote_ip6);
  }

  e->info.sport = bpf_ntohl(skops->local_port);
  e->info.dport = bpf_ntohl(skops->remote_port);

  e->cookie = bpf_get_socket_cookie(skops);
  e->event_type = event_type;

  bpf_ringbuf_submit(e, 0);
  return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";