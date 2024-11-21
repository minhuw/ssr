#ifndef __SSR_COMMON_H
#define __SSR_COMMON_H

#define TASK_COMM_LEN 16

#include "vmlinux.h"

struct flow {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 socket_cookie;
};

static inline int filter_conn(struct sock *sk, __u16 tgt_src_port, __u16 tgt_dst_port) {
  __u16 src_port = sk->__sk_common.skc_num;
  __u16 dst_port = sk->__sk_common.skc_dport;

  if (((src_port == tgt_src_port) || (tgt_src_port == 0)) &&
      ((dst_port == tgt_dst_port) || (tgt_dst_port == 0))) {
    return 1;
  }
  return 0;
}

#define PRINTK_DEBUG 0

#endif /* __SSR_COMMON_H */
