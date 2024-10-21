// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established_handle_kprobe)
{
    bpf_printk("kprobe triggered at tcp_rcv_established\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
