// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// Copyright (c) 2026 UnBuild Labs
// Pass C: low-rate events into a ring buffer, plus per-CPU drop-reason counters.
//
// Attached in v1: oom/mark_victim, block/block_rq_error (5.14+, CapBlockErr),
// skb/kfree_skb (variant by arity: 3 args below 6.11, 4 from 6.11).
// Opt-in (D12): tracepoint/syscalls/sys_exit_{openat,write,pwrite64,writev}.
// Not attached (D13): sched_process_{exec,exit}, tcp_retransmit_skb, tcp_receive_reset.

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* bpf2go's -type event_record needs the struct in the object's BTF; a
 * program that only reaches it through a ring-buffer pointer does not put
 * it there (measured with clang-16; see task_iter.bpf.c). Never referenced. */
const struct event_record *phv_event_record_anchor __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u64);
} drop_reason_count SEC(".maps");

SEC("tp_btf/mark_victim")
int BPF_PROG(phv_oom, int pid)
{
	struct event_record *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;
	e->ts_ns = bpf_ktime_get_ns();
	e->tgid = pid; /* init-ns pid; comm/rss fields from 6.9 via bpf_core_field_exists (TODO M5) */
	e->kind = EV_OOM_KILL;
	e->arg = 0;
	e->a = 0;
	e->b = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* TODO(M5): phv_blkerr (tp_btf/block_rq_error), phv_kfree_skb3 / phv_kfree_skb4,
 * phv_sysexit_* behind collect.syscall_errors. */
