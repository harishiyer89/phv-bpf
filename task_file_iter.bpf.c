// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// Copyright (c) 2026 UnBuild Labs
// Pass B: per-TGID TCP socket aggregate, computed IN THE KERNEL (D2, §7.3).
//
//   - bpf_sock_from_file(file) (5.11+) selects sockets; AF_INET/AF_INET6 + IPPROTO_TCP only
//   - skip a task when task->files == group_leader->files && pid != tgid (dedupes threads on any kernel)
//   - chronos in jiffies including the in-progress chrono (tcp_get_info semantics)
//   - icsk_ca_state via BPF_CORE_READ_BITFIELD_PROBED

/* Named sock_agg in 06 §7.3; bpf2go's -type sock_agg then finds both the
 * struct and this variable and refuses ("found multiple types"), so the map
 * carries the _by_tgid suffix (amendment recorded on #1). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192); /* collect.max_procs; resized at load */
	__type(key, __u32);
	__type(value, struct sock_agg);
} sock_agg_by_tgid SEC(".maps");

SEC("iter/task_file")
int phv_task_file(struct bpf_iter__task_file *ctx)
{
	struct task_struct *t = ctx->task;
	struct file *f = ctx->file;

	if (!t || !f)
		return 0;
	/* TODO(M5): dedupe threads; sk = bpf_sock_from_file(f); aggregate into sock_agg[tgid]. */
	return 0;
}
