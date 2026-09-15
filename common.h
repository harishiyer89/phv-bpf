/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 * Copyright (c) 2026 UnBuild Labs
 *
 * The three structs shared between the BPF programs and Go. THESE ARE THE
 * SOURCE OF TRUTH: Go mirrors them and a test compares every offset
 * (06 §7.2, D11). Rules: u64 first, then u32, then u16/u8, then arrays;
 * explicit padding; no pointers.
 */
#ifndef PHV_COMMON_H
#define PHV_COMMON_H

#define TASK_COMM_LEN 16

/* RecFlags bits (D11). REC_HAS_IO is set when the seven io accounting fields
 * were read (CONFIG_TASK_XACCT and CONFIG_TASK_IO_ACCOUNTING both present); the
 * /proc fallback sets the same Go-side bit when /proc/[pid]/io was read. */
#define REC_HAS_DELAYS    (1u << 0)
#define REC_IS_LEADER     (1u << 1)
#define REC_STATE_IS_NEW  (1u << 2)
#define REC_HAS_IRQ_DELAY (1u << 3)
#define REC_HAS_WPCOPY    (1u << 4)
#define REC_HAS_IO        (1u << 5)

/* 336 bytes (D11: 04's "288" was a slip). One per THREAD per Pass A (04 §1.3). */
struct task_record {
	__u64 cgroup_id;        /* task->cgroups->dfl_cgrp->kn->id */
	__u64 start_boottime;

	__u64 utime, stime, gtime, sum_exec_runtime;
	__u64 run_delay;        /* sched_info.run_delay */
	__u64 run_periods;      /* sched_info.pcount */
	__u64 last_queued;
	__u64 nvcsw, nivcsw;

	__u64 min_flt, maj_flt;
	__u64 total_vm, hiwater_rss, data_vm, stack_vm;

	__u64 rchar, wchar, syscr, syscw;
	__u64 read_bytes, write_bytes, cancelled_write_bytes;

	__u64 blkio_delay, swapin_delay, freepages_delay;
	__u64 thrashing_delay, compact_delay;
	__u64 wpcopy_delay, irq_delay;

	__u32 blkio_count, swapin_count, freepages_count, thrashing_count;

	__s32 nr_dirtied, nr_dirtied_pause;

	__u32 tgid, pid;
	__s32 num_threads;
	__u32 policy;
	__s32 prio, nice;
	__s32 nr_cpus_allowed;
	__u32 state;
	__s32 last_cpu;
	__u32 flags;

	__s16 oom_score_adj;
	__u16 rec_flags;

	char comm[TASK_COMM_LEN];
};

/* 128 bytes. Per-TGID aggregate written by task_file_iter (§7.2). */
struct sock_agg {
	__u64 bytes_sent, bytes_received, total_retrans;
	__u64 chrono_busy, chrono_rwnd_lim, chrono_sndbuf_lim;   /* jiffies */
	__u64 notsent_bytes;
	__u64 wmem_queued, sndbuf;
	__u64 drops;
	__u32 n_sockets, n_listen, n_err;
	__u32 backlog_ratio_max;   /* x65536 */
	__u32 rcvbuf_ratio_max;    /* x65536 */
	__u32 ca_state_max;
	__u32 _pad[6];
};

/* 32 bytes. Pass C ring-buffer record. */
#define EV_OOM_KILL       1
#define EV_BLOCK_RQ_ERROR 2

struct event_record {
	__u64 ts_ns;
	__u64 a, b;
	__u32 tgid;
	__u16 kind;
	__u16 arg;
};

#endif /* PHV_COMMON_H */
