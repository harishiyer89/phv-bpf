// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// Copyright (c) 2026 UnBuild Labs
// Pass A: one task_record per THREAD through the iterator seq_file (D1).
//
// Rules (04 §1, §10.3):
//   - cgroup id from task->cgroups->dfl_cgrp->kn->id, never bpf_get_current_cgroup_id() (04 §1.4)
//   - versioned fields via bpf_core_field_exists: __state (5.14), irq_delay (6.4), wpcopy_delay (5.19)
//   - task->delays == NULL => REC_HAS_DELAYS clear, delay fields left 0 (I3)
//   - io fields behind CONFIG_TASK_XACCT / CONFIG_TASK_IO_ACCOUNTING => REC_HAS_IO says they were read
//   - every function <= 25 lines: fill_identity / fill_cpu / fill_mm / fill_io / fill_delays

/* task->state before 5.14; the ___old suffix is CO-RE's flavour naming, and
 * bpf_core_field_exists on it is false on a kernel that renamed it. */
struct task_struct___old {
	long state;
} __attribute__((preserve_access_index));

/* task->cpu on a kernel without CONFIG_THREAD_INFO_IN_TASK, where task_cpu()
 * does not read thread_info.cpu; every CO-RE field read is guarded so one
 * absent member cannot make the verifier refuse all of Pass A. */
struct task_struct___nocpu {
	unsigned int cpu;
} __attribute__((preserve_access_index));

/* Self-counter slots: 0 seq_write failures, 1 records emitted, 2 tasks skipped. */
#define CTR_SEQ_WRITE_FAIL 0
#define CTR_EMITTED        1
#define CTR_SKIPPED        2

/* task_nice(): PRIO_TO_NICE(static_prio) = static_prio - (MAX_RT_PRIO + NICE_WIDTH / 2)
 * = static_prio - 120, and task_prio(): prio - MAX_RT_PRIO = prio - 100, which is
 * what /proc/[pid]/stat f18 prints (fs/proc/array.c; 04 §1 gives the range
 * -100..39). Both are measured against /proc/self/stat by the kernel test. */
#define DEFAULT_PRIO_BASE 120
#define MAX_RT_PRIO_BASE  100

/* bpf2go's -type task_record needs the struct in the object's BTF, and a
 * stack local does not put it there (measured: clang-16 emitted only the
 * map value type sock_agg). The anchor is never referenced. */
const struct task_record *phv_task_record_anchor __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} self_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64[2]);
} hz_probe SEC(".maps"); /* {bpf_jiffies64(), bpf_ktime_get_ns()} */

static __always_inline void count(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&self_counters, &slot);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Field access is direct. ctx->task is a BTF-typed pointer the verifier
 * trusts, so `t->field` compiles to one fault-safe load (a NULL pointer on
 * the way, mm or delays, reads as 0 through the exception table) instead of
 * a bpf_probe_read_kernel call per field; measured on the 6.8 VM at 20,000
 * threads the BPF_CORE_READ form cost 15 ms per walk. bpf_core_field_exists
 * still gates every member that a supported kernel may lack. */

/* task_cpu(t) (04 §1 cpu.last_cpu, /proc f39): thread_info.cpu with
 * CONFIG_THREAD_INFO_IN_TASK, task_struct.cpu without, 0 when neither
 * member exists. A gauge that is stale the moment it is read. */
static __always_inline __s32 last_cpu(struct task_struct *t)
{
	if (bpf_core_field_exists(t->thread_info.cpu))
		return t->thread_info.cpu;

	if (bpf_core_field_exists(((struct task_struct___nocpu *)t)->cpu))
		return ((struct task_struct___nocpu *)t)->cpu;

	return 0;
}

static __always_inline void fill_identity(struct task_record *rec, struct task_struct *t)
{
	struct signal_struct *sig = t->signal;

	rec->cgroup_id = t->cgroups->dfl_cgrp->kn->id;
	rec->start_boottime = t->start_boottime;
	rec->tgid = t->tgid;
	rec->pid = t->pid;
	rec->num_threads = sig->nr_threads;
	rec->oom_score_adj = sig->oom_score_adj;
	rec->policy = t->policy;
	rec->prio = t->prio - MAX_RT_PRIO_BASE;
	rec->nice = t->static_prio - DEFAULT_PRIO_BASE;
	rec->nr_cpus_allowed = t->nr_cpus_allowed;
	rec->flags = t->flags;
	rec->last_cpu = last_cpu(t);
	__builtin_memcpy(rec->comm, t->comm, TASK_COMM_LEN);

	if (rec->pid == rec->tgid)
		rec->rec_flags |= REC_IS_LEADER;

	if (bpf_core_field_exists(t->__state)) {
		rec->state = t->__state;
		rec->rec_flags |= REC_STATE_IS_NEW;
	} else {
		rec->state = ((struct task_struct___old *)t)->state;
	}
}

static __always_inline void fill_cpu(struct task_record *rec, struct task_struct *t)
{
	rec->utime = t->utime;
	rec->stime = t->stime;
	rec->gtime = t->gtime;
	rec->sum_exec_runtime = t->se.sum_exec_runtime;
	rec->run_delay = t->sched_info.run_delay; /* live without the sysctl on >= 5.14 (04 §1.1) */
	rec->run_periods = t->sched_info.pcount;
	rec->last_queued = t->sched_info.last_queued;
	rec->nvcsw = t->nvcsw;
	rec->nivcsw = t->nivcsw;
}

/* The mm fields stay 0 when task->mm is NULL (a kernel thread, a zombie
 * leader), and iter.Aggregate takes total_vm == 0 as "no mm" (§7.4). */
static __always_inline void fill_mm(struct task_record *rec, struct task_struct *t)
{
	struct mm_struct *mm = t->mm;

	rec->min_flt = t->min_flt;
	rec->maj_flt = t->maj_flt;
	rec->nr_dirtied = t->nr_dirtied;
	rec->nr_dirtied_pause = t->nr_dirtied_pause;

	if (!mm)
		return;

	rec->total_vm = mm->total_vm;
	rec->hiwater_rss = mm->hiwater_rss;
	rec->data_vm = mm->data_vm;
	rec->stack_vm = mm->stack_vm;
}

/* rchar..syscw are CONFIG_TASK_XACCT, read/write/cancelled bytes are
 * CONFIG_TASK_IO_ACCOUNTING (04 §5); REC_HAS_IO is set only when all seven
 * were read, so a partial layout reads as unavailable, not zero (I3). The
 * fallback's parseIO requires the same seven lines of /proc/[pid]/io, so a
 * kernel with one option and not the other gets no flag on either path. */
static __always_inline void fill_io(struct task_record *rec, struct task_struct *t)
{
	if (!bpf_core_field_exists(t->ioac.rchar) || !bpf_core_field_exists(t->ioac.read_bytes))
		return;

	rec->rchar = t->ioac.rchar;
	rec->wchar = t->ioac.wchar;
	rec->syscr = t->ioac.syscr;
	rec->syscw = t->ioac.syscw;
	rec->read_bytes = t->ioac.read_bytes;
	rec->write_bytes = t->ioac.write_bytes;
	rec->cancelled_write_bytes = t->ioac.cancelled_write_bytes;
	rec->rec_flags |= REC_HAS_IO;
}

static __always_inline void fill_delays(struct task_record *rec, struct task_struct *t)
{
	struct task_delay_info *d = t->delays;

	if (!d)
		return; /* delayacct off for this task: fields stay 0 and unflagged (04 §1.2, I3) */

	rec->rec_flags |= REC_HAS_DELAYS;
	rec->blkio_delay = d->blkio_delay;
	rec->swapin_delay = d->swapin_delay;
	rec->freepages_delay = d->freepages_delay;
	rec->thrashing_delay = d->thrashing_delay;
	rec->blkio_count = d->blkio_count;
	rec->swapin_count = d->swapin_count;
	rec->freepages_count = d->freepages_count;
	rec->thrashing_count = d->thrashing_count;

	if (bpf_core_field_exists(d->compact_delay))
		rec->compact_delay = d->compact_delay;

	if (bpf_core_field_exists(d->wpcopy_delay)) {
		rec->wpcopy_delay = d->wpcopy_delay;
		rec->rec_flags |= REC_HAS_WPCOPY;
	}

	if (bpf_core_field_exists(d->irq_delay)) {
		rec->irq_delay = d->irq_delay;
		rec->rec_flags |= REC_HAS_IRQ_DELAY;
	}
}

SEC("iter/task")
int phv_task(struct bpf_iter__task *ctx)
{
	struct task_struct *t = ctx->task;
	struct task_record rec = {};

	if (!t)
		return 0;

	fill_identity(&rec, t);
	fill_cpu(&rec, t);
	fill_mm(&rec, t);
	fill_io(&rec, t);
	fill_delays(&rec, t);

	if (bpf_seq_write(ctx->meta->seq, &rec, sizeof(rec))) {
		count(CTR_SEQ_WRITE_FAIL);
		return 0;
	}

	count(CTR_EMITTED);
	return 0;
}

/* Writes once per run: user space zeroes the slot before each shot, and a
 * non-zero return from an iterator program makes the read fail with EAGAIN
 * (measured on 6.8), so the program returns 0 and lets the walk finish. */
SEC("iter/task")
int phv_hz(struct bpf_iter__task *ctx)
{
	__u32 key = 0;
	__u64 *slot = bpf_map_lookup_elem(&hz_probe, &key);

	if (!ctx->task || !slot || slot[1])
		return 0;

	slot[0] = bpf_jiffies64();
	slot[1] = bpf_ktime_get_ns();
	return 0;
}
