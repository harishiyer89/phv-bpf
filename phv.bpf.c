// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// Copyright (c) 2026 UnBuild Labs
//
// Single translation unit for bpf2go: every program lives in its own file and
// is #included here so one object carries them all. Each program is loaded
// individually by loader.go, so a verifier rejection disables one source.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/* One of the six strings the kernel accepts (include/linux/license.h). Without
 * one, bpf_seq_write and the iterator context itself are refused at load
 * (measured on 6.8). Dual: the C is GPL-2.0-only OR BSD-2-Clause, see LICENSE
 * beside it (owner, 2026-09-15). */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "task_iter.bpf.c"
#include "task_file_iter.bpf.c"
#include "events.bpf.c"
