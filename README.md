# phv-bpf

The eBPF programs of the Process Health Vector agent: per-thread task
records from a `bpf_iter/task` walk, a per-process TCP socket aggregate from
`bpf_iter/task_file`, and kernel events (OOM kill, block request errors)
through a ring buffer. They transcribe kernel fields; every judgement about
what the fields mean is made in user space, in the agent that loads them.

## Licence

`GPL-2.0-only OR BSD-2-Clause`, at your option, for every `.c` and `.h` file
at the root; see `LICENSE`. The programs declare `Dual BSD/GPL` to the kernel,
which is one of the six strings the kernel accepts before a BPF program may
call GPL-only helpers or read the iterator context: under any other string the
load is refused (measured on Linux 6.8). `include/bpf/` is libbpf's helper
headers under their own licence; `include/vmlinux.h` is a dump of a kernel's
BTF type information.

## Layout

| File | What |
|---|---|
| `common.h` | The three records shared with user space: `task_record` (336 B, one per thread), `sock_agg` (128 B, one per process), `event_record` (32 B). These are the source of truth; the consumer mirrors them and tests every offset. |
| `phv.bpf.c` | The single translation unit: includes, the licence string, and the three program files. |
| `task_iter.bpf.c` | `phv_task` (`iter/task`): one `task_record` per thread through `bpf_seq_write`; `phv_hz`: the HZ probe. |
| `task_file_iter.bpf.c` | `phv_task_file` (`iter/task_file`): the socket aggregate map. Stub until the consumer's M5. |
| `events.bpf.c` | `phv_oom` (`tp_btf/mark_victim`) and the drop-reason counters. Stub until M5. |
| `include/vmlinux.h` | Kernel types dumped with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`, from a 6.8 arm64 kernel. |
| `include/bpf/` | libbpf's `bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_core_read.h`, `bpf_tracing.h`, with their LICENSE. |
| `build/bpf.Dockerfile` | The toolchain image: Debian bookworm, clang-16, llvm-16, bpftool, libbpf-dev. |

## How the one object runs on every kernel

The object is compiled once for the BPF instruction set and loaded unchanged
on every supported kernel (CO-RE). `vmlinux.h` only supplies names and types
at compile time: every struct in it carries `preserve_access_index`, so each
field access becomes a relocation record that the loader resolves against the
running kernel's BTF before the verifier sees the program. A field a kernel
may lack is guarded with `bpf_core_field_exists`; a field the header lacks is
described by a flavour struct (`task_struct___old`, `task_struct___nocpu`).
Fields are read through direct loads from the iterator's trusted task pointer
rather than `BPF_CORE_READ`, which halved the walk time at 20,000 threads.

## Building

`make image` once, then `make check` compiles the translation unit with the
same flags the consumer's bpf2go run uses (`-O2 -g -Wall -Werror`). The
consumer (`commotion-agent`) runs bpf2go against `phv.bpf.c` with `-I include`
and commits the generated object and Go bindings on its side; nothing
generated is committed here.

## What goes here and what does not

These programs read kernel fields and may sum them per process. They carry no
threshold, baseline, predicate, cross-resource edge, root-cause rule or tier
logic; that belongs to the consumer, under the consumer's licence. A change
that moves any of it here is out of scope by design.

## Verified so far

Loads and runs on Linux 6.8 (arm64): all four programs load, the task walk
emits the caller's own record, the HZ probe reports 1000. The 5.15 / 6.1 /
6.6 / 6.12 matrix is the consumer's CI and has not run yet.
