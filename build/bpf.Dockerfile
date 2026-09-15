# Toolchain for `make gen` (06 §7.3): clang >= 15 with the BPF backend, llvm-strip,
# bpftool for vmlinux.h, libbpf's helper headers. Built and run through colima's
# docker; nothing here runs on the macOS host.
FROM golang:1.25-bookworm
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends clang-16 llvm-16 bpftool libbpf-dev make \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/bin/clang-16 /usr/local/bin/clang \
 && ln -s /usr/bin/llvm-strip-16 /usr/local/bin/llvm-strip
