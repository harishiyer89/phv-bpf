# The programs are consumed by bpf2go from the commotion-agent repository;
# this file only proves they compile. clang runs in the toolchain image so no
# host needs a BPF-capable clang (bookworm, clang-16, bpftool, libbpf-dev).
IMAGE = phv-bpf-build

.PHONY: check image vmlinux

check: ## compile the single translation unit for the BPF target
	docker run --rm -v $(CURDIR):/src -w /src $(IMAGE) clang -target bpf -O2 -g -Wall -Werror -I include -c phv.bpf.c -o /dev/null

image: ## build the toolchain image
	docker build -t $(IMAGE) -f build/bpf.Dockerfile build/

vmlinux: ## regenerate include/vmlinux.h from the running (Linux or VM) kernel's BTF
	docker run --rm -v $(CURDIR):/src -v /sys/kernel/btf:/sys/kernel/btf:ro $(IMAGE) sh -c 'bpftool btf dump file /sys/kernel/btf/vmlinux format c > /src/include/vmlinux.h'
