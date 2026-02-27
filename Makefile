# Makefile for eBPF execve tracer

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
              -I/usr/include/$(shell uname -m)-linux-gnu/asm \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I/usr/include/asm-generic

# Detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
    TARGET_ARCH := arm64
else
    TARGET_ARCH := x86
endif

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH)

# Output files
BPF_OBJ := ebpf/execve.bpf.o
USER_GEN := ebpf/execve.go

# Default target
all: $(BPF_OBJ) $(USER_GEN)

# Compile eBPF program
$(BPF_OBJ): ebpf/execve.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Generate Go bindings (using bpf2go or cilium/ebpf's go generate)
$(USER_GEN): $(BPF_OBJ)
	go generate ./ebpf/

# Generate using go:generate
generate: $(BPF_OBJ)
	go generate ./...

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ) $(USER_GEN)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Run the program
run: all
	go run cmd/main.go

# Build the binary
build: all
	go build -o bin/pluggable-ebpf ./cmd

.PHONY: all clean generate run build install-deps
