CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
PYTHON ?= python3

BUILD_DIR := build
SRC_DIR := src
ARCH_RAW := $(shell uname -m)
ARCH := $(ARCH_RAW)

ifeq ($(ARCH_RAW),x86_64)
ARCH := x86
endif
ifneq ($(filter $(ARCH_RAW),aarch64 arm64),)
ARCH := arm64
endif

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
	-I$(BUILD_DIR) -I$(SRC_DIR) $(LIBBPF_CFLAGS)
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror -I$(BUILD_DIR) -I$(SRC_DIR) \
	$(LIBBPF_CFLAGS)

.PHONY: all clean doctor test check demo-review-1 demo-review-2 \
	demo-review-3 demo-review-all

all: $(BUILD_DIR)/agent-monitor

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR)
	@test -r /sys/kernel/btf/vmlinux || \
		(echo "error: /sys/kernel/btf/vmlinux is unavailable; enable kernel BTF"; exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/monitor.bpf.o: $(SRC_DIR)/monitor.bpf.c $(SRC_DIR)/monitor.h $(BUILD_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/monitor.skel.h: $(BUILD_DIR)/monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/agent-monitor: $(SRC_DIR)/monitor.c $(SRC_DIR)/monitor.h $(BUILD_DIR)/monitor.skel.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

doctor:
	@command -v $(CLANG) >/dev/null || echo "missing: clang"
	@command -v $(BPFTOOL) >/dev/null || echo "missing: bpftool"
	@command -v $(PKG_CONFIG) >/dev/null || echo "missing: pkg-config"
	@$(PKG_CONFIG) --exists libbpf || echo "missing: libbpf development package"
	@$(PYTHON) -c 'import yaml' >/dev/null 2>&1 || echo "missing: python3-yaml (needed by analyzer)"
	@test -r /sys/kernel/btf/vmlinux || echo "missing: kernel BTF at /sys/kernel/btf/vmlinux"

test:
	mkdir -p $(BUILD_DIR)/pycache
	PYTHONPYCACHEPREFIX=$(BUILD_DIR)/pycache $(PYTHON) -m unittest discover -s tests -v

check:
	$(PYTHON) tools/acceptance_check.py

demo-review-1: all
	$(PYTHON) tools/run_review_demo.py --config config/demos/review-1-functional-causality.yaml

demo-review-2: all
	$(PYTHON) tools/run_review_demo.py --config config/demos/review-2-observability.yaml

demo-review-3: all
	$(PYTHON) tools/run_review_demo.py --config config/demos/review-3-performance.yaml

demo-review-all: all
	$(PYTHON) tools/run_review_demo.py --all

clean:
	rm -rf $(BUILD_DIR)
