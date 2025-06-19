# Makefile for eBPF Multi-System Call Monitor
CLANG_BUILTIN_INCLUDE := /usr/lib/llvm-18/lib/clang/18/include

# CLANG/LLVM 경로 설정 (시스템에 따라 다를 수 있음)
CLANG ?= /usr/bin/clang
LLVM_STRIP ?= /usr/bin/llc
BPFTOOL ?= /usr/sbin/bpftool

LIBBPF_SYSTEM_INCLUDE ?= /usr/include/bpf

# Get target architecture for BPF programs
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture $(ARCH) for BPF compilation. Please add __TARGET_ARCH_xxx manually to BPF_CFLAGS.)
endif

# BPF 소스 및 출력 파일 경로
BPF_SRC = multi_monitor.bpf.c
BPF_OBJ = $(BPF_SRC:.c=.o)
BPF_SKEL_H = $(BPF_SRC:.c=.skel.h)

# 사용자 공간 소스 및 출력 파일 경로
USER_SRC = multi_monitor_user.c
USER_BIN = multi_monitor_user

# libbpf 설치 경로 (시스템에 따라 다름)
# libbpf는 /usr/lib/x86_64-linux-gnu/libbpf.a 나 /usr/local/lib/libbpf.a 등에 위치할 수 있습니다.
# 헤더 파일은 /usr/include/bpf 에 있습니다.
LIBBPF_DIR ?= /usr/lib/x86_64-linux-gnu/include # Ubuntu/Debian 기준
# LIBBPF_DIR ?= /usr/local # 직접 설치한 경우

KERNEL_HEADERS_DIR ?= /usr/src/linux-headers-$(shell uname -r)

# 컴파일러 플래그
BPF_CFLAGS := -g -O2 -target bpf -Wall $(ARCH_HDR_DEFINE) \
	      -I$(CLANG_BUILTIN_INCLUDE) \
	      -I$(LIBBPF_SYSTEM_INCLUDE) \
	      -I$(KERNEL_HEADERS_DIR)/arch/x86/include \
              -I$(KERNEL_HEADERS_DIR)/include

# libbpf 라이브러리와 헤더 경로 포함
USER_CFLAGS := -g -Wall -I. -I$(LIBBPF_SYSTEM_INCLUDE) -L$(LIBBPF_DIR)
USER_LDFLAGS := -lbpf -lelf

# 모든 타겟
.PHONY: all clean

all: $(USER_BIN)

# BPF 프로그램 컴파일 및 스켈레톤 헤더 생성
$(BPF_SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 사용자 공간 프로그램 컴파일
$(USER_BIN): $(USER_SRC) $(BPF_SKEL_H)
	$(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

# 클린 (모든 생성 파일 삭제)
clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL_H) $(USER_BIN)

