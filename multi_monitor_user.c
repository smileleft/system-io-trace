// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* multi_monitor_user.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h> // libbpf 라이브러리 헤더
#include <linux/types.h> // __u32, __u64 등을 위해 필요

// bpftool gen skeleton 명령으로 생성될 스켈레톤 헤더 파일
// BPF 프로그램 (multi_monitor.bpf.c)과 사용자 공간 프로그램 간의 인터페이스를 제공합니다.
#include "multi_monitor.bpf.skel.h"

// 이벤트 유형 정의 (BPF 코드의 enum event_type과 동일해야 함)
enum event_type {
    EVENT_CPU_EXEC = 1,
    EVENT_CPU_FORK,
    EVENT_MEM_MMAP,
    EVENT_MEM_MUNMAP,
    EVENT_MEM_BRK,
    EVENT_FILE_OPEN,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CLOSE,
};

// 이벤트 데이터 구조체 (BPF 코드의 'struct event'와 동일해야 함)
struct event {
    __u32 pid;
    char comm[16]; // TASK_COMM_LEN은 보통 16
    enum event_type type;

    char filename[256];

    __u64 mem_addr;
    __u64 mem_len;
    __u64 mem_brk_val;

    int fd;
    __s64 bytes_rw;
};

static struct multi_monitor_bpf *skel; // BPF 스켈레톤 구조체 포인터
static volatile bool exiting = false;  // 프로그램 종료 플래그
static __u32 my_pid;

// Perf buffer에서 이벤트를 수신할 때 호출되는 콜백 함수
static void handle_event(void *ctx, int cpu, void *data, __u32 data_len)
{
    // 수신된 데이터를 'struct event' 타입으로 캐스팅
    const struct event *e = (const struct event *)data;

    // 데이터 길이 유효성 검사 (안전성 강화)
    if (data_len < sizeof(*e)) {
        fprintf(stderr, "Received truncated event data (expected %zu, got %u)\n",
                sizeof(*e), data_len);
        return;
    }

    //if (e->pid != my_pid) return;
    if (strncmp(e->comm, "vim", sizeof(e->comm)) != 0) return;

    // 이벤트 유형에 따라 출력 포맷 변경
    switch (e->type) {
        case EVENT_CPU_EXEC:
            //printf("[CPU_EXEC] PID: %-6d | COMM: %-16s | FILENAME: %s\n", e->pid, e->comm, e->filename);
            break;
        case EVENT_CPU_FORK:
            //printf("[CPU_FORK] PID: %-6d | COMM: %-16s | CHILD_PID: %u\n", e->pid, e->comm, e->pid);
            break;
        case EVENT_MEM_MMAP:
            //printf("[MEM_MMAP] PID: %-6d | COMM: %-16s | ADDR: 0x%-16llx | LEN: %lld\n", e->pid, e->comm, e->mem_addr, e->mem_len);
            break;
        case EVENT_MEM_MUNMAP:
            //printf("[MEM_UNMAP]PID: %-6d | COMM: %-16s | ADDR: 0x%-16llx | LEN: %lld\n", e->pid, e->comm, e->mem_addr, e->mem_len);
            break;
        case EVENT_MEM_BRK:
            //printf("[MEM_BRK]  PID: %-6d | COMM: %-16s | NEW_BRK: 0x%-16llx\n", e->pid, e->comm, e->mem_brk_val);
            break;
        case EVENT_FILE_OPEN:
            //printf("[FILE_OPEN]PID: %-6d | COMM: %-16s | FILENAME: %s\n", e->pid, e->comm, e->filename);
            break;
        case EVENT_FILE_READ:
            printf("[FILE_READ]PID: %-6d | COMM: %-16s | FD: %-4d | BYTES: %lld\n", e->pid, e->comm, e->fd, e->bytes_rw);
            break;
        case EVENT_FILE_WRITE:
            //printf("[FILE_WRITE]PID: %-6d | COMM: %-16s | FD: %-4d | BYTES: %lld\n", e->pid, e->comm, e->fd, e->bytes_rw);
            break;
        case EVENT_FILE_CLOSE:
            //printf("[FILE_CLOSE]PID: %-6d | COMM: %-16s | FD: %-4d\n", e->pid, e->comm, e->fd);
            break;
        default:
            printf("[UNKNOWN]  PID: %-6d | COMM: %-16s | TYPE: %d\n", e->pid, e->comm, e->type);
            break;
    }
}

// 시그널 핸들러 (Ctrl+C 또는 kill 시그널 처리)
static void sig_handler(int sig)
{
    printf("\nExiting...\n");
    exiting = true; // 종료 플래그 설정
}

int main(int argc, char **argv)
{
    int err;
    struct perf_buffer *pb = NULL; // Perf buffer 구조체 포인터

    my_pid = getpid();

    // SIGINT (Ctrl+C)와 SIGTERM 시그널에 대한 핸들러 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. BPF 스켈레톤 열기:
    skel = multi_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 2. BPF program load:
    err = multi_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s (errno: %d)\n", strerror(errno), errno);
        multi_monitor_bpf__destroy(skel);
        return 1;
    }

    // 3. BPF progarm attach:
    err = multi_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s (errno: %d)\n", strerror(errno), errno);
        multi_monitor_bpf__destroy(skel);
        return 1;
    }

    // 4. Perf buffer init:
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        multi_monitor_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully started! Tracing CPU, Memory, File I/O system calls. Press Ctrl+C to stop.\n");

    // 5. 이벤트 폴링 루프:
    while (!exiting) {
        err = perf_buffer__poll(pb, 100); // 100ms 타임아웃
        if (err == -EINTR) {
            err = 0; // 시그널 수신 시 루프 종료
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(errno));
            break;
        }
    }

    // 6. 자원 해제:
    perf_buffer__free(pb);
    multi_monitor_bpf__destroy(skel);
    return 0;
}

