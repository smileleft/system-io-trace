// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* multi_monitor.bpf.c */

#include "vmlinux.h" // bpftool btf dump-btf-file /sys/kernel/btf/vmlinux format c > vmlinux.h 명령으로 생성
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/sched.h>   // TASK_COMM_LEN을 위해 필요

#define TASK_COMM_LEN 16

// 이벤트를 사용자 공간으로 보내기 위한 perf event array 맵 정의
// CPU당 하나의 버퍼를 관리하며, bpf_perf_event_output 헬퍼를 사용합니다.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// 이벤트 유형 정의
// 사용자 공간에서 어떤 종류의 이벤트인지 구분하는 데 사용됩니다.
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

// 사용자 공간으로 보낼 이벤트 데이터 구조체
// 모든 이벤트 타입에 필요한 필드를 포함하며, union을 사용하여 메모리를 최적화할 수도 있지만,
// 예제에서는 단순함을 위해 모든 필드를 포함합니다.
struct event {
    __u32 pid;          // 프로세스 ID
    char comm[TASK_COMM_LEN]; // 프로세스 이름 (보통 16바이트)
    enum event_type type; // 이벤트 유형

    // CPU 관련 필드
    char filename[256]; // execve, openat 등에 사용

    // 메모리 관련 필드
    __u64 mem_addr;     // mmap, munmap, brk 등에 사용되는 주소
    __u64 mem_len;      // mmap, munmap 등에 사용되는 길이
    __u64 mem_brk_val;  // brk 시스템 호출의 새 break 값

    // 파일 I/O 관련 필드
    int fd;             // 파일 디스크립터 (read, write, close 등에 사용)
    __s64 bytes_rw;     // 읽거나 쓴 바이트 수 (read, write의 retval)
};

// ========================
// CPU 모니터링 (프로세스 실행/생성)
// ========================

// sys_execve 시스템 호출 진입점 Kprobe (프로세스 실행)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep execve` 로 확인하세요.
SEC("kprobe/__x64_sys_execve")
//int BPF_KPROBE(sys_execve_entry, const char *filename, const char *const argv[], const char *const envp[])
int sys_execve_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    const char *filename;

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_CPU_EXEC;

    filename = (const char *)PT_REGS_PARM1(ctx);

    bpf_probe_read_user_str(&event_data.filename, sizeof(event_data.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_fork 시스템 호출 반환점 Kretprobe (프로세스 생성)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep fork` 로 확인하세요.
SEC("kretprobe/__x64_sys_fork")
//int BPF_KRETPROBE(sys_fork_exit, long retval)
int sys_fork_exit(struct pt_regs *ctx)
{
    // retval은 새로 생성된 자식 프로세스의 PID입니다.
    long retval = PT_REGS_RC(ctx);
    if (retval < 0) return 0; // fork 실패 시 무시

    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_CPU_FORK;
    event_data.pid = retval; // 새로 생성된 자식 PID

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// ========================
// 메모리 모니터링
// ========================

// sys_mmap 시스템 호출 진입점 Kprobe (메모리 매핑)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep mmap` 로 확인하세요.
SEC("kprobe/__x64_sys_mmap")
//int BPF_KPROBE(sys_mmap_entry, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long offset)
int sys_mmap_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    unsigned long addr = PT_REGS_PARM1(ctx);
    unsigned long len = PT_REGS_PARM2(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_MEM_MMAP;
    event_data.mem_addr = addr;
    event_data.mem_len = len;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_munmap 시스템 호출 진입점 Kprobe (메모리 매핑 해제)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep munmap` 로 확인하세요.
SEC("kprobe/__x64_sys_munmap")
//int BPF_KPROBE(sys_munmap_entry, unsigned long addr, unsigned long len)
int sys_munmap_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    unsigned long addr = PT_REGS_PARM1(ctx);
    unsigned long len = PT_REGS_PARM2(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_MEM_MUNMAP;
    event_data.mem_addr = addr;
    event_data.mem_len = len;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_brk 시스템 호출 진입점 Kprobe (프로그램 break 조정)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep brk` 로 확인하세요.
SEC("kprobe/__x64_sys_brk")
//int BPF_KPROBE(sys_brk_entry, unsigned long brk)
int sys_brk_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    unsigned long brk = PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_MEM_BRK;
    event_data.mem_brk_val = brk; // 새로운 break 주소

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}


// ========================
// 파일 I/O 모니터링
// ========================

// sys_openat 시스템 호출 진입점 Kprobe (파일 열기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep openat` 로 확인하세요.
SEC("kprobe/__x64_sys_openat")
//int BPF_KPROBE(sys_openat_entry, int dfd, const char __user *filename, int flags, umode_t mode)
int sys_openat_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    // sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
    // x86_64 시스템 호출 인자: RDI, RSI, RDX, RCX, R8, R9
    // dfd: RDI (PT_REGS_PARM1)
    // filename: RSI (PT_REGS_PARM2)
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_OPEN;
    bpf_probe_read_user_str(&event_data.filename, sizeof(event_data.filename), filename);
    // fd는 kretprobe에서 얻을 수 있습니다.

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_read 시스템 호출 반환점 Kretprobe (파일 읽기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep read` 로 확인하세요.
SEC("kretprobe/__x64_sys_read")
//int BPF_KRETPROBE(sys_read_exit, int fd, char __user *buf, size_t count, long retval)
int sys_read_exit(struct pt_regs *ctx)
{

    long retval = PT_REGS_RC(ctx);
    if (retval <= 0) return 0;

    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_READ;
    event_data.fd = fd;
    event_data.bytes_rw = retval;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_write 시스템 호출 반환점 Kretprobe (파일 쓰기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep write` 로 확인하세요.
SEC("kretprobe/__x64_sys_write")
//int BPF_KRETPROBE(sys_write_exit, int fd, const char __user *buf, size_t count, long retval)
int sys_write_exit(struct pt_regs *ctx)
{
    long retval = PT_REGS_RC(ctx);
    if (retval <= 0) return 0; // 쓰기 실패 또는 0바이트 쓴 경우 무시

    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_WRITE;
    event_data.fd = fd;
    event_data.bytes_rw = retval;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_close 시스템 호출 진입점 Kprobe (파일 닫기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep close` 로 확인하세요.
SEC("kprobe/__x64_sys_close")
//int BPF_KPROBE(sys_close_entry, int fd)
int sys_close_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_CLOSE;
    event_data.fd = fd;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; // BPF 프로그램 라이선스

