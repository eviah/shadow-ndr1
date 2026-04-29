// SPDX-License-Identifier: GPL-2.0
//
// Shadow NDR JIT Chaos Engineering — eBPF Fault Injector
// =========================================================
//
// Attaches kprobe-style fault injection to a configurable set of syscalls.
// For each kprobe target, the userspace controller writes a `chaos_rule`
// into the `rules` map specifying:
//
//   * syscall_id   — which entry in the program's syscall table this rule
//                    targets (we only attach probes for ids that have rules)
//   * pid_filter   — if non-zero, only trip on this PID (0 = all PIDs)
//   * fail_per_1k  — failure rate in tenths of a percent (0..1000)
//   * inject_errno — errno to return (e.g., 4=EINTR, 11=EAGAIN, 110=ETIMEDOUT)
//   * armed_until  — ktime_ns until which this rule is active
//
// Stats are emitted via a ringbuf so the controller can reason about which
// rule fired, on which task, and how often.
//
// Required kernel: BPF_FUNC_override_return (CONFIG_BPF_KPROBE_OVERRIDE=y)
// and tagged "ALLOW_ERROR_INJECTION" syscalls. On modern kernels this is
// the case for {read, write, openat, connect, sendmsg, recvmsg, accept4}.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_RULES 64
#define EVENT_RING_SIZE (1 << 18)

struct chaos_rule {
    __u32 syscall_id;
    __u32 pid_filter;
    __u32 fail_per_1k;
    __s32 inject_errno;
    __u64 armed_until_ns;
};

struct chaos_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 syscall_id;
    __s32 inject_errno;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct chaos_rule);
    __uint(max_entries, MAX_RULES);
} rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENT_RING_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} counters SEC(".maps");

static __always_inline __u64 prng(__u64 x) {
    // xorshift64 — cheap deterministic-from-tsc randomness.
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

static __always_inline int maybe_inject(__u32 syscall_id) {
    struct chaos_rule *rule = bpf_map_lookup_elem(&rules, &syscall_id);
    if (!rule) {
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
    if (rule->armed_until_ns && now > rule->armed_until_ns) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (rule->pid_filter && rule->pid_filter != pid) {
        return 0;
    }

    __u64 r = prng(now ^ pid_tgid);
    __u32 dice = (__u32)(r % 1000);
    if (dice >= rule->fail_per_1k) {
        return 0;
    }

    // Increment "fired" counter slot.
    __u32 slot = 0;
    __u64 *fired = bpf_map_lookup_elem(&counters, &slot);
    if (fired) {
        __sync_fetch_and_add(fired, 1);
    }

    // Emit observability event.
    struct chaos_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->ts_ns = now;
        e->pid = pid;
        e->syscall_id = syscall_id;
        e->inject_errno = rule->inject_errno;
        e->_pad = 0;
        bpf_ringbuf_submit(e, 0);
    }
    return rule->inject_errno;
}

// Override macros — userspace pins these and dynamically attaches them only
// to syscalls the controller has armed via `rules`. Attachment metadata
// (kprobe target) lives in BTF/CORE so the same .o works across kernels.

SEC("kprobe/__x64_sys_read")
int chaos_read(struct pt_regs *ctx) {
    int errno = maybe_inject(0);
    if (errno) {
        bpf_override_return(ctx, (long)errno);
    }
    return 0;
}

SEC("kprobe/__x64_sys_openat")
int chaos_openat(struct pt_regs *ctx) {
    int errno = maybe_inject(257);
    if (errno) {
        bpf_override_return(ctx, (long)errno);
    }
    return 0;
}

SEC("kprobe/__x64_sys_connect")
int chaos_connect(struct pt_regs *ctx) {
    int errno = maybe_inject(42);
    if (errno) {
        bpf_override_return(ctx, (long)errno);
    }
    return 0;
}

SEC("kprobe/__x64_sys_sendmsg")
int chaos_sendmsg(struct pt_regs *ctx) {
    int errno = maybe_inject(46);
    if (errno) {
        bpf_override_return(ctx, (long)errno);
    }
    return 0;
}

SEC("kprobe/__x64_sys_recvmsg")
int chaos_recvmsg(struct pt_regs *ctx) {
    int errno = maybe_inject(47);
    if (errno) {
        bpf_override_return(ctx, (long)errno);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
