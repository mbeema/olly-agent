// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Author: Madhukar Beema, Distinguished Engineer

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// olly.bpf.c — eBPF programs for syscall and SSL hooking.
// Attached via kprobes/kretprobes to observe all network I/O.
// Events are emitted to a BPF ring buffer for zero-copy userspace consumption.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_CAPTURE 256

// Event types — must match Go constants in ringbuf.go.
#define EVENT_CONNECT   1
#define EVENT_DATA_OUT  2
#define EVENT_DATA_IN   3
#define EVENT_CLOSE     4
#define EVENT_SSL_OUT   5
#define EVENT_SSL_IN    6
#define EVENT_ACCEPT    7
#define EVENT_LOG_WRITE 8

// Connection direction.
#define DIR_OUTBOUND 0
#define DIR_INBOUND  1

// Address families (may not be in vmlinux.h constants).
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// ──────────────────────────────────────────────────────────────────────
// Ring buffer event structure
// ──────────────────────────────────────────────────────────────────────

struct olly_event {
    __u8  event_type;
    __u8  has_trace_ctx;  // 1 if trace_id/span_id are populated
    __u8  _pad[2];
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 payload_len;    // actual captured bytes (up to MAX_CAPTURE)
    __u32 original_len;   // original syscall buffer length
    __u64 timestamp_ns;
    // For CONNECT/ACCEPT events: remote address info
    __u32 remote_addr;    // IPv4 address in network byte order
    __u16 remote_port;    // port in host byte order
    __u8  direction;      // DIR_OUTBOUND or DIR_INBOUND
    __u8  _pad2;
    __u8  trace_id[32];   // hex-encoded trace ID from BPF-generated context
    __u8  span_id[16];    // hex-encoded span ID from BPF-generated context
    __u8  payload[MAX_CAPTURE]; // variable-length in ring buffer
};

// ──────────────────────────────────────────────────────────────────────
// BPF maps
// ──────────────────────────────────────────────────────────────────────

// Connection tracking: {pid, fd} → {addr, port, direction}
struct conn_key {
    __u32 pid;
    __s32 fd;
};

struct conn_val {
    __u32 addr;
    __u16 port;
    __u8  dir;
    __u8  _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} conn_map SEC(".maps");

// PID filter: only observe listed processes. Empty map = observe all.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

// Log FD classification: {pid, fd} → 1 if this fd writes to a log file.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct conn_key);
    __type(value, __u8);
} log_fd_map SEC(".maps");

// SSL context → fd mapping for uprobe-based SSL capture.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // SSL* pointer
    __type(value, __s32); // fd
} ssl_fd_map SEC(".maps");

// Tracing enabled flag. Key=0, value=1 means active. Used for on-demand toggle.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tracing_enabled SEC(".maps");

// Ring buffer for events → userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MB
} events SEC(".maps");

// ──────────────────────────────────────────────────────────────────────
// Traceparent injection maps (sockops + sk_msg)
// ──────────────────────────────────────────────────────────────────────

// Thread trace context: PID+TID → pre-formatted traceparent header.
// Populated by userspace when an inbound HTTP request generates a trace.
// Read by sk_msg to inject into outbound HTTP requests on the same thread.
#define TRACEPARENT_HEADER_LEN 70 // "traceparent: 00-{32hex}-{16hex}-01\r\n" = exactly 70 chars

struct thread_key {
    __u32 pid;
    __u32 tid;
};

struct trace_ctx {
    __u8  valid;
    __u8  _pad[3];
    __u32 header_len;                         // actual header length (without \0)
    char  header[TRACEPARENT_HEADER_LEN + 1]; // "traceparent: 00-xxxx-yyyy-01\r\n"
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct thread_key);
    __type(value, struct trace_ctx);
} thread_trace_ctx SEC(".maps");

// PID-level trace context for cross-thread forwarding.
// When Go goroutines migrate between OS threads, the TID at read time differs
// from the TID at write time. This map stores the most recent inbound trace
// context per PID, allowing kprobe_write to forward it to the writing thread's
// thread_trace_ctx so sk_msg can find it.
//
// Concurrency guard: if two distinct inbound FDs generate trace context within
// 2 seconds, the concurrent flag is set and kprobe_write skips forwarding to
// prevent injecting the wrong traceparent into an unrelated request.
struct pid_ctx {
    struct trace_ctx ctx;       // pre-formatted traceparent header
    __u64 timestamp_ns;         // when context was generated
    __u32 inbound_fd;           // which inbound FD generated this context
    __u8  concurrent;           // 1 if multiple inbound FDs active
    __u8  _pad2[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);         // PID
    __type(value, struct pid_ctx);
} pid_trace_ctx SEC(".maps");

// Per-CPU scratch space for pid_ctx to avoid 512-byte BPF stack limit.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pid_ctx);
} pid_ctx_scratch SEC(".maps");

// Sockhash for sk_msg attachment: 4-tuple → socket
// Uses 128-bit IP fields to support both IPv4 and IPv6 sockets in the same map.
// For IPv4: src_ip[0]=ip, src_ip[1..3]=0. For IPv6: full 128-bit address.
struct sock_key {
    __u32 src_ip[4];
    __u32 dst_ip[4];
    __u32 src_port;
    __u32 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_ops_map SEC(".maps");

// ──────────────────────────────────────────────────────────────────────
// Temporary storage for kprobe → kretprobe data passing
// ──────────────────────────────────────────────────────────────────────

// For sys_connect: stash sockaddr before the call returns.
struct connect_args {
    __u64 addr;   // const struct sockaddr* stored as u64 for bpf2go compatibility
    __s32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // pid_tgid
    __type(value, struct connect_args);
} connect_args_map SEC(".maps");

// For sys_read/sys_recvfrom: stash buf pointer and fd before ret.
struct rw_args {
    __u64 buf;    // void* stored as u64 for bpf2go compatibility
    __s32 fd;
    __u32 count;
    __u32 flags;  // recvfrom flags (MSG_PEEK=0x2); 0 for read()
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // pid_tgid
    __type(value, struct rw_args);
} rw_args_map SEC(".maps");

// For sys_accept4: stash sockaddr pointer.
struct accept_args {
    __u64 addr;  // sockaddr pointer stored as u64 for bpf2go compatibility
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct accept_args);
} accept_args_map SEC(".maps");

// For SSL_write/SSL_read: stash buf+len.
struct ssl_rw_args {
    __u64 buf;    // void* stored as u64 for bpf2go compatibility
    __u32 len;
    __u64 ssl_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ssl_rw_args);
} ssl_rw_args_map SEC(".maps");

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

static __always_inline int should_trace(void) {
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&tracing_enabled, &key);
    return val && *val == 1;
}

static __always_inline int pid_allowed(__u32 pid) {
    // If the pid_filter map is populated, only observe listed PIDs.
    // We use a special key=0 as a "filter active" marker.
    __u32 marker_key = 0;
    __u8 *marker = bpf_map_lookup_elem(&pid_filter, &marker_key);
    if (!marker) {
        // No filter configured — observe all.
        return 1;
    }
    __u8 *val = bpf_map_lookup_elem(&pid_filter, &pid);
    return val != NULL;
}

static __always_inline int is_tracked_conn(__u32 pid, __s32 fd) {
    struct conn_key key = {.pid = pid, .fd = fd};
    return bpf_map_lookup_elem(&conn_map, &key) != NULL;
}

// Address info extracted from sockaddr (IPv4 or IPv6).
struct addr_info {
    __u32 addr;    // IPv4 address (or v4-mapped part of IPv6), 0 for pure IPv6
    __u16 port;    // port in host byte order
    __u8  valid;   // 1 if successfully parsed
};

// Extract address info from a userspace sockaddr pointer.
// Handles AF_INET, AF_INET6 (including IPv4-mapped), and AF_UNSPEC (0).
static __always_inline struct addr_info read_sockaddr(const struct sockaddr *uaddr) {
    struct addr_info info = {};

    if (!uaddr)
        return info;

    // Read family (first 2 bytes of any sockaddr)
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), uaddr);

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        info.addr = sin.sin_addr.s_addr;
        info.port = bpf_ntohs(sin.sin_port);
        info.valid = 1;
    } else if (family == AF_INET6) {
        // Read port from offset 2 (same as sockaddr_in6.sin6_port)
        __be16 port_be = 0;
        bpf_probe_read_user(&port_be, sizeof(port_be), (__u8 *)uaddr + 2);
        info.port = bpf_ntohs(port_be);

        // Read the 16-byte IPv6 address from offset 8
        __u8 v6addr[16] = {};
        bpf_probe_read_user(v6addr, sizeof(v6addr), (__u8 *)uaddr + 8);

        // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
        // Bytes 0-9 = 0, bytes 10-11 = 0xff, bytes 12-15 = IPv4 addr
        if (v6addr[0] == 0 && v6addr[1] == 0 && v6addr[2] == 0 && v6addr[3] == 0 &&
            v6addr[4] == 0 && v6addr[5] == 0 && v6addr[6] == 0 && v6addr[7] == 0 &&
            v6addr[8] == 0 && v6addr[9] == 0 && v6addr[10] == 0xff && v6addr[11] == 0xff) {
            __builtin_memcpy(&info.addr, &v6addr[12], 4);
        }
        // For pure IPv6 (::1, etc.), addr stays 0.
        // Connection tracking uses {pid,fd} as key, so this is fine.
        info.valid = 1;
    } else if (family == 0) {
        // AF_UNSPEC — accept may return this for some socket types
        info.valid = 1;
    }

    return info;
}

// ──────────────────────────────────────────────────────────────────────
// BPF-side trace context generation for sk_msg injection
// ──────────────────────────────────────────────────────────────────────
//
// When we see HTTP request data arriving on an INBOUND connection, we
// generate a traceparent header immediately in BPF and store it in the
// thread_trace_ctx map. This way, when the same thread makes an outbound
// HTTP call (intercepted by sk_msg), the traceparent is already available.
//
// This eliminates the race condition where the userspace agent processes
// ring buffer events too slowly — by the time SetTraceContext() runs in Go,
// the application has already sent the outbound request.

static const char hex_chars[] = "0123456789abcdef";

// Convert a 32-bit random value to 8 hex characters at dst.
static __always_inline void u32_to_hex(__u32 val, char *dst) {
    #pragma clang loop unroll(full)
    for (int i = 7; i >= 0; i--) {
        dst[i] = hex_chars[val & 0xf];
        val >>= 4;
    }
}

// Scan HTTP headers in payload for "traceparent: 00-" prefix.
// Returns offset of the trace ID (first hex char after "traceparent: 00-"),
// or -1 if not found. Requires at least offset+49 bytes for full traceparent.
// "traceparent: 00-" is 16 chars, then 32 hex (traceID) + "-" + 16 hex (spanID).
static __always_inline __s32 find_traceparent(const __u8 *payload, __u32 len) {
    // "traceparent: 00-" = 16 chars, need 16 + 32 + 1 + 16 = 65 chars minimum
    if (len < 65)
        return -1;

    __u32 scan_end = len - 65;
    if (scan_end > 200) // cap scan range for verifier
        scan_end = 200;

    // Scan for '\ntraceparent: ' (after first header line) or
    // 'traceparent: ' at start (unlikely but handle it)
    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < scan_end && i < 200; i++) {
        // Check for "\ntraceparent: 00-" or "\r\ntraceparent: 00-"
        if (payload[i] != '\n')
            continue;
        __u32 start = i + 1;
        if (start + 16 + 32 + 1 + 16 > len)
            break;
        // Verify "traceparent: 00-" at start
        if (payload[start]     == 't' && payload[start+1]  == 'r' &&
            payload[start+2]   == 'a' && payload[start+3]  == 'c' &&
            payload[start+4]   == 'e' && payload[start+5]  == 'p' &&
            payload[start+6]   == 'a' && payload[start+7]  == 'r' &&
            payload[start+8]   == 'e' && payload[start+9]  == 'n' &&
            payload[start+10]  == 't' && payload[start+11] == ':' &&
            payload[start+12]  == ' ' && payload[start+13] == '0' &&
            payload[start+14]  == '0' && payload[start+15] == '-') {
            // Return offset of trace ID start (32 hex chars)
            return (__s32)(start + 16);
        }
    }
    return -1;
}

// trace_result carries BPF-generated trace context back to the caller
// for embedding directly into the ring buffer event. This eliminates
// the race where Go reads from the BPF map after it's been overwritten.
struct trace_result {
    __u8  generated;      // 1 if trace context was generated
    __u8  trace_id[32];   // hex-encoded trace ID
    __u8  span_id[16];    // hex-encoded span ID
};

// maybe_generate_trace_ctx checks if this is an HTTP request on an inbound
// connection and generates/extracts a traceparent header for the BPF map.
//
// If the request already contains a "traceparent:" header (injected by upstream
// sk_msg), the trace ID is EXTRACTED from it to maintain cross-service trace
// continuity. A new span ID is generated for this service's span.
//
// If no traceparent is present, a fully random trace ID + span ID are generated.
//
// The generated trace context is returned via trace_result for embedding
// directly in the ring buffer event, eliminating BPF map read races.
//
// Called from kretprobe_read/kretprobe_recvfrom after reading payload.
static __always_inline void maybe_generate_trace_ctx(
    __u32 pid, __u32 tid, __s32 fd, const __u8 payload[MAX_CAPTURE], __u32 len,
    struct trace_result *result)
{
    // Only for inbound connections
    struct conn_key ckey = {.pid = pid, .fd = fd};
    struct conn_val *cval = bpf_map_lookup_elem(&conn_map, &ckey);
    if (!cval || cval->dir != DIR_INBOUND)
        return;

    // Always generate fresh context for each new HTTP request.
    // The old validity guard (checking existing->valid) caused stale context
    // reuse when Go's ClearTraceContext hadn't run yet.
    struct thread_key tkey = {.pid = pid, .tid = tid};

    // Need at least 4 bytes to check HTTP method
    if (len < 4)
        return;

    // Quick check for HTTP request methods
    int is_http = 0;
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') ||
        (payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C') ||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D'))
        is_http = 1;

    if (!is_http)
        return;

    struct trace_ctx tctx = {};
    tctx.valid = 1;
    char *h = tctx.header;

    // Check if the request already contains a traceparent header (from upstream injection)
    __s32 tp_offset = find_traceparent(payload, len);

    // Always generate a new span ID for this service's span
    __u32 r4 = bpf_get_prandom_u32();
    __u32 r5 = bpf_get_prandom_u32();

    __builtin_memcpy(h, "traceparent: 00-", 16);

    if (tp_offset >= 0 && tp_offset + 32 + 1 + 16 <= (__s32)len) {
        // Extract existing trace ID from the incoming traceparent header.
        // This preserves cross-service trace continuity.
        // Copy 32 hex chars of trace ID from payload
        __u32 safe_off = (__u32)tp_offset;
        if (safe_off + 49 <= MAX_CAPTURE) {
            #pragma clang loop unroll(full)
            for (int j = 0; j < 32; j++)
                h[16 + j] = payload[safe_off + j];
        } else {
            // Fallback: generate random
            __u32 r0 = bpf_get_prandom_u32();
            __u32 r1 = bpf_get_prandom_u32();
            __u32 r2 = bpf_get_prandom_u32();
            __u32 r3 = bpf_get_prandom_u32();
            u32_to_hex(r0, h + 16);
            u32_to_hex(r1, h + 24);
            u32_to_hex(r2, h + 32);
            u32_to_hex(r3, h + 40);
        }
    } else {
        // No traceparent found — generate fully random trace ID
        __u32 r0 = bpf_get_prandom_u32();
        __u32 r1 = bpf_get_prandom_u32();
        __u32 r2 = bpf_get_prandom_u32();
        __u32 r3 = bpf_get_prandom_u32();
        u32_to_hex(r0, h + 16);
        u32_to_hex(r1, h + 24);
        u32_to_hex(r2, h + 32);
        u32_to_hex(r3, h + 40);
    }

    h[48] = '-';
    // span ID: always new for this service's span
    u32_to_hex(r4, h + 49);
    u32_to_hex(r5, h + 57);
    h[65] = '-';
    h[66] = '0';
    h[67] = '1';
    h[68] = '\r';
    h[69] = '\n';
    tctx.header_len = 70;

    bpf_map_update_elem(&thread_trace_ctx, &tkey, &tctx, BPF_ANY);

    // Store PID-level context for cross-thread forwarding (Go goroutine TID mismatch).
    // Uses per-CPU scratch map to avoid exceeding 512-byte BPF stack limit.
    {
        __u32 zero = 0;
        struct pid_ctx *scratch = bpf_map_lookup_elem(&pid_ctx_scratch, &zero);
        if (scratch) {
            scratch->ctx = tctx;
            scratch->timestamp_ns = bpf_ktime_get_ns();
            scratch->inbound_fd = (__u32)fd;
            scratch->concurrent = 0;

            struct pid_ctx *existing_pctx = bpf_map_lookup_elem(&pid_trace_ctx, &pid);
            if (existing_pctx && existing_pctx->inbound_fd != (__u32)fd) {
                __u64 age = scratch->timestamp_ns - existing_pctx->timestamp_ns;
                if (age < 2000000000ULL) { // 2 seconds
                    scratch->concurrent = 1;
                }
            }
            bpf_map_update_elem(&pid_trace_ctx, &pid, scratch, BPF_ANY);
        }
    }

    // Return trace context via result for embedding in ring buffer event.
    // trace_id is at h[16..48], span_id is at h[49..65].
    if (result) {
        result->generated = 1;
        #pragma clang loop unroll(full)
        for (int j = 0; j < 32; j++)
            result->trace_id[j] = (__u8)h[16 + j];
        #pragma clang loop unroll(full)
        for (int j = 0; j < 16; j++)
            result->span_id[j] = (__u8)h[49 + j];
    }
}

// emit_data_event_ex sends a DATA_IN or DATA_OUT event to the ring buffer,
// optionally embedding BPF-generated trace context directly in the event.
// This eliminates the race where Go reads from the BPF map after overwrite.
static __always_inline int emit_data_event_ex(__u8 event_type, __u32 pid,
                                              __u32 tid, __s32 fd,
                                              const void *buf, __u32 len,
                                              struct trace_result *trace) {
    __u32 capture = len;
    if (capture > MAX_CAPTURE)
        capture = MAX_CAPTURE;

    struct olly_event *e = bpf_ringbuf_reserve(&events,
        sizeof(struct olly_event), 0);
    if (!e)
        return 0;

    e->event_type = event_type;
    e->pid = pid;
    e->tid = tid;
    e->fd = fd;
    e->payload_len = capture;
    e->original_len = len;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = 0;
    e->remote_port = 0;
    e->direction = 0;

    // Embed trace context if available
    if (trace && trace->generated) {
        e->has_trace_ctx = 1;
        __builtin_memcpy(e->trace_id, trace->trace_id, 32);
        __builtin_memcpy(e->span_id, trace->span_id, 16);
    } else {
        e->has_trace_ctx = 0;
        __builtin_memset(e->trace_id, 0, 32);
        __builtin_memset(e->span_id, 0, 16);
    }

    if (capture > 0) {
        bpf_probe_read_user(e->payload, capture & (MAX_CAPTURE - 1 | MAX_CAPTURE), buf);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// emit_data_event sends a DATA_IN or DATA_OUT event without trace context.
static __always_inline int emit_data_event(__u8 event_type, __u32 pid,
                                           __u32 tid, __s32 fd,
                                           const void *buf, __u32 len) {
    return emit_data_event_ex(event_type, pid, tid, fd, buf, len, NULL);
}

// ──────────────────────────────────────────────────────────────────────
// sys_connect kprobe / kretprobe
// ──────────────────────────────────────────────────────────────────────

// On x86_64 kernel 6.1+, kprobes on sys_connect resolve to __x64_sys_connect
// which takes a single struct pt_regs* argument containing the real syscall args.
// We must read from the inner pt_regs, not the kprobe context directly.
SEC("kprobe/sys_connect")
int BPF_KPROBE(kprobe_connect, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    int fd = PT_REGS_PARM1_CORE(regs);
    const struct sockaddr *addr = (const struct sockaddr *)PT_REGS_PARM2_CORE(regs);

    struct connect_args args = {};
    args.fd = fd;
    args.addr = (__u64)addr;
    bpf_map_update_elem(&connect_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(kretprobe_connect, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct connect_args *args = bpf_map_lookup_elem(&connect_args_map, &pid_tgid);
    if (!args) return 0;

    __s32 fd = args->fd;
    const struct sockaddr *addr = (const struct sockaddr *)args->addr;
    bpf_map_delete_elem(&connect_args_map, &pid_tgid);

    // ret == 0 or EINPROGRESS for non-blocking connect
    if (ret != 0 && ret != -115) // -EINPROGRESS
        return 0;

    // Read sockaddr — handles both AF_INET and AF_INET6
    struct addr_info ainfo = read_sockaddr(addr);
    if (!ainfo.valid)
        return 0;

    // Add to connection map
    struct conn_key ckey = {.pid = pid, .fd = fd};
    struct conn_val cval = {
        .addr = ainfo.addr,
        .port = ainfo.port,
        .dir = DIR_OUTBOUND,
    };
    bpf_map_update_elem(&conn_map, &ckey, &cval, BPF_ANY);

    // Emit CONNECT event
    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_CONNECT;
    e->has_trace_ctx = 0;
    e->pid = pid;
    e->tid = tid;
    e->fd = fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = ainfo.addr;
    e->remote_port = ainfo.port;
    e->direction = DIR_OUTBOUND;
    __builtin_memset(e->trace_id, 0, 32);
    __builtin_memset(e->span_id, 0, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// sys_accept4 kprobe / kretprobe
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_accept4")
int BPF_KPROBE(kprobe_accept4, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2_CORE(regs);

    struct accept_args args = {};
    args.addr = (__u64)addr;
    bpf_map_update_elem(&accept_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(kretprobe_accept4, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (!args) return 0;

    struct sockaddr *addr = (struct sockaddr *)args->addr;
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);

    if (ret < 0)
        return 0;

    __s32 new_fd = ret;

    // Read sockaddr — handles AF_INET, AF_INET6, AF_UNSPEC, and NULL addr.
    // Node.js/libuv passes addr=NULL to accept4 (doesn't need peer address).
    // We must still register the connection for SERVER span creation.
    struct addr_info ainfo = read_sockaddr(addr);
    if (!ainfo.valid && addr != NULL)
        return 0;

    // Add to connection map
    struct conn_key ckey = {.pid = pid, .fd = new_fd};
    struct conn_val cval = {
        .addr = ainfo.addr,
        .port = ainfo.port,
        .dir = DIR_INBOUND,
    };
    bpf_map_update_elem(&conn_map, &ckey, &cval, BPF_ANY);

    // Emit ACCEPT event
    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_ACCEPT;
    e->has_trace_ctx = 0;
    e->pid = pid;
    e->tid = tid;
    e->fd = new_fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = ainfo.addr;
    e->remote_port = ainfo.port;
    e->direction = DIR_INBOUND;
    __builtin_memset(e->trace_id, 0, 32);
    __builtin_memset(e->span_id, 0, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Also hook sys_accept (some applications use accept instead of accept4).
SEC("kprobe/sys_accept")
int BPF_KPROBE(kprobe_accept, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2_CORE(regs);

    struct accept_args args = {};
    args.addr = (__u64)addr;
    bpf_map_update_elem(&accept_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_accept")
int BPF_KRETPROBE(kretprobe_accept, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (!args) return 0;

    struct sockaddr *addr = (struct sockaddr *)args->addr;
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);

    if (ret < 0)
        return 0;

    __s32 new_fd = ret;

    // Read sockaddr — handles AF_INET, AF_INET6, AF_UNSPEC, and NULL addr.
    struct addr_info ainfo = read_sockaddr(addr);
    if (!ainfo.valid && addr != NULL)
        return 0;

    struct conn_key ckey = {.pid = pid, .fd = new_fd};
    struct conn_val cval = {
        .addr = ainfo.addr,
        .port = ainfo.port,
        .dir = DIR_INBOUND,
    };
    bpf_map_update_elem(&conn_map, &ckey, &cval, BPF_ANY);

    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_ACCEPT;
    e->has_trace_ctx = 0;
    e->pid = pid;
    e->tid = tid;
    e->fd = new_fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = ainfo.addr;
    e->remote_port = ainfo.port;
    e->direction = DIR_INBOUND;
    __builtin_memset(e->trace_id, 0, 32);
    __builtin_memset(e->span_id, 0, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// Cross-thread trace context forwarding
// ──────────────────────────────────────────────────────────────────────
//
// Go goroutines migrate between OS threads, so the TID that reads an
// inbound HTTP request may differ from the TID that writes the outbound
// HTTP request. sk_msg looks up thread_trace_ctx[PID+TID] and finds
// nothing if the TIDs differ.
//
// maybe_forward_trace_ctx bridges this gap: called from kprobe_write
// (which fires SYNCHRONOUSLY before sk_msg on the same TID), it copies
// the PID-level trace context to the writing thread's thread_trace_ctx
// so sk_msg can find it.
//
// Concurrency guard: skips forwarding when concurrent inbound requests
// are detected (concurrent flag in pid_trace_ctx) to prevent injecting
// the wrong traceparent into an unrelated outbound request.
static __always_inline void maybe_forward_trace_ctx(
    __u32 pid, __u32 tid, const void *buf, __u32 count)
{
    // Skip if this thread already has trace context (TID matched correctly).
    struct thread_key tkey = {.pid = pid, .tid = tid};
    struct trace_ctx *existing = bpf_map_lookup_elem(&thread_trace_ctx, &tkey);
    if (existing && existing->valid)
        return;

    // Look up PID-level context
    struct pid_ctx *pctx = bpf_map_lookup_elem(&pid_trace_ctx, &pid);
    if (!pctx || !pctx->ctx.valid)
        return;

    // Concurrency guard: don't forward if multiple inbound FDs are active.
    if (pctx->concurrent)
        return;

    // Freshness check: context must be recent
    __u64 age = bpf_ktime_get_ns() - pctx->timestamp_ns;
    if (age > 5000000000ULL) // 5 seconds
        return;

    // Only forward for HTTP requests — non-HTTP outbound writes (Redis,
    // MySQL, etc.) should not get trace context that sk_msg might pick up
    // on a subsequent HTTP write from a different goroutine on this TID.
    if (count < 5)
        return;

    __u8 peek[5] = {};
    if (bpf_probe_read_user(peek, 5, buf) != 0)
        return;

    int is_http = 0;
    if ((peek[0] == 'G' && peek[1] == 'E' && peek[2] == 'T' && peek[3] == ' ') ||
        (peek[0] == 'P' && peek[1] == 'O' && peek[2] == 'S' && peek[3] == 'T') ||
        (peek[0] == 'P' && peek[1] == 'U' && peek[2] == 'T' && peek[3] == ' ') ||
        (peek[0] == 'D' && peek[1] == 'E' && peek[2] == 'L' && peek[3] == 'E') ||
        (peek[0] == 'P' && peek[1] == 'A' && peek[2] == 'T' && peek[3] == 'C') ||
        (peek[0] == 'H' && peek[1] == 'E' && peek[2] == 'A' && peek[3] == 'D'))
        is_http = 1;

    if (!is_http)
        return;

    // Forward PID-level trace context to this thread's thread_trace_ctx.
    // sk_msg fires immediately after kprobe_write on the same TID, so it
    // will find this context and inject the traceparent header.
    bpf_map_update_elem(&thread_trace_ctx, &tkey, &pctx->ctx, BPF_ANY);
}

// ──────────────────────────────────────────────────────────────────────
// sys_write kprobe — outbound data + log capture
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_write")
int BPF_KPROBE(kprobe_write, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    int fd = PT_REGS_PARM1_CORE(regs);
    const void *buf = (const void *)PT_REGS_PARM2_CORE(regs);
    size_t count = PT_REGS_PARM3_CORE(regs);
    __u32 tid = (__u32)pid_tgid;

    // Check if this is a tracked network connection
    struct conn_key ckey = {.pid = pid, .fd = fd};
    struct conn_val *conn = bpf_map_lookup_elem(&conn_map, &ckey);
    if (conn) {
        // Forward PID-level trace context for outbound HTTP writes when
        // the thread doesn't have context (Go goroutine TID mismatch).
        if (conn->dir == DIR_OUTBOUND) {
            maybe_forward_trace_ctx(pid, tid, buf, (__u32)count);
        }
        return emit_data_event(EVENT_DATA_OUT, pid, tid, fd, buf, (__u32)count);
    }

    // Check if this is a log fd
    __u8 *is_log = bpf_map_lookup_elem(&log_fd_map, &ckey);
    if (is_log) {
        return emit_data_event(EVENT_LOG_WRITE, pid, tid, fd, buf, (__u32)count);
    }

    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// sys_sendto kprobe — outbound data (used by some protocols)
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_sendto")
int BPF_KPROBE(kprobe_sendto, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (!pid_allowed(pid))
        return 0;

    int fd = PT_REGS_PARM1_CORE(regs);
    const void *buf = (const void *)PT_REGS_PARM2_CORE(regs);
    size_t len = PT_REGS_PARM3_CORE(regs);

    struct conn_key ckey = {.pid = pid, .fd = fd};
    struct conn_val *conn = bpf_map_lookup_elem(&conn_map, &ckey);
    if (!conn)
        return 0;

    // Forward PID-level trace context for outbound HTTP sends
    if (conn->dir == DIR_OUTBOUND) {
        maybe_forward_trace_ctx(pid, tid, buf, (__u32)len);
    }

    return emit_data_event(EVENT_DATA_OUT, pid, tid, fd, buf, (__u32)len);
}

// ──────────────────────────────────────────────────────────────────────
// sys_read kprobe + kretprobe — inbound data
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_read")
int BPF_KPROBE(kprobe_read, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    int fd = PT_REGS_PARM1_CORE(regs);
    void *buf = (void *)PT_REGS_PARM2_CORE(regs);
    size_t count = PT_REGS_PARM3_CORE(regs);

    if (!is_tracked_conn(pid, fd))
        return 0;

    struct rw_args args = {};
    args.fd = fd;
    args.buf = (__u64)buf;
    args.count = (__u32)count;
    bpf_map_update_elem(&rw_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_read")
int BPF_KRETPROBE(kretprobe_read, ssize_t ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct rw_args *args = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
    if (!args) return 0;

    __s32 fd = args->fd;
    void *buf = (void *)args->buf;
    bpf_map_delete_elem(&rw_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // BPF-side trace context generation: read first bytes to check for HTTP
    // on inbound connections, and generate traceparent immediately.
    // The trace_result is embedded directly in the ring buffer event to
    // eliminate the race between BPF map writes and Go's async reads.
    struct trace_result trace = {};
    __u8 peek[MAX_CAPTURE];
    __u32 peek_len = (__u32)ret;
    if (peek_len > MAX_CAPTURE)
        peek_len = MAX_CAPTURE;
    if (bpf_probe_read_user(peek, peek_len & (MAX_CAPTURE - 1 | MAX_CAPTURE), buf) == 0) {
        maybe_generate_trace_ctx(pid, tid, fd, peek, peek_len, &trace);
    }

    return emit_data_event_ex(EVENT_DATA_IN, pid, tid, fd, buf, (__u32)ret, &trace);
}

// ──────────────────────────────────────────────────────────────────────
// sys_recvfrom kprobe + kretprobe — inbound data
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_recvfrom")
int BPF_KPROBE(kprobe_recvfrom, struct pt_regs *regs) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    int fd = PT_REGS_PARM1_CORE(regs);
    void *buf = (void *)PT_REGS_PARM2_CORE(regs);
    size_t len = PT_REGS_PARM3_CORE(regs);
    // 4th syscall arg is in r10 (not rcx) on x86_64.
    // PT_REGS_PARM4_CORE reads rcx which is clobbered by SYSCALL instruction.
    unsigned int flags = (__u32)BPF_CORE_READ(regs, r10);

    if (!is_tracked_conn(pid, fd))
        return 0;

    struct rw_args args = {};
    args.fd = fd;
    args.buf = (__u64)buf;
    args.count = (__u32)len;
    args.flags = flags;
    bpf_map_update_elem(&rw_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_recvfrom")
int BPF_KRETPROBE(kretprobe_recvfrom, ssize_t ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct rw_args *args = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
    if (!args) return 0;

    __s32 fd = args->fd;
    void *buf = (void *)args->buf;
    __u32 flags = args->flags;
    bpf_map_delete_elem(&rw_args_map, &pid_tgid);

    // Skip MSG_PEEK reads — .NET Kestrel does recvfrom(fd, buf, 1, MSG_PEEK)
    // before the actual read. Without this filter, the peek byte gets appended
    // to sendBuf alongside the full read, producing "GGET" instead of "GET".
    if (flags & 2)  // MSG_PEEK = 0x2
        return 0;

    if (ret <= 0)
        return 0;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // BPF-side trace context generation for recvfrom
    struct trace_result trace = {};
    __u8 peek[MAX_CAPTURE];
    __u32 peek_len = (__u32)ret;
    if (peek_len > MAX_CAPTURE)
        peek_len = MAX_CAPTURE;
    if (bpf_probe_read_user(peek, peek_len & (MAX_CAPTURE - 1 | MAX_CAPTURE), buf) == 0) {
        maybe_generate_trace_ctx(pid, tid, fd, peek, peek_len, &trace);
    }

    return emit_data_event_ex(EVENT_DATA_IN, pid, tid, fd, buf, (__u32)ret, &trace);
}

// ──────────────────────────────────────────────────────────────────────
// sys_close kprobe — connection cleanup
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_close")
int BPF_KPROBE(kprobe_close, struct pt_regs *regs) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    int fd = PT_REGS_PARM1_CORE(regs);

    struct conn_key ckey = {.pid = pid, .fd = fd};

    // Remove from conn_map (if present)
    struct conn_val *conn = bpf_map_lookup_elem(&conn_map, &ckey);
    if (!conn) {
        // Also clean up log_fd_map if present
        bpf_map_delete_elem(&log_fd_map, &ckey);
        return 0;
    }

    bpf_map_delete_elem(&conn_map, &ckey);
    bpf_map_delete_elem(&log_fd_map, &ckey);

    if (!should_trace())
        return 0;

    // Emit CLOSE event
    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_CLOSE;
    e->has_trace_ctx = 0;
    e->pid = pid;
    e->tid = tid;
    e->fd = fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = 0;
    e->remote_port = 0;
    e->direction = 0;
    __builtin_memset(e->trace_id, 0, 32);
    __builtin_memset(e->span_id, 0, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// SSL uprobes — plaintext capture before encryption / after decryption
// ──────────────────────────────────────────────────────────────────────

// BPF_UPROBE/BPF_URETPROBE may not be defined in older libbpf headers.
// On x86_64, uprobes use the same pt_regs as kprobes.
#ifndef BPF_UPROBE
#define BPF_UPROBE(name, args...) BPF_KPROBE(name, ##args)
#endif
#ifndef BPF_URETPROBE
#define BPF_URETPROBE(name, args...) BPF_KRETPROBE(name, ##args)
#endif

// SSL_set_fd(SSL *ssl, int fd) — maps SSL* → fd
SEC("uprobe/SSL_set_fd")
int BPF_UPROBE(uprobe_ssl_set_fd, void *ssl, int fd) {
    __u64 ssl_ptr = (__u64)ssl;
    __s32 sfd = fd;
    bpf_map_update_elem(&ssl_fd_map, &ssl_ptr, &sfd, BPF_ANY);
    return 0;
}

// SSL_write(SSL *ssl, const void *buf, int num) — plaintext before encryption
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct ssl_rw_args args = {};
    args.buf = (__u64)buf;
    args.len = (__u32)num;
    args.ssl_ptr = (__u64)ssl;
    bpf_map_update_elem(&ssl_rw_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_rw_args *args = bpf_map_lookup_elem(&ssl_rw_args_map, &pid_tgid);
    if (!args) return 0;

    void *buf = (void *)args->buf;
    __u64 ssl_ptr = args->ssl_ptr;
    bpf_map_delete_elem(&ssl_rw_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    // Look up the fd for this SSL*
    __s32 *fdp = bpf_map_lookup_elem(&ssl_fd_map, &ssl_ptr);
    __s32 fd = fdp ? *fdp : -1;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    return emit_data_event(EVENT_SSL_OUT, pid, tid, fd, buf, (__u32)ret);
}

// SSL_read(SSL *ssl, void *buf, int num) — plaintext after decryption
SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, void *buf, int num) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct ssl_rw_args args = {};
    args.buf = (__u64)buf;
    args.len = (__u32)num;
    args.ssl_ptr = (__u64)ssl;
    bpf_map_update_elem(&ssl_rw_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_rw_args *args = bpf_map_lookup_elem(&ssl_rw_args_map, &pid_tgid);
    if (!args) return 0;

    void *buf = (void *)args->buf;
    __u64 ssl_ptr = args->ssl_ptr;
    bpf_map_delete_elem(&ssl_rw_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    __s32 *fdp = bpf_map_lookup_elem(&ssl_fd_map, &ssl_ptr);
    __s32 fd = fdp ? *fdp : -1;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    return emit_data_event(EVENT_SSL_IN, pid, tid, fd, buf, (__u32)ret);
}

// ──────────────────────────────────────────────────────────────────────
// Process exec tracepoint — for SSL library auto-discovery
// ──────────────────────────────────────────────────────────────────────

// Emit a lightweight event so userspace can scan /proc/<pid>/maps for libssl.
SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (!pid_allowed(pid))
        return 0;

    // Emit a zero-payload CONNECT event with fd=-1 as a "new process" signal.
    // Userspace interprets fd=-1 + event_type=CONNECT as "scan this PID for SSL".
    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_CONNECT;
    e->has_trace_ctx = 0;
    e->pid = pid;
    e->tid = tid;
    e->fd = -1; // sentinel: not a real fd
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = 0;
    e->remote_port = 0;
    e->direction = 0;
    __builtin_memset(e->trace_id, 0, 32);
    __builtin_memset(e->span_id, 0, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// Sockops program — populate sockhash for sk_msg traceparent injection
// ──────────────────────────────────────────────────────────────────────

// Constants for sockops/sk_msg (may not be in vmlinux.h)
#ifndef SK_PASS
#define SK_PASS 1
#endif

#ifndef BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4
#endif

// olly_sockops intercepts outbound TCP connections and adds them to the
// sockhash map so the sk_msg program can intercept their sends.
// Only outbound (ACTIVE_ESTABLISHED) connections are tracked since we only
// inject traceparent into outgoing HTTP requests, not responses.
// Supports both IPv4 and IPv6 connections.
SEC("sockops")
int olly_sockops(struct bpf_sock_ops *skops) {
    __u32 op = skops->op;

    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 1;

    struct sock_key key = {};
    key.src_port = skops->local_port;
    key.dst_port = bpf_ntohl(skops->remote_port);

    if (skops->family == AF_INET) {
        key.src_ip[0] = skops->local_ip4;
        key.dst_ip[0] = skops->remote_ip4;
    } else if (skops->family == AF_INET6) {
        key.src_ip[0] = skops->local_ip6[0];
        key.src_ip[1] = skops->local_ip6[1];
        key.src_ip[2] = skops->local_ip6[2];
        key.src_ip[3] = skops->local_ip6[3];
        key.dst_ip[0] = skops->remote_ip6[0];
        key.dst_ip[1] = skops->remote_ip6[1];
        key.dst_ip[2] = skops->remote_ip6[2];
        key.dst_ip[3] = skops->remote_ip6[3];
    } else {
        return 1; // unsupported family
    }

    bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    return 1;
}

// ──────────────────────────────────────────────────────────────────────
// sk_msg program — inject traceparent into outbound HTTP requests
// ──────────────────────────────────────────────────────────────────────

// Maximum bytes to scan for \r\n\r\n (must be < MAX_CAPTURE - 4)
#define SCAN_MAX 248

// olly_sk_msg intercepts sendmsg on sockets in the sockhash. When the
// message starts with an HTTP method, it looks up the current thread's
// trace context (populated by the agent from the inbound request) and
// injects a "traceparent: ..." header before the end-of-headers marker.
//
// This enables cross-service distributed tracing WITHOUT any application
// code changes. The injected traceparent follows W3C Trace Context spec.
//
// Safety: ALWAYS returns SK_PASS. If anything fails (no context, can't
// find headers, can't push data), the message is passed through unmodified.
//
// BPF verifier compliance notes:
//   - All msg->data/data_end accesses use (void *)(long) cast
//   - All bounds checks use compile-time constant offsets
//   - Pointers are re-fetched after every helper call
//   - Writes use __builtin_memcpy with constant size
SEC("sk_msg")
int olly_sk_msg(struct sk_msg_md *msg) {
    __u32 sz = msg->size;

    // Minimum HTTP request: "GET / HTTP/1.1\r\n\r\n" = ~18 bytes
    if (sz < 18)
        return SK_PASS;

    // Pull first bytes into the linear data/data_end window.
    // sk_msg data may be in scatterlist pages — pull linearizes them.
    __u32 pull_len = sz;
    if (pull_len > MAX_CAPTURE)
        pull_len = MAX_CAPTURE;

    if (bpf_msg_pull_data(msg, 0, pull_len, 0) != 0)
        return SK_PASS;

    // CRITICAL: Use (void *)(long) cast for BPF verifier packet tracking
    void *data = (void *)(long)msg->data;
    void *data_end = (void *)(long)msg->data_end;

    // Constant-offset bounds check: need at least 5 bytes for HTTP method
    if (data + 5 > data_end)
        return SK_PASS;

    // Quick check: does this look like an HTTP request?
    __u8 *p = (__u8 *)data;
    int is_http = 0;
    if ((p[0] == 'G' && p[1] == 'E' && p[2] == 'T' && p[3] == ' ') ||
        (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T' && p[4] == ' ') ||
        (p[0] == 'P' && p[1] == 'U' && p[2] == 'T' && p[3] == ' ') ||
        (p[0] == 'D' && p[1] == 'E' && p[2] == 'L' && p[3] == 'E') ||
        (p[0] == 'P' && p[1] == 'A' && p[2] == 'T' && p[3] == 'C') ||
        (p[0] == 'H' && p[1] == 'E' && p[2] == 'A' && p[3] == 'D' && p[4] == ' '))
        is_http = 1;

    if (!is_http) {
        return SK_PASS;
    }

    // Look up trace context for the calling thread
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct thread_key tkey = {
        .pid = pid_tgid >> 32,
        .tid = (__u32)pid_tgid,
    };

    struct trace_ctx *tctx = bpf_map_lookup_elem(&thread_trace_ctx, &tkey);
    if (!tctx || !tctx->valid) {
        return SK_PASS;
    }

    __u32 hdr_len = tctx->header_len;
    if (hdr_len == 0 || hdr_len > TRACEPARENT_HEADER_LEN) {
        return SK_PASS;
    }

    // Copy header to stack — map values may be invalidated by helper calls.
    // Use fixed-size copy so the verifier sees constant bounds.
    char hdr_buf[TRACEPARENT_HEADER_LEN + 1];
    __builtin_memset(hdr_buf, 0, sizeof(hdr_buf));
    __builtin_memcpy(hdr_buf, tctx->header, TRACEPARENT_HEADER_LEN);

    // Re-fetch pointers (map lookup doesn't invalidate, but be safe)
    data = (void *)(long)msg->data;
    data_end = (void *)(long)msg->data_end;

    // Search for \r\n\r\n with per-iteration constant-offset bounds check.
    // The verifier tracks bounded loop + per-iteration check.
    __s32 insert_pos = -1;

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < SCAN_MAX; i++) {
        // Constant offset 4 from a variable base — verifier can track
        // this because the loop is bounded and i is provably < SCAN_MAX
        if ((void *)((__u8 *)data + i + 4) > data_end)
            break;
        __u8 *c = (__u8 *)data + i;
        if (c[0] == '\r' && c[1] == '\n' && c[2] == '\r' && c[3] == '\n') {
            // Insert after the last header's \r\n, before blank line's \r\n
            insert_pos = (__s32)(i + 2);
            break;
        }
    }

    if (insert_pos < 0) {
        return SK_PASS;
    }

    // All sizes use the compile-time constant TRACEPARENT_HEADER_LEN.
    // This ensures push, pull, bounds check, and memcpy all agree on size
    // and the BPF verifier can track everything statically.

    // Push space for the traceparent header at the insertion point.
    // After this call ALL prior pointers are invalidated.
    int push_ret = bpf_msg_push_data(msg, (__u32)insert_pos, TRACEPARENT_HEADER_LEN, 0);
    if (push_ret != 0) {
        return SK_PASS;
    }

    // Pull the pushed region into the linear data window so we can write.
    // After this call ALL prior pointers are invalidated again.
    int pull_ret = bpf_msg_pull_data(msg, (__u32)insert_pos,
                          (__u32)insert_pos + TRACEPARENT_HEADER_LEN, 0);
    if (pull_ret != 0) {
        return SK_PASS;
    }

    // CRITICAL: Re-fetch pointers with (void *)(long) cast after helpers
    data = (void *)(long)msg->data;
    data_end = (void *)(long)msg->data_end;

    // CRITICAL: Bounds check with CONSTANT offset.
    // TRACEPARENT_HEADER_LEN is a compile-time constant (70).
    if (data + TRACEPARENT_HEADER_LEN > data_end) {
        return SK_PASS;
    }

    // Write header using __builtin_memcpy with constant size.
    // hdr_buf is zero-filled to TRACEPARENT_HEADER_LEN+1, so this is safe.
    __builtin_memcpy(data, hdr_buf, TRACEPARENT_HEADER_LEN);

    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
