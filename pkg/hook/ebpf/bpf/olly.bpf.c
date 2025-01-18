// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// olly.bpf.c — eBPF programs for syscall and SSL hooking.
// Attached via kprobes/kretprobes to observe all network I/O.
// Events are emitted to a BPF ring buffer for zero-copy userspace consumption.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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

// ──────────────────────────────────────────────────────────────────────
// Ring buffer event structure
// ──────────────────────────────────────────────────────────────────────

struct olly_event {
    __u8  event_type;
    __u8  _pad[3];
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
// Temporary storage for kprobe → kretprobe data passing
// ──────────────────────────────────────────────────────────────────────

// For sys_connect: stash sockaddr before the call returns.
struct connect_args {
    const struct sockaddr *addr;
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
    void *buf;
    __s32 fd;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // pid_tgid
    __type(value, struct rw_args);
} rw_args_map SEC(".maps");

// For sys_accept4: stash sockaddr pointer.
struct accept_args {
    struct sockaddr *addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct accept_args);
} accept_args_map SEC(".maps");

// For SSL_write/SSL_read: stash buf+len.
struct ssl_rw_args {
    void *buf;
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

// emit_data_event sends a DATA_IN or DATA_OUT event to the ring buffer.
static __always_inline int emit_data_event(__u8 event_type, __u32 pid,
                                           __u32 tid, __s32 fd,
                                           const void *buf, __u32 len) {
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

    if (capture > 0) {
        bpf_probe_read_user(e->payload, capture & (MAX_CAPTURE - 1 | MAX_CAPTURE), buf);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// sys_connect kprobe / kretprobe
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_connect")
int BPF_KPROBE(kprobe_connect, int fd, const struct sockaddr *addr, int addrlen) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct connect_args args = {};
    args.fd = fd;
    args.addr = addr;
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
    const struct sockaddr *addr = args->addr;
    bpf_map_delete_elem(&connect_args_map, &pid_tgid);

    // ret == 0 or EINPROGRESS for non-blocking connect
    if (ret != 0 && ret != -115) // -EINPROGRESS
        return 0;

    // Read sockaddr to get address family
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    if (sin.sin_family != 2) // AF_INET only for now
        return 0;

    // Add to connection map
    struct conn_key ckey = {.pid = pid, .fd = fd};
    struct conn_val cval = {
        .addr = sin.sin_addr.s_addr,
        .port = bpf_ntohs(sin.sin_port),
        .dir = DIR_OUTBOUND,
    };
    bpf_map_update_elem(&conn_map, &ckey, &cval, BPF_ANY);

    // Emit CONNECT event
    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_CONNECT;
    e->pid = pid;
    e->tid = tid;
    e->fd = fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = sin.sin_addr.s_addr;
    e->remote_port = bpf_ntohs(sin.sin_port);
    e->direction = DIR_OUTBOUND;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// sys_accept4 kprobe / kretprobe
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_accept4")
int BPF_KPROBE(kprobe_accept4, int sockfd, struct sockaddr *addr, int *addrlen, int flags) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct accept_args args = {};
    args.addr = addr;
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

    struct sockaddr *addr = args->addr;
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);

    if (ret < 0)
        return 0;

    __s32 new_fd = ret;
    struct sockaddr_in sin = {};
    if (addr) {
        bpf_probe_read_user(&sin, sizeof(sin), addr);
    }

    if (sin.sin_family != 2 && sin.sin_family != 0)
        return 0;

    // Add to connection map
    struct conn_key ckey = {.pid = pid, .fd = new_fd};
    struct conn_val cval = {
        .addr = sin.sin_addr.s_addr,
        .port = bpf_ntohs(sin.sin_port),
        .dir = DIR_INBOUND,
    };
    bpf_map_update_elem(&conn_map, &ckey, &cval, BPF_ANY);

    // Emit ACCEPT event
    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_ACCEPT;
    e->pid = pid;
    e->tid = tid;
    e->fd = new_fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = sin.sin_addr.s_addr;
    e->remote_port = bpf_ntohs(sin.sin_port);
    e->direction = DIR_INBOUND;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Also hook sys_accept (some applications use accept instead of accept4).
SEC("kprobe/sys_accept")
int BPF_KPROBE(kprobe_accept, int sockfd, struct sockaddr *addr, int *addrlen) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    struct accept_args args = {};
    args.addr = addr;
    bpf_map_update_elem(&accept_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_accept")
int BPF_KRETPROBE(kretprobe_accept, int ret) {
    // Reuse accept4 return logic
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (!args) return 0;

    struct sockaddr *addr = args->addr;
    bpf_map_delete_elem(&accept_args_map, &pid_tgid);

    if (ret < 0)
        return 0;

    __s32 new_fd = ret;
    struct sockaddr_in sin = {};
    if (addr) {
        bpf_probe_read_user(&sin, sizeof(sin), addr);
    }

    if (sin.sin_family != 2 && sin.sin_family != 0)
        return 0;

    struct conn_key ckey = {.pid = pid, .fd = new_fd};
    struct conn_val cval = {
        .addr = sin.sin_addr.s_addr,
        .port = bpf_ntohs(sin.sin_port),
        .dir = DIR_INBOUND,
    };
    bpf_map_update_elem(&conn_map, &ckey, &cval, BPF_ANY);

    struct olly_event *e = bpf_ringbuf_reserve(&events, sizeof(struct olly_event), 0);
    if (!e) return 0;

    e->event_type = EVENT_ACCEPT;
    e->pid = pid;
    e->tid = tid;
    e->fd = new_fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = sin.sin_addr.s_addr;
    e->remote_port = bpf_ntohs(sin.sin_port);
    e->direction = DIR_INBOUND;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// sys_write kprobe — outbound data + log capture
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_write")
int BPF_KPROBE(kprobe_write, int fd, const void *buf, size_t count) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;

    // Check if this is a tracked network connection
    struct conn_key ckey = {.pid = pid, .fd = fd};
    struct conn_val *conn = bpf_map_lookup_elem(&conn_map, &ckey);
    if (conn) {
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
int BPF_KPROBE(kprobe_sendto, int fd, const void *buf, size_t len,
               int flags, const struct sockaddr *dest_addr, int addrlen) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (!pid_allowed(pid))
        return 0;

    if (!is_tracked_conn(pid, fd))
        return 0;

    return emit_data_event(EVENT_DATA_OUT, pid, tid, fd, buf, (__u32)len);
}

// ──────────────────────────────────────────────────────────────────────
// sys_read kprobe + kretprobe — inbound data
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_read")
int BPF_KPROBE(kprobe_read, int fd, void *buf, size_t count) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    if (!is_tracked_conn(pid, fd))
        return 0;

    struct rw_args args = {};
    args.fd = fd;
    args.buf = buf;
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
    void *buf = args->buf;
    bpf_map_delete_elem(&rw_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    return emit_data_event(EVENT_DATA_IN, pid, tid, fd, buf, (__u32)ret);
}

// ──────────────────────────────────────────────────────────────────────
// sys_recvfrom kprobe + kretprobe — inbound data
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_recvfrom")
int BPF_KPROBE(kprobe_recvfrom, int fd, void *buf, size_t len,
               int flags, struct sockaddr *src_addr, int *addrlen) {
    if (!should_trace())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!pid_allowed(pid))
        return 0;

    if (!is_tracked_conn(pid, fd))
        return 0;

    struct rw_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.count = (__u32)len;
    bpf_map_update_elem(&rw_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_recvfrom")
int BPF_KRETPROBE(kretprobe_recvfrom, ssize_t ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct rw_args *args = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
    if (!args) return 0;

    __s32 fd = args->fd;
    void *buf = args->buf;
    bpf_map_delete_elem(&rw_args_map, &pid_tgid);

    if (ret <= 0)
        return 0;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    return emit_data_event(EVENT_DATA_IN, pid, tid, fd, buf, (__u32)ret);
}

// ──────────────────────────────────────────────────────────────────────
// sys_close kprobe — connection cleanup
// ──────────────────────────────────────────────────────────────────────

SEC("kprobe/sys_close")
int BPF_KPROBE(kprobe_close, int fd) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

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
    e->pid = pid;
    e->tid = tid;
    e->fd = fd;
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = 0;
    e->remote_port = 0;
    e->direction = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ──────────────────────────────────────────────────────────────────────
// SSL uprobes — plaintext capture before encryption / after decryption
// ──────────────────────────────────────────────────────────────────────

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
    args.buf = (void *)buf;
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

    void *buf = args->buf;
    __u32 len = args->len;
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
    args.buf = buf;
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

    void *buf = args->buf;
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
    e->pid = pid;
    e->tid = tid;
    e->fd = -1; // sentinel: not a real fd
    e->payload_len = 0;
    e->original_len = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->remote_addr = 0;
    e->remote_port = 0;
    e->direction = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
