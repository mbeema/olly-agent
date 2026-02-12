// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Author: Madhukar Beema, Distinguished Engineer

/*
 * libolly.c - LD_PRELOAD shared library for zero-instrumentation observability
 *
 * Hooks plaintext I/O (connect, send, recv, read, write, close) and
 * TLS plaintext (SSL_write, SSL_read) to capture traffic before encryption.
 *
 * Sends binary messages to the olly agent via Unix DGRAM socket.
 *
 * Safety guarantees:
 *   - Re-entrancy safe: thread-local guard prevents nested hook calls
 *   - Signal safe: lock-free connection table using atomics
 *   - FD reuse safe: generation counters detect stale entries
 *   - Non-blocking: agent socket is O_NONBLOCK, fire-and-forget
 *
 * Build: cc -shared -fPIC -O2 -o libolly.so libolly.c -ldl -lpthread
 * Usage: LD_PRELOAD=./libolly.so <command>
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#define GET_TID() ((uint32_t)syscall(SYS_gettid))
#elif defined(__APPLE__)
#include <pthread.h>
static uint32_t GET_TID(void) {
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
    return (uint32_t)tid;
}
#else
#define GET_TID() ((uint32_t)pthread_self())
#endif

/* ─── Re-entrancy guard ─────────────────────────────────────────── */
/*
 * Thread-local flag prevents nested hook calls.
 * When send_msg() calls the real sendto(), we must NOT re-intercept it.
 * Also prevents deadlocks if a signal handler calls a hooked function.
 */
static __thread int in_hook = 0;

#define HOOK_GUARD_ENTER() do { if (in_hook) goto passthrough; in_hook = 1; } while(0)
#define HOOK_GUARD_EXIT()  do { in_hook = 0; } while(0)

/* Raw syscall fallbacks for use before init completes (orig_* still NULL) */
#ifdef __linux__
#include <sys/syscall.h>
static inline int     raw_connect(int fd, const struct sockaddr *a, socklen_t l) { return syscall(SYS_connect, fd, a, l); }
static inline int     raw_accept(int fd, struct sockaddr *a, socklen_t *l)      { return syscall(SYS_accept, fd, a, l); }
static inline int     raw_accept4(int fd, struct sockaddr *a, socklen_t *l, int f) { return syscall(SYS_accept4, fd, a, l, f); }
static inline ssize_t raw_send(int fd, const void *buf, size_t n, int f)        { return syscall(SYS_sendto, fd, buf, n, f, NULL, 0); }
static inline ssize_t raw_recv(int fd, void *buf, size_t n, int f)              { return syscall(SYS_recvfrom, fd, buf, n, f, NULL, NULL); }
static inline ssize_t raw_write(int fd, const void *buf, size_t n)              { return syscall(SYS_write, fd, buf, n); }
static inline ssize_t raw_read(int fd, void *buf, size_t n)                     { return syscall(SYS_read, fd, buf, n); }
static inline ssize_t raw_sendto(int fd, const void *buf, size_t n, int f, const struct sockaddr *a, socklen_t l)
    { return syscall(SYS_sendto, fd, buf, n, f, a, l); }
static inline ssize_t raw_recvfrom(int fd, void *buf, size_t n, int f, struct sockaddr *a, socklen_t *l)
    { return syscall(SYS_recvfrom, fd, buf, n, f, a, l); }
static inline int     raw_close(int fd) { return syscall(SYS_close, fd); }
#endif

/* ─── Wire protocol ─────────────────────────────────────────────── */

#define MSG_CONNECT    1
#define MSG_DATA_OUT   2
#define MSG_DATA_IN    3
#define MSG_CLOSE      4
#define MSG_SSL_OUT    5
#define MSG_SSL_IN     6
#define MSG_ACCEPT     7
#define MSG_LOG_WRITE  8

#define MAX_PAYLOAD   (16 * 1024)
#define HEADER_SIZE   32

typedef struct __attribute__((packed)) {
    uint8_t  msg_type;
    uint8_t  _pad[3];
    uint32_t pid;
    uint32_t tid;
    int32_t  fd;
    uint32_t payload_len;
    uint32_t _reserved;    /* explicit padding to keep timestamp at offset 24 */
    uint64_t timestamp_ns;
} msg_header_t;

_Static_assert(sizeof(msg_header_t) == HEADER_SIZE, "header must be 32 bytes");

/* ─── Lock-free connection tracking ─────────────────────────────── */
/*
 * Uses atomic operations instead of mutexes for signal safety.
 * Each slot has a generation counter to detect fd reuse:
 *   - On connect: set generation = global_gen++, mark active
 *   - On data: check fd matches AND slot is active
 *   - On close: mark inactive, increment generation
 *   - New connect on same fd: old generation won't match
 */

#define MAX_CONNECTIONS 16384  /* power of 2 for hash masking */
#define CONN_HASH_MASK  (MAX_CONNECTIONS - 1)

typedef struct {
    _Atomic(int32_t)  fd;          /* -1 = empty */
    _Atomic(uint32_t) generation;  /* increments on each reuse */
    _Atomic(int)      active;      /* 1 = in use, 0 = free */
    uint16_t          remote_port; /* set once on connect, immutable after */
    uint32_t          remote_addr; /* set once on connect, immutable after */
    uint8_t           direction;   /* CONN_DIR_OUTBOUND or CONN_DIR_INBOUND */
} conn_slot_t;

#define CONN_DIR_OUTBOUND 0
#define CONN_DIR_INBOUND  1

static conn_slot_t conn_table[MAX_CONNECTIONS];
static _Atomic(uint32_t) global_generation = 0;

/* ─── Agent socket ──────────────────────────────────────────────── */

static int agent_sock = -1;
static struct sockaddr_un agent_addr;
static socklen_t agent_addr_len;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_once_t ssl_once  = PTHREAD_ONCE_INIT;
static int debug_enabled = 0;
#ifdef __linux__
static int urandom_fd = -1;
#endif

/* ─── On-demand tracing control (shared memory) ────────────────── */
/*
 * Zero-overhead dormant mode: the agent creates a shared memory file
 * and writes a single byte to enable/disable tracing. Each hooked
 * function checks this byte via mmap — a single L1-cache memory load
 * (~0.3ns). When the byte is 0, hooks pass through to the original
 * function with no further work. When no control file exists, tracing
 * is always active (backward compatible with agents that don't create it).
 */
static volatile uint8_t *g_control = NULL;
static int control_fd = -1;
#define CONTROL_FILE_SIZE 4096
#define DEFAULT_CONTROL_PATH "/var/run/olly/control"

#define DEFAULT_SOCKET_PATH "/var/run/olly/hook.sock"

/* ─── Log FD cache ──────────────────────────────────────────────── */
/*
 * Caches whether an fd points to a regular file or stdout/stderr.
 * Used by write() hook to decide whether to send MSG_LOG_WRITE.
 * Hash-indexed by fd, invalidated on close().
 */

#define LOG_FD_CACHE_SIZE 256
#define LOG_FD_CACHE_MASK (LOG_FD_CACHE_SIZE - 1)

#define LOG_FD_UNKNOWN   0  /* not yet classified */
#define LOG_FD_YES       1  /* regular file, stdout, or stderr */
#define LOG_FD_NO        2  /* socket, pipe, agent fd, etc. */

typedef struct {
    _Atomic(int32_t) fd;     /* cached fd value, -1 = empty */
    _Atomic(uint8_t) result; /* LOG_FD_UNKNOWN / YES / NO */
} log_fd_entry_t;

static log_fd_entry_t log_fd_cache[LOG_FD_CACHE_SIZE];

static inline uint32_t log_fd_hash(int fd) {
    return ((uint32_t)fd) & LOG_FD_CACHE_MASK;
}

/*
 * is_log_fd: Returns 1 if fd is a regular file, stdout, or stderr.
 * Uses cached result when available. First call does fstat (~200ns),
 * subsequent calls are ~2ns (cache lookup).
 */
static int is_log_fd(int fd) {
    /* stdout/stderr are always log FDs */
    if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
        return 1;

    /* Our internal fds are never log FDs */
    if (fd == agent_sock || fd == control_fd)
        return 0;
#ifdef __linux__
    if (fd == urandom_fd)
        return 0;
#endif

    uint32_t idx = log_fd_hash(fd);
    log_fd_entry_t *entry = &log_fd_cache[idx];

    int32_t cached_fd = atomic_load_explicit(&entry->fd, memory_order_acquire);
    if (cached_fd == fd) {
        uint8_t r = atomic_load_explicit(&entry->result, memory_order_relaxed);
        if (r != LOG_FD_UNKNOWN)
            return r == LOG_FD_YES;
    }

    /* Cache miss — classify with fstat */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        atomic_store_explicit(&entry->fd, (int32_t)fd, memory_order_relaxed);
        atomic_store_explicit(&entry->result, LOG_FD_NO, memory_order_release);
        return 0;
    }

    uint8_t result = S_ISREG(st.st_mode) ? LOG_FD_YES : LOG_FD_NO;
    atomic_store_explicit(&entry->fd, (int32_t)fd, memory_order_relaxed);
    atomic_store_explicit(&entry->result, result, memory_order_release);
    return result == LOG_FD_YES;
}

static void log_fd_cache_invalidate(int fd) {
    uint32_t idx = log_fd_hash(fd);
    log_fd_entry_t *entry = &log_fd_cache[idx];
    if (atomic_load(&entry->fd) == fd) {
        atomic_store_explicit(&entry->result, LOG_FD_UNKNOWN, memory_order_relaxed);
        atomic_store_explicit(&entry->fd, (int32_t)-1, memory_order_release);
    }
}

/* Async-signal-safe debug: uses write() not fprintf() */
static void dbg_write(const char *msg) {
    if (!debug_enabled) return;
    /* Use raw syscall to avoid re-entering our write() hook */
    const char prefix[] = "[olly-hook] ";
#ifdef __linux__
    (void)raw_write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
    (void)raw_write(STDERR_FILENO, msg, strlen(msg));
    (void)raw_write(STDERR_FILENO, "\n", 1);
#else
    (void)!write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
    (void)!write(STDERR_FILENO, msg, strlen(msg));
    (void)!write(STDERR_FILENO, "\n", 1);
#endif
}

/* ─── Shared memory control ────────────────────────────────────── */

/*
 * try_mmap_control: Map the control file into this process's address space.
 * The control file path is derived from OLLY_CONTROL env, or from the
 * socket directory (sibling of hook.sock), or the default path.
 */
static void try_mmap_control(void) {
    if (g_control) return;

    const char *path = getenv("OLLY_CONTROL");

    /* Derive from socket directory if not explicitly set */
    static char derived_path[256];
    if (!path) {
        const char *sock = getenv("OLLY_SOCKET");
        if (!sock) sock = DEFAULT_SOCKET_PATH;
        const char *slash = strrchr(sock, '/');
        if (slash && (size_t)(slash - sock) + 9 < sizeof(derived_path)) {
            memcpy(derived_path, sock, (size_t)(slash - sock));
            memcpy(derived_path + (size_t)(slash - sock), "/control", 9);
            path = derived_path;
        } else {
            path = DEFAULT_CONTROL_PATH;
        }
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        dbg_write("no control file (tracing always active)");
        return;
    }

    void *p = mmap(NULL, CONTROL_FILE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
#ifdef __linux__
        syscall(SYS_close, fd);
#else
        close(fd);
#endif
        return;
    }

    control_fd = fd;
    g_control = (volatile uint8_t *)p;
    dbg_write("control file mapped (on-demand mode)");
}

/*
 * olly_active: Check if tracing is currently enabled.
 * When no control file is mapped (legacy/standalone mode), returns 1 (always active).
 * When control file exists, returns its first byte (0=dormant, 1=active).
 * Cost: one NULL check + one memory load ≈ 0.3–1ns.
 */
static inline int olly_active(void) {
    return g_control == NULL || *(volatile uint8_t *)g_control;
}

/* ─── Original function pointers ────────────────────────────────── */

typedef int     (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int     (*accept_fn)(int, struct sockaddr *, socklen_t *);
#ifdef __linux__
typedef int     (*accept4_fn)(int, struct sockaddr *, socklen_t *, int);
#endif
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef int     (*close_fn)(int);

static connect_fn  orig_connect;
static accept_fn   orig_accept;
#ifdef __linux__
static accept4_fn  orig_accept4;
#endif
static send_fn     orig_send;
static recv_fn     orig_recv;
static write_fn    orig_write;
static read_fn     orig_read;
static sendto_fn   orig_sendto;
static recvfrom_fn orig_recvfrom;
static close_fn    orig_close;

/* SSL function pointers (resolved via pthread_once) */
typedef int (*ssl_write_fn)(void *, const void *, int);
typedef int (*ssl_read_fn)(void *, void *, int);
typedef int (*ssl_get_fd_fn)(const void *);

static ssl_write_fn  orig_ssl_write;
static ssl_read_fn   orig_ssl_read;
static ssl_get_fd_fn orig_ssl_get_fd;

/* ─── Helpers ───────────────────────────────────────────────────── */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void init_agent_socket(void) {
    debug_enabled = (getenv("OLLY_DEBUG") != NULL);

    const char *path = getenv("OLLY_SOCKET");
    if (!path) path = DEFAULT_SOCKET_PATH;

    agent_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (agent_sock < 0) {
        dbg_write("failed to create unix socket");
        return;
    }

    /* Non-blocking so we never stall the application */
    int flags = fcntl(agent_sock, F_GETFL, 0);
    fcntl(agent_sock, F_SETFL, flags | O_NONBLOCK);
    fcntl(agent_sock, F_SETFD, FD_CLOEXEC);

    memset(&agent_addr, 0, sizeof(agent_addr));
    agent_addr.sun_family = AF_UNIX;
    strncpy(agent_addr.sun_path, path, sizeof(agent_addr.sun_path) - 1);
    agent_addr_len = sizeof(agent_addr);

    dbg_write("socket initialized");

    /* Resolve original functions via RTLD_NEXT */
    orig_connect  = (connect_fn)dlsym(RTLD_NEXT, "connect");
    orig_accept   = (accept_fn)dlsym(RTLD_NEXT, "accept");
#ifdef __linux__
    orig_accept4  = (accept4_fn)dlsym(RTLD_NEXT, "accept4");
#endif
    orig_send     = (send_fn)dlsym(RTLD_NEXT, "send");
    orig_recv     = (recv_fn)dlsym(RTLD_NEXT, "recv");
    orig_write    = (write_fn)dlsym(RTLD_NEXT, "write");
    orig_read     = (read_fn)dlsym(RTLD_NEXT, "read");
    orig_sendto   = (sendto_fn)dlsym(RTLD_NEXT, "sendto");
    orig_recvfrom = (recvfrom_fn)dlsym(RTLD_NEXT, "recvfrom");
    orig_close    = (close_fn)dlsym(RTLD_NEXT, "close");

    /* Initialize log FD cache */
    for (int i = 0; i < LOG_FD_CACHE_SIZE; i++) {
        atomic_store_explicit(&log_fd_cache[i].fd, (int32_t)-1, memory_order_relaxed);
        atomic_store_explicit(&log_fd_cache[i].result, LOG_FD_UNKNOWN, memory_order_relaxed);
    }

    /* Initialize connection table */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        atomic_store_explicit(&conn_table[i].fd, -1, memory_order_relaxed);
        atomic_store_explicit(&conn_table[i].active, 0, memory_order_relaxed);
        atomic_store_explicit(&conn_table[i].generation, 0, memory_order_relaxed);
    }

#ifdef __linux__
    /* Cache /dev/urandom fd for trace ID generation */
    urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (urandom_fd < 0) {
        dbg_write("warning: cannot open /dev/urandom");
    }
#endif

    /* Map shared memory control file for on-demand tracing */
    try_mmap_control();
}

static _Atomic(int) init_state = 0; /* 0=not started, 1=in progress, 2=done */
static __thread int init_thread = 0; /* 1 if this thread is running init */

static void ensure_init(void) {
    if (atomic_load_explicit(&init_state, memory_order_acquire) == 2)
        return; /* fast path: already initialized */
    if (init_thread)
        return; /* re-entrant call from init_agent_socket on this thread */
    int expected = 0;
    if (atomic_compare_exchange_strong(&init_state, &expected, 1)) {
        init_thread = 1;
        init_agent_socket();
        init_thread = 0;
        atomic_store_explicit(&init_state, 2, memory_order_release);
    } else {
        /* Another thread is initializing; spin-wait */
        while (atomic_load_explicit(&init_state, memory_order_acquire) != 2)
            ;
    }
}

static void resolve_ssl_once(void) {
    void *ssl_handle = NULL;

#ifdef __linux__
    const char *ssl_libs[] = {
        "libssl.so.3", "libssl.so.1.1", "libssl.so.1.0.0", "libssl.so", NULL
    };
#elif defined(__APPLE__)
    const char *ssl_libs[] = {
        "libssl.3.dylib", "libssl.1.1.dylib", "libssl.dylib", NULL
    };
#else
    const char *ssl_libs[] = { NULL };
#endif

    for (int i = 0; ssl_libs[i]; i++) {
        ssl_handle = dlopen(ssl_libs[i], RTLD_NOLOAD | RTLD_NOW);
        if (ssl_handle) {
            dbg_write("found SSL library");
            break;
        }
    }

    if (!ssl_handle) {
        dbg_write("no SSL library found");
        return;
    }

    orig_ssl_write  = (ssl_write_fn)dlsym(ssl_handle, "SSL_write");
    orig_ssl_read   = (ssl_read_fn)dlsym(ssl_handle, "SSL_read");
    orig_ssl_get_fd = (ssl_get_fd_fn)dlsym(ssl_handle, "SSL_get_fd");
}

static void resolve_ssl(void) {
    pthread_once(&ssl_once, resolve_ssl_once);
}

/*
 * send_msg: fire-and-forget message to agent.
 * Called with in_hook=1 so the sendto() inside won't recurse.
 */
static void send_msg(uint8_t type, int fd, const void *payload, uint32_t len) {
    if (agent_sock < 0 || !orig_sendto) return;

    if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;

    /* Stack-allocated buffer: header + payload */
    uint8_t buf[HEADER_SIZE + MAX_PAYLOAD];
    msg_header_t *hdr = (msg_header_t *)buf;

    hdr->msg_type     = type;
    hdr->_pad[0]      = 0;
    hdr->_pad[1]      = 0;
    hdr->_pad[2]      = 0;
    hdr->pid          = (uint32_t)getpid();
    hdr->tid          = GET_TID();
    hdr->fd           = (int32_t)fd;
    hdr->payload_len  = len;
    hdr->_reserved    = 0;
    hdr->timestamp_ns = now_ns();

    if (payload && len > 0) {
        memcpy(buf + HEADER_SIZE, payload, len);
    }

    /* Direct syscall-level sendto - in_hook=1 prevents re-interception */
    orig_sendto(agent_sock, buf, HEADER_SIZE + len, MSG_DONTWAIT,
                (struct sockaddr *)&agent_addr, agent_addr_len);
}

/* ─── Random number generation for trace context ────────────────── */

static void fill_random(uint8_t *buf, size_t len) {
#ifdef __APPLE__
    arc4random_buf(buf, len);
#else
    if (urandom_fd >= 0 && orig_read) {
        ssize_t r = orig_read(urandom_fd, buf, len);
        if (r == (ssize_t)len) return;
    }
    /* Fallback: LCG seeded with time+pid+tid */
    uint64_t seed = now_ns() ^ ((uint64_t)getpid() << 32) ^ (uint64_t)GET_TID();
    for (size_t i = 0; i < len; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(seed >> 33);
    }
#endif
}

static const char hex_lut[] = "0123456789abcdef";

static void bytes_to_hex(const uint8_t *bytes, int n, char *out) {
    for (int i = 0; i < n; i++) {
        out[i * 2]     = hex_lut[bytes[i] >> 4];
        out[i * 2 + 1] = hex_lut[bytes[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* Thread-local trace context generated per outbound HTTP request */
typedef struct {
    char trace_id[33];  /* 32 hex chars + NUL */
    char span_id[17];   /* 16 hex chars + NUL */
} trace_ctx_t;

static __thread trace_ctx_t tl_trace_ctx;

static void generate_trace_context(void) {
    uint8_t raw[24]; /* 16 bytes trace ID + 8 bytes span ID */
    fill_random(raw, 24);
    bytes_to_hex(raw, 16, tl_trace_ctx.trace_id);
    bytes_to_hex(raw + 16, 8, tl_trace_ctx.span_id);
}

/* ─── HTTP traceparent injection ────────────────────────────────── */

/* Check if buffer starts with an HTTP request method */
static int is_http_request(const void *buf, size_t len) {
    if (len < 16) return 0; /* minimum: "GET / HTTP/1.0\r\n" */
    const char *p = (const char *)buf;
    return (memcmp(p, "GET ",  4) == 0 ||
            memcmp(p, "POST ", 5) == 0 ||
            memcmp(p, "PUT ",  4) == 0 ||
            memcmp(p, "HEAD ", 5) == 0 ||
            memcmp(p, "DELE",  4) == 0 ||
            memcmp(p, "PATC",  4) == 0 ||
            memcmp(p, "OPTI",  4) == 0);
}

/* Find "\r\n\r\n" header terminator. Returns pointer to first \r or NULL. */
static const char *find_header_end(const void *buf, size_t len) {
    const char *p = (const char *)buf;
    if (len < 4) return NULL;
    for (size_t i = 0; i <= len - 4; i++) {
        if (p[i] == '\r' && p[i+1] == '\n' && p[i+2] == '\r' && p[i+3] == '\n') {
            return p + i;
        }
    }
    return NULL;
}

/* Case-insensitive check for existing "traceparent:" header */
static int has_traceparent(const void *buf, size_t len) {
    const char *p = (const char *)buf;
    if (len < 16) return 0;
    for (size_t i = 0; i + 15 < len; i++) {
        if (p[i] == '\r' && p[i+1] == '\n') {
            const char *h = p + i + 2;
            size_t remain = len - i - 2;
            if (remain >= 13 &&
                (h[0]  == 't' || h[0]  == 'T') &&
                (h[1]  == 'r' || h[1]  == 'R') &&
                (h[2]  == 'a' || h[2]  == 'A') &&
                (h[3]  == 'c' || h[3]  == 'C') &&
                (h[4]  == 'e' || h[4]  == 'E') &&
                (h[5]  == 'p' || h[5]  == 'P') &&
                (h[6]  == 'a' || h[6]  == 'A') &&
                (h[7]  == 'r' || h[7]  == 'R') &&
                (h[8]  == 'e' || h[8]  == 'E') &&
                (h[9]  == 'n' || h[9]  == 'N') &&
                (h[10] == 't' || h[10] == 'T') &&
                h[11] == ':') {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * try_inject_traceparent: If buf is an outbound HTTP request without a
 * traceparent header, returns a malloc'd buffer with the header injected
 * before the \r\n\r\n terminator. Sets *new_len to the new buffer size.
 * Returns NULL if no injection needed (caller uses original buffer).
 * Caller must free() the returned buffer.
 */
static uint8_t *try_inject_traceparent(const void *buf, size_t len, size_t *new_len) {
    if (!is_http_request(buf, len)) return NULL;

    const char *hdr_end = find_header_end(buf, len);
    if (!hdr_end) return NULL; /* headers incomplete in this buffer */

    size_t header_section = (size_t)(hdr_end - (const char *)buf) + 4;
    if (has_traceparent(buf, header_section)) return NULL;

    /* Generate fresh trace context for this request */
    generate_trace_context();

    /* Build: "traceparent: 00-{trace_id}-{span_id}-03\r\n"
     * = 16 + 32 + 1 + 16 + 5 = 70 chars + NUL = 71 bytes */
    char tp_hdr[128];
    int tp_len = snprintf(tp_hdr, sizeof(tp_hdr),
        "traceparent: 00-%s-%s-03\r\n",
        tl_trace_ctx.trace_id, tl_trace_ctx.span_id);
    if (tp_len <= 0 || (size_t)tp_len >= sizeof(tp_hdr)) return NULL;

    /*
     * Split at \r\n\r\n: insert new header between last header's \r\n
     * and the empty-line \r\n.
     *   prefix = everything up to and including the last header's \r\n
     *   suffix = empty-line \r\n + body
     */
    size_t prefix_len = (size_t)(hdr_end - (const char *)buf) + 2;
    const char *suffix_start = hdr_end + 2;
    size_t suffix_len = len - prefix_len;
    *new_len = prefix_len + (size_t)tp_len + suffix_len;

    uint8_t *result = (uint8_t *)malloc(*new_len);
    if (!result) return NULL;

    memcpy(result, buf, prefix_len);
    memcpy(result + prefix_len, tp_hdr, (size_t)tp_len);
    memcpy(result + prefix_len + (size_t)tp_len, suffix_start, suffix_len);

    dbg_write("injected traceparent header");
    return result;
}

/* ─── Lock-free connection table ────────────────────────────────── */

/* Hash fd to a starting slot index */
static inline uint32_t conn_hash(int fd) {
    return ((uint32_t)fd * 2654435761U) & CONN_HASH_MASK;
}

/*
 * track_connect: register a new connection. Returns slot generation.
 * Uses linear probing from hash(fd).
 * direction: CONN_DIR_OUTBOUND (connect) or CONN_DIR_INBOUND (accept)
 */
static uint32_t track_connect(int fd, uint32_t addr, uint16_t port, uint8_t direction) {
    uint32_t gen = atomic_fetch_add(&global_generation, 1);
    uint32_t start = conn_hash(fd);

    for (uint32_t i = 0; i < MAX_CONNECTIONS; i++) {
        uint32_t idx = (start + i) & CONN_HASH_MASK;
        conn_slot_t *slot = &conn_table[idx];

        int expected_active = 0;
        if (atomic_compare_exchange_strong(&slot->active, &expected_active, 1)) {
            /* Claimed an empty slot */
            slot->remote_port = port;
            slot->remote_addr = addr;
            slot->direction = direction;
            atomic_store(&slot->fd, (int32_t)fd);
            atomic_store_explicit(&slot->generation, gen, memory_order_release);
            return gen;
        }

        /* Also claim slots with the same fd (fd reuse - overwrite stale entry) */
        int32_t existing_fd = atomic_load(&slot->fd);
        if (existing_fd == fd) {
            slot->remote_port = port;
            slot->remote_addr = addr;
            slot->direction = direction;
            atomic_store_explicit(&slot->generation, gen, memory_order_release);
            atomic_store(&slot->active, 1);
            return gen;
        }
    }

    /* Table full - drop silently */
    return 0;
}

/* Find the active slot for an fd. Returns NULL if not found. */
static conn_slot_t *find_conn(int fd) {
    uint32_t start = conn_hash(fd);

    for (uint32_t i = 0; i < 64; i++) {  /* limit probe distance */
        uint32_t idx = (start + i) & CONN_HASH_MASK;
        conn_slot_t *slot = &conn_table[idx];

        if (atomic_load_explicit(&slot->active, memory_order_acquire) &&
            atomic_load(&slot->fd) == fd) {
            return slot;
        }

        /* Empty slot means fd was never inserted at or beyond this point */
        if (!atomic_load(&slot->active) && atomic_load(&slot->fd) == -1) {
            break;
        }
    }
    return NULL;
}

/* Remove connection and return 1 if found, 0 if not. */
static int untrack_conn(int fd) {
    conn_slot_t *slot = find_conn(fd);
    if (slot) {
        atomic_store(&slot->active, 0);
        atomic_store(&slot->fd, (int32_t)-1);
        return 1;
    }
    return 0;
}

/*
 * try_discover_conn: Auto-discover a pre-existing socket connection.
 * When tracing activates on-demand, connections established while dormant
 * aren't in our table. On the first data event for such an fd, we call
 * getpeername() to discover it and register it.
 * Cost: ~200ns (getpeername + getsockname syscalls). Called once per fd.
 */
static conn_slot_t *try_discover_conn(int fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);

    if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0)
        return NULL;  /* Not a connected socket (file, pipe, etc.) */

    uint32_t ip = 0;
    uint16_t port = 0;
    uint16_t nport = 0;

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&ss;
        ip = in->sin_addr.s_addr;
        port = ntohs(in->sin_port);
        nport = in->sin_port;
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
        port = ntohs(in6->sin6_port);
        nport = in6->sin6_port;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
            memcpy(&ip, &in6->sin6_addr.s6_addr[12], 4);
    } else {
        return NULL;  /* Unix socket or other unsupported family */
    }

    /* Direction heuristic: if remote port is in the ephemeral range (>=32768)
     * and our local port is low (<32768), we're likely a server (inbound).
     * This correctly handles: app→DB:5432 (outbound), client→app:8080 (inbound). */
    uint8_t direction = CONN_DIR_OUTBOUND;
    struct sockaddr_storage local_ss;
    socklen_t local_len = sizeof(local_ss);
    if (getsockname(fd, (struct sockaddr *)&local_ss, &local_len) == 0) {
        uint16_t local_port = 0;
        if (local_ss.ss_family == AF_INET)
            local_port = ntohs(((struct sockaddr_in *)&local_ss)->sin_port);
        else if (local_ss.ss_family == AF_INET6)
            local_port = ntohs(((struct sockaddr_in6 *)&local_ss)->sin6_port);
        if (port >= 32768 && local_port > 0 && local_port < 32768)
            direction = CONN_DIR_INBOUND;
    }

    track_connect(fd, ip, port, direction);

    /* Notify agent of the discovered connection */
    uint8_t payload[6];
    memcpy(payload, &ip, 4);
    memcpy(payload + 4, &nport, 2);
    send_msg(direction == CONN_DIR_INBOUND ? MSG_ACCEPT : MSG_CONNECT,
             fd, payload, 6);

    dbg_write("discovered pre-existing connection");
    return find_conn(fd);
}

/* ─── Hooked functions ──────────────────────────────────────────── */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    ensure_init();
    if (!orig_connect) return raw_connect(sockfd, addr, addrlen);
    if (!olly_active()) goto passthrough;

    /* Always call the real connect first */
    int ret = orig_connect(sockfd, addr, addrlen);

    /* Only track successful connections (0 or EINPROGRESS for non-blocking) */
    if (ret != 0 && errno != EINPROGRESS) {
        return ret;
    }

    HOOK_GUARD_ENTER();

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint16_t port = ntohs(in->sin_port);
        uint32_t ip = in->sin_addr.s_addr;

        track_connect(sockfd, ip, port, CONN_DIR_OUTBOUND);

        /* Send connect info: 4 bytes IP + 2 bytes port (network order) */
        uint8_t payload[6];
        memcpy(payload, &ip, 4);
        memcpy(payload + 4, &in->sin_port, 2);
        send_msg(MSG_CONNECT, sockfd, payload, 6);

    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        uint16_t port = ntohs(in6->sin6_port);

        uint32_t ip = 0;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            memcpy(&ip, &in6->sin6_addr.s6_addr[12], 4);
        }

        track_connect(sockfd, ip, port, CONN_DIR_OUTBOUND);

        uint8_t payload[6];
        memcpy(payload, &ip, 4);
        memcpy(payload + 4, &in6->sin6_port, 2);
        send_msg(MSG_CONNECT, sockfd, payload, 6);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : raw_connect(sockfd, addr, addrlen);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    ensure_init();
    if (!orig_accept) return raw_accept(sockfd, addr, addrlen);
    if (!olly_active()) goto passthrough;

    int ret = orig_accept(sockfd, addr, addrlen);
    if (ret < 0) {
        return ret;
    }

    HOOK_GUARD_ENTER();

    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint16_t port = ntohs(in->sin_port);
        uint32_t ip = in->sin_addr.s_addr;

        track_connect(ret, ip, port, CONN_DIR_INBOUND);

        uint8_t payload[6];
        memcpy(payload, &ip, 4);
        memcpy(payload + 4, &in->sin_port, 2);
        send_msg(MSG_ACCEPT, ret, payload, 6);

    } else if (addr && addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        uint16_t port = ntohs(in6->sin6_port);

        uint32_t ip = 0;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            memcpy(&ip, &in6->sin6_addr.s6_addr[12], 4);
        }

        track_connect(ret, ip, port, CONN_DIR_INBOUND);

        uint8_t payload[6];
        memcpy(payload, &ip, 4);
        memcpy(payload + 4, &in6->sin6_port, 2);
        send_msg(MSG_ACCEPT, ret, payload, 6);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_accept ? orig_accept(sockfd, addr, addrlen) : raw_accept(sockfd, addr, addrlen);
}

#ifdef __linux__
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    ensure_init();
    if (!orig_accept4) return raw_accept4(sockfd, addr, addrlen, flags);
    if (!olly_active()) goto passthrough;

    int ret = orig_accept4(sockfd, addr, addrlen, flags);
    if (ret < 0) {
        return ret;
    }

    HOOK_GUARD_ENTER();

    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        uint16_t port = ntohs(in->sin_port);
        uint32_t ip = in->sin_addr.s_addr;

        track_connect(ret, ip, port, CONN_DIR_INBOUND);

        uint8_t payload[6];
        memcpy(payload, &ip, 4);
        memcpy(payload + 4, &in->sin_port, 2);
        send_msg(MSG_ACCEPT, ret, payload, 6);

    } else if (addr && addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        uint16_t port = ntohs(in6->sin6_port);

        uint32_t ip = 0;
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            memcpy(&ip, &in6->sin6_addr.s6_addr[12], 4);
        }

        track_connect(ret, ip, port, CONN_DIR_INBOUND);

        uint8_t payload[6];
        memcpy(payload, &ip, 4);
        memcpy(payload + 4, &in6->sin6_port, 2);
        send_msg(MSG_ACCEPT, ret, payload, 6);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_accept4 ? orig_accept4(sockfd, addr, addrlen, flags) : raw_accept4(sockfd, addr, addrlen, flags);
}
#endif

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    ensure_init();
    if (!orig_send) return raw_send(sockfd, buf, len, flags);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    conn_slot_t *conn = find_conn(sockfd);
    if (!conn) conn = try_discover_conn(sockfd);
    const void *send_buf = buf;
    size_t send_len = len;
    uint8_t *injected = NULL;

    /* Inject traceparent only on outbound connections */
    if (conn && conn->direction == CONN_DIR_OUTBOUND) {
        injected = try_inject_traceparent(buf, len, &send_len);
        if (injected) send_buf = injected;
    }

    ssize_t ret = orig_send(sockfd, send_buf, send_len, flags);

    if (injected) {
        /* Retry remaining bytes if partial send of injected buffer */
        if (ret > 0 && (size_t)ret < send_len) {
            size_t sent = (size_t)ret;
            while (sent < send_len) {
                ssize_t n = orig_send(sockfd, send_buf + sent, send_len - sent, flags);
                if (n <= 0) break;
                sent += (size_t)n;
            }
            ret = (ssize_t)sent;
        }
        if (ret > 0 && conn) {
            uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
            send_msg(MSG_DATA_OUT, sockfd, send_buf, cap);
        }
        free(injected);
        HOOK_GUARD_EXIT();
        return (ret > 0) ? (ssize_t)len : ret;
    }

    if (ret > 0 && conn) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_DATA_OUT, sockfd, send_buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_send ? orig_send(sockfd, buf, len, flags) : raw_send(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    ensure_init();
    if (!orig_recv) return raw_recv(sockfd, buf, len, flags);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    ssize_t ret = orig_recv(sockfd, buf, len, flags);
    if (ret > 0 && (find_conn(sockfd) || try_discover_conn(sockfd))) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_DATA_IN, sockfd, buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_recv ? orig_recv(sockfd, buf, len, flags) : raw_recv(sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    ensure_init();
    if (!orig_write) return raw_write(fd, buf, count);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    conn_slot_t *conn = find_conn(fd);
    if (!conn) conn = try_discover_conn(fd);
    const void *write_buf = buf;
    size_t write_len = count;
    uint8_t *injected = NULL;

    if (conn && conn->direction == CONN_DIR_OUTBOUND) {
        injected = try_inject_traceparent(buf, count, &write_len);
        if (injected) write_buf = injected;
    }

    ssize_t ret = orig_write(fd, write_buf, write_len);

    if (injected) {
        /* Retry remaining bytes if partial write of injected buffer */
        if (ret > 0 && (size_t)ret < write_len) {
            size_t written = (size_t)ret;
            while (written < write_len) {
                ssize_t n = orig_write(fd, (const uint8_t *)write_buf + written, write_len - written);
                if (n <= 0) break;
                written += (size_t)n;
            }
            ret = (ssize_t)written;
        }
        if (ret > 0 && conn) {
            uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
            send_msg(MSG_DATA_OUT, fd, write_buf, cap);
        }
        free(injected);
        HOOK_GUARD_EXIT();
        return (ret > 0) ? (ssize_t)count : ret;
    }

    if (ret > 0 && conn) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_DATA_OUT, fd, write_buf, cap);
    }

    /* R6: Capture log writes to regular files and stdout/stderr */
    if (!conn && ret > 0 && is_log_fd(fd)) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_LOG_WRITE, fd, buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_write ? orig_write(fd, buf, count) : raw_write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    ensure_init();
    if (!orig_read) return raw_read(fd, buf, count);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    ssize_t ret = orig_read(fd, buf, count);
    if (ret > 0 && (find_conn(fd) || try_discover_conn(fd))) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_DATA_IN, fd, buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_read ? orig_read(fd, buf, count) : raw_read(fd, buf, count);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    ensure_init();
    if (!orig_sendto) return raw_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    conn_slot_t *conn = find_conn(sockfd);
    if (!conn) conn = try_discover_conn(sockfd);
    const void *send_buf = buf;
    size_t send_len = len;
    uint8_t *injected = NULL;

    if (conn && conn->direction == CONN_DIR_OUTBOUND) {
        injected = try_inject_traceparent(buf, len, &send_len);
        if (injected) send_buf = injected;
    }

    ssize_t ret = orig_sendto(sockfd, send_buf, send_len, flags, dest_addr, addrlen);

    if (injected) {
        /* For injected buffers on connected sockets, retry partial sends */
        if (ret > 0 && (size_t)ret < send_len) {
            size_t sent = (size_t)ret;
            while (sent < send_len) {
                ssize_t n = orig_sendto(sockfd, (const uint8_t *)send_buf + sent,
                                        send_len - sent, flags, NULL, 0);
                if (n <= 0) break;
                sent += (size_t)n;
            }
            ret = (ssize_t)sent;
        }
        if (ret > 0 && conn) {
            uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
            send_msg(MSG_DATA_OUT, sockfd, send_buf, cap);
        }
        free(injected);
        HOOK_GUARD_EXIT();
        return (ret > 0) ? (ssize_t)len : ret;
    }

    if (ret > 0 && conn) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_DATA_OUT, sockfd, send_buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_sendto ? orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen)
                       : raw_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    ensure_init();
    if (!orig_recvfrom) return raw_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    ssize_t ret = orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (ret > 0 && (find_conn(sockfd) || try_discover_conn(sockfd))) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_DATA_IN, sockfd, buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_recvfrom ? orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
                         : raw_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

int close(int fd) {
    ensure_init();
    if (!orig_close) return raw_close(fd);
    if (!olly_active()) goto passthrough;
    HOOK_GUARD_ENTER();

    if (untrack_conn(fd)) {
        send_msg(MSG_CLOSE, fd, NULL, 0);
    }

    /* Invalidate log FD cache on close */
    log_fd_cache_invalidate(fd);

    HOOK_GUARD_EXIT();
    return orig_close(fd);

passthrough:
    return orig_close ? orig_close(fd) : raw_close(fd);
}

/* ─── SSL hooks ─────────────────────────────────────────────────── */

int SSL_write(void *ssl, const void *buf, int num) {
    ensure_init();
    resolve_ssl();

    if (!orig_ssl_write) {
        errno = ENOSYS;
        return -1;
    }
    if (!olly_active()) goto passthrough;

    HOOK_GUARD_ENTER();

    int fd = -1;
    if (orig_ssl_get_fd) {
        fd = orig_ssl_get_fd(ssl);
    }

    const void *write_buf = buf;
    int write_num = num;
    uint8_t *injected = NULL;

    /* Inject traceparent on outbound SSL connections */
    if (fd >= 0) {
        conn_slot_t *conn = find_conn(fd);
        if (!conn) conn = try_discover_conn(fd);
        if (conn && conn->direction == CONN_DIR_OUTBOUND) {
            size_t new_len;
            injected = try_inject_traceparent(buf, (size_t)num, &new_len);
            if (injected) {
                write_buf = injected;
                write_num = (int)new_len;
            }
        }
    }

    int ret = orig_ssl_write(ssl, write_buf, write_num);
    if (ret > 0) {
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_SSL_OUT, fd, write_buf, cap);
    }

    if (injected) {
        free(injected);
        HOOK_GUARD_EXIT();
        return (ret > 0) ? num : ret;
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_ssl_write(ssl, buf, num);
}

int SSL_read(void *ssl, void *buf, int num) {
    ensure_init();
    resolve_ssl();

    if (!orig_ssl_read) {
        errno = ENOSYS;
        return -1;
    }
    if (!olly_active()) goto passthrough;

    HOOK_GUARD_ENTER();

    int ret = orig_ssl_read(ssl, buf, num);
    if (ret > 0) {
        int fd = -1;
        if (orig_ssl_get_fd) {
            fd = orig_ssl_get_fd(ssl);
        }
        if (fd >= 0 && !find_conn(fd))
            try_discover_conn(fd);
        uint32_t cap = (uint32_t)(ret < MAX_PAYLOAD ? ret : MAX_PAYLOAD);
        send_msg(MSG_SSL_IN, fd, buf, cap);
    }

    HOOK_GUARD_EXIT();
    return ret;

passthrough:
    return orig_ssl_read(ssl, buf, num);
}

/* ─── Constructor / Destructor ──────────────────────────────────── */

__attribute__((constructor))
static void olly_init(void) {
    /* Do NOT call ensure_init() here: on some glibc versions (Amazon Linux 2023),
     * dlsym(RTLD_NEXT, ...) during constructor execution deadlocks because the
     * dynamic linker lock is still held. Lazy init via ensure_init() in each
     * hook function is safe because those are called after ld.so is done. */
}

__attribute__((destructor))
static void olly_fini(void) {
    /* Unmap shared memory control file */
    if (g_control) {
        munmap((void *)g_control, CONTROL_FILE_SIZE);
        g_control = NULL;
    }
    if (control_fd >= 0) {
#ifdef __linux__
        if (orig_close) orig_close(control_fd);
        else raw_close(control_fd);
#else
        if (orig_close) orig_close(control_fd);
#endif
        control_fd = -1;
    }

#ifdef __linux__
    if (urandom_fd >= 0 && orig_close) {
        orig_close(urandom_fd);
        urandom_fd = -1;
    }
#endif
    if (agent_sock >= 0 && orig_close) {
        orig_close(agent_sock);
        agent_sock = -1;
    }
    dbg_write("library unloaded");
}
