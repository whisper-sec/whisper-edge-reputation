/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * A server module is never a trace build: WE_TRACE compiles the core's read hooks and admits the
 * WE_TEST_* policy mutants, which are the test harnesses' alone (the policy core's guard refuses them
 * only outside WE_TRACE), so a module built with it could carry a planted defect unrefused.
 */
#ifdef WE_TRACE
#error "a server module is never built with WE_TRACE, the test harnesses' build that admits the WE_TEST_* mutants"
#endif
/*
 * mod_whisper_edge.c - the LiteSpeed / OpenLiteSpeed module over the Whisper edge policy core.
 *
 * WHY THIS IS A SEPARATE MODULE AND NOT THE APACHE ONE. LiteSpeed Enterprise reads Apache
 * configuration directives, which makes it easy to assume it also loads Apache modules. It does not:
 * there is no httpd module ABI in it. Both LiteSpeed Enterprise and OpenLiteSpeed load modules
 * through LSIAPI, which is a different API with a different lifecycle. Shipping the Apache .so and
 * telling people it works would be a recipe that fails on their machine, so this is a real module.
 *
 * WHAT IT SPEAKS. The policy language: `whisper_edge_policy <rule>`, `whisper_edge_set @name
 * members`, `whisper_edge_policy_floor <rule>`, `whisper_edge_data <directory>`, and the old
 * directives (`whisper_edge_snapshot`, `_mode`, `_threshold`, `_allow_inferred`) as sugar over the
 * same compiled programs. The language, its compiler and its evaluator are the core's (POLICY.md);
 * this file knows where OpenLiteSpeed hooks, how it hands a module its configuration and its request,
 * how to log, and how to schedule the one thread that does the module's file work.
 *
 * THE LIFECYCLE, AS MEASURED ON OPENLITESPEED 1.9.3 (never assumed). The main process parses the
 * server-level block (parse_config), runs init, parses every virtual host's block (parse_config per
 * host, the context level never reaches a module), then runs MAIN_INITED once, and only then forks the
 * workers (MAIN_PREFORK and MAIN_POSTFORK once per worker, WORKER_INIT inside each). So:
 *
 *   parse_config   records what was written, refuses what cannot be right at once (a second definition
 *                  of a single-valued key, a status outside the allow-list, a header name that is not a
 *                  token), and compiles nothing;
 *   MAIN_INITED    compiles the WHOLE configuration once (every host's lines after the server's; a
 *                  context whose lines are refused runs the empty program and is logged, the rest
 *                  stand), builds the request path's configuration in a read-only arena, binds the
 *                  planes (verified by the main process before any fork, decision 7), prints the
 *                  configuration-time lines and seals the arena;
 *   WORKER_INIT    the worker-start check, the counter shard, the module's thread (the status, counter
 *                  and configuration files, the plane jobs) and the 100 ms poll that applies the
 *                  thread's results on the loop, which is the planes' single writer here;
 *   HTTP_AUTH      the decision, through one `noinline` wrapper the gate disassembles out of the built
 *                  object; everything else per request (the walk, the record, the exported values, the
 *                  response) is outside it;
 *   WORKER_ATEXIT  the thread's stop, bounded by a deadline, so the counts since the last tick are
 *                  written on a graceful restart (every old worker runs it, measured) and on a stop.
 *
 * ONE HONEST DIFFERENCE FROM THE OTHER TWO. LSIAPI hands a module the client address as a STRING
 * (get_client_ip), so this module pays one inet_pton per request, outside the gated function. The module
 * judges the address the server reports; it trusts only an explicit `useIpInProxyHeader 0`: any other
 * setting, or none, and it says so at ERROR and marks its status.
 *
 * THE GRANULARITY IS SERVER AND VIRTUAL HOST. A per-context module block is read by the server's
 * configuration parser and never reaches a module's parse_config (measured, again, on 1.9.3; the
 * server's own source has had context-level module enabling disabled since 2018). LSI_CFG_CONTEXT is
 * declared on the keys because it costs nothing if a later release honours it; the documentation
 * promises server and virtual host.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "ls.h"

/*
 * The server's API table. The LSIAPI header declares its pointer thread-local (`extern __thread const lsi_api_t
 * *g_api`), so every use in a shared object is a TLS access: on x86_64 a call to __tls_get_addr, which may allocate
 * on a thread's first use, and on aarch64 a TLSDESC indirect call. The table is one per server, so the module reads
 * the pointer once, at its configuration-time entry points (init, the configuration parser, main and worker init),
 * into this plain pointer, and the request path never touches thread-local storage. The module's own thread, where
 * the server never set its thread-local copy, reads the same table.
 */
static const lsi_api_t *ls_api;

static void ls_api_bind(void)
{
    if (ls_api == NULL) {
        ls_api = g_api;
    }
}
#include "lsr/ls_xpool.h"

#include "whisper_edge.h"
#include "we_policy.h"
#include "we_eval.h"
#include "we_module.h"
#include "we_procid.h"

#define MNAME mod_whisper_edge
lsi_module_t MNAME;

/*
 * THE GATE'S CONTROLS, this module's own: each plants one known defect a named gate row must catch, and
 * none may reach a shipped module, so every one is refused outside a control build.
 *   WE_LS_TEST_MODE_OFF_RETURN  the pin's early return on a mode-off context, which skipped the floor
 *   WE_LS_TEST_DROP_NOSTORE     a deny without Cache-Control: no-store
 *   WE_LS_TEST_NO_EXIT_FLUSH    an exit that does not stop the thread, so the counts since the last tick are lost
 *   WE_LS_TEST_LATE_BUILD       a virtual host's block arriving in a worker after the configuration was built (the
 *                               late build the server never produces on 1.9.3, measured; the gate's row needs one)
 *   WE_LS_TEST_DUP_LOG          the planes' lines written through a descriptor of the error log opened at worker start
 *                               instead of the server's log call, so a line after a roll lands in the rolled file
 *   WE_LS_TEST_NO_UNREADABLE_FIELD  the configuration file written with no `unreadable` field, so a plane the
 *                               configuration reader could not open reads as a bare path
 *   WE_LS_TEST_FLAT_STOP        the exit's flat 2 s stop in place of the core's bounded one, so the abandonment line
 *                               names no stage
 * and two the core's guard list declares for this server:
 *   WE_MOD_TEST_LEGACY_HOLD     a seam, not a defect: the thread's writer runs a test hook between loading the live
 *                               legacy counter set and writing it, so a test can publish twice inside one write
 *   WE_MOD_TEST_LEGACY_LOOP_FREES  the one-slot handoff the retired list replaced: a second publish frees the set the
 *                               first handed over, which the writer is still using (a use-after-free under the seam)
 * and one of the core's, by its name there:
 *   WE_MOD_TEST_INLINE_HANDLER  the decision frame inlines the evaluator instead of calling the wrapper, so a
 *                               second evaluation-site record lands outside the wrapper (the gate's H2 row)
 * and the syscall-count row's test build, which adds two calls and nothing else (below):
 *   WE_TEST_MARKERS             the HTTP_AUTH hook bracketed by two marker syscalls
 */
#if !defined(WE_MOD_CONTROL_BUILD) && (defined(WE_LS_TEST_MODE_OFF_RETURN) || defined(WE_LS_TEST_DROP_NOSTORE) \
                                        || defined(WE_LS_TEST_NO_EXIT_FLUSH) || defined(WE_LS_TEST_LATE_BUILD) \
                                        || defined(WE_LS_TEST_DUP_LOG) || defined(WE_LS_TEST_NO_UNREADABLE_FIELD) \
                                        || defined(WE_LS_TEST_FLAT_STOP) || defined(WE_TEST_MARKERS))
#error "the WE_LS_TEST_* controls and WE_TEST_MARKERS exist only in a gate's control build (WE_MOD_CONTROL_BUILD)"
#endif

/*
 * THE MARKERS of the gate's syscall-count row (a control build): the HTTP_AUTH hook is bracketed by two
 * system calls that do nothing (getpgid of a pid above PID_MAX_LIMIT, answered ESRCH), each carrying a
 * distinguishing argument, so a trace of the worker's loop thread attributes every call between them to
 * the module by position. errno is saved and restored, so the build differs from production by the two
 * calls alone. The exit hook is not a request handler and carries no marker.
 */
#ifdef WE_TEST_MARKERS
#include <sys/syscall.h>
#define LS_MARK(a)      do { int e_ = errno; (void) syscall(SYS_getpgid, (long) (a)); errno = e_; } while (0)
#define LS_MARK_ENTER() LS_MARK(0x7ffffffeL)
#define LS_MARK_EXIT()  LS_MARK(0x7ffffffdL)
#else
#define LS_MARK_ENTER() ((void) 0)
#define LS_MARK_EXIT()  ((void) 0)
#endif

#define LS_LOG_PFX           "[whisper_edge] "
#define LS_DEFAULT_REFRESH_MS 60000u
#define LS_POLL_MS            100u          /* the loop's poll of the thread's results: the handoff term */
#define LS_DEFAULT_STATUS     403u
#define LS_IOV_STACK          128           /* header lines read into the handler's own frame; more from the pool */
#define LS_DEFAULT_HDR_BYTES  32768u        /* OpenLiteSpeed's default maxReqHeaderSize, measured */
#define LS_SHORTEST_LINE      4u            /* `a:` CRLF, the shortest header line it accepts, measured */
#define LS_MAX_VHOSTS         8192u
#define LS_SERVER_STRING      "OpenLiteSpeed (LSIAPI " LSIAPI_VERSION_STRING ")"

/* ---------------------------------------------------------------------------------------------- */
/* The keys                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

enum {
    K_SNAPSHOT = 0, K_REFRESH, K_MODE, K_THRESHOLD, K_ALLOW_INFERRED, K_SUMMARY,
    K_POLICY, K_SET, K_FLOOR, K_DATA, K_DENY_STATUS, K_EXPORT,
    K_TRUSTED_PROXY, K_TRUSTED_HEADER, K_TRUSTED_HOPS,
    K_COUNT
};

/*
 * THE LEVELS ARE EXPLICIT, and the ids are non-zero: with 0 the server called parse_config for the
 * SERVER block only (measured). key_index is the array index, so the dispatch does not depend on the ids.
 */
/*
 * Every key is declared for every level, the http-only ones included: the server's parser drops a key
 * whose declared levels exclude the block it is written in BEFORE parse_config, silently (measured), and
 * an operator who writes whisper_edge_data in a virtual host must read a refusal, not silence. The level
 * is enforced here, by ls_parse_one, with the line that names the key and the level it belongs to.
 */
#define WE_ANY   (LSI_CFG_SERVER | LSI_CFG_VHOST | LSI_CFG_CONTEXT)

static lsi_config_key_t we_config_keys[] = {
    { "whisper_edge_snapshot",       K_SNAPSHOT       + 1, WE_ANY },
    { "whisper_edge_refresh",        K_REFRESH        + 1, WE_ANY },
    { "whisper_edge_mode",           K_MODE           + 1, WE_ANY },
    { "whisper_edge_threshold",      K_THRESHOLD      + 1, WE_ANY },
    { "whisper_edge_allow_inferred", K_ALLOW_INFERRED + 1, WE_ANY },
    { "whisper_edge_summary",        K_SUMMARY        + 1, WE_ANY },
    { "whisper_edge_policy",         K_POLICY         + 1, WE_ANY },
    { "whisper_edge_set",            K_SET            + 1, WE_ANY },
    { "whisper_edge_policy_floor",   K_FLOOR          + 1, WE_ANY },
    { "whisper_edge_data",           K_DATA           + 1, WE_ANY },
    { "whisper_edge_deny_status",    K_DENY_STATUS    + 1, WE_ANY },
    { "whisper_edge_export",         K_EXPORT         + 1, WE_ANY },
    { "whisper_edge_trusted_proxy",  K_TRUSTED_PROXY  + 1, WE_ANY },
    { "whisper_edge_trusted_header", K_TRUSTED_HEADER + 1, WE_ANY },
    { "whisper_edge_trusted_hops",   K_TRUSTED_HOPS   + 1, WE_ANY },
    { NULL, 0, 0 }
};

static const char *const ls_key_name[K_COUNT] = {
    "whisper_edge_snapshot", "whisper_edge_refresh", "whisper_edge_mode", "whisper_edge_threshold",
    "whisper_edge_allow_inferred", "whisper_edge_summary", "whisper_edge_policy", "whisper_edge_set",
    "whisper_edge_policy_floor", "whisper_edge_data", "whisper_edge_deny_status", "whisper_edge_export",
    "whisper_edge_trusted_proxy", "whisper_edge_trusted_header", "whisper_edge_trusted_hops"
};

/* ---------------------------------------------------------------------------------------------- */
/* What a configuration holds                                                                      */
/* ---------------------------------------------------------------------------------------------- */

/* one directive as written, for the compiler: its kind, its bytes and where it stood */
typedef struct {
    uint8_t   kind;        /* WE_DIR_* */
    uint32_t  ordinal;     /* its index among this block's module parameters, 1-based: the place a refusal names */
    uint8_t  *arg;
    size_t    len;
} ls_dir_t;

/* one context the module names: the server level, or one virtual host */
typedef struct ls_ctx {
    char           name[160];      /* the operator's: the virtual host's name; "server" for the server level */
    char           path[32];       /* the ordinal path the compiler is given: "http", "http/v1", ... */
    ls_dir_t      *d;
    size_t         n, cap;
    uint16_t       deny_status;    /* 0: the http level's */
    uint8_t        export_all, export_set;
    uint32_t       export_attrs;   /* bit i: attribute i named by whisper_edge_export */
    uint8_t        threshold;      /* the sugar level written here, 255 for none (row G1) */
    int            refused;
    char           refusal[768];
    uint32_t       index;          /* into the context arrays */
    we_mod_ctx_t  *ctx;            /* the request path's context, after the build */
} ls_ctx_t;

/* what get_config returns for a request: a handle to the context record, never the record itself */
typedef struct {
    ls_ctx_t *c;
} we_conf_t;

/* the http level's own directives, outside the compiler's source */
static struct {
    char      snapshot[PATH_MAX];
    char      data_dir[PATH_MAX];
    char      plane_file[8][PATH_MAX];  /* whisper_edge_data <plane> <file>: that plane's file, over the directory */
    uint32_t  plane_file_ordinal[8];    /* each plane's line, for the second-definition refusal */
    char      summary_dir[PATH_MAX];
    int       summary_off;
    unsigned  refresh_ms;
    char    **trusted;                  /* whisper_edge_trusted_proxy's entries, as many as are written */
    size_t    ntrusted, ctrusted;
    int       trust_refused;            /* a trust directive refused: the configuration is, and no program runs */
    char      trusted_header[128];
    uint32_t  trusted_hops;
    uint32_t  first_ordinal[K_COUNT];   /* the first definition's ordinal, for the second-definition refusal */
    int       floor_refused;
} g_http;

static ls_ctx_t   g_server;              /* the http level */
static ls_ctx_t  *g_vhost[LS_MAX_VHOSTS];
static uint32_t   g_nvhost;
static int        g_main_inited;         /* every parse_config call precedes it, measured */
static int        g_worker_init_seen;

/* the server's own settings, read from its configuration files at init (the main process, as root) */
static struct {
    char     root[PATH_MAX];
    char     main_conf[PATH_MAX];
    int      use_ip_in_proxy_header;     /* useIpInProxyHeader as configured; -1 unread */
    int      proxy_protocol;             /* a proxyProtocol key was found */
    char     proxy_protocol_line[256];
    int      unix_listener;              /* a listener block names a non-TCP address (uds:, unix: or a path) */
    uint32_t max_req_header_bytes;
    uid_t    worker_uid;
    uid_t    conf_owner;                 /* the owner of $SERVER_ROOT/conf: the admin account the module trusts */
    int      strict_failed;
    char     strict_why[512];
} g_srv;

/* the built configuration */
static we_mod_arena_t   *g_arena;
static we_policy_build_t *g_build;
static we_mod_cfg_t      g_cfg;
static we_mod_ctx_t     *g_ctxs;
static size_t            g_nctx;
static uint32_t          g_stride;
static uint8_t           g_bound_mask;    /* the planes with a handle after the bind: the only ones the export fill reads */
static uint64_t         *g_sink;
static we_mod_planes_t  *g_planes;
static we_mod_trust_t    g_trust;
static int               g_trust_built;
static int               g_built;
static char              g_config16[17];
static we_mod_ctrmap_entry_t *g_ctrmap_e;
static uint32_t          g_ctrmap_n;
static we_mod_text_t     g_conf_text;        /* the configuration file's bytes, rendered once */
static char              g_conf_name[29];
static uint8_t           g_hdr_line_bound_set;
static uint32_t          g_hdr_line_bound;

/* the attributes' environment names, WHISPER_EDGE_<NAME>, built once so the request path formats nothing */
static char              g_env_name[WE_MOD_ATTRS][40];
static unsigned          g_env_name_len[WE_MOD_ATTRS];

/* the worker */
static uint64_t         *g_shard;            /* this worker's; the sink when none could be allocated */
static we_mod_thread_t  *g_thread;
static int               g_no_thread, g_no_shard, g_late_build;
/* the virtual hosts whose configuration file fails the trust rule, read from the main file's virtualHost blocks */
static struct { char name[256]; char why[400]; } g_vh_strict[64];
static unsigned g_nvh_strict;

static we_procid_t       g_id;
static int               g_counters_dirfd = -1;
static int               g_counters_said;
static uint64_t          g_started_ms, g_last_written_ms, g_jitter_ms;
/*
 * The legacy snapshot's per-range counters. The loop builds a set for each generation it publishes and swaps
 * it in with a release store; the thread reads it with an acquire load to write it, so it never reads a set
 * whose contents it cannot yet see. A replaced set goes onto the retired list (a lock-free push by the loop) and
 * only the thread frees it, at the start of its tick, when it holds no set: the loop never frees one, because
 * the thread may still be writing the set it read before the swap. A replaced set's counts since the last tick
 * are not written: the counter file is named per process, not per generation, so the live set's next write
 * would replace it, and its own map may already be retired. A publish drops at most one interval of them.
 */
typedef struct ls_retired {
    we_counters_t     *set;
    struct ls_retired *next;
} ls_retired_t;
static we_counters_t    *g_legacy_counters;         /* the live set: loop stores (release), thread loads (acquire) */
static ls_retired_t     *g_legacy_retired;          /* the replaced sets, pushed by the loop, freed by the thread */
#ifdef WE_MOD_TEST_LEGACY_HOLD
static void (*ls_test_legacy_hold)(void);           /* the seam: run by the writer between loading the live set and using it */
#endif
static const we_map_t   *g_legacy_map;               /* the map the loop's counters were built for */
static int               g_timer_id = -1;
static uint64_t          g_would_deny, g_denied, g_would_at_last, g_denied_at_last;
static uint64_t          g_last_would_sec, g_last_deny_sec;
static char             *g_status_buf, *g_rules_buf;   /* the thread's buffers, allocated at its start */
static size_t            g_status_cap, g_rules_cap;
static uint64_t         *g_sum;                        /* the thread's copy of the shard */

/* ---------------------------------------------------------------------------------------------- */
/* Logging, time, small helpers                                                                    */
/* ---------------------------------------------------------------------------------------------- */

static void ls_log(int level, const char *fmt, ...)
{
    char line[2048];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    ls_api->log(NULL, level, LS_LOG_PFX "%s\n", line);
}

/* the configuration-time lines, one grammar on every server */
static void ls_policy_line(int level, const char *fmt, ...)
{
    char line[2048];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    ls_api->log(NULL, level, LS_LOG_PFX "whisper edge: policy: %s\n", line);
}

/* the request path's clock: the server's cached time, no syscall (lsiapilib's get_cur_time reads two words) */
static uint64_t ls_now_ms(void)
{
    int32_t usec = 0;
    time_t s = ls_api->get_cur_time(&usec);

    return (uint64_t) s * 1000ull + (uint64_t) (usec / 1000);
}

/* the thread's clock: the module's thread never calls the server's API (ls_api is a thread-local the server sets
 * for its own threads), and a status file's times are printed for people */
static uint64_t ls_wall_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t) ts.tv_sec * 1000ull + (uint64_t) ts.tv_nsec / 1000000ull;
}

static const char *ls_mode_word(const we_ctx_conf_t *c)
{
    switch (we_conf_mode(c)) {
    case WE_MODE_OFF:  return "off";
    case WE_MODE_DENY: return "deny";
    default:           return "log";
    }
}

/* the one rendering of a block's digest on every surface: its first eight bytes in byte order, lowercase hex */
static void ls_program_digest(const we_program_t *p, char out[17])
{
    uint8_t dg[32];

    if (p == NULL) {
        snprintf(out, 17, "-");
        return;
    }
    we_sha256(p, we_program_size(p), dg);
    we_digest16(dg, out);
}

static char *ls_escaped(const char *s, char *buf, size_t n)
{
    we_mod_escape(s, buf, n);
    return buf;
}

/* ---------------------------------------------------------------------------------------------- */
/* Parsing one block                                                                               */
/* ---------------------------------------------------------------------------------------------- */

static int ls_ctx_add(ls_ctx_t *c, uint8_t kind, uint32_t ordinal, const char *v, size_t len)
{
    ls_dir_t *d;

    if (c->n == c->cap) {
        size_t ncap = c->cap != 0u ? c->cap * 2u : 8u;
        ls_dir_t *nd = realloc(c->d, ncap * sizeof *nd);

        if (nd == NULL) {
            return -1;
        }
        c->d = nd;
        c->cap = ncap;
    }
    d = &c->d[c->n];
    d->kind = kind;
    d->ordinal = ordinal;
    d->arg = malloc(len + 1u);
    if (d->arg == NULL) {
        return -1;
    }
    memcpy(d->arg, v, len);
    d->arg[len] = '\0';
    d->len = len;
    c->n++;
    return 0;
}

static int ls_word_is(const char *v, size_t len, const char *w)
{
    return strlen(w) == len && strncasecmp(v, w, len) == 0;
}

/* the status allow-list: every other code is refused by its class, each reason ending `use 403` */
static const char *ls_status_refusal(long code)
{
    static char buf[256];

    switch (code) {
    case 400: case 403: case 404: case 406: case 409: case 410: case 413: case 415: case 422: case 428:
    case 429: case 451:
        return NULL;
    case 401: snprintf(buf, sizeof buf, "401 requires a WWW-Authenticate header, which this module does not send; use 403"); return buf;
    case 405: snprintf(buf, sizeof buf, "405 requires an Allow header, which this module does not send; use 403"); return buf;
    case 407: snprintf(buf, sizeof buf, "407 requires a Proxy-Authenticate header, which this module does not send; use 403"); return buf;
    case 426: snprintf(buf, sizeof buf, "426 requires an Upgrade header, which this module does not send; use 403"); return buf;
    case 416: snprintf(buf, sizeof buf, "416 requires a Content-Range header, which this module does not send; use 403"); return buf;
    case 408: case 411: case 417: case 421: case 431:
        snprintf(buf, sizeof buf, "%ld is not sent as written, or tells the client to change the request and send it again; use 403", code);
        return buf;
    case 412: case 414:
        snprintf(buf, sizeof buf, "%ld describes the request, not a decision; use 403", code);
        return buf;
    case 511: snprintf(buf, sizeof buf, "511 is another protocol role (a client reads it as a captive portal); use 403"); return buf;
    case 444: snprintf(buf, sizeof buf, "444 is nginx's close without a response, which this server has no way to send; use 403"); return buf;
    case 494: case 495: case 496: case 497: case 499:
        snprintf(buf, sizeof buf, "%ld is never on the wire as written (an nginx-internal code); use 403", code);
        return buf;
    case 402: snprintf(buf, sizeof buf, "402 is reserved (RFC 9110 section 15.5.3); use 403"); return buf;
    default:
        break;
    }
    if (code >= 500 && code <= 599) {
        snprintf(buf, sizeof buf, "a 5xx says the server failed (RFC 9110 section 15.6); balancers and health checks in "
                 "front (nginx proxy_next_upstream, HAProxy observe layer7, Envoy outlier detection) count it, retry it "
                 "and can eject this origin under denied traffic; use 403");
        return buf;
    }
    if (code < 400) {
        snprintf(buf, sizeof buf, "%ld is not an error status; use 403", code);
        return buf;
    }
    snprintf(buf, sizeof buf, "%ld is not a status RFC 9110 registers; use 403", code);
    return buf;
}

/* RFC 9110 section 5.1: a field name is a token */
static int ls_is_token(const char *v, size_t len)
{
    static const char tchar[] = "!#$%&'*+-.^_`|~";
    size_t i;

    if (len == 0u) {
        return 0;
    }
    for (i = 0u; i < len; i++) {
        unsigned char c = (unsigned char) v[i];

        if (!(isalnum(c) || strchr(tchar, (int) c) != NULL)) {
            return 0;
        }
    }
    return 1;
}

static int ls_attr_index(const char *v, size_t len)
{
    uint32_t i;

    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        const we_mod_attr_t *a = we_mod_attr(i);

        if (a != NULL && strlen(a->name) == len && memcmp(a->name, v, len) == 0) {
            return (int) i;
        }
    }
    return -1;
}

/* a single-valued http-level key written twice: refused naming both ordinals (the panel case) */
static int ls_second_definition(int key, uint32_t ordinal, const char *name)
{
    if (g_http.first_ordinal[key] != 0u) {
        ls_policy_line(LSI_LOG_ERROR, "%s: %s #%u is a second definition at the server level (the first is #%u); refused, "
                       "so that no later file can change what the first said", name, ls_key_name[key], ordinal,
                       g_http.first_ordinal[key]);
        return 1;
    }
    g_http.first_ordinal[key] = ordinal;
    return 0;
}

/*
 * A refused trust directive (whisper_edge_trusted_proxy, _header, _hops) refuses the configuration, as nginx and
 * Apache refuse it: dropping the line and serving would leave a skip mode or no header walk the operator did not
 * write. Each refusal says its own reason now; the build then runs no program, and every request is served (fail
 * open) until the line is fixed.
 */
static void ls_trust_refuse(const char *fmt, ...)
{
    char line[768];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    ls_policy_line(LSI_LOG_ERROR, "%s; the configuration is refused and the module runs no program until it is fixed",
                   line);
    g_http.trust_refused = 1;
}

static void ls_parse_one(ls_ctx_t *c, int key, uint32_t ordinal, const char *v, size_t len, int server_level)
{
    char e[640];
    const char *where = c->name;

    if (!server_level) {
        switch (key) {
        case K_SNAPSHOT: case K_REFRESH: case K_SUMMARY: case K_FLOOR: case K_DATA:
        case K_TRUSTED_PROXY: case K_TRUSTED_HEADER: case K_TRUSTED_HOPS:
            ls_policy_line(LSI_LOG_ERROR, "vhost %s: %s #%u: %s is http level only, so that no virtual host can change the "
                           "floor; the line is refused and the host's other lines stand", ls_escaped(c->name, e, sizeof e),
                           ls_key_name[key], ordinal, ls_key_name[key]);
            return;
        default:
            break;
        }
    }
    switch (key) {
    case K_POLICY:
        ls_ctx_add(c, WE_DIR_POLICY, ordinal, v, len);
        break;
    case K_SET:
        ls_ctx_add(c, WE_DIR_SET, ordinal, v, len);
        break;
    case K_FLOOR:
        ls_ctx_add(c, WE_DIR_FLOOR, ordinal, v, len);
        break;
    case K_MODE:
        if (server_level && ls_second_definition(key, ordinal, where)) {
            return;
        }
        if (ls_word_is(v, len, "off") || ls_word_is(v, len, "log") || ls_word_is(v, len, "deny")) {
            char w[8];

            snprintf(w, sizeof w, "%.*s", (int) len, v);
            for (size_t i = 0u; w[i] != '\0'; i++) { w[i] = (char) tolower((unsigned char) w[i]); }
            ls_ctx_add(c, WE_DIR_MODE, ordinal, w, strlen(w));
        } else {
            ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_mode #%u takes off, log or deny; \"%.*s\" is refused and the "
                           "context keeps the mode it inherits", ls_escaped(where, e, sizeof e), ordinal, (int) len, v);
        }
        break;
    case K_THRESHOLD: {
        static const char *const lv[5] = { "off", "low", "medium", "high", "critical" };
        unsigned i;

        if (server_level && ls_second_definition(key, ordinal, where)) {
            return;
        }
        for (i = 0u; i < 5u; i++) {
            if (ls_word_is(v, len, lv[i])) {
                ls_ctx_add(c, WE_DIR_THRESHOLD, ordinal, lv[i], strlen(lv[i]));
                c->threshold = (uint8_t) i;
                return;
            }
        }
        ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_threshold #%u takes off, low, medium, high or critical; \"%.*s\" is "
                       "refused", ls_escaped(where, e, sizeof e), ordinal, (int) len, v);
        break;
    }
    case K_ALLOW_INFERRED: {
        const char *w = NULL;

        if (server_level && ls_second_definition(key, ordinal, where)) {
            return;
        }
        /* liberal in what is accepted: on/1/true/yes and off/0/false/no, one spelling to the compiler */
        if (ls_word_is(v, len, "on") || ls_word_is(v, len, "1") || ls_word_is(v, len, "true") || ls_word_is(v, len, "yes")) {
            w = "on";
        } else if (ls_word_is(v, len, "off") || ls_word_is(v, len, "0") || ls_word_is(v, len, "false") || ls_word_is(v, len, "no")) {
            w = "off";
        }
        if (w != NULL) {
            ls_ctx_add(c, WE_DIR_ALLOW_INFERRED, ordinal, w, strlen(w));
        } else {
            ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_allow_inferred #%u takes on or off; \"%.*s\" is refused",
                           ls_escaped(where, e, sizeof e), ordinal, (int) len, v);
        }
        break;
    }
    case K_DENY_STATUS: {
        char *end = NULL;
        char tmp[16];
        long code;
        const char *why;

        if (server_level && ls_second_definition(key, ordinal, where)) {
            return;
        }
        snprintf(tmp, sizeof tmp, "%.*s", (int) (len < 15u ? len : 15u), v);
        code = strtol(tmp, &end, 10);
        if (end == tmp || *end != '\0' || len > 3u) {
            ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_deny_status #%u takes a status code; \"%.*s\" is refused; use 403",
                           ls_escaped(where, e, sizeof e), ordinal, (int) len, v);
            return;
        }
        why = ls_status_refusal(code);
        if (why != NULL) {
            ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_deny_status #%u: %s", ls_escaped(where, e, sizeof e), ordinal, why);
            return;
        }
        c->deny_status = (uint16_t) code;
        break;
    }
    case K_EXPORT: {
        size_t i = 0u;

        c->export_set = 1u;
        c->export_attrs = 0u;
        c->export_all = 0u;
        while (i < len) {
            size_t j;

            while (i < len && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) { i++; }
            j = i;
            while (j < len && v[j] != ' ' && v[j] != '\t' && v[j] != ',') { j++; }
            if (j == i) {
                break;
            }
            if (ls_word_is(v + i, j - i, "all")) {
                c->export_all = 1u;
            } else {
                int a = ls_attr_index(v + i, j - i);

                if (a < 0) {
                    ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_export #%u names \"%.*s\", which is not an attribute of "
                                   "the language; the name is refused and the others stand", ls_escaped(where, e, sizeof e),
                                   ordinal, (int) (j - i), v + i);
                } else {
                    c->export_attrs |= 1u << a;
                }
            }
            i = j;
        }
        break;
    }
    case K_SNAPSHOT:
        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        if (len > 0u && len < sizeof g_http.snapshot && v[0] == '/') {
            memcpy(g_http.snapshot, v, len);
            g_http.snapshot[len] = '\0';
        } else {
            ls_policy_line(LSI_LOG_ERROR, "server: whisper_edge_snapshot #%u needs an absolute path to snapshot.bin; \"%.*s\" "
                           "is refused", ordinal, (int) len, v);
        }
        break;
    case K_DATA: {
        size_t sp = 0u;

        while (sp < len && v[sp] != ' ' && v[sp] != '\t') { sp++; }
        if (sp < len) {
            /* the per-plane form, `whisper_edge_data <plane> <file>`: that plane's file, over the directory's */
            size_t f = sp;
            uint32_t p;

            while (f < len && (v[f] == ' ' || v[f] == '\t')) { f++; }
            for (p = 0u; p < 8u; p++) {
                const char *w = we_mod_plane_word(p);

                if (strlen(w) == sp && strncmp(w, v, sp) == 0) {
                    break;
                }
            }
            if (p == 8u) {
                ls_policy_line(LSI_LOG_ERROR, "server: whisper_edge_data #%u: \"%.*s\" names no plane; write whisper_edge_data "
                               "<plane> <file> with one of reputation, tor, rpki-unreachable, routing, anonymizer, threat, "
                               "registry, tenant, or whisper_edge_data <directory>", ordinal, (int) sp, v);
                return;
            }
            if (g_http.plane_file_ordinal[p] != 0u) {
                ls_policy_line(LSI_LOG_ERROR, "%s: whisper_edge_data #%u is a second definition of plane %s at the server level "
                               "(the first is #%u); refused, so that no later file can change what the first said", where,
                               ordinal, we_mod_plane_word(p), g_http.plane_file_ordinal[p]);
                return;
            }
            if (len - f < 2u || len - f >= sizeof g_http.plane_file[p] || v[f] != '/') {
                ls_policy_line(LSI_LOG_ERROR, "server: whisper_edge_data #%u: the %s file needs an absolute path; \"%.*s\" is "
                               "refused", ordinal, we_mod_plane_word(p), (int) (len - f), v + f);
                return;
            }
            g_http.plane_file_ordinal[p] = ordinal;
            memcpy(g_http.plane_file[p], v + f, len - f);
            g_http.plane_file[p][len - f] = '\0';
            break;
        }
        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        if (len > 1u && len < sizeof g_http.data_dir && v[0] == '/') {
            memcpy(g_http.data_dir, v, len);
            g_http.data_dir[len] = '\0';
            while (strlen(g_http.data_dir) > 1u && g_http.data_dir[strlen(g_http.data_dir) - 1u] == '/') {
                g_http.data_dir[strlen(g_http.data_dir) - 1u] = '\0';
            }
        } else {
            ls_policy_line(LSI_LOG_ERROR, "server: whisper_edge_data #%u needs an absolute directory; \"%.*s\" is refused",
                           ordinal, (int) len, v);
        }
        break;
    }
    case K_SUMMARY:
        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        if (ls_word_is(v, len, "off")) {
            g_http.summary_off = 1;
            g_http.summary_dir[0] = '\0';
        } else if (len > 0u && len < sizeof g_http.summary_dir && v[0] == '/') {
            memcpy(g_http.summary_dir, v, len);
            g_http.summary_dir[len] = '\0';
            g_http.summary_off = 0;
        } else {
            ls_policy_line(LSI_LOG_ERROR, "server: whisper_edge_summary #%u needs an absolute directory path, or off; \"%.*s\" "
                           "is refused", ordinal, (int) len, v);
        }
        break;
    case K_REFRESH: {
        char tmp[16];
        long secs;

        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        snprintf(tmp, sizeof tmp, "%.*s", (int) (len < 15u ? len : 15u), v);
        secs = strtol(tmp, NULL, 10);
        /* clamped rather than refused: a nonsense interval must not stop the module working */
        if (secs < 10) { secs = 10; }
        if (secs > 86400) { secs = 86400; }
        g_http.refresh_ms = (unsigned) secs * 1000u;
        break;
    }
    case K_TRUSTED_PROXY: {
        size_t i = 0u, before;

        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        before = g_http.ntrusted;
        /* split on whitespace alone, as Apache and nginx split it: a comma stays inside its entry, which the table
         * then refuses; and every entry written is kept, with no cap */
        for (;;) {
            size_t j;
            char *e1;

            while (i < len && (v[i] == ' ' || v[i] == '\t')) { i++; }
            if (i == len) {
                break;
            }
            j = i;
            while (j < len && v[j] != ' ' && v[j] != '\t') { j++; }
            if (g_http.ntrusted == g_http.ctrusted) {
                size_t nc = g_http.ctrusted != 0u ? g_http.ctrusted * 2u : 16u;
                char **nt = realloc(g_http.trusted, nc * sizeof *nt);

                if (nt == NULL) {
                    ls_trust_refuse("server: whisper_edge_trusted_proxy #%u: out of memory for entry %zu", ordinal,
                                    g_http.ntrusted + 1u);
                    return;
                }
                g_http.trusted = nt;
                g_http.ctrusted = nc;
            }
            e1 = malloc(j - i + 1u);
            if (e1 == NULL) {
                ls_trust_refuse("server: whisper_edge_trusted_proxy #%u: out of memory for entry %zu", ordinal,
                                g_http.ntrusted + 1u);
                return;
            }
            memcpy(e1, v + i, j - i);
            e1[j - i] = '\0';
            g_http.trusted[g_http.ntrusted++] = e1;
            i = j;
        }
        if (g_http.ntrusted == before) {
            ls_trust_refuse("server: whisper_edge_trusted_proxy #%u takes addresses, CIDR prefixes or unix:", ordinal);
        }
        break;
    }
    case K_TRUSTED_HEADER:
        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        if (!ls_is_token(v, len)) {
            ls_trust_refuse("server: whisper_edge_trusted_header #%u: a header name is a token (RFC 9110 section 5.1); "
                            "\"%.*s\" is refused", ordinal, (int) (len < 256u ? len : 256u), v);
            return;
        }
        if (ls_word_is(v, len, "forwarded")) {
            ls_trust_refuse("server: whisper_edge_trusted_header #%u: Forwarded uses the RFC 7239 syntax, which this module "
                            "does not read; name X-Forwarded-For, or a single-address header such as X-Real-IP", ordinal);
            return;
        }
        if (len >= sizeof g_http.trusted_header) {
            ls_trust_refuse("server: whisper_edge_trusted_header #%u: the name is longer than %zu bytes; refused", ordinal,
                            sizeof g_http.trusted_header - 1u);
            return;
        }
        memcpy(g_http.trusted_header, v, len);
        g_http.trusted_header[len] = '\0';
        break;
    case K_TRUSTED_HOPS: {
        char *tmp, *end = NULL;
        long n;

        if (ls_second_definition(key, ordinal, where)) {
            return;
        }
        /* the whole value, as Apache reads it (strtol, and the end must be the end): never a prefix of it */
        tmp = malloc(len + 1u);
        if (tmp == NULL) {
            ls_trust_refuse("server: whisper_edge_trusted_hops #%u: out of memory", ordinal);
            return;
        }
        memcpy(tmp, v, len);
        tmp[len] = '\0';
        errno = 0;
        n = strtol(tmp, &end, 10);
        if (end == tmp || *end != '\0' || errno != 0 || n < 1 || n > (long) WE_MOD_HOPS_MAX) {
            free(tmp);
            ls_trust_refuse("server: whisper_edge_trusted_hops #%u takes 1 to %u; \"%.*s\" is refused", ordinal,
                            WE_MOD_HOPS_MAX, (int) (len < 256u ? len : 256u), v);
            return;
        }
        free(tmp);
        g_http.trusted_hops = (uint32_t) n;
        break;
    }
    default:
        break;
    }
}

static void *we_parse_config(module_param_info_t *params, int param_count, void *initial_config, int level,
                             const char *name)
{
    we_conf_t *conf;
    ls_ctx_t *c;
    char ename[700];
    unsigned q;
    int i;

    ls_api_bind();
    if (level & LSI_CFG_SERVER) {
        c = &g_server;
        if (c->name[0] == '\0') {
            snprintf(c->name, sizeof c->name, "server");
            snprintf(c->path, sizeof c->path, "http");
            c->threshold = 255u;
            g_http.refresh_ms = LS_DEFAULT_REFRESH_MS;
        }
    } else if (level & LSI_CFG_VHOST) {
        if (g_main_inited) {
            /* never seen on 1.9.3 (every build precedes MAIN_INITED, measured); said if a release changes it */
            g_late_build = 1;
            ls_policy_line(LSI_LOG_ERROR, "vhost %s: its module block arrived after the configuration was built and the "
                           "planes bound (a late build); it runs no context rules of its own, the floor still runs, and "
                           "the status marks late-build", name != NULL ? name : "");
            conf = malloc(sizeof *conf);
            if (conf != NULL) {
                conf->c = &g_server;
            }
            return conf;
        }
        if (g_nvhost >= LS_MAX_VHOSTS) {
            ls_policy_line(LSI_LOG_ERROR, "vhost %s: more than %u virtual hosts carry a module block; this one runs the "
                           "server's program", name != NULL ? name : "", LS_MAX_VHOSTS);
            conf = malloc(sizeof *conf);
            if (conf != NULL) {
                conf->c = &g_server;
            }
            return conf;
        }
        c = calloc(1, sizeof *c);
        if (c == NULL) {
            return NULL;
        }
        c->index = g_nvhost + 1u;
        c->threshold = 255u;
        snprintf(c->name, sizeof c->name, "%s", name != NULL ? name : "");
        snprintf(c->path, sizeof c->path, "http/v%u", c->index);
        g_vhost[g_nvhost++] = c;
        for (q = 0u; q < g_nvh_strict; q++) {
            if (strcmp(g_vh_strict[q].name, c->name) == 0) {
                /* the host's configuration file fails the trust rule: the host runs no context rule of its own */
                c->refused = 1;
                snprintf(c->refusal, sizeof c->refusal, "its configuration file fails the trust rule: %s; chown root "
                         "(or uid %u, the owner of %.200sconf) and chmod go-w the file and every directory above it",
                         g_vh_strict[q].why, (unsigned) g_srv.conf_owner, g_srv.root);
                ls_policy_line(LSI_LOG_ERROR, "policy refused: %s: %s. The context's policy is refused as a whole: it runs "
                               "no context rule; the floor, the pre-stage and every other context are untouched",
                               ls_escaped(c->name, ename, sizeof ename), c->refusal);
                break;
            }
        }
    } else {
        /* a context-level block: read by the server's parser and, on 1.9.3, never handed to a module; if a release
         * does hand one over, the policy stays the virtual host's, and the host's configuration is what this request
         * sees */
        we_conf_t *parent = initial_config;

        ls_policy_line(LSI_LOG_NOTICE, "a context-level module block (%s) is not a policy context on this server: the "
                       "policy is the virtual host's", name != NULL ? name : "");
        conf = malloc(sizeof *conf);
        if (conf != NULL) {
            conf->c = parent != NULL && parent->c != NULL ? parent->c : &g_server;
        }
        return conf;
    }
    (void) initial_config;
    for (i = 0; i < param_count; i++) {
        int key = params[i].key_index;

        if (key < 0 || key >= K_COUNT) {
            continue;
        }
        ls_parse_one(c, key, (uint32_t) i + 1u, params[i].val, params[i].val_len, (level & LSI_CFG_SERVER) != 0);
    }
    conf = malloc(sizeof *conf);
    if (conf != NULL) {
        conf->c = c;
    }
    return conf;
}

/* the server frees a block's configuration at teardown: the handle only, the records live with the process */
static void we_free_config(void *p)
{
    free(p);
}

/* ---------------------------------------------------------------------------------------------- */
/* The server's own settings, from its files (the main process, at init)                            */
/* ---------------------------------------------------------------------------------------------- */

/*
 * A configuration file under the trust rule: the core checks every directory of its resolved chain; the file
 * itself must be a regular file owned by root or the server's admin account and writable by neither group nor
 * world. 0, or -1 with `why`.
 */
static int ls_conf_file_check(const char *path, char *why, size_t whyn)
{
    struct stat st;

    if (we_mod_chain_check(path, (unsigned) g_srv.conf_owner, why, whyn) != 0) {
        return -1;
    }
    if (stat(path, &st) != 0) {
        snprintf(why, whyn, "cannot be read: %s", strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(why, whyn, "is not a regular file");
        return -1;
    }
    if (st.st_uid != 0u && st.st_uid != (uid_t) g_srv.conf_owner) {
        snprintf(why, whyn, "is owned by uid %u, neither root nor the server's admin account", (unsigned) st.st_uid);
        return -1;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
        snprintf(why, whyn, "is writable by group or world (mode %04o)", (unsigned) (st.st_mode & 07777u));
        return -1;
    }
    return 0;
}

static void ls_scan_conf_file(const char *path, int depth)
{
    FILE *f = fopen(path, "r");
    char line[4096];
    int in_listener = 0, listener_depth = 0, in_vhost = 0, vhost_depth = 0;
    char cur_vh[256] = "";

    if (f == NULL || depth > 4) {
        if (f != NULL) {
            fclose(f);
        }
        return;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char *p = line, *key, *val;

        while (*p == ' ' || *p == '\t') { p++; }
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue;
        }
        key = p;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n') { p++; }
        if (*p != '\0') {
            *p++ = '\0';
        }
        while (*p == ' ' || *p == '\t') { p++; }
        val = p;
        p = val + strlen(val);
        while (p > val && (p[-1] == '\n' || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\r')) { *--p = '\0'; }
        /*
         * Listener blocks, for the trusted-header configuration check: the peer of a unix listener is a
         * socket, not an address, so a trusted_header line beside one can only run its walk once the peer
         * is trusted as unix: (the rule: a unix listener with trusted_header set and no unix:
         * entry is a configuration error, said at the build once the trust list is final). This server's
         * listener addresses are TCP (a port with an optional host part and no slash); uds:, unix: and a
         * bare path all name a socket, and 1.9.3 binds the address (measured: the stop line at shutdown
         * names the socket path with its fd), so the configured listener is a live listener and this
         * check reads a real bind.
         */
        if (in_listener) {
            if (strcmp(key, "}") == 0) {
                if (listener_depth == 0) {
                    in_listener = 0;
                } else {
                    listener_depth--;
                }
            } else if (strcasecmp(key, "address") == 0) {
                if (strchr(val, '/') != NULL || strncasecmp(val, "uds:", 4) == 0 ||
                    strncasecmp(val, "unix:", 5) == 0) {
                    g_srv.unix_listener = 1;
                }
            } else if (*val != '\0' && val[strlen(val) - 1u] == '{') {
                listener_depth++;
            }
        } else if (strcasecmp(key, "listener") == 0 && *val != '\0' && val[strlen(val) - 1u] == '{') {
            in_listener = 1;
        }
        /* a virtualHost block names the file the controller reads for that host: the same trust rule, per host */
        if (in_vhost) {
            if (strcmp(key, "}") == 0) {
                if (vhost_depth == 0) {
                    in_vhost = 0;
                } else {
                    vhost_depth--;
                }
            } else if (strcasecmp(key, "configFile") == 0 && val[0] != '\0' && val[0] != '$') {
                char vhc[PATH_MAX], why[512];

                if (val[0] == '/') {
                    snprintf(vhc, sizeof vhc, "%.4000s", val);
                } else {
                    snprintf(vhc, sizeof vhc, "%.2000s%.2000s", g_srv.root, val);
                }
                if (ls_conf_file_check(vhc, why, sizeof why) != 0
                    && g_nvh_strict < sizeof g_vh_strict / sizeof g_vh_strict[0]) {
                    snprintf(g_vh_strict[g_nvh_strict].name, sizeof g_vh_strict[0].name, "%s", cur_vh);
                    snprintf(g_vh_strict[g_nvh_strict].why, sizeof g_vh_strict[0].why, "%.200s: %.190s", vhc, why);
                    g_nvh_strict++;
                }
            } else if (*val != '\0' && val[strlen(val) - 1u] == '{') {
                vhost_depth++;
            }
        } else if (strcasecmp(key, "virtualHost") == 0 && *val != '\0' && val[strlen(val) - 1u] == '{') {
            size_t nl = strlen(val) - 1u;

            while (nl > 0u && (val[nl - 1u] == ' ' || val[nl - 1u] == '\t')) { nl--; }
            snprintf(cur_vh, sizeof cur_vh, "%.*s", (int) (nl < 255u ? nl : 255u), val);
            in_vhost = 1;
            vhost_depth = 0;
        }
        if (strcasecmp(key, "useIpInProxyHeader") == 0) {
            g_srv.use_ip_in_proxy_header = atoi(val);
        } else if (strcasecmp(key, "proxyProtocol") == 0) {
            g_srv.proxy_protocol = 1;
            snprintf(g_srv.proxy_protocol_line, sizeof g_srv.proxy_protocol_line, "%.60s %.190s", key, val);
        } else if (strcasecmp(key, "maxReqHeaderSize") == 0) {
            long n = strtol(val, NULL, 10);

            if (n >= 1024 && n <= 1048576) {
                g_srv.max_req_header_bytes = (uint32_t) n;
            }
        } else if (strcasecmp(key, "user") == 0 && val[0] != '\0') {
            struct passwd *pw = getpwnam(val);

            if (pw != NULL) {
                g_srv.worker_uid = pw->pw_uid;
            }
        } else if (strcasecmp(key, "include") == 0 && val[0] != '\0') {
            char inc[PATH_MAX], why[512];

            if (val[0] == '/') {
                snprintf(inc, sizeof inc, "%.4000s", val);
            } else {
                snprintf(inc, sizeof inc, "%.2000s%.2000s", g_srv.root, val);
            }
            if (!g_srv.strict_failed && ls_conf_file_check(inc, why, sizeof why) != 0) {
                g_srv.strict_failed = 1;
                snprintf(g_srv.strict_why, sizeof g_srv.strict_why, "%.250s: %.250s", inc, why);
            }
            ls_scan_conf_file(inc, depth + 1);
        }
    }
    fclose(f);
}

/*
 * Whether the module distrusts the client address the server reports: a useIpInProxyHeader other than an
 * explicit 0 is not trusted, and neither is no setting at all.
 */
static int ls_client_ip_from_header(void)
{
    return g_srv.use_ip_in_proxy_header != 0;
}

static void ls_read_server_settings(void)
{
    const char *root = ls_api->get_server_root();
    struct stat st;
    char confdir[PATH_MAX], why[512];

    g_srv.use_ip_in_proxy_header = -1;
    g_srv.max_req_header_bytes = LS_DEFAULT_HDR_BYTES;
    g_srv.worker_uid = geteuid();
    snprintf(g_srv.root, sizeof g_srv.root, "%.4000s%s", root != NULL ? root : "/usr/local/lsws/",
             root != NULL && root[0] != '\0' && root[strlen(root) - 1u] != '/' ? "/" : "");
    snprintf(confdir, sizeof confdir, "%.4000sconf", g_srv.root);
    snprintf(g_srv.main_conf, sizeof g_srv.main_conf, "%.4000s/httpd_config.conf", confdir);
    /*
     * The StrictModes rule on the files that define http-level directives (the panel case), with the
     * owner this server's layout makes: the stock install keeps conf/ as the admin account's (lsadm), read by
     * root. Refusing that would disarm the floor on every stock server, so the owner trusted beside root is the
     * owner of $SERVER_ROOT/conf, printed below; the chain rule (no group or world write, every ancestor) stays.
     */
    g_srv.conf_owner = stat(confdir, &st) == 0 ? st.st_uid : 0u;
    if (ls_conf_file_check(g_srv.main_conf, why, sizeof why) != 0) {
        g_srv.strict_failed = 1;
        snprintf(g_srv.strict_why, sizeof g_srv.strict_why, "%.250s: %.250s", g_srv.main_conf, why);
    }
    ls_scan_conf_file(g_srv.main_conf, 0);
}

/* ---------------------------------------------------------------------------------------------- */
/* The whole-configuration build, at MAIN_INITED                                                   */
/* ---------------------------------------------------------------------------------------------- */

typedef struct {
    we_policy_directive_t *d;
    size_t                 n, cap;
    ls_ctx_t             **owner;    /* d[i]'s context record */
    uint32_t              *ordinal;
} ls_src_t;

static int ls_src_add(ls_src_t *s, ls_ctx_t *c, uint8_t kind, uint32_t ordinal, const uint8_t *arg, size_t len)
{
    if (s->n == s->cap) {
        size_t ncap = s->cap != 0u ? s->cap * 2u : 64u;
        we_policy_directive_t *nd = realloc(s->d, ncap * sizeof *nd);
        ls_ctx_t **no = realloc(s->owner, ncap * sizeof *no);
        uint32_t *nn = realloc(s->ordinal, ncap * sizeof *nn);

        if (nd != NULL) { s->d = nd; }
        if (no != NULL) { s->owner = no; }
        if (nn != NULL) { s->ordinal = nn; }
        if (nd == NULL || no == NULL || nn == NULL) {
            return -1;
        }
        s->cap = ncap;
    }
    s->d[s->n].kind = kind;
    s->d[s->n].context = c->path;
    s->d[s->n].arg = arg;
    s->d[s->n].len = len;
    s->owner[s->n] = c;
    s->ordinal[s->n] = ordinal;
    s->n++;
    return 0;
}

static const uint8_t ls_off_word[] = "off";

/* the source: every context's lines in order, a refused context's policy lines replaced by `threshold off` */
static int ls_gather(ls_src_t *s)
{
    uint32_t k;
    size_t i;

    s->n = 0u;
    for (k = 0u; k <= g_nvhost; k++) {
        ls_ctx_t *c = k == 0u ? &g_server : g_vhost[k - 1u];
        int keep_policy = !c->refused;

        for (i = 0u; i < c->n; i++) {
            const ls_dir_t *d = &c->d[i];

            if (d->kind == WE_DIR_FLOOR && g_http.floor_refused) {
                continue;
            }
            if (!keep_policy && (d->kind == WE_DIR_POLICY || d->kind == WE_DIR_SET || d->kind == WE_DIR_THRESHOLD
                                 || d->kind == WE_DIR_FLOOR)) {
                continue;
            }
            if (ls_src_add(s, c, d->kind, d->ordinal, d->arg, d->len) != 0) {
                return -1;
            }
        }
        if (!keep_policy && ls_src_add(s, c, WE_DIR_THRESHOLD, 0u, ls_off_word, 3u) != 0) {
            return -1;              /* the empty program: a refused context runs no context rule */
        }
    }
    return 0;
}

static void ls_report_cb(void *ud, const we_policy_report_line_t *r)
{
    (void) ud;
    if (r->kind == WE_DIR_SET) {
        ls_policy_line(LSI_LOG_NOTICE, "report %s: set @%s: %s", r->context, r->name != NULL ? r->name : "", r->msg);
    } else {
        ls_policy_line(LSI_LOG_NOTICE, "report %s: rule %u: %s", r->context, r->rule, r->msg);
    }
}

/* the planes present in the data directory that this process, the configuration reader, cannot open (EACCES or
 * EPERM), and each one's errno text. The environment keeps the probe's word for them, absent, so the compiler and
 * the lookup tool agree; the binding still takes them, which records them unreadable (`-u`, inert), and the
 * configuration line and the configuration file's `unreadable "<errno text>"` field say why */
static uint8_t g_unread_mask;
static char    g_unreadable[8][128];

/* the counters directory, set once by the main process at configuration and inherited by every worker: the
 * whisper_edge_summary directive's, or the core's placement beside the data (we_mod_bind_counters_dir, the one rule
 * every server applies), empty for off, for no data, and for data files in two directories (refused, said) */
static char    g_counters_dir[PATH_MAX];

/* the planes named by a per-plane line */
static uint8_t ls_file_mask(void)
{
    uint8_t m = 0u;
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        m = (uint8_t) (m | (g_http.plane_file[p][0] != '\0' ? 1u << p : 0u));
    }
    return m;
}

/* the snapshot is the legacy synonym only as the configuration's one data directive; beside any other it is the
 * reputation plane's file */
static int ls_legacy(void)
{
    return g_http.snapshot[0] != '\0' && g_http.data_dir[0] == '\0' && ls_file_mask() == 0u;
}

/* one plane's own file, peeked as the configuration reader: present, its schema, or unreadable (as nginx reads it) */
static void ls_env_file(we_policy_env_t *env, uint32_t p, const char *path)
{
    char dir[PATH_MAX], why[256];
    const char *slash = strrchr(path, '/');
    we_mod_peek_t pk;
    int dfd;

    env->present = (uint8_t) (env->present & ~(1u << p));
    env->schema_ok = (uint8_t) (env->schema_ok & ~(1u << p));
    g_unread_mask = (uint8_t) (g_unread_mask & ~(1u << p));
    g_unreadable[p][0] = '\0';
    if (slash == NULL) {
        return;
    }
    snprintf(dir, sizeof dir, "%.*s", slash == path ? 1 : (int) (slash - path), path);
    dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        return;
    }
    memset(&pk, 0, sizeof pk);
    if (we_plane_peek(dfd, slash + 1, p + 1u, &pk, why, sizeof why) == 0) {
        env->present = (uint8_t) (env->present | (1u << p));
        env->schema_ok = (uint8_t) (env->schema_ok | (1u << p));
    } else if (!pk.absent && (pk.err == EACCES || pk.err == EPERM)) {
        g_unread_mask = (uint8_t) (g_unread_mask | (1u << p));
        snprintf(g_unreadable[p], sizeof g_unreadable[p], "%s", strerror(pk.err));
    } else if (!pk.absent) {
        env->present = (uint8_t) (env->present | (1u << p));   /* present, bound, refused at run time */
    }
    close(dfd);
}

/* the plane environment the module compiles in: what is present in the data directory, each plane's own file over
 * it, the snapshot as the reputation file beside them, or the legacy synonym alone */
static void ls_env(we_policy_env_t *env)
{
    memset(env, 0, sizeof *env);
    g_unread_mask = 0u;
    memset(g_unreadable, 0, sizeof g_unreadable);
    if (g_http.data_dir[0] != '\0') {
        int dfd;

        if (we_policy_env_probe(g_http.data_dir, env) != 0) {
            memset(env, 0, sizeof *env);
        }
        dfd = open(g_http.data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
            uint32_t p;

            for (p = 0u; p < 8u; p++) {
                we_mod_peek_t pk;
                char name[40], why[256];

                memset(&pk, 0, sizeof pk);
                snprintf(name, sizeof name, "%s.bin", we_mod_plane_word(p));
                if (we_plane_peek(dfd, name, p + 1u, &pk, why, sizeof why) != 0 && !pk.absent
                    && (pk.err == EACCES || pk.err == EPERM)) {
                    g_unread_mask = (uint8_t) (g_unread_mask | (1u << p));
                    snprintf(g_unreadable[p], sizeof g_unreadable[p], "%s", strerror(pk.err));
                }
            }
            close(dfd);
        }
    }
    if (ls_legacy()) {
        env->present = 0x01u;
        env->schema_ok = 0x01u;
        env->legacy = 1u;           /* never inert, arms on appearance */
        return;
    }
    {
        uint32_t p;

        if (g_http.snapshot[0] != '\0' && g_http.plane_file[0][0] == '\0') {
            ls_env_file(env, 0u, g_http.snapshot);   /* the snapshot beside other data: the reputation plane's file */
        }
        for (p = 0u; p < 8u; p++) {
            if (g_http.plane_file[p][0] != '\0') {
                ls_env_file(env, p, g_http.plane_file[p]);
            }
        }
    }
}

static int ls_build_once(ls_src_t *s, const we_policy_env_t *env, we_policy_build_t **b, we_policy_error_t *e, int report)
{
    we_policy_source_t src;
    we_policy_report_t rep = { ls_report_cb, NULL };

    memset(&src, 0, sizeof src);
    src.d = s->d;
    src.n = s->n;
    memset(e, 0, sizeof *e);
    *b = NULL;
    return we_policy_build(&src, env, NULL, b, e, report ? &rep : NULL);
}

/* the mask of planes a context's lines read: its program's, the floor's and the tenant's, plus its exports */
/*
 * The default export set: the attributes of every plane the floor and the context's program name, and the
 * tenant plane; `whisper_edge_export` adds attributes, `all` adds every plane. The set is NOT cut to the
 * planes bound here: a named plane that is absent is never filled (the fill runs over the bound planes
 * only, g_bound_mask, because an unbound plane has no binding to fill through) and renders `unknown` with
 * the generations token `-a`, which is what tells the operator the rule that reads it is inert and why.
 */
static uint8_t ls_export_mask(const ls_ctx_t *c, const we_program_t *floor, const we_program_t *prog)
{
    uint8_t m = (uint8_t) ((floor != NULL ? floor->plane_mask : 0u) | (prog != NULL ? prog->plane_mask : 0u) | 0x80u);
    uint32_t i;

    if (c->export_all) {
        return 0xffu;
    }
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        if ((c->export_attrs >> i) & 1u) {
            m = (uint8_t) (m | (1u << we_mod_attr(i)->plane));
        }
    }
    return m;
}

static uint8_t ls_explicit_planes(const ls_ctx_t *c)
{
    uint8_t m = 0u;
    uint32_t i;

    if (c->export_all) {
        return 0xffu;
    }
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        if ((c->export_attrs >> i) & 1u) {
            m = (uint8_t) (m | (1u << we_mod_attr(i)->plane));
        }
    }
    return m;
}

#ifdef WE_LS_TEST_DUP_LOG
static int g_dup_log_fd = -1;           /* the control's descriptor of the error log, opened at worker start */
#endif

static void ls_bind_log(void *ud, const char *entry)
{
    (void) ud;
#ifdef WE_LS_TEST_DUP_LOG
    if (g_dup_log_fd >= 0) {
        /* the control: a line written to the descriptor the worker opened, which a roll leaves pointing at the
         * rolled file; the server's own log call, used in production, follows the live file */
        char line[WE_MOD_RING_ENTRY + 64];
        int n = snprintf(line, sizeof line, "[whisper_edge] whisper edge: policy: %s\n", entry);

        if (n > 0) {
            (void) !write(g_dup_log_fd, line, (size_t) n);
        }
        return;
    }
#endif
    if (strncmp(entry, "whisper edge: ", 14) == 0) {
        /* a sentence the core words for every server (a plane refused at configuration): verbatim, as an error */
        ls_api->log(NULL, LSI_LOG_ERROR, LS_LOG_PFX "%s\n", entry);
        return;
    }
    ls_policy_line(LSI_LOG_NOTICE, "%s", entry);
}

#define LS_KEYED_PLANES ((1u << 3) | (1u << 6))    /* routing and registry: bound from the http level only */

static int ls_build(void)
{
    ls_src_t s;
    we_policy_env_t env1, env2;
    we_policy_error_t e;
    we_policy_build_t *b = NULL;
    we_mod_ctx_spec_t *spec = NULL;
    uint32_t attempts, k, read_any = 0u, read_http = 0u, bound_want, cap_rounds = 0u;
    char msg[1024], d16[17], fl16[17], ename[700];
    int rc;

restart:
    memset(&s, 0, sizeof s);
    if (g_srv.strict_failed) {
        /* StrictModes on the file that defines the http-level directives: nothing from it is read */
        struct stat fst;
        int have = stat(g_srv.main_conf, &fst) == 0;

        ls_policy_line(LSI_LOG_ERROR, "the file that defines http-level directives fails the trust rule: %s; the file is "
                       "owned by uid %u, mode %04o; the server's admin account (uid %u, the owner of %sconf) and root are "
                       "the owners this module trusts. Fix: chown root (or uid %u) and chmod go-w the file and every "
                       "directory above it. The module runs no program until then",
                       g_srv.strict_why, have ? (unsigned) fst.st_uid : 0u, have ? (unsigned) (fst.st_mode & 07777u) : 0u,
                       (unsigned) g_srv.conf_owner, g_srv.root, (unsigned) g_srv.conf_owner);
        goto fail;
    }
    if (g_http.trust_refused) {
        goto fail;                               /* each refused trust line has said why, once */
    }
    ls_env(&env1);
    /* every refusal refuses the whole build, so the refused context is found, marked and replaced, and the
     * build runs again: bounded by the number of contexts plus the floor */
    for (attempts = 0u; attempts <= g_nvhost + 2u; attempts++) {
        ls_ctx_t *c;

        if (ls_gather(&s) != 0) {
            ls_policy_line(LSI_LOG_ERROR, "out of memory gathering the configuration; the module runs no program");
            goto fail;
        }
        rc = ls_build_once(&s, &env1, &b, &e, 0);
        if (rc == WE_POLICY_OK) {
            break;
        }
        if (rc != WE_POLICY_REFUSED) {
            ls_policy_line(LSI_LOG_ERROR, "the compiler is out of memory; the module runs no program");
            goto fail;
        }
        c = e.directive < s.n ? s.owner[e.directive] : &g_server;
        we_policy_error_format(&e, msg, sizeof msg);
        if (e.kind == WE_DIR_FLOOR) {
            g_http.floor_refused = 1;
            ls_policy_line(LSI_LOG_ERROR, "policy refused: server: whisper_edge_policy_floor #%u: %s. The floor is refused "
                           "and no floor runs; every context's own lines stand",
                           e.directive < s.n ? s.ordinal[e.directive] : 0u, msg);
            snprintf(g_server.refusal, sizeof g_server.refusal, "whisper_edge_policy_floor #%u: %.700s",
                     e.directive < s.n ? s.ordinal[e.directive] : 0u, msg);
            continue;
        }
        c->refused = 1;
        snprintf(c->refusal, sizeof c->refusal, "%s #%u: %.700s", we_policy_kind_name(e.kind),
                 e.directive < s.n ? s.ordinal[e.directive] : 0u, msg);
        ls_policy_line(LSI_LOG_ERROR, "policy refused: %s: %s. The context's policy is refused as a whole: it runs no "
                       "context rule; the floor, the pre-stage and every other context are untouched",
                       c == &g_server ? "server" : ls_escaped(c->name, ename, sizeof ename), c->refusal);
    }
    if (b == NULL) {
        ls_policy_line(LSI_LOG_ERROR, "the configuration could not be compiled after %u refusals; the module runs no program",
                       attempts);
        goto fail;
    }
    /* which planes something reads, and from which level: a keyed plane binds from the http level only */
    {
        const we_program_t *floor = we_policy_floor(b);
        const we_program_t *hp = we_policy_program(b, "http");

        read_http = (floor != NULL ? floor->plane_mask : 0u) | (hp != NULL ? hp->plane_mask : 0u) | ls_explicit_planes(&g_server)
                    | ls_file_mask();   /* a per-plane line binds its plane from the http level (the core binds it) */
        read_any = read_http;
        for (k = 0u; k < g_nvhost; k++) {
            const we_program_t *vp = we_policy_program(b, g_vhost[k]->path);

            read_any |= (vp != NULL ? vp->plane_mask : 0u) | ls_explicit_planes(g_vhost[k]);
        }
    }
    bound_want = ((read_any & ~LS_KEYED_PLANES) | (read_http & LS_KEYED_PLANES) | 0x80u) & (env1.present | g_unread_mask);
    if (env1.legacy) {
        bound_want |= 0x01u;
    }
    env2 = env1;
    env2.present = (uint8_t) (env1.present & bound_want);
    env2.schema_ok = (uint8_t) (env1.schema_ok & bound_want);
    if (env1.legacy) {
        env2.present |= 0x01u;
        env2.schema_ok |= 0x01u;
    }
    for (k = 0u; k < g_nvhost; k++) {
        const we_program_t *vp = we_policy_program(b, g_vhost[k]->path);
        uint32_t inert = (vp != NULL ? vp->plane_mask : 0u) & LS_KEYED_PLANES & ~read_http & env1.present;
        uint32_t p;

        for (p = 0u; p < 8u && inert != 0u; p++) {
            if ((inert >> p) & 1u) {
                ls_policy_line(LSI_LOG_NOTICE, "vhost %s reads plane \"%s\", which only http-level configuration can bind: "
                               "its rules on that plane are inert; add a server-level rule or whisper_edge_export that reads "
                               "it to bind it", ls_escaped(g_vhost[k]->name, ename, sizeof ename), we_mod_plane_word(p));
            }
        }
    }
    if (env2.present != env1.present) {
        we_policy_build_free(b);
        b = NULL;
        rc = ls_build_once(&s, &env2, &b, &e, 1);
        if (rc != WE_POLICY_OK || b == NULL) {
            ls_policy_line(LSI_LOG_ERROR, "the second compile (the bound planes only) was refused where the first was not; "
                           "the module runs no program");
            goto fail;
        }
    } else {
        /* the reports, once, on the build that stands */
        we_policy_build_free(b);
        b = NULL;
        rc = ls_build_once(&s, &env2, &b, &e, 1);
        if (rc != WE_POLICY_OK || b == NULL) {
            goto fail;
        }
    }
    g_build = b;
    /* the request path's configuration: one arena, every block interned, one context per record */
    g_arena = we_mod_arena_new();
    spec = calloc(g_nvhost + 1u, sizeof *spec);
    if (g_arena == NULL || spec == NULL) {
        ls_policy_line(LSI_LOG_ERROR, "out of memory; the module runs no program");
        goto fail;
    }
    for (k = 0u; k <= g_nvhost; k++) {
        ls_ctx_t *c = k == 0u ? &g_server : g_vhost[k - 1u];
        const we_program_t *prog = we_policy_program(b, c->path);

        spec[k].path = c->path;
        spec[k].name = c->name;
        spec[k].deny_status = c->deny_status;
        spec[k].export_mask = ls_export_mask(c, we_policy_floor(b), prog);
        spec[k].gen_mask = (uint8_t) (spec[k].export_mask | ls_explicit_planes(c));
    }
    rc = we_mod_config_build(WE_MODULE_ABI_VERSION, g_arena, b, &(we_policy_source_t){ s.d, s.n, NULL, 0 }, spec,
                             g_nvhost + 1u, g_server.deny_status != 0u ? g_server.deny_status : LS_DEFAULT_STATUS,
                             &g_cfg, &g_ctxs, &g_stride, msg, sizeof msg);
    if (rc == WE_MOD_ERR_CAP && cap_rounds <= g_nvhost) {
        /* the counter cap: the crossing virtual host, the last in configuration order with lines of its own, is
         * refused with the core's message (which names the five largest contexts), and the build runs again; the
         * floor and every other context stand */
        uint32_t v;

        for (v = g_nvhost; v > 0u; v--) {
            ls_ctx_t *c = g_vhost[v - 1u];

            if (!c->refused && c->n != 0u) {
                c->refused = 1;
                snprintf(c->refusal, sizeof c->refusal, "the configuration's counted rule slots cross the cap at this "
                         "host: %.600s", msg);
                ls_policy_line(LSI_LOG_ERROR, "policy refused: %s: %s. The context's policy is refused as a whole: it runs "
                               "no context rule; the floor, the pre-stage and every other context are untouched",
                               ls_escaped(c->name, ename, sizeof ename), c->refusal);
                break;
            }
        }
        if (v != 0u) {
            cap_rounds++;
            we_policy_build_free(b);
            b = NULL;
            we_mod_arena_free(g_arena);
            g_arena = NULL;
            free(spec);
            spec = NULL;
            free(s.d);
            free(s.owner);
            free(s.ordinal);
            goto restart;
        }
    }
    if (rc != 0) {
        ls_policy_line(LSI_LOG_ERROR, "the configuration is refused: %s; the module runs no program", msg);
        goto fail;
    }
    g_nctx = g_nvhost + 1u;
    for (k = 0u; k <= g_nvhost; k++) {
        ls_ctx_t *c = k == 0u ? &g_server : g_vhost[k - 1u];

        c->ctx = &g_ctxs[k];
    }
    /* the sink: one full shard nothing reads, for a worker whose own shard cannot be allocated */
    g_sink = aligned_alloc(64, (size_t) g_stride * 8u);
    if (g_sink == NULL) {
        ls_policy_line(LSI_LOG_ERROR, "out of memory for the counter sink; the module runs no program");
        goto fail;
    }
    memset(g_sink, 0, (size_t) g_stride * 8u);
    /* the trusted-proxy table */
    if (g_http.ntrusted != 0u) {
        we_mod_trust_report_t rep;
        char err[256];

        memset(&rep, 0, sizeof rep);
        if (we_mod_trust_build((const char *const *) g_http.trusted, g_http.ntrusted, &g_trust, &rep, err, sizeof err) != 0) {
            ls_policy_line(LSI_LOG_ERROR, "whisper_edge_trusted_proxy: %s; the configuration is refused and the module runs no "
                           "program until it is fixed", err);
            goto fail;
        } else {
            g_trust_built = 1;
            ls_policy_line(LSI_LOG_NOTICE, "trusted proxies: %u IPv4 and %u IPv6 prefixes as written, merged to %u and %u "
                           "intervals%s%s", rep.configured4, rep.configured6, g_trust.n4, g_trust.n6,
                           rep.broad != 0u ? "; a prefix broader than /16 or /32 is listed: a shared range lets anyone "
                           "originate from it, so prefer whisper_edge_trusted_hops" : "",
                           rep.covers_mapped != 0u ? "; an IPv6 prefix covers ::ffff:0:0/96, which cannot match an IPv4 "
                           "peer after canonicalisation: add the IPv4 prefix" : "");
        }
    }
    /*
     * The unix-listener rule (T4): a unix listener's peer is a socket, not an address, and the module
     * judges it only through a unix: trust entry (as :: with the header walked). With trusted_header set
     * and no unix: entry the unix peer is never trusted, so the header is never read from it and the
     * listener would allow every request it forwards while the operator reads the header line as
     * protection: a configuration error, and the header line is refused as a whole, like every other
     * refused directive here. 1.9.3 binds such a listener (measured: the stop line at shutdown names
     * the socket path with its fd), so this refusal guards a live listener, not a hypothetical one.
     */
    if (g_srv.unix_listener && g_http.trusted_header[0] != '\0' && !g_trust.unix_ok) {
        ls_policy_line(LSI_LOG_ERROR, "server: a listener is a unix socket and whisper_edge_trusted_header is set, but "
                       "whisper_edge_trusted_proxy names no unix: entry; the unix peer is never trusted, so the header "
                       "is never read from it and the listener would allow every request it forwards: add unix: to "
                       "whisper_edge_trusted_proxy; the configuration is refused and the module runs no program until it "
                       "is fixed");
        goto fail;
    }
    if (g_http.trusted_header[0] != '\0' && g_http.ntrusted == 0u) {
        ls_policy_line(LSI_LOG_NOTICE, "whisper_edge_trusted_header is set with no whisper_edge_trusted_proxy: the header is "
                       "never read, because no peer is trusted");
    }
    /* the planes: verified by this main process before any fork, mapped and published on module-owned handles */
    {
        we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;

        uint32_t p;

        /* the core decides what the snapshot is: the legacy synonym alone, the reputation plane's file beside any
         * other data directive (refused, naming both, beside a per-plane reputation line) */
        args.data_dir = g_http.data_dir[0] != '\0' ? g_http.data_dir : NULL;
        args.legacy_file = g_http.snapshot[0] != '\0' ? g_http.snapshot : NULL;
        for (p = 0u; p < 8u; p++) {
            args.plane_file[p] = g_http.plane_file[p][0] != '\0' ? g_http.plane_file[p] : NULL;
        }
        args.read_mask = (uint8_t) (bound_want & 0x7fu);
        args.uid = (unsigned) g_srv.worker_uid;
        args.log = ls_bind_log;
        g_counters_dir[0] = '\0';
        if (g_http.summary_dir[0] != '\0') {
            snprintf(g_counters_dir, sizeof g_counters_dir, "%.4000s", g_http.summary_dir);
        } else if (!g_http.summary_off) {
            char why[512];
            int crc = we_mod_bind_counters_dir(&args, g_counters_dir, sizeof g_counters_dir, why, sizeof why);

            if (crc == -1) {
                ls_policy_line(LSI_LOG_ERROR, "%s; no counter file is written until then, and blocking is unaffected", why);
            } else if (crc == -2) {
                ls_policy_line(LSI_LOG_ERROR, "the counters directory beside the data is longer than this build holds; name "
                               "one with whisper_edge_summary <dir>");
            }
            if (crc != 1) {
                g_counters_dir[0] = '\0';
            }
        }
        rc = we_mod_bind(&g_cfg, &args, &g_planes, msg, sizeof msg);
        if (rc != 0) {
            /* the one configuration error refused whole (the core leaves g_cfg as it was): the core's words */
            ls_policy_line(LSI_LOG_ERROR, "%s (%s); every rule reads unknown and the module denies nothing", msg,
                           we_mod_strerror(rc));
            g_planes = NULL;
        }
    }
    g_bound_mask = 0u;
    for (k = 0u; k < 8u; k++) {
        g_bound_mask = (uint8_t) (g_bound_mask | (g_cfg.handle[k] != NULL ? 1u << k : 0u));
        /* the peek's errno text stays only for a plane the binding recorded unreadable, and the configuration
         * line says so, as nginx and Apache do */
        if (g_cfg.static_reason[k] == WE_MOD_NOMAP_UNREADABLE) {
            if (g_unreadable[k][0] == '\0') {
                snprintf(g_unreadable[k], sizeof g_unreadable[k], "unreadable at binding");
            }
            ls_policy_line(LSI_LOG_NOTICE, "%s present, unreadable by uid %u (%s): rules on it are inert",
                           we_mod_plane_word(k), (unsigned) geteuid(), g_unreadable[k]);
        } else {
            g_unreadable[k][0] = '\0';
        }
        /* from here on the mask names the planes the binding recorded unreadable, which the export fills */
        g_unread_mask = (uint8_t) ((g_unread_mask & ~(1u << k))
                                   | (g_cfg.static_reason[k] == WE_MOD_NOMAP_UNREADABLE ? 1u << k : 0u));
    }
    /* the configuration-time lines */
#ifdef WE_MOD_DEBUG
    ls_policy_line(LSI_LOG_NOTICE, "debug build (WE_MOD_DEBUG): the core's debug counters and assertions are on; this "
                   "object is for a gate's debug rows, never the release build");
#endif
    ls_program_digest(g_cfg.floor, fl16);
    if (g_cfg.floor != NULL && g_cfg.floor->rule_count != 0u) {
        int any_deny = 0;

        ls_policy_line(LSI_LOG_NOTICE, "floor: %u rules, program %s, mode %s and deny status %u from the http level",
                       g_cfg.floor->rule_count, fl16, ls_mode_word(&g_cfg.floor_conf), g_cfg.floor_status);
        for (k = 1u; k <= g_nvhost; k++) {
            any_deny |= we_conf_mode(&g_ctxs[k].conf) == WE_MODE_DENY;
        }
        if (we_conf_mode(&g_cfg.floor_conf) != WE_MODE_DENY && any_deny) {
            ls_policy_line(LSI_LOG_NOTICE, "the floor will not deny: its mode is the http level's (%s); add \"whisper_edge_mode "
                           "deny\" at the server level", ls_mode_word(&g_cfg.floor_conf));
        }
    } else if (g_http.floor_refused) {
        ls_policy_line(LSI_LOG_NOTICE, "floor: refused (%s); no floor runs", g_server.refusal);
    } else {
        ls_policy_line(LSI_LOG_NOTICE, "floor: none written; program %s", fl16);
    }
    for (k = 0u; k <= g_nvhost; k++) {
        ls_ctx_t *c = k == 0u ? &g_server : g_vhost[k - 1u];
        we_mod_ctx_t *x = c->ctx;
        char label[800];

        if (k == 0u) {
            snprintf(label, sizeof label, "server");
        } else {
            snprintf(label, sizeof label, "vhost %s", ls_escaped(c->name, ename, sizeof ename));
        }
        ls_program_digest(x->prog, d16);
        if (c->refused) {
            ls_policy_line(LSI_LOG_NOTICE, "%s: refused (%s); runs no context rule under mode %s", label, c->refusal,
                           ls_mode_word(&x->conf));
        } else if (x->prog == NULL) {
            ls_policy_line(LSI_LOG_NOTICE, "%s: no lines of its own; runs no program under mode %s", label, ls_mode_word(&x->conf));
        } else if (x->cold != NULL && x->cold->own) {
            if (c->threshold != 255u) {
                /* row G1: the sugar block and the compiled canonical line are one block, so the two digests are one */
                we_program_t *sugar = NULL;
                char s16[17];

                snprintf(s16, sizeof s16, "-");
                if (we_policy_sugar_env(c->threshold, &env2, NULL, &sugar) == 0 && sugar != NULL) {
                    ls_program_digest(sugar, s16);
                    we_program_free(NULL, sugar);
                }
                ls_policy_line(LSI_LOG_NOTICE, "%s: %u rules, program %s (the threshold line's sugar program %s equals the written "
                               "rule %s), mode %s, inherits nothing", label, x->rule_count, d16, s16,
                               x->rule_count != 0u ? x->cold->rule_text[0] : "(none)", ls_mode_word(&x->conf));
            } else {
                ls_policy_line(LSI_LOG_NOTICE, "%s: %u rules, program %s, mode %s, inherits nothing", label, x->rule_count, d16,
                               ls_mode_word(&x->conf));
            }
            if (k != 0u && g_ctxs[0].prog != NULL && g_ctxs[0].prog->rule_count != 0u) {
                ls_policy_line(LSI_LOG_NOTICE, "%s replaces %u inherited rules", label, g_ctxs[0].prog->rule_count);
            }
        } else {
            ls_policy_line(LSI_LOG_NOTICE, "%s: no lines of its own; runs program %s under mode %s", label, d16,
                           ls_mode_word(&x->conf));
        }
    }
    /* the counters' identity table, for the rules file: the floor first, then every context that owns lines */
    g_ctrmap_e = calloc(g_nvhost + 2u, sizeof *g_ctrmap_e);
    if (g_ctrmap_e != NULL) {
        g_ctrmap_n = 0u;
        if (g_cfg.floor != NULL && g_cfg.floor->rule_count != 0u) {
            g_ctrmap_e[g_ctrmap_n].ctr_off = WE_MOD_CTR_FLOOR;
            g_ctrmap_e[g_ctrmap_n].rule_count = g_cfg.floor->rule_count;
            memcpy(g_ctrmap_e[g_ctrmap_n].digest16, fl16, 17);
            g_ctrmap_n++;
        }
        for (k = 0u; k <= g_nvhost; k++) {
            we_mod_ctx_t *x = &g_ctxs[k];

            if (x->prog != NULL && x->cold != NULL && x->cold->own && x->rule_count != 0u) {
                ls_program_digest(x->prog, g_ctrmap_e[g_ctrmap_n].digest16);
                g_ctrmap_e[g_ctrmap_n].ctr_off = x->ctr_off;
                g_ctrmap_e[g_ctrmap_n].rule_count = x->rule_count;
                g_ctrmap_n++;
            }
        }
    }
    /* the configuration file's bytes and name, once: every worker's thread writes it when it is absent */
    {
        const char *plane_path[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
        const char *unreadable[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
        const char *refused[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
        static char pathbuf[8][PATH_MAX];
        uint32_t p;

        for (p = 0u; p < 8u; p++) {
            /* a bound plane's path, and an unreadable one's with the errno text the configuration reader met */
            /* a bound plane's file, an unreadable one's with its errno text, and one refused at configuration with the
             * core's reason and fix */
            refused[p] = g_planes != NULL ? we_mod_plane_config_refusal(g_planes, p) : NULL;
            if ((g_cfg.handle[p] != NULL || g_unreadable[p][0] != '\0' || refused[p] != NULL) && g_planes != NULL
                && we_mod_plane_path(g_planes, p) != NULL) {
                snprintf(pathbuf[p], sizeof pathbuf[p], "%s", we_mod_plane_path(g_planes, p));   /* the file named */
                plane_path[p] = pathbuf[p];
            }
#ifndef WE_LS_TEST_NO_UNREADABLE_FIELD
            if (g_unreadable[p][0] != '\0') {
                unreadable[p] = g_unreadable[p];
            }
#endif
        }
        /* the configuration file carries every rule's text, so its size follows the configuration: the render is
         * tried at a first estimate and the buffer doubled until it fits, bounded at 64 MiB, far above anything the
         * counter cap admits (a configuration of 65,528 rules needs about 3 MiB; the old single 4 KiB per context
         * left it with no configuration file at all) */
        g_conf_text.cap = 64u * 1024u + (size_t) g_nctx * 4096u;
        for (;;) {
            g_conf_text.len = 0u;
            g_conf_text.over = 0;
            g_conf_text.buf = malloc(g_conf_text.cap);
            if (g_conf_text.buf == NULL) {
                break;
            }
            we_mod_render_conf(&g_conf_text, &g_cfg, g_ctxs, g_nctx, plane_path, unreadable, refused);
            /* the refused contexts, a configuration-time fact, in the configuration file (the status writer carries
             * only what changes per tick) */
            for (k = 0u; k <= g_nvhost && !g_conf_text.over; k++) {
                ls_ctx_t *c = k == 0u ? &g_server : g_vhost[k - 1u];

                if (c->refused || (k == 0u && g_http.floor_refused)) {
                    char ep[128], er[4 * 768 + 3];
                    int w;

                    we_mod_escape(c->path, ep, sizeof ep);
                    we_mod_escape(c->refusal, er, sizeof er);
                    w = snprintf(g_conf_text.buf + g_conf_text.len, g_conf_text.cap - g_conf_text.len, "refused %s %s\n", ep, er);
                    if (w < 0 || (size_t) w >= g_conf_text.cap - g_conf_text.len) {
                        g_conf_text.over = 1;
                    } else {
                        g_conf_text.len += (size_t) w;
                    }
                }
            }
            if (!g_conf_text.over || g_conf_text.cap >= 64u * 1024u * 1024u) {
                break;
            }
            free(g_conf_text.buf);
            g_conf_text.buf = NULL;
            g_conf_text.cap *= 2u;
        }
        if (g_conf_text.buf != NULL && !g_conf_text.over) {
            we_mod_conf_name(&g_conf_text, g_conf_name);
            memcpy(g_config16, g_conf_name + 5, 16);
            g_config16[16] = '\0';
        }
        if (g_conf_text.buf == NULL || g_conf_text.over) {
            snprintf(g_config16, sizeof g_config16, "0000000000000000");
            g_conf_name[0] = '\0';
        }
    }
    /* the header-line bound (the walk's W term): the server's request-header limit over its shortest line */
    g_hdr_line_bound = g_srv.max_req_header_bytes / LS_SHORTEST_LINE;
    g_hdr_line_bound_set = 1u;
    /* the arena sealed here, before any fork: pages never written after fork stay shared (WORKER_INIT seals again) */
    if (we_mod_arena_seal(g_arena) != 0) {
        ls_policy_line(LSI_LOG_ERROR, "the program arena cannot be made read-only: %s", strerror(errno));
    }
    {
        uint32_t nrules = 0u, nctx_lines = 0u;
        char blocks[1024];
        size_t o = 0u;

        for (k = 0u; k <= g_nvhost; k++) {
            if (g_ctxs[k].cold != NULL && g_ctxs[k].cold->own) {
                nctx_lines++;
                nrules += g_ctxs[k].rule_count;
            }
        }
        o += (size_t) snprintf(blocks + o, sizeof blocks - o, "%p %p", (const void *) g_cfg.floor, (const void *) g_cfg.hh);
        for (k = 0u; k <= g_nvhost && o < sizeof blocks - 24u; k++) {
            if (g_ctxs[k].prog != NULL && g_ctxs[k].cold != NULL && g_ctxs[k].cold->own) {
                o += (size_t) snprintf(blocks + o, sizeof blocks - o, " %p", (const void *) g_ctxs[k].prog);
            }
        }
        ls_policy_line(LSI_LOG_NOTICE, "%u distinct programs and the floor, %zu hot bytes in all (configuration-wide, after "
                       "interning); counters %u contexts, %u rules, 8 pre-stage, 1 shard per worker, %u bytes per shard; "
                       "header-line bound %u (%u-byte request headers over %u-byte lines); configuration %s; arena %zu "
                       "pages, read-only; blocks at %s", we_policy_block_count(b), we_policy_hot_total(b), nctx_lines,
                       nrules, g_stride * 8u, g_hdr_line_bound, g_srv.max_req_header_bytes, LS_SHORTEST_LINE, g_config16,
                       we_mod_arena_pages(g_arena), blocks);
    }
    if (ls_client_ip_from_header()) {
        char why[256];

        if (g_srv.use_ip_in_proxy_header == -1) {
            snprintf(why, sizeof why, "is not set");
        } else {
            snprintf(why, sizeof why, "is %d", g_srv.use_ip_in_proxy_header);
        }
        ls_log(LSI_LOG_ERROR, "the floor does not trust the client address the server reports: useIpInProxyHeader %s, "
               "and the module trusts only an explicit 0; set it to 0 and name your proxies with "
               "whisper_edge_trusted_proxy", why);
    }
    if (g_srv.proxy_protocol) {
        ls_policy_line(LSI_LOG_NOTICE, "the floor judges the PROXY header's source on this server, not the load balancer, "
                       "because LiteSpeed exposes no other peer address (%s)", g_srv.proxy_protocol_line);
    }
    free(spec);
    free(s.d);
    free(s.owner);
    free(s.ordinal);
    g_built = 1;
    return 0;
fail:
    if (b != NULL && g_build == NULL) {
        we_policy_build_free(b);
    }
    free(spec);
    free(s.d);
    free(s.owner);
    free(s.ordinal);
    return -1;
}

/* ---------------------------------------------------------------------------------------------- */
/* The hooks of the main process                                                                   */
/* ---------------------------------------------------------------------------------------------- */

static int we_init(lsi_module_t *module)
{
    ls_api_bind();
    (void) module;
    ls_read_server_settings();
    ls_policy_line(LSI_LOG_NOTICE, "module loaded: ABI %u, %s; the configuration is compiled once every virtual host "
                   "has been read", WE_MODULE_ABI_VERSION, LS_SERVER_STRING);
    return 0;
}

static int we_main_inited(lsi_param_t *param)
{
    ls_api_bind();
    (void) param;
    if (g_main_inited) {
        return LSI_OK;
    }
    g_main_inited = 1;
    for (uint32_t i = 0u; i < WE_MOD_ATTRS; i++) {
        size_t k;

        snprintf(g_env_name[i], sizeof g_env_name[i], "WHISPER_EDGE_%s", we_mod_attr(i)->name);
        for (k = 13u; g_env_name[i][k] != '\0'; k++) {
            g_env_name[i][k] = (char) toupper((unsigned char) g_env_name[i][k]);
        }
        g_env_name_len[i] = (unsigned) strlen(g_env_name[i]);
    }
    if (g_server.name[0] == '\0') {
        /* no module block at the server level: the defaults (log mode, threshold high), no planes */
        snprintf(g_server.name, sizeof g_server.name, "server");
        snprintf(g_server.path, sizeof g_server.path, "http");
        g_server.threshold = 255u;
        g_http.refresh_ms = LS_DEFAULT_REFRESH_MS;
    }
    if (g_http.snapshot[0] == '\0' && g_http.data_dir[0] == '\0' && ls_file_mask() == 0u) {
        ls_policy_line(LSI_LOG_NOTICE, "no whisper_edge_data and no whisper_edge_snapshot: every rule reads unknown and the "
                       "module denies nothing until a data source is configured");
    }
    (void) ls_build();
    return LSI_OK;
}

/* ---------------------------------------------------------------------------------------------- */
/* The worker: the thread's tick, the writers, the poll                                            */
/* ---------------------------------------------------------------------------------------------- */

/* the thread's writes: the status file every tick, the rule counters, the configuration file when absent */
static void ls_write_files(uint64_t tick, int final)
{
    char why[512];
    uint64_t now = ls_wall_ms();

    if (g_counters_dirfd < 0 || g_status_buf == NULL || g_rules_buf == NULL) {
        return;
    }
    /* the configuration file, when absent or not a regular file: the first worker to find it so writes it */
    if (g_conf_name[0] != '\0' && g_conf_text.buf != NULL && !g_conf_text.over) {
        struct stat st;

        if (fstatat(g_counters_dirfd, g_conf_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
            (void) we_mod_write_file(g_counters_dirfd, &g_id, "conf", g_conf_name, g_conf_text.buf, g_conf_text.len, why,
                                     sizeof why);
        }
    }
    /* the status */
    {
        static we_mod_status_t st;
        we_mod_text_t t = { g_status_buf, 0u, g_status_cap, 0 };
        char name[64];

        memset(&st, 0, sizeof st);
        st.server = LS_SERVER_STRING;
        st.started_ms = g_started_ms;
        st.written_ms = now;
        st.interval_ms = g_http.refresh_ms;
        st.jitter_ms = g_jitter_ms;
        st.handoff_ms = LS_POLL_MS;
        st.tick = tick;
        memcpy(st.config16, g_config16, 17);
        st.no_thread = (uint8_t) g_no_thread;
        st.late_build = (uint8_t) g_late_build;
        st.client_ip_from_header = (uint8_t) ls_client_ip_from_header();
        st.shards = 1u;
        if (g_planes != NULL) {
            we_mod_planes_status(g_planes, &st, now);
        }
        we_mod_render_status(&t, &g_id, &st);
        if (!t.over) {
            snprintf(name, sizeof name, "%llu-%s.status", (unsigned long long) g_id.pid, g_id.id16);
            (void) we_mod_write_file(g_counters_dirfd, &g_id, "status", name, t.buf, t.len, why, sizeof why);
        }
    }
    /* the rule counters: the shard read with relaxed atomic loads, the one writer being the loop */
    if (g_sum != NULL && g_shard != NULL) {
        we_mod_text_t t = { g_rules_buf, 0u, g_rules_cap, 0 };
        we_mod_ctrmap_t map = { g_ctrmap_e, g_ctrmap_n };
        char name[64];
        uint32_t i;

        for (i = 0u; i < g_stride; i++) {
            g_sum[i] = __atomic_load_n(&g_shard[i], __ATOMIC_RELAXED);
        }
        we_mod_render_rules(&t, &g_id, &map, g_sum, g_started_ms, tick, now, now, g_config16);
        if (!t.over) {
            snprintf(name, sizeof name, "%llu-%s.rules.cnt", (unsigned long long) g_id.pid, g_id.id16);
            (void) we_mod_write_file(g_counters_dirfd, &g_id, "rules", name, t.buf, t.len, why, sizeof why);
        }
    }
    /* the legacy snapshot's per-range counters, the pin's summary: the replaced sets freed, then the live one written */
    {
        ls_retired_t *r = __atomic_exchange_n(&g_legacy_retired, NULL, __ATOMIC_ACQUIRE);
        we_counters_t *live = __atomic_load_n(&g_legacy_counters, __ATOMIC_ACQUIRE);
        const char *dir = g_counters_dir;

        while (r != NULL) {
            ls_retired_t *next = r->next;

            we_counters_free(r->set);
            free(r);
            r = next;
        }
#ifdef WE_MOD_TEST_LEGACY_HOLD
        if (ls_test_legacy_hold != NULL) {
            ls_test_legacy_hold();               /* the seam: the loop publishes while this write holds the live set */
        }
#endif
        if (live != NULL && dir[0] != '\0' && g_cfg.handle[0] != NULL) {
            const we_map_t *m = we_current(g_cfg.handle[0]);

            if (m != NULL) {
                (void) we_counters_write(live, m, dir, now);   /* a set built for another generation writes nothing */
            }
        }
    }
    g_last_written_ms = now;
    (void) final;
}

static void ls_tick(void *ud, uint64_t tick, const int *stop)
{
    (void) ud;
    if (g_planes != NULL) {
        we_mod_planes_tick(g_planes, tick, stop);
    }
    ls_write_files(tick, 0);
}

static void ls_final(void *ud, uint64_t tick, const int *stop)
{
    (void) ud;
    (void) stop;
    ls_write_files(tick, 1);
}

static void ls_loop_log(void *ud, const char *entry)
{
    (void) ud;
    ls_api->log(NULL, LSI_LOG_NOTICE, LS_LOG_PFX "whisper edge: policy: %s\n", entry);
}

/*
 * The loop's publish of the legacy copy's counter set: the set belongs to one generation, so a new map replaces it,
 * and the replaced set goes onto the retired list for the thread to free (the loop never frees one: the thread may
 * still be writing the set it read before the swap).
 */
static void ls_legacy_publish(const we_map_t *m)
{
    we_counters_t *old;

    if (m == g_legacy_map) {
        return;
    }
    old = __atomic_load_n(&g_legacy_counters, __ATOMIC_RELAXED);   /* the loop's own store */
    __atomic_store_n(&g_legacy_counters, (m != NULL && !g_http.summary_off) ? we_counters_new(m, ls_now_ms()) : NULL,
                     __ATOMIC_RELEASE);
    g_legacy_map = m;
    if (old != NULL) {
        ls_retired_t *node = malloc(sizeof *node);

#ifdef WE_MOD_TEST_LEGACY_LOOP_FREES
        {
            /* the control: the one-slot handoff this replaced, where a second publish inside a tick freed the set
             * the first had handed over, which the thread may still be writing */
            ls_retired_t *prev = __atomic_exchange_n(&g_legacy_retired, NULL, __ATOMIC_ACQ_REL);

            while (prev != NULL) {
                ls_retired_t *next = prev->next;

                we_counters_free(prev->set);
                free(prev);
                prev = next;
            }
        }
#endif
        if (node == NULL) {
            /* the thread may still be writing it, so it cannot be freed here: kept, and said */
            ls_log(LSI_LOG_WARN, "out of memory retiring a legacy counter set; it is kept unfreed");
        } else {
            node->set = old;
            node->next = __atomic_load_n(&g_legacy_retired, __ATOMIC_RELAXED);
            while (!__atomic_compare_exchange_n(&g_legacy_retired, &node->next, node, 1, __ATOMIC_RELEASE,
                                                __ATOMIC_RELAXED)) {
            }
        }
    }
}

/* the loop's 100 ms poll: one relaxed load of the list slot, then the apply (the planes' single writer here) */
static void ls_poll(const void *param)
{
    (void) param;
    if (g_planes == NULL || !we_mod_planes_pending(g_planes)) {
        return;
    }
    if (we_mod_planes_apply(g_planes, ls_loop_log, NULL) != 0u && g_cfg.handle[0] != NULL && ls_legacy()) {
        ls_legacy_publish(we_current(g_cfg.handle[0]));
    }
}

static int we_worker_init(lsi_param_t *param)
{
    ls_api_bind();
    char why[512], dir[PATH_MAX];
    we_mod_worker_args_t w;
    uint64_t offset = 0u;
    int rc;

    (void) param;
    g_worker_init_seen = 1;
    if (!g_built) {
        return LSI_OK;
    }
#ifdef WE_LS_TEST_LATE_BUILD
    /* the control: a virtual host's block handed over in a worker, after the configuration was built and bound */
    free(we_parse_config(NULL, 0, NULL, LSI_CFG_VHOST, "late-test"));
#endif
#ifdef WE_LS_TEST_DUP_LOG
    {
        char lp[PATH_MAX];

        snprintf(lp, sizeof lp, "%.4000slogs/error.log", g_srv.root);
        g_dup_log_fd = open(lp, O_WRONLY | O_APPEND | O_CLOEXEC);
    }
#endif
    if (g_arena != NULL) {
        (void) we_mod_arena_seal(g_arena);
    }
    g_started_ms = ls_now_ms();
    if (we_mod_procid(&g_id) != 0) {
        ls_log(LSI_LOG_WARN, "this process's identity cannot be read from /proc; it writes no status or counter file");
    }
    /* the counters directory: the worker's own descriptor, close-on-exec */
    snprintf(dir, sizeof dir, "%s", g_counters_dir);
    if (dir[0] != '\0') {
        g_counters_dirfd = we_openat_cloexec(AT_FDCWD, dir, O_RDONLY | O_DIRECTORY, 0);
        if (g_counters_dirfd < 0) {
            (void) mkdir(dir, 0755);
            g_counters_dirfd = we_openat_cloexec(AT_FDCWD, dir, O_RDONLY | O_DIRECTORY, 0);
        }
        if (g_counters_dirfd < 0 && !g_counters_said) {
            g_counters_said = 1;
            ls_log(LSI_LOG_WARN, "cannot open the counters directory %s (%s); blocking is unaffected and whisper-edge-summary "
                   "will have nothing to read. Set whisper_edge_summary to a writable directory, or to off.", dir,
                   strerror(errno));
        }
    }
    /* the shard: this worker's counter array, 64-byte aligned, one writer (the loop) */
    g_shard = aligned_alloc(64, (size_t) g_stride * 8u);
    if (g_shard == NULL) {
        g_shard = g_sink;
        g_no_shard = 1;
        ls_log(LSI_LOG_WARN, "no-shard: this worker's counters cannot be allocated; its counts go to the sink nobody reads");
    } else {
        memset(g_shard, 0, (size_t) g_stride * 8u);
    }
    g_sum = malloc((size_t) g_stride * 8u);
    /* the worker-start check and the arm-time mlock, before the first accept */
    if (g_planes != NULL) {
        memset(&w, 0, sizeof w);
        w.interval_ms = g_http.refresh_ms;
        w.log = ls_bind_log;
        rc = we_mod_worker_start(g_planes, &w, why, sizeof why);
        if (rc != 0) {
            ls_log(LSI_LOG_ERROR, "the worker-start check failed: %s", why);
        }
        if (g_cfg.handle[0] != NULL && ls_legacy() && !g_http.summary_off) {
            const we_map_t *m = we_current(g_cfg.handle[0]);

            g_legacy_map = m;
            __atomic_store_n(&g_legacy_counters, m != NULL ? we_counters_new(m, g_started_ms) : NULL, __ATOMIC_RELEASE);
        }
    }
    /* the module's thread: its offset drawn from this process's identity, not from a clock */
    {
        uint32_t h = 0u;
        size_t i;

        for (i = 0u; i < 16u; i++) {
            h = h * 31u + (uint32_t) (unsigned char) g_id.id16[i];
        }
        g_jitter_ms = g_http.refresh_ms != 0u ? h % g_http.refresh_ms : 0u;
        offset = g_jitter_ms;
    }
    g_status_cap = 32u * 1024u;
    g_rules_cap = 64u + (size_t) g_stride * 48u + 1024u;
    g_status_buf = malloc(g_status_cap);
    g_rules_buf = malloc(g_rules_cap);
    rc = we_mod_thread_start(&g_thread, g_http.refresh_ms, offset, ls_tick, ls_final, NULL, why, sizeof why);
    if (rc != 0) {
        g_no_thread = 1;
        ls_log(LSI_LOG_ERROR, "no-thread: %s; this worker serves its inherited planes until their valid-until and writes no "
               "counter file, so its counts are lost", why);
        ls_write_files(0u, 0);          /* the one status line, before serving */
    }
    g_timer_id = ls_api->set_timer(LS_POLL_MS, 1, ls_poll, NULL);
    if (g_timer_id == -1) {
        ls_log(LSI_LOG_WARN, "the 100 ms poll could not be registered; the thread's results are applied at the next tick");
    }
    return LSI_OK;
}

static int we_worker_atexit(lsi_param_t *param)
{
    (void) param;
#ifdef WE_LS_TEST_NO_EXIT_FLUSH
    return LSI_OK;                       /* the control: the counts since the last tick leave with the worker */
#endif
    if (g_thread != NULL) {
#ifndef WE_LS_TEST_FLAT_STOP
        /* the core's bounded stop: 2 s windows granted again while the thread makes progress or is outside a plane
         * job (its own files, its final write), so a slow host still writes the counts; a plane job with no progress
         * for a window is abandoned; 6 s in all. The line names the stage the thread was in */
        uint32_t stage = WE_MOD_STAGE_WAIT;

        if (we_mod_thread_stop_bounded(g_thread, &stage) != 0) {
            ls_log(LSI_LOG_WARN, "the module's thread was abandoned at exit%s, within the %u ms cap; the counts since the "
                   "last write (%llu ms ago) are at risk and no file was written by this exit", we_mod_stage_text(stage),
                   WE_MOD_STOP_CAP_MS, (unsigned long long) (ls_now_ms() - g_last_written_ms));
        }
#else
        if (we_mod_thread_stop(g_thread, 2000u) != 0) {   /* the control: the flat 2 s stop, no stage named */
            ls_log(LSI_LOG_WARN, "the module's thread did not finish within %u ms at exit; the counts since the last write "
                   "(%llu ms ago) are at risk and no file was written by this exit", 2000u,
                   (unsigned long long) (ls_now_ms() - g_last_written_ms));
        }
#endif
    }
    return LSI_OK;
}

/* ---------------------------------------------------------------------------------------------- */
/* The request path                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/*
 * THE ONE GATED FUNCTION of this module: the wrapper every evaluation site calls, disassembled out of
 * the built object by the gate (no call, no syscall, no atomic beyond the acquire loads of the views).
 * `noinline` so it stays a symbol; on gcc `noipa` too, which also forbids the clones `noinline` alone
 * permits.
 */
#if defined(__GNUC__) && !defined(__clang__)
#define LS_WRAPPER_ATTR __attribute__((noinline, noipa, used))
#else
#define LS_WRAPPER_ATTR __attribute__((noinline, used))
#endif
LS_WRAPPER_ATTR static void ls_whisper_edge_decide(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s,
                                                   uint64_t *shard, const we_mod_req_t *req, uint64_t now_ms)
{
    we_mod_decide(c, x, s, shard, req, now_ms);
}

static int ls_parse_peer(const char *ip, int iplen, we_addr_t *out)
{
    char buf[64];
    uint8_t b[16];

    if (ip == NULL || iplen <= 0 || iplen >= (int) sizeof buf) {
        return -1;
    }
    memcpy(buf, ip, (size_t) iplen);
    buf[iplen] = '\0';
    if (memchr(buf, ':', (size_t) iplen) != NULL) {
        struct in6_addr a6;

        if (inet_pton(AF_INET6, buf, &a6) != 1) {
            return -1;
        }
        memcpy(b, &a6, 16);
        we_addr_canon(b, 6, out);
        return 0;
    } else {
        struct in_addr a4;

        if (inet_pton(AF_INET, buf, &a4) != 1) {
            return -1;
        }
        memcpy(b, &a4, 4);
        memset(b + 4, 0, 12);
        we_addr_canon(b, 4, out);
        return 0;
    }
}

/*
 * THE WALK'S INPUT: the newest 16 lines of the configured header, in arrival order, from the server's
 * iov list (every line is a separate entry in received order, measured), read in this function's own
 * frame (the iov arrays never share a frame with the decision's scratch). Above the header-line bound
 * the walk does not run: a truncated list would hold the client's lines and drop the proxy's appended
 * last one, so the peer is judged with the `capped` note.
 */
__attribute__((noinline)) static int ls_gather_lines(const lsi_session_t *s, we_mod_line_t lines[WE_MOD_WALK_LINES],
                                                    uint32_t *n, int *older, uint32_t *capped)
{
    struct iovec kstack[LS_IOV_STACK], vstack[LS_IOV_STACK];
    struct iovec *k = kstack, *v = vstack;
    int count = ls_api->get_req_headers_count(s), got, i;
    size_t hl = strlen(g_http.trusted_header);
    uint32_t total = 0u;

    *n = 0u;
    *older = 0;
    *capped = 0u;
    if (count <= 0) {
        return 0;
    }
    if ((uint32_t) count > g_hdr_line_bound) {
        *capped = (uint32_t) count;
        return 0;
    }
    if (count > LS_IOV_STACK) {
        ls_xpool_t *pool = ls_api->get_session_pool(s);

        k = pool != NULL ? ls_xpool_alloc(pool, (uint32_t) count * sizeof *k) : NULL;
        v = pool != NULL ? ls_xpool_alloc(pool, (uint32_t) count * sizeof *v) : NULL;
        if (k == NULL || v == NULL) {
            *capped = (uint32_t) count;
            return 0;
        }
    }
    got = ls_api->get_req_headers(s, k, v, count);
    for (i = 0; i < got; i++) {
        if (k[i].iov_len == hl && strncasecmp((const char *) k[i].iov_base, g_http.trusted_header, hl) == 0) {
            lines[total % WE_MOD_WALK_LINES].p = (const uint8_t *) v[i].iov_base;
            lines[total % WE_MOD_WALK_LINES].len = v[i].iov_len;
            total++;
        }
    }
    if (total > WE_MOD_WALK_LINES) {
        /* the ring holds the newest 16 in arrival order: rotate so lines[0] is the oldest kept */
        we_mod_line_t tmp[WE_MOD_WALK_LINES];
        uint32_t start = total % WE_MOD_WALK_LINES, j;

        for (j = 0u; j < WE_MOD_WALK_LINES; j++) {
            tmp[j] = lines[(start + j) % WE_MOD_WALK_LINES];
        }
        memcpy(lines, tmp, sizeof tmp);
        *n = WE_MOD_WALK_LINES;
        *older = 1;
    } else {
        *n = total;
    }
    return 0;
}

/*
 * The ACME exemption: GET or HEAD, no query at all (a bare `?` included), and the ORIGINAL request path
 * byte for byte equal to the normalised one under /.well-known/acme-challenge/ (so `%74ok`, `%2e` and a
 * leading `//` are judged, the plain token is not). The query's presence comes from
 * get_req_query_string, which is NULL when the request line carries no `?` and non-NULL and empty for a
 * bare `?` (measured); the original path from get_req_org_uri, the pre-rewrite path without the query,
 * kept as written (measured). The raw header block is never read: on this server it starts with four
 * bytes of its own before the request line (measured), and nothing here needs it.
 */
static int ls_acme(const lsi_session_t *s, const char *norm, size_t nlen)
{
    static const char pfx[] = "/.well-known/acme-challenge/";
    char org[2048];
    int olen, qlen = 0;
    const char *method;
    size_t mlen;

    if (nlen <= sizeof pfx - 1u || memcmp(norm, pfx, sizeof pfx - 1u) != 0) {
        return 0;                        /* the cheap test first: nothing else is read for an ordinary path */
    }
    switch (ls_api->get_req_method(s)) {
    case LSI_METHOD_GET:  method = "GET";  mlen = 3u; break;
    case LSI_METHOD_HEAD: method = "HEAD"; mlen = 4u; break;
    default: return 0;
    }
    if (ls_api->get_req_query_string(s, &qlen) != NULL) {
        return 0;                        /* any query, an empty one included */
    }
    olen = ls_api->get_req_org_uri(s, org, (int) sizeof org);
    if (olen <= 0 || (size_t) olen >= sizeof org) {
        return 0;
    }
    return we_mod_acme((const uint8_t *) method, mlen, (const uint8_t *) org, (size_t) olen, (const uint8_t *) norm, nlen);
}

static void ls_env_set(const lsi_session_t *s, const char *name, const char *val, size_t vlen)
{
    ls_api->set_req_env(s, name, (unsigned) strlen(name), val, (int) vlen);
}

/* the deny on this server: the header, the status, the module's fixed text and the end of the response, so
 * `Cache-Control: no-store` reaches the wire (a header set before a bare LSI_DENY is dropped, measured) */
static void ls_deny_response(const lsi_session_t *s, unsigned status)
{
#ifndef WE_LS_TEST_DROP_NOSTORE
    ls_api->set_resp_header(s, LSI_RSPHDR_CACHE_CTRL, NULL, 0, "no-store", 8, LSI_HEADEROP_SET);
#endif
    ls_api->set_status_code(s, (int) status);
    (void) ls_api->append_resp_body(s, WE_MOD_DENY_TEXT, (int) (sizeof WE_MOD_DENY_TEXT - 1u));
    ls_api->end_resp(s);
}

/*
 * At most one line per second per process per outcome, carrying the count it suppressed: without the
 * limit the module is a disk-fill amplifier against the operator it protects. The line names the rule,
 * the program and, for a decision on a fresh reputation entry, the listing's citable evidence, read from
 * the view the decision used (inside its grace, on the handler's thread). The counters stay exact.
 */
static void ls_log_outcome(const lsi_session_t *s, const we_mod_record_t *rec, const we_addr_t *floor,
                           const we_addr_t *server, const we_map_t *rep, int enforced, uint64_t now_ms)
{
    uint64_t now_sec = now_ms / 1000u, total;
    uint64_t *at_last = enforced ? &g_denied_at_last : &g_would_at_last;
    uint64_t *last_sec = enforced ? &g_last_deny_sec : &g_last_would_sec;
    const char *ev = NULL, *rule_id = we_mod_render_rule(rec, &g_cfg, 0), *rule_text = we_mod_render_rule(rec, &g_cfg, 1);
    char addr[WE_ADDR_TEXT_MAX], fired[64];

    total = enforced ? ++g_denied : ++g_would_deny;
    if (*last_sec == now_sec) {
        return;
    }
    *last_sec = now_sec;
    we_addr_format(floor, addr);
    if (!enforced) {
        /* a would-deny decides nothing (the default allow does): name the fired rules, the first few */
        uint32_t k, r, n = 0u;
        size_t o = 0u;

        for (k = 0u; k < 2u && o < sizeof fired - 16u; k++) {
            for (r = 0u; r < 256u && n < 6u && o < sizeof fired - 16u; r++) {
                if (((rec->log_fired[k][r >> 3] >> (r & 7u)) & 1u) != 0u) {
                    o += (size_t) snprintf(fired + o, sizeof fired - o, "%s%s:%u", n != 0u ? "," : "", k == 0u ? "floor" : "ctx", r + 1u);
                    n++;
                }
            }
        }
        if (o == 0u) {
            snprintf(fired, sizeof fired, "-");
        }
        rule_id = fired;
        rule_text = n == 1u ? we_mod_render_rule(rec, &g_cfg, 1) : "the rules logged";
    }
    if (rep != NULL && rec->slot.state[0] == WE_ST_FRESH_HIT) {
        if (server->family == 4u) {
            ev = we_evidence4(rep, (uint32_t) server->b[0] << 24 | (uint32_t) server->b[1] << 16 | (uint32_t) server->b[2] << 8
                              | server->b[3]);
        } else {
            ev = we_evidence6(rep, server->b);
        }
    }
    /* the verdict in the core's canonical spelling, byte-identical with the nginx and Apache lines for one
     * listing (POLICY.md's rendering section); at error, as on nginx and Apache, so the deny and the log
     * mode's WOULD DENY are seen at every logLevel this server takes, ERROR the strictest */
#ifndef WE_MOD_TEST_DENY_AT_WARN
    ls_api->log(s, LSI_LOG_ERROR, LS_LOG_PFX "%s %s by %s \"%s\" (program %s; verdict %s; evidence %s%s; %llu %s so far, %llu "
               "since the last line)\n", enforced ? "denied" : "WOULD DENY", addr, rule_id, rule_text,
               we_mod_render_program(rec, &g_cfg), we_mod_render_verdict(rec, WE_MOD_SPELL_SPAMHAUS),
               ev != NULL ? ev : "none carried",
               enforced ? "" : "; mode is log, request allowed", (unsigned long long) total, enforced ? "denied" : "would-deny",
               (unsigned long long) (total - *at_last));
#else
    ls_api->log(s, LSI_LOG_WARN, LS_LOG_PFX "%s %s by %s \"%s\" (program %s; verdict %s; evidence %s%s; %llu %s so far, %llu "
               "since the last line)\n", enforced ? "denied" : "WOULD DENY", addr, rule_id, rule_text,   /* the control: at warn */
               we_mod_render_program(rec, &g_cfg), we_mod_render_verdict(rec, WE_MOD_SPELL_SPAMHAUS),
               ev != NULL ? ev : "none carried",
               enforced ? "" : "; mode is log, request allowed", (unsigned long long) total, enforced ? "denied" : "would-deny",
               (unsigned long long) (total - *at_last));
#endif
    *at_last = total;
}

typedef struct {
    we_mod_req_t   req;
    we_addr_t      server;
    const we_mod_ctx_t *x;
    uint64_t       now_ms;
} ls_eval_t;

/*
 * THE DECISION'S FRAME: owns the scratch (1,024 bytes, 64-byte aligned), calls the wrapper, and does
 * everything after the verdict: the record, the export, the log line, the response. The walk ran and
 * returned before this frame was entered, so the iov arrays never stack on the scratch.
 */
__attribute__((noinline)) static int ls_decide_frame(const lsi_session_t *s, const ls_eval_t *ev)
{
    WE_ALIGN64 we_mod_scratch_t sc;
    we_mod_record_t *rec;
    ls_xpool_t *pool;
    void *raw;
    const we_mod_ctx_t *x = ev->x;
    const we_map_t *rep_view;
    uint32_t i, sev;
    char floor_txt[WE_ADDR_TEXT_MAX];
    const char *w;
    size_t wl;

#ifdef WE_MOD_TEST_INLINE_HANDLER
    /* the control: the evaluator inlined here leaves its evaluation-site record in this frame, outside the
     * wrapper (which the `used` attribute keeps, with its own record), so the gate's row reads two */
    we_mod_decide(&g_cfg, x, &sc, g_shard, &ev->req, ev->now_ms);
#else
    ls_whisper_edge_decide(&g_cfg, x, &sc, g_shard, &ev->req, ev->now_ms);
#endif
    /* the record, in the session's memory, aligned by hand */
    pool = ls_api->get_session_pool(s);
    raw = pool != NULL ? ls_xpool_alloc(pool, (uint32_t) WE_MOD_RECORD_ALLOC) : NULL;
    if (raw == NULL) {
        /* no memory for the record: the decision stands, nothing is exported */
        if (sc.v.enforce != 0u) {
            ls_deny_response(s, sc.v.program == WE_VPROG_FLOOR || sc.v.step != WE_STEP_CONTEXT ? g_cfg.floor_status : x->deny_status);
            return LSI_DENY;
        }
        return LSI_OK;
    }
    rec = we_mod_record_at(raw);
    we_mod_record_init(rec, x);
    we_mod_record_write(rec, &g_cfg, x, &sc, &ev->req.r.floor, &ev->server);
    sev = rec->severity;
    rep_view = sc.e.view[0].m;           /* the reputation view the decision used, read before the fill re-takes views */
    /* the legacy snapshot's per-range count, the pin's summary: a would-deny or a deny on a fresh listed range */
    we_counters_t *lc_set = __atomic_load_n(&g_legacy_counters, __ATOMIC_RELAXED);   /* the loop's own: this thread stores it */

    if (lc_set != NULL && sev != 0u && rec->slot.state[0] == WE_ST_FRESH_HIT && sc.e.view[0].m != NULL) {
        if (ev->server.family == 4u) {
            uint32_t a4 = (uint32_t) ev->server.b[0] << 24 | (uint32_t) ev->server.b[1] << 16 | (uint32_t) ev->server.b[2] << 8
                        | ev->server.b[3];

            we_counters_count4(lc_set, sc.e.view[0].m, a4);
        } else {
            we_counters_count6(lc_set, sc.e.view[0].m, ev->server.b);
        }
    }
    /* the export: every BOUND plane of the context's export set filled through the decision's own scratch, once,
     * and every plane the binding recorded unreadable, whose fill reads no map and records why (`-u`); any other
     * unbound plane has no binding to fill through and renders unknown and `-a` below without one */
    we_mod_fill(rec, &g_cfg, &sc, (uint32_t) ((x->export_mask | x->gen_mask) & (g_bound_mask | g_unread_mask)), ev->now_ms);
    w = we_mod_render_action(rec);
    ls_env_set(s, "WHISPER_EDGE_ACTION", w, strlen(w));
    w = we_mod_render_rule(rec, &g_cfg, 1);
    ls_env_set(s, "WHISPER_EDGE_RULE", w, strlen(w));
    w = we_mod_render_rule(rec, &g_cfg, 0);
    ls_env_set(s, "WHISPER_EDGE_RULE_ID", w, strlen(w));
    w = we_mod_render_reason(rec, ev->req.r.walk, ev->req.note);
    ls_env_set(s, "WHISPER_EDGE_REASON", w, strlen(w));
    w = we_mod_render_program(rec, &g_cfg);
    ls_env_set(s, "WHISPER_EDGE_PROGRAM", w, strlen(w));
    {
        uint64_t any = 0u, word[8];

        memcpy(word, &rec->log_fired[0][0], sizeof word);
        for (i = 0u; i < 8u; i++) {
            any |= word[i];
        }
        if (any == 0u) {
            ls_env_set(s, "WHISPER_EDGE_LOGGED", "-", 1u);
        } else {
            char *lg = ls_xpool_alloc(pool, (uint32_t) WE_MOD_LOGGED_MAX);

            if (lg != NULL) {
                wl = we_mod_render_logged(rec, lg);
                ls_env_set(s, "WHISPER_EDGE_LOGGED", lg, wl);
            }
        }
    }
    {
        char *gen = ls_xpool_alloc(pool, (uint32_t) WE_MOD_GEN_MAX);

        if (gen != NULL) {
            wl = we_mod_render_generations(rec, gen);
            ls_env_set(s, "WHISPER_EDGE_GENERATIONS", wl != 0u ? gen : "-", wl != 0u ? wl : 1u);
        }
    }
    wl = we_mod_render_floor(rec, floor_txt);
    ls_env_set(s, "WHISPER_EDGE_FLOOR_ADDR", floor_txt, wl);
    w = we_mod_render_verdict(rec, WE_MOD_SPELL_SPAMHAUS);
    ls_env_set(s, "WHISPER_EDGE_VERDICT", w, strlen(w));
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        const we_mod_attr_t *a = we_mod_attr(i);

        if (((x->export_mask >> a->plane) & 1u) == 0u) {
            continue;
        }
        if (((g_bound_mask >> a->plane) & 1u) == 0u) {
            w = "unknown";                  /* a named plane that is not bound here: unknown, never unread */
            wl = 7u;
        } else if (we_mod_render_attr(rec, i, &w, &wl) != 0) {
            continue;
        }
        ls_api->set_req_env(s, g_env_name[i], g_env_name_len[i], w, (int) wl);
    }
    /*
     * The response is decided from the RECORD, never from the scratch: the fill above clears the scratch
     * verdict when it has a plane to fill (a floor deny leaves every plane the context's rules would have
     * read unread), and a frame that read `sc.v.enforce` here served a floor-denied client a 200 while its
     * own log line said deny. Severity 2 is a deny the core enforced (we_mod_record_write), and the
     * deciding block and step are the record's.
     */
    if (sev == 2u) {
        ls_log_outcome(s, rec, &ev->req.r.floor, &ev->server, rep_view, 1, ev->now_ms);
        /* a pre-stage or floor decision uses the http level's status; a context rule the context's */
        ls_deny_response(s, rec->program == WE_VPROG_FLOOR || rec->step != WE_STEP_CONTEXT ? g_cfg.floor_status : x->deny_status);
        return LSI_DENY;
    }
    if (sev == 1u) {
        ls_log_outcome(s, rec, &ev->req.r.floor, &ev->server, rep_view, 0, ev->now_ms);
    }
    return LSI_OK;
}

/*
 * LSI_HKPT_HTTP_AUTH, the LSIAPI analogue of Apache's access_checker: after LSI_HKPT_URI_MAP has mapped
 * the request to a context, at the point the API designates for an access decision. Not RCVD_REQ_HEADER
 * and not HTTP_BEGIN: there get_config returns the server-level configuration for every request, so a
 * host's own lines would never apply (measured, and asserted by the gate). OpenLiteSpeed may pass this
 * point more than once for one request (an internal rewrite, an index file): each pass is judged under
 * the virtual host's one policy and counted.
 */
/* the hook's body: inlined into we_check below, so the symbol the gate enumerates holds every return path */
static inline __attribute__((always_inline)) int we_check_judge(lsi_param_t *param)
{
    const lsi_session_t *s = param->session;
    we_conf_t *conf;
    ls_ctx_t *lc;
    ls_eval_t ev;
    we_mod_walk_t walk;
    const char *ip, *uri;
    int iplen = 0, urilen = 0, have_peer;
    we_addr_t peer;

    if (!g_built) {
        return LSI_OK;                   /* no configuration: nothing to judge */
    }
    conf = ls_api->get_config(s, &MNAME);
    lc = conf != NULL && conf->c != NULL ? conf->c : &g_server;
    ev.x = lc->ctx != NULL ? lc->ctx : g_server.ctx;
    if (ev.x == NULL) {
        return LSI_OK;
    }
#ifdef WE_LS_TEST_MODE_OFF_RETURN
    if (we_conf_mode(&ev.x->conf) == WE_MODE_OFF) {
        return LSI_OK;                   /* the control: the pin's early return, which skipped the floor */
    }
#endif
    ev.now_ms = ls_now_ms();
    ip = ls_api->get_client_ip(s, &iplen);
    have_peer = ls_parse_peer(ip, iplen, &peer) == 0;
    memset(&walk, 0, sizeof walk);
    if (have_peer && g_trust_built && g_http.trusted_header[0] != '\0' && we_mod_trusted(&g_trust, &peer, NULL)) {
        we_mod_line_t lines[WE_MOD_WALK_LINES];
        uint32_t n = 0u, capped = 0u;
        int older = 0;

        ls_gather_lines(s, lines, &n, &older, &capped);
        if (capped != 0u) {
            /* more lines than the server accepts at its own limit: unreachable in theory, said loudly when hit */
            static int said;

            we_mod_walk(&g_trust, g_http.trusted_hops, 1, &peer, lines, 0u, 1, &walk);
            walk.note = WE_MOD_NOTE_CAPPED;
            walk.eligible = 0u;
            if (!said) {
                said = 1;
                ls_log(LSI_LOG_ERROR, "a request carried %u header lines, above the %u this server's limit admits; the peer "
                       "is judged with the capped note", capped, g_hdr_line_bound);
            }
        } else {
            we_mod_walk(&g_trust, g_http.trusted_hops, 1, &peer, lines, n, older, &walk);
        }
    } else {
        we_mod_walk(&g_trust, g_http.trusted_hops, 0, have_peer ? &peer : NULL, NULL, 0u, 0, &walk);
    }
    uri = ls_api->get_req_uri(s, &urilen);
    ev.server = walk.floor;
    if (!have_peer) {
        memset(&ev.server, 0, sizeof ev.server);
    }
    we_mod_req_build(&ev.req, &walk, &ev.server, uri != NULL && urilen > 0 ? ls_acme(s, uri, (size_t) urilen) : 0);
    return ls_decide_frame(s, &ev);
}

/* LSI_HKPT_HTTP_AUTH: the one request handler, and the one the syscall-count row brackets */
static int we_check(lsi_param_t *param)
{
    int rc;

    LS_MARK_ENTER();
    rc = we_check_judge(param);
    LS_MARK_EXIT();
    return rc;
}

/* ---------------------------------------------------------------------------------------------- */
/* The module                                                                                       */
/* ---------------------------------------------------------------------------------------------- */

static lsi_serverhook_t we_hooks[] = {
    { LSI_HKPT_MAIN_INITED,   we_main_inited,   LSI_HOOK_NORMAL, LSI_FLAG_ENABLED },
    { LSI_HKPT_WORKER_INIT,   we_worker_init,   LSI_HOOK_NORMAL, LSI_FLAG_ENABLED },
    { LSI_HKPT_HTTP_AUTH,     we_check,         LSI_HOOK_NORMAL, LSI_FLAG_ENABLED },
    { LSI_HKPT_WORKER_ATEXIT, we_worker_atexit, LSI_HOOK_NORMAL, LSI_FLAG_ENABLED },
    LSI_HOOK_END
};

static lsi_confparser_t we_confparser = {
    we_parse_config, we_free_config, we_config_keys
};

LSMODULE_EXPORT lsi_module_t MNAME = {
    LSI_MODULE_SIGNATURE, we_init, NULL, &we_confparser, "v2.0", we_hooks, { 0 }
};
