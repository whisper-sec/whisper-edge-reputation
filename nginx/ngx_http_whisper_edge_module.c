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
 * ngx_http_whisper_edge_module.c - the nginx module over the edge policy core.
 *
 * What is nginx's here: where to hook, how to read the client address and the request, how to log,
 * how a configuration block becomes a context, and how a worker schedules the module's thread. The
 * language, its compiler, the evaluator, the planes' verification and the writers live in the core
 * (we_module.h, we_module.c), written once and gated once; this file calls them.
 *
 * THE PROPERTIES THIS FILE EXISTS TO PRESERVE.
 *
 * 1. It defaults to NOT BLOCKING. A context with no policy line and no threshold line runs
 *    `deny if listed >= high` under `whisper_edge_mode log`: it logs the verdict it WOULD have acted on
 *    without acting on it. Nothing here blocks until somebody writes `deny` in their configuration.
 *
 * 2. A configuration the module cannot compile fails `nginx -t`, with the directive's own file and
 *    line in front of the compiler's refusal, so the installer's "reload only if the test passes" is
 *    the gate and nothing partial ever loads. A plane that is absent or fails to verify is never a
 *    configuration error: its rules are inert or read UNKNOWN, and the module says so once.
 *
 * 3. The decision makes no syscall, takes no lock and allocates nothing: one force-inlined core
 *    function behind one `noinline` wrapper of this module's own, which the module gate disassembles
 *    out of the built object.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * The deny line and the log mode's WOULD DENY line, at error: nginx's own level for a denial (the access
 * module's "access forbidden by rule"), so a stock `error_log`, which names no level and keeps error and
 * above, shows both, and the README's promise that log mode writes what it would deny into the error log
 * holds on a distribution's configuration. Both stay rate-limited to one line a second per worker.
 */
#ifndef WE_MOD_TEST_DENY_AT_WARN
#define WE_NGX_DENY_LEVEL NGX_LOG_ERR
#else
#define WE_NGX_DENY_LEVEL NGX_LOG_WARN    /* the control: both lines at warn, under a stock error_log's floor */
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "whisper_edge.h"
#include "we_module.h"
#include "we_procid.h"
#include "we_sha256.h"

#if !defined(WE_MOD_CONTROL_BUILD) && (defined(WE_MOD_TEST_LEXICAL) || defined(WE_TEST_MARKERS) || defined(WE_MOD_TEST_BIND_ALL) \
                                       || defined(WE_MOD_TEST_NO_STORE_OFF) || defined(WE_MOD_TEST_FLOOR_ERROR_PAGE) \
                                       || defined(WE_MOD_TEST_BIND_ANY_REF) || defined(WE_MOD_TEST_BIND_ON_INDEX) || defined(WE_MOD_TEST_MODE_OFF_RETURN) \
                                       || defined(WE_MOD_TEST_PLANTED_KEY) || defined(WE_MOD_TEST_BIND_IN_INIT) \
                                       || defined(WE_MOD_TEST_NO_FINAL_UID) \
                                       || defined(WE_MOD_TEST_ORDER_IN_INIT) \
                                       || defined(WE_MOD_TEST_RING_OLDEST) \
                                       || defined(WE_MOD_TEST_CONFLICT_CLOSED) || defined(WE_MOD_TEST_NGX_FLAT_STOP) \
                                       || defined(WE_MOD_TEST_REFUSED_WARN) \
                                       || defined(WE_MOD_TEST_COUNT_ENFORCED_ONLY) \
                                       || defined(WE_MOD_TEST_NGX_LIST_ONLY))
#error "the WE_MOD_TEST_* defines of this module and WE_TEST_MARKERS are a gate's builds and exist only in a control build (WE_MOD_CONTROL_BUILD)"
#endif

/* The level of the core's own sentences (a plane refused at configuration, the conflict's open start): error,
 * because nginx's stock error_log names no level and keeps error and above. The control puts them at warn. */
#ifndef WE_MOD_TEST_REFUSED_WARN
#define WE_NGX_REFUSED_LEVEL NGX_LOG_ERR
#else
#define WE_NGX_REFUSED_LEVEL NGX_LOG_WARN
#endif

/*
 * THE DECIDE WRAPPER AND THE HANDLERS KEEP THEIR SYMBOLS. The module gate disassembles the one wrapper
 * every evaluation site calls and every handler by name out of the built object, so the wrapper is never
 * inlined or cloned (noinline, and on gcc noipa, which also forbids the .constprop and .isra clones) and
 * the handlers are hidden non-static symbols, which a -flto link neither renames nor interposes.
 */
#if defined(__clang__)
#define WE_NGX_WRAPPER __attribute__((noinline, used, visibility("hidden")))
#else
#define WE_NGX_WRAPPER __attribute__((noinline, noipa, used, visibility("hidden")))
#endif
#define WE_NGX_HANDLER __attribute__((used, visibility("hidden")))

#ifdef WE_MOD_TEST_PLANTED_KEY
/* the control of the keyless-equals-keyed row: a key-shaped string planted in the object, spelt in pieces so the
 * source scan of that row (which greps for the header name) does not read it from this file */
static const char we_planted_key[] __attribute__((used)) = "whisper_live_planted_" "X-API" "-Key";
#endif

/*
 * THE MARKERS of the gate's syscall-count row: a test build brackets every handler invocation with two
 * system calls that do nothing (getpgid of a pid above PID_MAX_LIMIT answers ESRCH), each carrying a
 * distinguishing argument, so a trace attributes every call in between to the module by position. The
 * macro saves and restores errno, so the test build differs from production by the two calls alone.
 */
#ifdef WE_TEST_MARKERS
#include <errno.h>
#include <sys/syscall.h>
#define WE_NGX_MARK(a) do { int e_ = errno; (void) syscall(SYS_getpgid, (long) (a)); errno = e_; } while (0)
#define WE_NGX_ENTER() WE_NGX_MARK(0x7ffffffeL)
#define WE_NGX_EXIT()  WE_NGX_MARK(0x7ffffffdL)
#else
#define WE_NGX_ENTER() ((void) 0)
#define WE_NGX_EXIT()  ((void) 0)
#endif

/* ---- the configuration as the module records it ---------------------------------------------- */

/* where a directive was written: its file and line, as nginx's parser had them */
typedef struct {
    ngx_str_t  file;
    ngx_uint_t line;
} we_ngx_place_t;

typedef struct ngx_http_whisper_edge_loc_conf_s ngx_http_whisper_edge_loc_conf_t;

/* one directive the compiler sees, in file order */
typedef struct {
    uint8_t                            kind;      /* WE_DIR_* */
    ngx_http_whisper_edge_loc_conf_t  *lcf;       /* the context it was written in */
    ngx_str_t                          name;      /* the directive as written */
    ngx_str_t                          arg;       /* its arguments, joined with one space */
    we_ngx_place_t                     place;
} we_ngx_directive_t;

/* what a command carries into its handler: its kind and whether it is http level only */
typedef struct {
    uint8_t     kind;
    uint8_t     http_only;
    const char *name;
} we_ngx_cmd_t;

struct ngx_http_whisper_edge_loc_conf_s {
    ngx_uint_t        mode;             /* WE_MODE_OFF, _LOG, _DENY as the core spells them; NGX_CONF_UNSET_UINT */
    ngx_uint_t        threshold;        /* WE_SEV_*; NGX_CONF_UNSET_UINT */
    ngx_flag_t        allow_inferred;   /* NGX_CONF_UNSET, 0 or 1 */
    ngx_uint_t        deny_status;      /* NGX_CONF_UNSET_UINT or a code of the deny-status allow-list */
    ngx_array_t      *exports;          /* ngx_str_t: the attribute names an export line adds */
    ngx_uint_t        export_all;
    we_ngx_place_t    mode_place, threshold_place, inferred_place, status_place, export_place;
    we_ngx_place_t    place;            /* where the block opened */
    unsigned          own:1;            /* carries whisper_edge_policy lines of its own */
    unsigned          own_threshold:1;  /* carries a threshold line of its own */
    /* assigned at postconfiguration */
    ngx_http_whisper_edge_loc_conf_t *parent;
    const char       *path;             /* the ordinal path the compiler is given: "http/s2/l1" */
    const char       *human;            /* the operator's name for it: server "example.com" */
    ngx_uint_t        ordinal;          /* index into the contexts; NGX_CONF_UNSET_UINT for an `if` block */
    ngx_uint_t        nchildren;        /* named children merged so far: the next child's ordinal among its siblings */
    unsigned          is_http:1;        /* the http block's own context */
    unsigned          noname:1;         /* an `if` or `limit_except` block: runs the enclosing context's program */
    const we_mod_ctx_t *ctx;            /* the request path's context: its own, or the enclosing one's */
};

typedef struct {
    ngx_array_t       directives;       /* we_ngx_directive_t, in file order */
    ngx_str_t         snapshot;         /* whisper_edge_snapshot, the legacy reputation file */
    we_ngx_place_t    snapshot_place;
    ngx_str_t         data_dir;         /* whisper_edge_data <dir> */
    we_ngx_place_t    data_place;
    ngx_str_t         plane_file[8];    /* whisper_edge_data <plane> <file> */
    we_ngx_place_t    plane_place[8];
    ngx_msec_t        refresh;
    we_ngx_place_t    refresh_place;
    ngx_str_t         counters_dir;
    we_ngx_place_t    summary_place;
    ngx_array_t      *trusted_proxy;    /* ngx_str_t items */
    we_ngx_place_t    trusted_proxy_place;
    ngx_str_t         trusted_header;
    we_ngx_place_t    trusted_header_place;
    ngx_uint_t        trusted_hops;
    we_ngx_place_t    trusted_hops_place;
    ngx_uint_t        floor_lines;
    we_ngx_place_t    floor_place;
    ngx_uint_t        export_lines;

    /* the configuration, built once at postconfiguration in the process that parses it */
    ngx_http_whisper_edge_loc_conf_t  *http;      /* the http-level context */
    ngx_http_whisper_edge_loc_conf_t **contexts;  /* every named context, in ordinal order */
    ngx_uint_t        nctx;
    ngx_array_t       merged;           /* every named server and location, in merge (file) order */
    ngx_array_t       noname;           /* the `if` and `limit_except` blocks: each runs its enclosing context's program */
    we_mod_arena_t   *arena;
    we_mod_cfg_t      cfg;
    we_mod_ctx_t     *ctxs;
    uint32_t          stride;
    uint64_t         *sink;             /* one full shard nothing reads: a thread with no shard counts here */
    we_policy_env_t   env;
    we_mod_peek_t     dir_snapshot;     /* a snapshot.bin beside the planes of whisper_edge_data: never bound, said */
    unsigned          dir_snapshot_here:1;
    uint8_t           read_mask;        /* the planes the programs, exports and variables read */
    unsigned          has_binding:1;    /* a data directive exists: the module decides */
    unsigned          legacy:1;         /* the snapshot synonym is the only data directive */
    uint8_t           plane_want;       /* the planes the configuration file lists */
    const char       *refused[8];       /* a plane refused at configuration: its reason with the fix (the core's) */
    ngx_array_t      *bind_lines;       /* the bind's lines, written by init_module into the cycle's own log */
    size_t            conf_bound_base;  /* the configuration file's bound before its plane lines */
    unsigned          bind_uid;         /* the workers' uid the binding (or its check) trusted */
    unsigned          bind_done:1;      /* the binding (or its check) ran at postconfiguration */
    uint8_t           plane_lines;      /* the planes a whisper_edge_data <plane> <file> line binds, read or not */
    unsigned          stale_single:1;   /* a single-process reload: this configuration decides over the first one's planes */
    ngx_log_t        *log;
    we_mod_planes_t  *planes;           /* bound in the process that parsed the configuration, before fork */
    we_mod_trust_t    trust;            /* the trusted-proxy table built from whisper_edge_trusted_proxy (empty: nobody) */
    ngx_uint_t        trusted_header_hash;   /* nginx's own hash of the lowercased name, compared before the bytes */
    unsigned          want_record:1;    /* a $whisper_edge_* variable is referenced or something is exported: the record is written at the decision */

    /*
     * The writers' configuration-time facts. The counter map is one entry per context that owns lines,
     * the floor first (section 6); the configuration file's bytes are rendered once here, in the process
     * that parses the configuration, so every worker that writes it writes the same bytes and every
     * per-process file can name the digest of those bytes. The workers write the file; a
     * configuration test renders it and writes nothing.
     */
    we_mod_ctrmap_entry_t *ctrmap;     /* ngx_pcalloc'd: nctrm entries, the floor first */
    uint32_t          nctrm;
    char             *conf_bytes;      /* the rendered configuration file, conf_bound bytes at most */
    size_t            conf_len, conf_bound;
    char              conf_name[29];   /* conf-<16 hex>.status: the digest of conf_bytes' own bytes */
    char              config16[17];    /* the same digest, what every per-process file carries */
    const char       *plane_path[8];   /* the bound planes' files, for the configuration file's plane lines */
    const char       *plane_unreadable[8];   /* the peek's errno text when the workers cannot read the file */
} ngx_http_whisper_edge_main_conf_t;

static ngx_int_t we_ngx_bind_planes(ngx_cycle_t *cycle, ngx_log_t *log, ngx_http_whisper_edge_main_conf_t *mcf);
static ngx_int_t we_ngx_bind_args(ngx_pool_t *pool, const ngx_http_whisper_edge_main_conf_t *mcf, we_mod_bind_args_t *args);
static ngx_int_t we_ngx_render_conf_file(ngx_log_t *log, ngx_pool_t *pool, ngx_http_whisper_edge_main_conf_t *mcf);

/* a plane the configuration file lists: one something reads, one its own line binds, or a present tenant */
static int we_ngx_plane_wanted(const ngx_http_whisper_edge_main_conf_t *mcf, uint32_t p, const we_mod_peek_t *peek)
{
    return ((mcf->read_mask >> p) & 1u) != 0u || ((mcf->plane_lines >> p) & 1u) != 0u
           || (p == 0u && mcf->snapshot.len > 0 && !mcf->legacy)
           || (p + 1u == WE_PLANE_TENANT && !peek->absent);
}

/* ---- the per-request node and the per-process worker state -------------------------------------- */

/*
 * One node per main request, a pool cleanup found again after an internal redirect (which zeroes
 * r->ctx) by its handler, the way realip finds its own: the TCP peer captured before any module could
 * rewrite it, the judged floor address with the walk's result, the decision's compact fields, and the
 * record when a variable needs one.
 */
typedef struct {
    we_addr_t          peer;            /* the TCP peer, canonical; family 0 for a unix socket */
    we_mod_walk_t      walk;            /* the judged floor address, the walk mark, eligibility, the note */
    const we_mod_ctx_t *ctx;            /* the context the decision ran under */
    we_mod_record_t   *record;          /* when a variable needs one; NULL otherwise */
    uint16_t           rule;            /* the decision's compact fields, for the variables and the log */
    uint8_t            step, action, program, reason, marks, severity, decided, has_peer;
    uint8_t            synth;           /* the record's decision fields came from these after the fact: no bitmaps */
} we_ngx_node_t;
WE_STATIC_ASSERT(sizeof(we_ngx_node_t) == 112u, "the per-request node is 112 bytes: the peer, the walk with the floor address, two pointers, the fields");

/*
 * The serving process's state: everything the module's thread touches, in process-lifetime memory
 * (malloc, never a pool), one per worker, started before the first accept.
 */
typedef struct {
    we_mod_planes_t  *planes;
    we_handle_t      *legacy_handle;    /* the reputation handle when the synonym is bound, for the per-range counters */
    we_mod_thread_t  *thread;
    uint64_t         *shard;            /* this worker's counter array, or the configuration's sink */
    uint32_t          stride;
    we_mod_procid_t   id;
    uint64_t          started_ms, interval_ms, offset_ms;
    int               efd;              /* the eventfd the thread writes to wake the loop */
    ngx_connection_t *efd_conn;
    char             *counters_dir;     /* NUL-terminated, or NULL for off */
    const void       *planes_cfg;       /* the we_mod_cfg_t the planes were bound into (a single-process reload copies it) */
    unsigned          no_thread:1, no_shard:1, started:1, abandoned:1, counters_said:1, single_stale:1;
    /* the legacy reputation copy's per-range counters: the loop counts into `legacy`; the thread builds a
     * fresh set when the armed map changes, posts it, and frees what the loop hands back */
    we_counters_t    *legacy;           /* the loop's: the set requests count into */
    we_counters_t    *thread_set;       /* the thread's view of the same set, and the map it was built for */
    const we_map_t   *thread_map;
    we_mod_item_t    *sets_to_loop;
    we_mod_item_t    *sets_to_thread;
    /* the rate-limited log lines, one per second per outcome */
    ngx_uint_t        denied, would_deny, denied_at_last_log, would_deny_at_last_log;
    time_t            last_deny_log, last_would_log;
    /*
     * THE WRITERS: everything below is this process's own, malloc'd at its start and
     * read by its thread alone. The counters directory is one held descriptor every writer is openat
     * relative to; the file names come from the process's identity, so a reused pid never overwrites
     * another process's file. The configuration's bytes, its name and its counter map are COPIES of the
     * configuration's (a single-process reload frees the cycle pool the first configuration lived in).
     */
    int               cdir_fd;         /* the counters directory, or -1: the writers are off */
    unsigned          client_header:1; /* the configuration reads the client address from a trusted header */
    char              status_name[64], rules_name[64], conf_name[29], config16[17];
    char             *conf_bytes;      /* the copy this process writes when it finds the name absent */
    size_t            conf_len;
    we_mod_ctrmap_t   ctrmap;          /* the copy of the configuration's map, the floor first */
    we_mod_ctrmap_entry_t *ctrmap_e;
    uint64_t         *snap;            /* the counters' snapshot: relaxed loads, one per stride word */
    we_mod_status_t  *status;          /* the status file's input, refilled on every write */
    char             *text;            /* one render buffer: the status file, then the rule counters */
    size_t            text_cap;
    uint64_t          posted_mono;      /* when the thread woke the loop; the loop answers the handoff */
    uint64_t          handoff_ms;      /* the loop's answer, one event-loop iteration on this server */
    unsigned          said_status:1, said_rules:1, said_conf:1, said_over:1;
} we_ngx_worker_t;

typedef struct {
    we_mod_item_t  link;
    we_counters_t *set;
} we_ngx_set_item_t;

static we_ngx_worker_t *g_worker;       /* one per serving process; NULL in the master and the helpers */

static ngx_int_t ngx_http_whisper_edge_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_whisper_edge_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_whisper_edge_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_whisper_edge_init_process(ngx_cycle_t *cycle);
static void ngx_http_whisper_edge_exit_process(ngx_cycle_t *cycle);
static void *ngx_http_whisper_edge_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_whisper_edge_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_whisper_edge_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_whisper_edge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
WE_NGX_HANDLER ngx_int_t ngx_http_whisper_edge_post_read(ngx_http_request_t *r);
WE_NGX_HANDLER ngx_int_t ngx_http_whisper_edge_preaccess(ngx_http_request_t *r);
WE_NGX_HANDLER ngx_int_t ngx_http_whisper_edge_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                                                        uintptr_t data);
WE_NGX_HANDLER void ngx_http_whisper_edge_node_cleanup(void *data);
WE_NGX_WRAPPER void ngx_http_whisper_edge_decide(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s,
                                                 uint64_t *shard, const we_mod_req_t *req, uint64_t now_ms);
static void ngx_http_whisper_edge_release(void *data);
static void we_ngx_bind_log(void *ud, const char *entry);

static char *we_ngx_policy_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_threshold(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_allow_inferred(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_deny_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_snapshot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_refresh(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_summary(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_trusted_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_trusted_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *we_ngx_trusted_hops(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static we_ngx_cmd_t we_ngx_cmd_policy  = { WE_DIR_POLICY, 0, "whisper_edge_policy" };
static we_ngx_cmd_t we_ngx_cmd_set     = { WE_DIR_SET, 0, "whisper_edge_set" };
static we_ngx_cmd_t we_ngx_cmd_floor   = { WE_DIR_FLOOR, 1, "whisper_edge_policy_floor" };

#define WE_NGX_ANY (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF)

static ngx_command_t ngx_http_whisper_edge_commands[] = {

    /* the language: a rule, a set declaration, the http-level floor (one deny or log rule) */
    { ngx_string("whisper_edge_policy"),
      WE_NGX_ANY | NGX_CONF_1MORE,
      we_ngx_policy_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &we_ngx_cmd_policy },

    { ngx_string("whisper_edge_set"),
      WE_NGX_ANY | NGX_CONF_1MORE,
      we_ngx_policy_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &we_ngx_cmd_set },

    { ngx_string("whisper_edge_policy_floor"),
      WE_NGX_ANY | NGX_CONF_1MORE,
      we_ngx_policy_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      &we_ngx_cmd_floor },

    /* the per-context scalars: the nearest wins */
    { ngx_string("whisper_edge_mode"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_threshold"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_threshold,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_allow_inferred"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_allow_inferred,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_deny_status"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_deny_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_export"),
      WE_NGX_ANY | NGX_CONF_1MORE,
      we_ngx_export,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* http level only: the data, the refresh, the summary directory, the trusted proxy */
    { ngx_string("whisper_edge_snapshot"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_snapshot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_data"),
      WE_NGX_ANY | NGX_CONF_TAKE12,
      we_ngx_data,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_refresh"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_refresh,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_summary"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_summary,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_trusted_proxy"),
      WE_NGX_ANY | NGX_CONF_1MORE,
      we_ngx_trusted_proxy,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_trusted_header"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_trusted_header,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whisper_edge_trusted_hops"),
      WE_NGX_ANY | NGX_CONF_TAKE1,
      we_ngx_trusted_hops,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_whisper_edge_module_ctx = {
    ngx_http_whisper_edge_add_variables,         /* preconfiguration: the variables, so a `set` on one is refused */
    ngx_http_whisper_edge_init,                  /* postconfiguration */
    ngx_http_whisper_edge_create_main_conf,
    ngx_http_whisper_edge_init_main_conf,
    NULL,                                        /* create server configuration */
    NULL,                                        /* merge server configuration */
    ngx_http_whisper_edge_create_loc_conf,
    ngx_http_whisper_edge_merge_loc_conf
};

ngx_module_t ngx_http_whisper_edge_module = {
    NGX_MODULE_V1,
    &ngx_http_whisper_edge_module_ctx,
    ngx_http_whisper_edge_commands,
    NGX_HTTP_MODULE,
    NULL,                                        /* init master */
    ngx_http_whisper_edge_init_module,           /* init module: the phase order, asserted */
    ngx_http_whisper_edge_init_process,
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    ngx_http_whisper_edge_exit_process,
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * THE VARIABLES: $whisper_edge_<attribute> for each of the 25 attributes (their index is the handler's
 * data), then the decision's words, the provenance token and the floor's address (codes from 100). All
 * registered at preconfiguration without NGX_HTTP_VAR_CHANGEABLE, so a `set` on one is refused by nginx
 * itself as a duplicate variable, and with NGX_HTTP_VAR_NOCACHEABLE, so the log phase reads the value
 * after the decision and never a rewrite-phase copy.
 */
enum {
    WE_NGX_VAR_VERDICT = 100, WE_NGX_VAR_ACTION, WE_NGX_VAR_REASON, WE_NGX_VAR_RULE_ID, WE_NGX_VAR_RULE,
    WE_NGX_VAR_PROGRAM, WE_NGX_VAR_LOGGED, WE_NGX_VAR_GENERATIONS, WE_NGX_VAR_FLOOR_ADDR
};
static const struct { const char *name; uintptr_t code; } we_ngx_decision_vars[] = {
    { "verdict", WE_NGX_VAR_VERDICT }, { "action", WE_NGX_VAR_ACTION }, { "reason", WE_NGX_VAR_REASON },
    { "rule_id", WE_NGX_VAR_RULE_ID }, { "rule", WE_NGX_VAR_RULE }, { "program", WE_NGX_VAR_PROGRAM },
    { "logged", WE_NGX_VAR_LOGGED }, { "generations", WE_NGX_VAR_GENERATIONS }, { "floor_addr", WE_NGX_VAR_FLOOR_ADDR },
};

static ngx_int_t we_ngx_add_variable(ngx_conf_t *cf, const char *tail, uintptr_t data)
{
    ngx_http_variable_t *var;
    ngx_str_t name;
    size_t tl = ngx_strlen(tail);

    name.len = sizeof("whisper_edge_") - 1 + tl;
    name.data = ngx_pnalloc(cf->temp_pool, name.len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(name.data, "whisper_edge_", sizeof("whisper_edge_") - 1);
    ngx_memcpy(name.data + sizeof("whisper_edge_") - 1, tail, tl);
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_whisper_edge_variable;
    var->data = data;
    return NGX_OK;
}

static ngx_int_t ngx_http_whisper_edge_add_variables(ngx_conf_t *cf)
{
    uint32_t i;

    for (i = 0; i < WE_MOD_ATTRS; i++) {
        if (we_ngx_add_variable(cf, we_mod_attr(i)->name, i) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    for (i = 0; i < sizeof we_ngx_decision_vars / sizeof we_ngx_decision_vars[0]; i++) {
        if (we_ngx_add_variable(cf, we_ngx_decision_vars[i].name, we_ngx_decision_vars[i].code) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* ---- small helpers ---------------------------------------------------------------------------- */

static void we_ngx_here(ngx_conf_t *cf, we_ngx_place_t *p)
{
    p->file = cf->conf_file->file.name;
    p->line = cf->conf_file->line;
}

/* for nginx's `%*s:%ui`: the width star takes a size_t, and the two casts below say so */
#define WE_NGX_PLACE(p) (size_t) (p)->file.len, (p)->file.data, (p)->line

/* a NUL-terminated copy of an ngx_str_t in the configuration pool */
static char *we_ngx_cstr(ngx_pool_t *pool, const ngx_str_t *s)
{
    char *c = ngx_pnalloc(pool, s->len + 1);

    if (c == NULL) {
        return NULL;
    }
    ngx_memcpy(c, s->data, s->len);
    c[s->len] = '\0';
    return c;
}

/* the arguments of a directive after its name, joined with one space: the bytes the compiler sees */
static int we_ngx_join_args(ngx_conf_t *cf, ngx_str_t *out)
{
    ngx_str_t *v = cf->args->elts;
    ngx_uint_t i;
    size_t n = 0;
    u_char *p;

    for (i = 1; i < cf->args->nelts; i++) {
        n += v[i].len + 1;
    }
    p = ngx_pnalloc(cf->pool, n > 0 ? n : 1);
    if (p == NULL) {
        return -1;
    }
    out->data = p;
    for (i = 1; i < cf->args->nelts; i++) {
        if (i > 1) {
            *p++ = ' ';
        }
        p = ngx_cpymem(p, v[i].data, v[i].len);
    }
    out->len = (size_t) (p - out->data);
    return 0;
}

/*
 * An http-only directive written in a server or location block, refused with the reason, so a
 * virtual host can never change the floor, the data or the trusted proxy (section 2.1).
 */
static char *we_ngx_http_only(ngx_conf_t *cf)
{
    if (cf->cmd_type & NGX_HTTP_MAIN_CONF) {
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "whisper edge: \"%V\" is http level only, so that no virtual host can change the floor",
                       &((ngx_str_t *) cf->args->elts)[0]);
    return NGX_CONF_ERROR;
}

/* a second definition of a single-valued directive, refused naming both places */
static char *we_ngx_second(ngx_conf_t *cf, const we_ngx_place_t *first)
{
    if (first->file.len == 0) {
        return NGX_CONF_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "whisper edge: \"%V\" is defined twice: here and at %*s:%ui; one definition per context, so "
                       "a file included later cannot change what an earlier one set",
                       &((ngx_str_t *) cf->args->elts)[0], WE_NGX_PLACE(first));
    return NGX_CONF_ERROR;
}

/* ---- the directive handlers ------------------------------------------------------------------- */

/* whisper_edge_policy, whisper_edge_set, whisper_edge_policy_floor: recorded for the compiler */
static char *we_ngx_policy_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_loc_conf_t *lcf = conf;
    ngx_http_whisper_edge_main_conf_t *mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_whisper_edge_module);
    we_ngx_cmd_t *c = cmd->post;
    we_ngx_directive_t *d;

    if (c->http_only && we_ngx_http_only(cf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    d = ngx_array_push(&mcf->directives);
    if (d == NULL || we_ngx_join_args(cf, &d->arg) != 0) {
        return NGX_CONF_ERROR;
    }
    d->kind = c->kind;
    d->lcf = lcf;
    d->name = ((ngx_str_t *) cf->args->elts)[0];
    we_ngx_here(cf, &d->place);
    if (c->kind == WE_DIR_POLICY) {
        lcf->own = 1;
    } else if (c->kind == WE_DIR_FLOOR) {
        if (mcf->floor_lines++ == 0) {
            mcf->floor_place = d->place;
        }
    }
    return NGX_CONF_OK;
}

/* the scalar directives are recorded for the compiler too, so one source carries the whole configuration */
static char *we_ngx_record_scalar(ngx_conf_t *cf, ngx_http_whisper_edge_loc_conf_t *lcf, uint8_t kind,
                                  we_ngx_place_t *place)
{
    ngx_http_whisper_edge_main_conf_t *mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_whisper_edge_module);
    we_ngx_directive_t *d;

    if (we_ngx_second(cf, place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, place);
    d = ngx_array_push(&mcf->directives);
    if (d == NULL || we_ngx_join_args(cf, &d->arg) != 0) {
        return NGX_CONF_ERROR;
    }
    d->kind = kind;
    d->lcf = lcf;
    d->name = ((ngx_str_t *) cf->args->elts)[0];
    d->place = *place;
    return NGX_CONF_OK;
}

static char *we_ngx_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_loc_conf_t *lcf = conf;
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    if (v[1].len == 3 && ngx_strncmp(v[1].data, "off", 3) == 0) {
        lcf->mode = WE_MODE_OFF;
    } else if (v[1].len == 3 && ngx_strncmp(v[1].data, "log", 3) == 0) {
        lcf->mode = WE_MODE_LOG;
    } else if (v[1].len == 4 && ngx_strncmp(v[1].data, "deny", 4) == 0) {
        lcf->mode = WE_MODE_DENY;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "whisper edge: whisper_edge_mode takes off, log or deny, not \"%V\"", &v[1]);
        return NGX_CONF_ERROR;
    }
    return we_ngx_record_scalar(cf, lcf, WE_DIR_MODE, &lcf->mode_place);
}

static char *we_ngx_threshold(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    static const struct { const char *w; ngx_uint_t v; } t[] = {
        { "off", WE_SEV_NONE }, { "low", WE_SEV_LOW }, { "medium", WE_SEV_MEDIUM },
        { "high", WE_SEV_HIGH }, { "critical", WE_SEV_CRITICAL }
    };
    ngx_http_whisper_edge_loc_conf_t *lcf = conf;
    ngx_str_t *v = cf->args->elts;
    size_t i;

    (void) cmd;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (v[1].len == ngx_strlen(t[i].w) && ngx_strncmp(v[1].data, t[i].w, v[1].len) == 0) {
            lcf->threshold = t[i].v;
            lcf->own_threshold = 1;
            return we_ngx_record_scalar(cf, lcf, WE_DIR_THRESHOLD, &lcf->threshold_place);
        }
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "whisper edge: whisper_edge_threshold takes off, low, medium, high or critical, not \"%V\"",
                       &v[1]);
    return NGX_CONF_ERROR;
}

static char *we_ngx_allow_inferred(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_loc_conf_t *lcf = conf;
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    if (v[1].len == 2 && ngx_strncasecmp(v[1].data, (u_char *) "on", 2) == 0) {
        lcf->allow_inferred = 1;
    } else if (v[1].len == 3 && ngx_strncasecmp(v[1].data, (u_char *) "off", 3) == 0) {
        lcf->allow_inferred = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "whisper edge: whisper_edge_allow_inferred takes on or off, not \"%V\"", &v[1]);
        return NGX_CONF_ERROR;
    }
    return we_ngx_record_scalar(cf, lcf, WE_DIR_ALLOW_INFERRED, &lcf->inferred_place);
}

/*
 * The deny status is an allow-list, and every other code is refused by its class with the reason
 * and the way out. The accepted codes are the ones a deny can send as written, with no header the
 * module does not have, that no client resends and no balancer counts against the origin.
 */
static const char *we_ngx_status_refusal(ngx_uint_t code)
{
    switch (code) {
    case 400: case 403: case 404: case 406: case 409: case 410: case 413: case 415:
    case 422: case 428: case 429: case 451:
    case 444:                                /* nginx's close without a response: this server only */
        return NULL;
    case 401: return "401 requires a WWW-Authenticate header, which this module does not send";
    case 405: return "405 requires an Allow header, which this module does not send";
    case 407: return "407 requires a Proxy-Authenticate header, which this module does not send";
    case 416: return "416 requires a Content-Range header, which this module does not send";
    case 426: return "426 requires an Upgrade header, which this module does not send";
    case 408: return "408 is not sent as written: nginx closes the connection with no status line and logs 408";
    case 411: return "411 tells the client to add a Content-Length and send the request again";
    case 417: return "417 makes a client such as curl resend the request without Expect";
    case 421: return "421 lets a client retry even a non-idempotent request on another connection (RFC 9110 section 15.5.20)";
    case 431: return "431 tells the client to shrink its header and send the request again";
    case 412: case 414:
        return "412 and 414 describe the request, not a decision";
    case 511: return "511 is another protocol role: a client reads it as a captive portal";
    case 494: case 495: case 496: case 497:
        return "494 to 497 are never on the wire as written: nginx sends them as 400";
    case 499: return "499 is nginx's own log code and is never sent";
    case 402: return "402 is reserved (RFC 9110 section 15.5.3)";
    default:
        if (code >= 500 && code <= 599) {
            return "a 5xx says the server failed (RFC 9110 section 15.6); balancers and health checks in front "
                   "(nginx proxy_next_upstream, HAProxy observe layer7, Envoy outlier detection) count it, retry it "
                   "and can eject this origin under denied traffic";
        }
        return "it is not a status code RFC 9110 registers for a deny";
    }
}

static char *we_ngx_deny_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_loc_conf_t *lcf = conf;
    ngx_str_t *v = cf->args->elts;
    ngx_int_t code;
    const char *why;

    (void) cmd;
    code = ngx_atoi(v[1].data, v[1].len);
    if (code == NGX_ERROR || code < 100 || code > 999) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "whisper edge: whisper_edge_deny_status takes a status code, not \"%V\"; use 403", &v[1]);
        return NGX_CONF_ERROR;
    }
    why = we_ngx_status_refusal((ngx_uint_t) code);
    if (why != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "whisper edge: whisper_edge_deny_status %i refused: %s; use 403",
                           code, why);
        return NGX_CONF_ERROR;
    }
    if (we_ngx_second(cf, &lcf->status_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &lcf->status_place);
    lcf->deny_status = (ngx_uint_t) code;
    return NGX_CONF_OK;
}

/* whisper_edge_export <attribute>... | all: accepted, and nginx renders every attribute on demand */
static char *we_ngx_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_loc_conf_t *lcf = conf;
    ngx_http_whisper_edge_main_conf_t *mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_whisper_edge_module);
    ngx_str_t *v = cf->args->elts;
    ngx_uint_t i;

    (void) cmd;
    if (we_ngx_second(cf, &lcf->export_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &lcf->export_place);
    lcf->exports = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (lcf->exports == NULL) {
        return NGX_CONF_ERROR;
    }
    for (i = 1; i < cf->args->nelts; i++) {
        uint32_t k;
        int known = 0;

        if (v[i].len == 3 && ngx_strncmp(v[i].data, "all", 3) == 0) {
            lcf->export_all = 1;
            continue;
        }
        for (k = 0; k < WE_MOD_ATTRS; k++) {
            const we_mod_attr_t *a = we_mod_attr(k);

            if (v[i].len == ngx_strlen(a->name) && ngx_strncmp(v[i].data, a->name, v[i].len) == 0) {
                known = 1;
                break;
            }
        }
        if (!known) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "whisper edge: whisper_edge_export names \"%V\", which is not an attribute; the "
                               "attributes are the 25 names whisper-edge-lookup prints, or \"all\"", &v[i]);
            return NGX_CONF_ERROR;
        }
        *(ngx_str_t *) ngx_array_push(lcf->exports) = v[i];
    }
    mcf->export_lines++;
    return NGX_CONF_OK;
}

static char *we_ngx_snapshot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK || we_ngx_second(cf, &mcf->snapshot_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &mcf->snapshot_place);
    mcf->snapshot = v[1];
    return NGX_CONF_OK;
}

/* whisper_edge_data <directory>, or whisper_edge_data <plane> <file> */
static char *we_ngx_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (cf->args->nelts == 2) {
        if (we_ngx_second(cf, &mcf->data_place) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
        we_ngx_here(cf, &mcf->data_place);
        mcf->data_dir = v[1];
        return NGX_CONF_OK;
    }
    {
        uint32_t p;

        for (p = 0; p < 8; p++) {
            const char *w = we_mod_plane_word(p);

            if (v[1].len == ngx_strlen(w) && ngx_strncmp(v[1].data, w, v[1].len) == 0) {
                break;
            }
        }
        if (p == 8) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "whisper edge: whisper_edge_data names plane \"%V\", which is not one of reputation, "
                               "tor, rpki-unreachable, routing, anonymizer, threat, registry, tenant", &v[1]);
            return NGX_CONF_ERROR;
        }
        if (we_ngx_second(cf, &mcf->plane_place[p]) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
        we_ngx_here(cf, &mcf->plane_place[p]);
        mcf->plane_file[p] = v[2];
    }
    return NGX_CONF_OK;
}

static char *we_ngx_refresh(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;
    ngx_int_t ms;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK || we_ngx_second(cf, &mcf->refresh_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    ms = ngx_parse_time(&v[1], 0);
    if (ms == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "whisper edge: whisper_edge_refresh takes a time, not \"%V\"", &v[1]);
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &mcf->refresh_place);
    mcf->refresh = (ngx_msec_t) ms;
    return NGX_CONF_OK;
}

static char *we_ngx_summary(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK || we_ngx_second(cf, &mcf->summary_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &mcf->summary_place);
    mcf->counters_dir = v[1];
    return NGX_CONF_OK;
}

static char *we_ngx_trusted_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;
    ngx_uint_t i;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK || we_ngx_second(cf, &mcf->trusted_proxy_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &mcf->trusted_proxy_place);
    mcf->trusted_proxy = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
    if (mcf->trusted_proxy == NULL) {
        return NGX_CONF_ERROR;
    }
    for (i = 1; i < cf->args->nelts; i++) {
        *(ngx_str_t *) ngx_array_push(mcf->trusted_proxy) = v[i];
    }
    return NGX_CONF_OK;
}

/* an RFC 9110 token: tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA */
static int we_ngx_is_tchar(u_char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+'
        || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

static char *we_ngx_trusted_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;
    size_t i;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK || we_ngx_second(cf, &mcf->trusted_header_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (v[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "whisper edge: whisper_edge_trusted_header takes a header name");
        return NGX_CONF_ERROR;
    }
    for (i = 0; i < v[1].len; i++) {
        if (!we_ngx_is_tchar(v[1].data[i])) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "whisper edge: a header name is a token (RFC 9110 section 5.1); \"%V\" contains %s",
                               &v[1], v[1].data[i] == ' ' ? "a space" : "a byte outside the token alphabet");
            return NGX_CONF_ERROR;
        }
    }
    if (v[1].len == 9 && ngx_strncasecmp(v[1].data, (u_char *) "forwarded", 9) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "whisper edge: Forwarded uses the RFC 7239 syntax, which this module does not read; name "
                           "X-Forwarded-For, or a single-address header such as X-Real-IP");
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &mcf->trusted_header_place);
    mcf->trusted_header = v[1];
    return NGX_CONF_OK;
}

static char *we_ngx_trusted_hops(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;
    ngx_str_t *v = cf->args->elts;
    ngx_int_t n;

    (void) cmd;
    if (we_ngx_http_only(cf) != NGX_CONF_OK || we_ngx_second(cf, &mcf->trusted_hops_place) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    n = ngx_atoi(v[1].data, v[1].len);
    if (n == NGX_ERROR || n < 1 || n > (ngx_int_t) WE_MOD_HOPS_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "whisper edge: whisper_edge_trusted_hops takes 1 to %ui, not \"%V\"",
                           (ngx_uint_t) WE_MOD_HOPS_MAX, &v[1]);
        return NGX_CONF_ERROR;
    }
    we_ngx_here(cf, &mcf->trusted_hops_place);
    mcf->trusted_hops = (ngx_uint_t) n;
    return NGX_CONF_OK;
}

/* ---- the configuration structures --------------------------------------------------------------- */

static void *
ngx_http_whisper_edge_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_whisper_edge_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_whisper_edge_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }
    if (ngx_array_init(&mcf->directives, cf->pool, 16, sizeof(we_ngx_directive_t)) != NGX_OK
            || ngx_array_init(&mcf->merged, cf->pool, 16, sizeof(ngx_http_whisper_edge_loc_conf_t *)) != NGX_OK
            || ngx_array_init(&mcf->noname, cf->pool, 4, sizeof(ngx_http_whisper_edge_loc_conf_t *)) != NGX_OK) {
        return NULL;
    }
    mcf->refresh = NGX_CONF_UNSET_MSEC;
    return mcf;
}

static char *
ngx_http_whisper_edge_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_whisper_edge_main_conf_t *mcf = conf;

    /* 60s: a snapshot is rebuilt hourly at most, so a minute of staleness after a rebuild costs
     * nothing, and a stat() per worker per minute is not a cost worth configuring away. */
    ngx_conf_init_msec_value(mcf->refresh, 60000);

    /*
     * A FLOOR, with a message. `whisper_edge_refresh 1ms` would otherwise produce a stat() per
     * millisecond per worker in a module whose selling point is making no syscall per request, and
     * drive the retire slots to exhaustion inside one grace window. Raised rather than refused, and
     * said out loud, because a too-eager interval is a misunderstanding and not a reason to refuse to
     * start.
     */
    if (mcf->refresh < 1000) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "whisper_edge_refresh %M is below the 1s floor; using 1s", mcf->refresh);
        mcf->refresh = 1000;
    }

    /*
     * The counters directory, when no whisper_edge_summary names one, is the core's (we_mod_bind_counters_dir):
     * `counters` inside the data directory, or beside the files the configuration names when they share one
     * directory. Files in two directories have no one place beside them: said, with the directive that names
     * one, and no counters are written. `off` is the opt-out.
     */
    if (mcf->counters_dir.len == 0) {
        we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
        char dir[4096], why[512];
        int rc;

        if (we_ngx_bind_args(cf->pool, mcf, &args) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        why[0] = '\0';
        rc = we_mod_bind_counters_dir(&args, dir, sizeof dir, why, sizeof why);
        if (rc == 1) {
            size_t n = strlen(dir);

            mcf->counters_dir.data = ngx_pnalloc(cf->pool, n);
            if (mcf->counters_dir.data == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(mcf->counters_dir.data, dir, n);
            mcf->counters_dir.len = n;
        } else if (rc == -1) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "whisper edge: %s; until then no rule counters are written", why);
        } else if (rc == -2) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "whisper edge: the counters directory beside the data is longer than "
                               "%uz bytes; name one with whisper_edge_summary <dir>", sizeof dir - 1);
        }
    }
    if (mcf->counters_dir.len == 3 && ngx_strncmp(mcf->counters_dir.data, "off", 3) == 0) {
        mcf->counters_dir.len = 0;
    }
    return NGX_CONF_OK;
}

static void *
ngx_http_whisper_edge_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_whisper_edge_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_whisper_edge_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->mode = NGX_CONF_UNSET_UINT;
    conf->threshold = NGX_CONF_UNSET_UINT;
    conf->allow_inferred = NGX_CONF_UNSET;
    conf->deny_status = NGX_CONF_UNSET_UINT;
    conf->ordinal = NGX_CONF_UNSET_UINT;
    we_ngx_here(cf, &conf->place);
    /*
     * The http block's own context is created while the `http` directive (a main-level command) is
     * being handled; a server's while `server` (an http-level command) is; a location's while
     * `location` is. The http one is the root: it is never merged into anything, so it is named here.
     */
    if (cf->cmd_type & NGX_MAIN_CONF) {
        conf->is_http = 1;
        conf->path = "http";
        conf->human = "http";
        conf->ordinal = 0;
    }
    return conf;
}

static char *
ngx_http_whisper_edge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_whisper_edge_loc_conf_t *prev = parent;
    ngx_http_whisper_edge_loc_conf_t *conf = child;

    (void) cf;
    /*
     * The defaults ARE the safety policy, so they are stated here rather than left to a document:
     * LOG, not deny. HIGH, so turning on `deny` without thinking about a threshold still only blocks
     * what a citable listing calls high or worse. And inferences off, so Tier 3 can be distributed
     * without it being enforceable by accident. The compiler applies the same defaults to the
     * programs; these scalars are the interim request path's and the configuration lines'.
     */
    ngx_conf_merge_uint_value(conf->mode, prev->mode, WE_MODE_LOG);
    ngx_conf_merge_uint_value(conf->threshold, prev->threshold, WE_SEV_HIGH);
    ngx_conf_merge_value(conf->allow_inferred, prev->allow_inferred, 0);
    /* the nearest deny status wins for the context's own rules; the http level's is the floor's */
    ngx_conf_merge_uint_value(conf->deny_status, prev->deny_status, NGX_CONF_UNSET_UINT);
    if (conf->exports == NULL) {
        conf->exports = prev->exports;
        conf->export_all = prev->export_all;
    }
    conf->parent = prev;

    /*
     * THE CONTEXT TREE, recorded here and nowhere else. nginx merges a server into the http block and
     * each location into its enclosing block in configuration order, parent before child, and only
     * afterwards sorts the location queues and moves regex, named and `if` blocks into structures of
     * their own; by postconfiguration the queues no longer hold every location. So the ordinal path
     * the compiler is given (`http/s2/l1`) and the operator's name for the lines are taken now,
     * while cf->ctx is the child's own: its core location conf carries the name, and its server conf
     * the server_name.
     */
    {
        ngx_http_whisper_edge_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_whisper_edge_module);
        ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        char *path, *human;
        size_t n;

        if (prev->is_http) {
            ngx_http_core_srv_conf_t *cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

            prev->nchildren++;
            path = ngx_pnalloc(cf->pool, 32);
            n = cscf->server_name.len + 24;
            human = ngx_pnalloc(cf->pool, n);
            if (path == NULL || human == NULL) {
                return NGX_CONF_ERROR;
            }
            snprintf(path, 32, "http/s%lu", (unsigned long) prev->nchildren);
            if (cscf->server_name.len > 0) {
                snprintf(human, n, "server \"%.*s\"", (int) cscf->server_name.len, cscf->server_name.data);
            } else {
                snprintf(human, n, "server #%lu", (unsigned long) prev->nchildren);
            }
            if (cscf->file_name != NULL) {
                conf->place.file.data = cscf->file_name;
                conf->place.file.len = ngx_strlen(cscf->file_name);
                conf->place.line = cscf->line;
            }
        } else if (clcf->noname) {
            /* an `if` or `limit_except` block: no directive of this module can be written in it (nginx
             * refuses them there), so it has no path of its own and runs the enclosing context's program */
            conf->noname = 1;
            *(ngx_http_whisper_edge_loc_conf_t **) ngx_array_push(&mcf->noname) = conf;
            return NGX_CONF_OK;
        } else {
            /* clcf->regex exists only in an nginx built with PCRE; one without it has no regex locations */
#if (NGX_PCRE)
            const char *mod = clcf->exact_match ? "= " : clcf->regex != NULL ? "~ " : "";
#else
            const char *mod = clcf->exact_match ? "= " : "";
#endif

            if (prev->path == NULL) {
                return NGX_CONF_ERROR;          /* a parent nginx never merged: cannot happen in file order */
            }
            prev->nchildren++;
            n = ngx_strlen(prev->path) + 24;
            path = ngx_pnalloc(cf->pool, n);
            if (path == NULL) {
                return NGX_CONF_ERROR;
            }
            snprintf(path, n, "%s/l%lu", prev->path, (unsigned long) prev->nchildren);
            n = clcf->name.len + 24;
            human = ngx_pnalloc(cf->pool, n);
            if (human == NULL) {
                return NGX_CONF_ERROR;
            }
            snprintf(human, n, "location %s\"%.*s\"", mod, (int) clcf->name.len, clcf->name.data);
        }
        conf->path = path;
        conf->human = human;
        conf->ordinal = mcf->merged.nelts + 1;   /* the http context is ordinal 0 */
        *(ngx_http_whisper_edge_loc_conf_t **) ngx_array_push(&mcf->merged) = conf;
    }
    return NGX_CONF_OK;
}

/* ---- postconfiguration: the contexts, the compile, the lines -------------------------------------- */

/* the planes a context's default export set names: the floor's, its program's, and the tenant's */
static uint8_t we_ngx_default_export(const we_policy_build_t *b, const char *path)
{
    const we_program_t *p = we_policy_program(b, path);
    uint8_t m = (uint8_t) (we_policy_floor(b)->plane_mask | 0x80u);

    if (p != NULL) {
        m = (uint8_t) (m | p->plane_mask);
    }
    return m;
}

/* the planes of the attributes an export line names */
static uint8_t we_ngx_export_planes(const ngx_http_whisper_edge_loc_conf_t *lcf)
{
    uint8_t m = 0;
    ngx_uint_t i;

    if (lcf->export_all) {
        return 0xffu;
    }
    if (lcf->exports == NULL) {
        return 0;
    }
    for (i = 0; i < lcf->exports->nelts; i++) {
        const ngx_str_t *n = &((ngx_str_t *) lcf->exports->elts)[i];
        uint32_t k;

        for (k = 0; k < WE_MOD_ATTRS; k++) {
            const we_mod_attr_t *a = we_mod_attr(k);

            if (n->len == ngx_strlen(a->name) && ngx_strncmp(n->data, a->name, n->len) == 0) {
                m = (uint8_t) (m | (1u << a->plane));
            }
        }
    }
    return m;
}

/* the planes of every $whisper_edge_<attribute> the configuration indexes anywhere */
static uint8_t we_ngx_variable_planes(ngx_conf_t *cf, ngx_uint_t *any)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_variable_t *v = cmcf->variables.elts;
    ngx_uint_t i;
    uint8_t m = 0;

    *any = 0;
    for (i = 0; i < cmcf->variables.nelts; i++) {
        uint32_t k;

        if (v[i].name.len < 13 || ngx_strncmp(v[i].name.data, "whisper_edge_", 13) != 0) {
            continue;
        }
        *any = 1;
        for (k = 0; k < WE_MOD_ATTRS; k++) {
            const we_mod_attr_t *a = we_mod_attr(k);

            if (v[i].name.len == 13 + ngx_strlen(a->name)
                    && ngx_strncmp(v[i].name.data + 13, a->name, v[i].name.len - 13) == 0) {
                m = (uint8_t) (m | (1u << a->plane));
            }
        }
    }
    return m;
}

/* the uid the workers run as: the configuration's `user`, resolved the way nginx will resolve it */
static unsigned we_ngx_worker_uid(ngx_cycle_t *cycle)
{
    ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf != NULL && ccf->user != (ngx_uid_t) NGX_CONF_UNSET_UINT) {
        return (unsigned) ccf->user;
    }
    if (geteuid() == 0) {
        struct passwd *pwd = getpwnam(NGX_USER);

        if (pwd != NULL) {
            return (unsigned) pwd->pw_uid;
        }
    }
    return (unsigned) geteuid();
}

/*
 * STRICTMODES FOR THE FILES THAT DEFINE THE HTTP LEVEL. "http level" is not "operator only" where a
 * panel includes the conf.d files there, so every file holding an http-level whisper_edge_* directive must
 * be owned by root or by the configuration reader and closed to group and world, and so must every
 * directory of its resolved path, the way sshd judges a key file; a root-owned sticky directory (/tmp
 * above a file named by an explicit path) is allowed as an ancestor, as sshd allows it. The RESOLVED
 * path is judged: a root-owned symlink in /etc/nginx that points into a tenant-writable tree is refused
 * by the tree it names. -1 with `why` naming the owner, the mode and the fix.
 */
static int we_ngx_conf_file_trusted(const char *path, unsigned reader, char *why, size_t n)
{
    char real[PATH_MAX], pre[PATH_MAX];
    struct stat st;
    size_t i, len;

#ifdef WE_MOD_TEST_LEXICAL
    /* the control: the path as written, a symlink judged by its own node and never by what it names */
    if (strlen(path) >= sizeof real) {
        snprintf(why, n, "the path is too long");
        return -1;
    }
    strcpy(real, path);
#else
    if (realpath(path, real) == NULL) {
        snprintf(why, n, "its path cannot be resolved: %s", strerror(errno));
        return -1;
    }
#endif
    len = strlen(real);
    for (i = 1; i <= len; i++) {
        if (i < len && real[i] != '/') {
            continue;
        }
        memcpy(pre, real, i);
        pre[i] = '\0';
#ifdef WE_MOD_TEST_LEXICAL
        if (lstat(pre, &st) != 0) {
#else
        if (stat(pre, &st) != 0) {
#endif
            snprintf(why, n, "\"%.1024s\" cannot be read: %s", pre, strerror(errno));
            return -1;
        }
#ifdef WE_MOD_TEST_LEXICAL
        if (S_ISLNK(st.st_mode)) {
            continue;                        /* the control: a link node is accepted as written, its target never seen */
        }
#endif
        /* the path is printed twice, each time bounded, so the message fits whatever the path's length */
        if (st.st_uid != 0u && st.st_uid != reader) {
            snprintf(why, n, "\"%.1024s\" is owned by uid %u, and only root or uid %u (the configuration reader) may own a path "
                     "that defines the floor; chown root \"%.1024s\"", pre, (unsigned) st.st_uid, reader, pre);
            return -1;
        }
        if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0u && !(i < len && (st.st_mode & S_ISVTX) != 0u && st.st_uid == 0u)) {
            snprintf(why, n, "\"%.1024s\" has mode %04o, writable by %s; a path that defines the floor is closed to group and "
                     "world: chmod %s \"%.1024s\"", pre, (unsigned) (st.st_mode & 07777u),
                     (st.st_mode & S_IWOTH) != 0u ? "world" : "its group", i < len ? "g-w,o-w" : "0644", pre);
            return -1;
        }
    }
    if (stat("/", &st) != 0 || st.st_uid != 0u || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
        snprintf(why, n, "/ is not root-owned and closed to group and world");
        return -1;
    }
    return 0;
}

/* the http-level directives' files, each checked once; -1 after the refusal was logged */
static ngx_int_t we_ngx_strict_modes(ngx_conf_t *cf, ngx_http_whisper_edge_main_conf_t *mcf, unsigned reader)
{
    const we_ngx_directive_t *d = mcf->directives.elts;
    const we_ngx_place_t *places[24];
    const ngx_str_t *dirnames[24];
    ngx_uint_t np = 0, i, k;
    static const ngx_str_t http_level_names[] = {
        ngx_string("whisper_edge_snapshot"), ngx_string("whisper_edge_data"), ngx_string("whisper_edge_refresh"),
        ngx_string("whisper_edge_summary"), ngx_string("whisper_edge_trusted_proxy"), ngx_string("whisper_edge_trusted_header"),
        ngx_string("whisper_edge_trusted_hops"), ngx_string("whisper_edge_deny_status"), ngx_string("whisper_edge_export")
    };
    const we_ngx_place_t *main_places[] = {
        &mcf->snapshot_place, &mcf->data_place, &mcf->refresh_place, &mcf->summary_place, &mcf->trusted_proxy_place,
        &mcf->trusted_header_place, &mcf->trusted_hops_place, &mcf->http->status_place, &mcf->http->export_place
    };

    for (i = 0; i < sizeof main_places / sizeof main_places[0]; i++) {
        if (main_places[i]->file.len > 0 && np < 24) {
            places[np] = main_places[i];
            dirnames[np++] = &http_level_names[i];
        }
    }
    for (i = 0; i < mcf->directives.nelts && np < 24; i++) {
        if (d[i].lcf == mcf->http) {
            places[np] = &d[i].place;
            dirnames[np++] = &d[i].name;
        }
    }
    for (i = 0; i < np; i++) {
        char *file, why[PATH_MAX + 256];

        for (k = 0; k < i; k++) {
            if (places[k]->file.len == places[i]->file.len
                    && ngx_strncmp(places[k]->file.data, places[i]->file.data, places[i]->file.len) == 0) {
                break;
            }
        }
        if (k < i) {
            continue;                        /* this file was checked for an earlier directive */
        }
        file = we_ngx_cstr(cf->pool, &places[i]->file);
        if (file == NULL) {
            return NGX_ERROR;
        }
        if (we_ngx_conf_file_trusted(file, reader, why, sizeof why) != 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "whisper edge: %s holds http-level whisper_edge_* directives (%V at line %ui), and %s",
                          file, dirnames[i], places[i]->line, why);
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* a configuration-time line, through the configuration's log, never through ngx_conf_log_error */
static void we_ngx_line(ngx_log_t *log, ngx_uint_t level, const char *fmt, ...)
{
    char buf[2048];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    ngx_log_error(level, log, 0, "whisper edge: policy: %s", buf);
}

/* the compiler's reports, each located at its directive (the refusal's shape, kind `report`) */
typedef struct {
    ngx_http_whisper_edge_main_conf_t *mcf;
    ngx_log_t                         *log;
} we_ngx_report_ud_t;

static const we_ngx_directive_t *we_ngx_find_directive(const ngx_http_whisper_edge_main_conf_t *mcf, uint8_t kind,
                                                       const char *context, uint32_t rule)
{
    const we_ngx_directive_t *d = mcf->directives.elts;
    ngx_uint_t i, n = 0;

    for (i = 0; i < mcf->directives.nelts; i++) {
        if (d[i].kind != kind || d[i].lcf->path == NULL || strcmp(d[i].lcf->path, context) != 0) {
            continue;
        }
        n++;
        if (rule == 0 || n == rule) {
            return &d[i];
        }
    }
    return NULL;
}

static void we_ngx_report_line(void *ud, const we_policy_report_line_t *r)
{
    we_ngx_report_ud_t *u = ud;
    const we_ngx_directive_t *d = we_ngx_find_directive(u->mcf, r->kind, r->context, r->rule);

    if (d != NULL) {
        we_ngx_line(u->log, NGX_LOG_WARN, "report %.*s:%lu: %s", (int) d->place.file.len, d->place.file.data,
                    (unsigned long) d->place.line, r->msg);
    } else {
        we_ngx_line(u->log, NGX_LOG_WARN, "report (%s): %s", r->context, r->msg);
    }
}

/* the contexts in ordinal order: the http block, then every server and location as nginx merged them */
static ngx_int_t we_ngx_name_contexts(ngx_conf_t *cf, ngx_http_whisper_edge_main_conf_t *mcf)
{
    ngx_http_whisper_edge_loc_conf_t **m = mcf->merged.elts;
    ngx_uint_t i;

    mcf->http = ngx_http_conf_get_module_loc_conf(cf, ngx_http_whisper_edge_module);
    if (!mcf->http->is_http) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "whisper edge: the http block's context was not recognised as such");
        return NGX_ERROR;
    }
    mcf->nctx = mcf->merged.nelts + 1;
    mcf->contexts = ngx_pcalloc(cf->pool, mcf->nctx * sizeof *mcf->contexts);
    if (mcf->contexts == NULL) {
        return NGX_ERROR;
    }
    mcf->contexts[0] = mcf->http;
    for (i = 0; i < mcf->merged.nelts; i++) {
        mcf->contexts[i + 1] = m[i];
    }
    return NGX_OK;
}

/* the digest of a block: the first eight bytes in byte order, as every surface prints it */
/* "valid until <UTC minute>" from a header's valid-until, or the words for none; `out` holds 40 bytes */
static const char *we_ngx_valid_until(uint64_t ms, char out[40])
{
    time_t secs = (time_t) (ms / 1000u);
    struct tm tm;

    if (ms == 0u) {
        return "no validity bound";
    }
    if (gmtime_r(&secs, &tm) == NULL || strftime(out, 40, "valid until %Y-%m-%dT%H:%MZ", &tm) == 0) {
        snprintf(out, 40, "valid until %llu ms", (unsigned long long) ms);
    }
    return out;
}

static void we_ngx_digest16(const we_program_t *p, char out[17])
{
    uint8_t dg[32];

    if (p == NULL) {
        snprintf(out, 17, "-");
        return;
    }
    we_sha256(p, we_program_size(p), dg);
    we_digest16(dg, out);
}

static const char *we_ngx_mode_word(const we_ctx_conf_t *c)
{
    switch (we_conf_mode(c)) {
    case WE_MODE_OFF:  return "off";
    case WE_MODE_LOG:  return "log";
    case WE_MODE_DENY: return "deny";
    default:           return "unset";
    }
}

/*
 * The bind's arguments from the data directives, for the check, the bind and the peek alike: the paths
 * are composed by the core (we_mod_bind_plane_path), never here, so nginx cannot name a plane's file a
 * second way. The strings live in the pool given.
 */
static ngx_int_t we_ngx_bind_args(ngx_pool_t *pool, const ngx_http_whisper_edge_main_conf_t *mcf, we_mod_bind_args_t *args)
{
    uint32_t p;

    if (mcf->data_dir.len > 0 && (args->data_dir = we_ngx_cstr(pool, &mcf->data_dir)) == NULL) {
        return NGX_ERROR;
    }
    /* the snapshot whenever it is named: the core makes it legacy only as the one data directive */
    if (mcf->snapshot.len > 0 && (args->legacy_file = we_ngx_cstr(pool, &mcf->snapshot)) == NULL) {
        return NGX_ERROR;
    }
    for (p = 0; p < 8; p++) {
        if (mcf->plane_file[p].len > 0 && (args->plane_file[p] = we_ngx_cstr(pool, &mcf->plane_file[p])) == NULL) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* one plane's header at the path the core composes, for the data line and the compiler's environment; no
 * rule is applied here (the check and the bind apply the path and trust rules), and a path nothing can open
 * reads absent */
static void we_ngx_peek_path(const char *path, uint32_t p, we_mod_peek_t *peek, char *why, size_t whyn,
                             uint8_t *present, uint8_t *schema_ok)
{
    char dir[4096], *slash;
    int fd;

    if (path[0] != '/' || strlen(path) >= sizeof dir) {
        return;
    }
    memcpy(dir, path, strlen(path) + 1);
    slash = strrchr(dir, '/');
    if (slash == NULL || slash[1] == '\0') {
        return;
    }
    *slash = '\0';
    fd = open(dir[0] != '\0' ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    if (we_plane_peek(fd, slash + 1, p + 1, peek, why, whyn) == 0) {
        *present = (uint8_t) (*present | (1u << p));
        *schema_ok = (uint8_t) (*schema_ok | (1u << p));
    } else if (!peek->absent && peek->err != EACCES && peek->err != EPERM) {
        *present = (uint8_t) (*present | (1u << p));                    /* present, bound, REFUSED at run time */
    }
    close(fd);
}

static ngx_int_t we_ngx_peek_planes(ngx_conf_t *cf, ngx_http_whisper_edge_main_conf_t *mcf,
                                    we_mod_peek_t peek[8], char peek_why[8][256], unsigned uid)
{
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    char path[4096];
    uint32_t p;

    (void) uid;
    memset(&mcf->env, 0, sizeof mcf->env);
    for (p = 0; p < 8; p++) {
        memset(&peek[p], 0, sizeof peek[p]);
        peek[p].absent = 1;
        peek_why[p][0] = '\0';
    }
    if (we_ngx_bind_args(cf->pool, mcf, &args) != NGX_OK) {
        return NGX_ERROR;
    }
    for (p = 0; p < 8; p++) {
        if (we_mod_bind_plane_path(&args, p, path, sizeof path) == 1) {
            we_ngx_peek_path(path, p, &peek[p], peek_why[p], sizeof peek_why[p], &mcf->env.present, &mcf->env.schema_ok);
        }
    }
    /* snapshot.bin beside the planes is read through the synonym alone, never by the directory form: its
     * header is peeked so the data line can say it is here, with its generation and validity, and the fix */
    memset(&mcf->dir_snapshot, 0, sizeof mcf->dir_snapshot);
    mcf->dir_snapshot_here = 0;
    if (args.data_dir != NULL && args.data_dir[0] == '/') {
        int fd = open(args.data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        char why[256];

        if (fd >= 0) {
            mcf->dir_snapshot_here = we_plane_peek(fd, "snapshot.bin", WE_PLANE_REPUTATION, &mcf->dir_snapshot, why,
                                                   sizeof why) == 0;
            close(fd);
        }
    }
    if (mcf->legacy) {
        mcf->env.legacy = 1;                /* the synonym: its rules are never inert, it arms on appearance */
    }
    return NGX_OK;
}

/*
 * THE TRUSTED PROXIES AND THE HEADER, at configuration test. whisper_edge_trusted_proxy's arguments become
 * the walk's table (an address, a CIDR prefix or `unix:` each; a bad one refuses the configuration at its
 * place); a prefix broader than /16 or /32 is a warning, because everyone inside it may choose the judged
 * address. whisper_edge_trusted_header with no proxy is a warning (nothing is ever read); a name with `_`
 * is refused while any server keeps nginx's default `underscores_in_headers off`, because nginx drops such a
 * line before any module sees it and the floor would judge the proxy itself; a unix listener with the header
 * set needs `unix:` among the proxies, because a unix-socket peer has no address to trust by. A
 * `proxy_protocol` listener is said out loud: the floor judges the balancer, never the PROXY header's source.
 */
static ngx_int_t we_ngx_trust_setup(ngx_conf_t *cf, ngx_http_whisper_edge_main_conf_t *mcf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    ngx_http_conf_port_t *port;
    ngx_uint_t i, j, k, has_unix = 0;
    we_mod_trust_report_t rep;
    char err[512];

    memset(&rep, 0, sizeof rep);
    if (mcf->trusted_proxy != NULL && mcf->trusted_proxy->nelts > 0) {
        ngx_str_t *v = mcf->trusted_proxy->elts;
        const char **items = ngx_pcalloc(cf->pool, mcf->trusted_proxy->nelts * sizeof *items);

        if (items == NULL) {
            return NGX_ERROR;
        }
        for (i = 0; i < mcf->trusted_proxy->nelts; i++) {
            if ((items[i] = we_ngx_cstr(cf->pool, &v[i])) == NULL) {
                return NGX_ERROR;
            }
        }
        if (we_mod_trust_build(items, mcf->trusted_proxy->nelts, &mcf->trust, &rep, err, sizeof err) != 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "whisper edge: whisper_edge_trusted_proxy (%*s:%ui): %s",
                          WE_NGX_PLACE(&mcf->trusted_proxy_place), err);
            return NGX_ERROR;
        }
        if (rep.broad != 0) {
            we_ngx_line(cf->log, NGX_LOG_WARN, "whisper_edge_trusted_proxy (%.*s:%lu) trusts %u prefix%s broader than /16 "
                        "(IPv4) or /32 (IPv6): every peer inside %s may choose the address the floor judges by sending the "
                        "header; trust the balancers' own addresses", (int) mcf->trusted_proxy_place.file.len,
                        mcf->trusted_proxy_place.file.data, (unsigned long) mcf->trusted_proxy_place.line, rep.broad,
                        rep.broad == 1 ? "" : "es", rep.broad == 1 ? "it" : "them");
        }
        if (rep.covers_mapped != 0) {
            we_ngx_line(cf->log, NGX_LOG_WARN, "whisper_edge_trusted_proxy (%.*s:%lu): %u IPv6 prefix%s cover%s ::ffff:0:0/96 "
                        "and can never match an IPv4 peer, which the module judges as IPv4; name the IPv4 prefix",
                        (int) mcf->trusted_proxy_place.file.len, mcf->trusted_proxy_place.file.data,
                        (unsigned long) mcf->trusted_proxy_place.line, rep.covers_mapped, rep.covers_mapped == 1 ? "" : "es",
                        rep.covers_mapped == 1 ? "s" : "");
        }
    }
    if (mcf->trusted_hops_place.line != 0 && mcf->trusted_header.len == 0) {
        we_ngx_line(cf->log, NGX_LOG_WARN, "whisper_edge_trusted_hops (%.*s:%lu) without whisper_edge_trusted_header does "
                    "nothing: no header is read", (int) mcf->trusted_hops_place.file.len, mcf->trusted_hops_place.file.data,
                    (unsigned long) mcf->trusted_hops_place.line);
    }
    /* the listeners: a unix one needs `unix:` when the header is read; a PROXY-protocol one is said */
    if (cmcf->ports != NULL) {
        port = cmcf->ports->elts;
        for (i = 0; i < cmcf->ports->nelts; i++) {
            ngx_http_conf_addr_t *addr = port[i].addrs.elts;

            for (j = 0; j < port[i].addrs.nelts; j++) {
                if (addr[j].opt.sockaddr->sa_family == AF_UNIX) {
                    has_unix = 1;
                    if (mcf->trusted_header.len > 0 && !mcf->trust.unix_ok) {
                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "whisper edge: whisper_edge_trusted_header is set and \"listen %V\" is a unix socket, whose "
                                      "peer has no address: name unix: in whisper_edge_trusted_proxy to read the header from it, "
                                      "or remove the header", &addr[j].opt.addr_text);
                        return NGX_ERROR;
                    }
                }
                if (addr[j].opt.proxy_protocol) {
                    we_ngx_line(cf->log, NGX_LOG_WARN, "the floor judges the PROXY-protocol load balancer on \"listen %.*s\", not "
                                "the client; the PROXY header's source is not read%s%.*s%s",
                                (int) addr[j].opt.addr_text.len, addr[j].opt.addr_text.data,
                                mcf->trusted_header.len > 0 ? ", and a balancer that does not append to " : "",
                                (int) mcf->trusted_header.len, mcf->trusted_header.data,
                                mcf->trusted_header.len > 0 ? " lets the client choose the judged address" : "");
                }
            }
        }
    }
    (void) has_unix;
    if (mcf->trusted_header.len == 0) {
        return NGX_OK;
    }
    mcf->trusted_header_hash = ngx_hash_key_lc(mcf->trusted_header.data, mcf->trusted_header.len);
    if (mcf->trust.n4 == 0 && mcf->trust.n6 == 0 && !mcf->trust.unix_ok) {
        we_ngx_line(cf->log, NGX_LOG_WARN, "whisper_edge_trusted_header %.*s (%.*s:%lu) is set and whisper_edge_trusted_proxy "
                    "names no proxy, so no peer is trusted and the header is never read: the floor judges the TCP peer",
                    (int) mcf->trusted_header.len, mcf->trusted_header.data, (int) mcf->trusted_header_place.file.len,
                    mcf->trusted_header_place.file.data, (unsigned long) mcf->trusted_header_place.line);
    }
    for (k = 0; k < mcf->trusted_header.len; k++) {
        if (mcf->trusted_header.data[k] == '_') {
            break;
        }
    }
    if (k < mcf->trusted_header.len) {
        for (i = 0; i < cmcf->servers.nelts; i++) {
            if (!cscfp[i]->underscores_in_headers) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "whisper edge: whisper_edge_trusted_header %V (%*s:%ui): nginx drops header names with underscores "
                              "unless underscores_in_headers is on (server \"%V\" at %s:%ui); rename the header or enable it",
                              &mcf->trusted_header, WE_NGX_PLACE(&mcf->trusted_header_place), &cscfp[i]->server_name,
                              cscfp[i]->file_name, cscfp[i]->line);   /* file_name is a u_char *, not an ngx_str_t */
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_whisper_edge_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_whisper_edge_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_whisper_edge_module);
    we_ngx_directive_t *dirs = mcf->directives.elts;
    we_policy_directive_t *src_d;
    we_policy_source_t src;
    we_policy_build_t *build = NULL;
    we_policy_error_t err;
    we_policy_report_t rep;
    we_ngx_report_ud_t rud;
    we_mod_ctx_spec_t *spec;
    we_mod_peek_t peek[8];
    char peek_why[8][256];
    char msg[1024], d16[17], fd16[17];
    ngx_uint_t i, var_any = 0, inject;
    uint32_t r;
    uint8_t var_planes;
    unsigned uid;
    uint16_t http_status;
    int rc;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    mcf->log = cf->log;
#ifdef WE_MOD_DEBUG
    /* the debug build (WE_MOD_DEBUG, build.sh --debug): the core's debug counters and assertions are on; the
     * gates build it for the rows that read those counters, and it says so on every configuration test */
    ngx_log_error(NGX_LOG_WARN, cf->log, 0, "whisper edge: this module is a debug build (WE_MOD_DEBUG): the core's "
                  "debug counters and assertions are on; never load it in production");
#endif

    /*
     * The decision runs LAST in PREACCESS: the handler is put at index 0 of the phase's array,
     * which nginx runs in reverse push order, so every module that rewrites the client address before
     * the access phase (realip in PREACCESS included) has run when the module judges. init_module
     * asserts it is still there.
     */
    if (cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers.nelts == 0) {
        h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        *h = ngx_http_whisper_edge_preaccess;
    } else {
        ngx_array_t *a = &cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers;
        ngx_http_handler_pt *e;

        if (ngx_array_push(a) == NULL) {
            return NGX_ERROR;
        }
        e = a->elts;
        ngx_memmove(e + 1, e, (a->nelts - 1) * sizeof(ngx_http_handler_pt));
        e[0] = ngx_http_whisper_edge_preaccess;
    }

    /* $whisper_edge_verdict, so an operator can log it and decide for themselves. In log mode this is
     * the whole point: it puts our opinion in their access log next to their own traffic. */
    /*
     * The floor judges the socket's peer, captured in POST_READ before anything can rewrite it: the
     * handler is pushed here, after every static module's (realip's included), so it runs FIRST in the
     * phase, which nginx runs in reverse push order; init_module asserts it stayed last in the array.
     */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_whisper_edge_post_read;
    {
        ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);

        if (cln == NULL) {
            return NGX_ERROR;
        }
        /* the planes, the arena and the sink go with the cycle that bound them: in the master only */
        cln->handler = ngx_http_whisper_edge_release;
        cln->data = mcf;
    }

    /* the data directives: which ones exist, and what this build can bind */
    mcf->plane_lines = 0;
    for (i = 0; i < 8; i++) {
        if (mcf->plane_file[i].len > 0) {
            mcf->plane_lines = (uint8_t) (mcf->plane_lines | (1u << i));
        }
    }
    mcf->has_binding = mcf->snapshot.len > 0 || mcf->data_dir.len > 0 || mcf->plane_lines != 0;
    /* the snapshot is legacy only as the configuration's one data directive; beside any other it is the
     * reputation plane's file, bound by its line as a per-plane file is (the core's rule, ABI 5) */
    mcf->legacy = mcf->snapshot.len > 0 && mcf->data_dir.len == 0 && mcf->plane_lines == 0;

    /* every named context gets its ordinal path and its name */
    if (we_ngx_name_contexts(cf, mcf) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * The source: every directive in file order, each under its context's path. THE DEFAULT: a
     * configuration whose http level writes neither a policy line nor a threshold runs
     * `deny if listed >= high`, which every context without lines of its own inherits; the compiler
     * compiles only what is written, so the module writes that one threshold line for it, first.
     */
    inject = !mcf->http->own && !mcf->http->own_threshold;
    src_d = ngx_pcalloc(cf->pool, (mcf->directives.nelts + 1) * sizeof(we_policy_directive_t));
    if (src_d == NULL) {
        return NGX_ERROR;
    }
    if (inject) {
        src_d[0].kind = WE_DIR_THRESHOLD;
        src_d[0].context = "http";
        src_d[0].arg = (const uint8_t *) "high";
        src_d[0].len = 4;
    }
    for (i = 0; i < mcf->directives.nelts; i++) {
        if (dirs[i].lcf->path == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "whisper edge: %V (%*s:%ui) is written in a block that is not http, server or location",
                          &dirs[i].name, WE_NGX_PLACE(&dirs[i].place));
            return NGX_ERROR;
        }
        src_d[i + inject].kind = dirs[i].kind;
        src_d[i + inject].context = dirs[i].lcf->path;
        src_d[i + inject].arg = dirs[i].arg.data;
        src_d[i + inject].len = dirs[i].arg.len;
    }
    src.d = src_d;
    src.n = mcf->directives.nelts + inject;
    src.context = NULL;
    src.floor = 0;

    /* the environment: the planes present, by their headers */
    uid = we_ngx_worker_uid(cf->cycle);
    if (geteuid() != 0 && (unsigned) geteuid() == uid && mcf->has_binding) {
        we_ngx_line(cf->log, NGX_LOG_WARN, "the configuration is read by uid %u, which is also the uid the workers run as, so "
                    "the trusted owner of the planes and of the files that define the floor is the workers' own uid; a "
                    "deployment where nginx starts as root trusts root alone", uid);
    }
    /* the trusted proxies, the header and what the listeners imply for the floor */
    if (we_ngx_trust_setup(cf, mcf, cmcf) != NGX_OK) {
        return NGX_ERROR;
    }
    /* the files that define the http level pass the trust rule, or the configuration is refused */
    if (we_ngx_strict_modes(cf, mcf, (unsigned) geteuid()) != NGX_OK) {
        return NGX_ERROR;
    }
    if (we_ngx_peek_planes(cf, mcf, peek, peek_why, uid) != NGX_OK) {
        return NGX_ERROR;
    }

    /* the compile: the whole configuration at once, refused as a whole on any refusal */
    memset(&err, 0, sizeof err);
    rud.mcf = mcf;
    rud.log = cf->log;
    rep.line = we_ngx_report_line;
    rep.ud = &rud;
    rc = we_policy_build(&src, &mcf->env, NULL, &build, &err, &rep);
    if (rc != WE_POLICY_OK) {
        char text[1600];
        const we_ngx_directive_t *d = err.directive >= inject && err.directive - inject < mcf->directives.nelts
                                      ? &dirs[err.directive - inject] : NULL;

        if (rc == WE_POLICY_NOMEM) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "whisper edge: policy refused: out of memory compiling the configuration");
            return NGX_ERROR;
        }
        we_policy_error_format(&err, text, sizeof text);
        if (d != NULL) {
            char esc[512];

            we_mod_escape(d->lcf->human, esc, sizeof esc);
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "whisper edge: policy refused: %*s:%ui: %V (%s): %s",
                          WE_NGX_PLACE(&d->place), &d->name, esc, text);
        } else {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "whisper edge: policy refused: %s (%s): %s",
                          we_policy_kind_name(err.kind), err.context, text);
        }
        return NGX_ERROR;
    }

    /* the request path's configuration: every block in the arena, one context per named block */
    var_planes = we_ngx_variable_planes(cf, &var_any);
    mcf->want_record = var_any || mcf->export_lines > 0;
    spec = ngx_pcalloc(cf->pool, mcf->nctx * sizeof(we_mod_ctx_spec_t));
    mcf->arena = we_mod_arena_new();
    if (spec == NULL || mcf->arena == NULL) {
        we_policy_build_free(build);
        return NGX_ERROR;
    }
    http_status = mcf->http->deny_status != NGX_CONF_UNSET_UINT ? (uint16_t) mcf->http->deny_status : 403u;
    for (i = 0; i < mcf->nctx; i++) {
        ngx_http_whisper_edge_loc_conf_t *lcf = mcf->contexts[i];
        uint8_t ex = (uint8_t) (we_ngx_default_export(build, lcf->path) | we_ngx_export_planes(lcf));

        spec[i].path = lcf->path;
        spec[i].name = lcf->human;
        spec[i].deny_status = lcf->deny_status != NGX_CONF_UNSET_UINT ? (uint16_t) lcf->deny_status : 0u;
        spec[i].export_mask = ex;
        spec[i].gen_mask = (uint8_t) (ex | var_planes);
    }
    rc = we_mod_config_build(WE_MODULE_ABI_VERSION, mcf->arena, build, &src, spec, mcf->nctx, http_status,
                             &mcf->cfg, &mcf->ctxs, &mcf->stride, msg, sizeof msg);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "whisper edge: policy refused: %s (%s)", msg, we_mod_strerror(rc));
        we_policy_build_free(build);
        return NGX_ERROR;
    }
    for (i = 0; i < mcf->nctx; i++) {
        mcf->contexts[i]->ctx = &mcf->ctxs[i];
    }
    /* an `if` or `limit_except` block runs its enclosing context's program */
    for (i = 0; i < mcf->noname.nelts; i++) {
        ngx_http_whisper_edge_loc_conf_t *lcf = ((ngx_http_whisper_edge_loc_conf_t **) mcf->noname.elts)[i], *p;

        for (p = lcf->parent; p != NULL && p->ctx == NULL; p = p->parent) {
        }
        lcf->ctx = p != NULL ? p->ctx : &mcf->ctxs[0];
    }

    /* the planes the configuration reads: the programs', the exports', the variables'. A keyed plane
     * (routing, registry) is bound only from the http level: an http-level rule, the floor or an http-level
     * export; a reference below the http level, or any variable, never binds one */
    {
        const uint8_t keyed = (uint8_t) ((1u << 3) | (1u << 6));
        uint8_t all = 0, http_only;

        http_only = (uint8_t) (mcf->cfg.floor != NULL ? mcf->cfg.floor->plane_mask : 0u);
        if (mcf->ctxs[0].prog != NULL) {
            http_only = (uint8_t) (http_only | mcf->ctxs[0].prog->plane_mask);
        }
        http_only = (uint8_t) (http_only | we_ngx_export_planes(mcf->http));
        for (i = 0; i < mcf->nctx; i++) {
            if (mcf->ctxs[i].prog != NULL) {
                all = (uint8_t) (all | mcf->ctxs[i].prog->plane_mask);
            }
            all = (uint8_t) (all | we_ngx_export_planes(mcf->contexts[i]));
        }
        all = (uint8_t) (all | var_planes);
        mcf->read_mask = (uint8_t) (http_only | (all & (uint8_t) ~keyed));
#ifdef WE_MOD_TEST_BIND_ALL
        mcf->read_mask = mcf->env.present;   /* the control: every present plane bound, read by nothing or not */
#endif
#ifdef WE_MOD_TEST_BIND_ANY_REF
        mcf->read_mask = (uint8_t) (http_only | all);   /* the control: a keyed plane bound by a reference below http level */
#endif
#ifdef WE_MOD_TEST_BIND_ON_INDEX
        mcf->read_mask = (uint8_t) (mcf->read_mask | var_planes);   /* the control: a variable reference binds its plane */
#endif
        /* a keyed plane read below the http level, or by a variable: inert, said with the fix */
        for (i = 0; i < 8; i++) {
            if (((keyed >> i) & 1u) == 0u || ((mcf->read_mask >> i) & 1u) != 0u || ((mcf->plane_lines >> i) & 1u) != 0u) {
                continue;                   /* read at http level, or bound by its own whisper_edge_data line */
            }
            if (((all >> i) & 1u) != 0u && ((var_planes >> i) & 1u) == 0u) {
                we_ngx_line(cf->log, NGX_LOG_WARN, "a rule or export below the http level reads plane \"%s\", which "
                            "only http-level configuration can bind: its attributes read unknown; add an http-level "
                            "rule, \"whisper_edge_policy_floor\" line or \"whisper_edge_export\" that reads it to bind it",
                            we_mod_plane_word((uint32_t) i));
            } else if (((var_planes >> i) & 1u) != 0u) {
                we_ngx_line(cf->log, NGX_LOG_WARN, "plane \"%s\" is referenced by a $whisper_edge_ variable and by "
                            "nothing at http level, so it is not bound and the variable renders unknown (%s:-a); add an "
                            "http-level \"whisper_edge_export\" of one of its attributes to bind it",
                            we_mod_plane_word((uint32_t) i), we_mod_plane_word((uint32_t) i));
            }
        }
    }

#ifndef WE_MOD_TEST_BIND_IN_INIT
    /* the binding, before the lines that name what it bound (see we_ngx_bind_planes for why it is here) */
    if (we_ngx_bind_planes(cf->cycle, cf->log, mcf) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    /* ---- the configuration-time lines (2.5) ---- */
    we_ngx_digest16(mcf->cfg.floor, fd16);
    /* the signal process (`nginx -s`) parses the configuration only to find the pid file and binds nothing, so
     * it cannot know a plane the binding refuses: it prints no data line rather than one it cannot stand by */
    if (mcf->has_binding && ngx_process != NGX_PROCESS_SIGNALLER) {
        char line[1536];
        size_t o = 0;
        uint32_t p;

        if (!mcf->legacy) {
            /* reputation's source: its own line, else the snapshot beside another directive, else the directory */
            const int rep_file = mcf->plane_file[0].len > 0 || mcf->snapshot.len > 0;

            if (mcf->data_dir.len > 0) {
                o += (size_t) snprintf(line + o, sizeof line - o, "data \"%.*s\":", (int) mcf->data_dir.len, mcf->data_dir.data);
            } else {
                o += (size_t) snprintf(line + o, sizeof line - o, "data:");
            }
            for (p = 0; p < 8 && o < sizeof line; p++) {
                const char *w = we_mod_plane_word(p);
                const ngx_str_t *own = mcf->plane_file[p].len > 0 ? &mcf->plane_file[p]
                                     : (p == 0 && mcf->snapshot.len > 0 ? &mcf->snapshot : NULL);

                if (mcf->refused[p] != NULL) {
                    /* the core's sentence carries the reason and the fix; the line says which plane */
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s refused at configuration;", w);
                    continue;
                }

                if (own != NULL) {
                    /* a file of the plane's own, bound by its line whatever reads it */
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s from %s\"%.*s\"", w,
                                           mcf->plane_file[p].len > 0 ? "" : "the snapshot ", (int) own->len, own->data);
                    if (o >= sizeof line) {
                        break;                  /* full: the next append would size itself past the end */
                    }
                    if (p == 0 && mcf->plane_file[0].len > 0 && mcf->snapshot.len > 0) {
                        o += (size_t) snprintf(line + o, sizeof line - o, " and the snapshot \"%.*s\";",
                                               (int) mcf->snapshot.len, mcf->snapshot.data);
                    } else if (peek[p].absent) {
                        o += (size_t) snprintf(line + o, sizeof line - o, " absent;");
                    } else if (peek[p].err == EACCES || peek[p].err == EPERM) {
                        o += (size_t) snprintf(line + o, sizeof line - o, " present, unreadable by uid %u (%s): rules on it are inert;",
                                               (unsigned) geteuid(), strerror((int) peek[p].err));
                    } else if (((mcf->env.schema_ok >> p) & 1u) == 0u) {
                        o += (size_t) snprintf(line + o, sizeof line - o, " present, refused (%s);", peek_why[p]);
                    } else {
                        char pd[17];

                        we_digest16(peek[p].digest, pd);
                        o += (size_t) snprintf(line + o, sizeof line - o, " generation %llu digest %s;",
                                               (unsigned long long) peek[p].generation, pd);
                    }
                    continue;
                }
                if (mcf->data_dir.len == 0) {
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s not named;", w);
                    continue;
                }
                if (peek[p].absent && p == 0 && mcf->dir_snapshot_here) {
                    char vu[40];

                    o += (size_t) snprintf(line + o, sizeof line - o, " %s absent (snapshot.bin is here, generation %llu, %s: "
                                           "add \"whisper_edge_snapshot %.*s/snapshot.bin\" to read it);", w,
                                           (unsigned long long) mcf->dir_snapshot.generation,
                                           we_ngx_valid_until(mcf->dir_snapshot.valid_until_ms, vu),
                                           (int) mcf->data_dir.len, mcf->data_dir.data);
                } else if (peek[p].absent) {
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s absent;", w);
                } else if (peek[p].err == EACCES || peek[p].err == EPERM) {
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s present, unreadable by uid %u (%s): rules on it are inert;",
                                           w, (unsigned) geteuid(), strerror((int) peek[p].err));
                } else if (((mcf->env.schema_ok >> p) & 1u) == 0u) {
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s present, refused (%s);", w, peek_why[p]);
                } else if (((mcf->read_mask >> p) & 1u) == 0u && p != WE_TENANT_IX) {
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s present, not bound: nothing in this configuration reads it;", w);
                } else {
                    char pd[17];

                    we_digest16(peek[p].digest, pd);
                    if (p == 0 && mcf->dir_snapshot_here) {
                        char vu[40];

                        o += (size_t) snprintf(line + o, sizeof line - o, " %s generation %llu digest %s (snapshot.bin here too, "
                                               "generation %llu, %s, not read);", w, (unsigned long long) peek[p].generation, pd,
                                               (unsigned long long) mcf->dir_snapshot.generation,
                                               we_ngx_valid_until(mcf->dir_snapshot.valid_until_ms, vu));
                    } else {
                        o += (size_t) snprintf(line + o, sizeof line - o, " %s generation %llu digest %s;", w,
                                               (unsigned long long) peek[p].generation, pd);
                    }
                }
            }
            we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s", line);
            if (!rep_file && mcf->dir_snapshot_here && !peek[0].absent && ((mcf->env.schema_ok & 1u) != 0u)
                    && mcf->dir_snapshot.generation > peek[0].generation) {
                we_ngx_line(cf->log, NGX_LOG_WARN, "snapshot.bin in \"%.*s\" is generation %llu, newer than the bound "
                            "reputation.bin (generation %llu), and the directory form never reads it: install the newer data "
                            "as reputation.bin, or remove the stale snapshot.bin", (int) mcf->data_dir.len, mcf->data_dir.data,
                            (unsigned long long) mcf->dir_snapshot.generation, (unsigned long long) peek[0].generation);
            }
        } else {
            char pd[17];

            if (mcf->refused[0] != NULL) {
                /* the core's sentence carries the reason and the fix */
                we_ngx_line(cf->log, NGX_LOG_NOTICE, "snapshot \"%.*s\": reputation, refused at configuration",
                            (int) mcf->snapshot.len, mcf->snapshot.data);
            } else if (peek[0].absent) {
                we_ngx_line(cf->log, NGX_LOG_NOTICE, "snapshot \"%.*s\": reputation, legacy, absent at configuration time; "
                            "the file arms when it appears, and its rules are never inert",
                            (int) mcf->snapshot.len, mcf->snapshot.data);
            } else {
                we_digest16(peek[0].digest, pd);
                we_ngx_line(cf->log, NGX_LOG_NOTICE, "snapshot \"%.*s\": reputation, format %u, legacy, generation %llu digest %s, "
                            "owner uid %u mode %04o", (int) mcf->snapshot.len, mcf->snapshot.data,
                            (unsigned) peek[0].format, (unsigned long long) peek[0].generation, pd,
                            (unsigned) peek[0].uid, (unsigned) (peek[0].mode & 07777u));
            }
        }
    } else if (!mcf->has_binding && mcf->directives.nelts > 0) {
        we_ngx_line(cf->log, NGX_LOG_WARN, "no whisper_edge_data or whisper_edge_snapshot: every plane is absent, so every rule "
                    "is inert and the module decides nothing");
    }
    if (mcf->cfg.floor != NULL && mcf->cfg.floor->rule_count > 0) {
        ngx_uint_t context_denies = 0, context_status = 0;

        we_ngx_line(cf->log, NGX_LOG_NOTICE, "floor (%.*s:%lu): %u rule%s, program %s, mode %s and deny status %u from the http level",
                    (int) mcf->floor_place.file.len, mcf->floor_place.file.data, (unsigned long) mcf->floor_place.line,
                    (unsigned) mcf->cfg.floor->rule_count, mcf->cfg.floor->rule_count == 1 ? "" : "s", fd16,
                    we_ngx_mode_word(&mcf->cfg.floor_conf), (unsigned) mcf->cfg.floor_status);
        for (i = 1; i < mcf->nctx; i++) {
            if (mcf->contexts[i]->mode_place.file.len > 0 && mcf->contexts[i]->mode == WE_MODE_DENY) {
                context_denies++;
            }
            if (mcf->contexts[i]->status_place.file.len > 0) {
                context_status++;
            }
        }
        /* the natural layout, the floor at http level and `mode deny` in each server block, is otherwise
         * a silent dry run: the floor runs under the http level's mode, whatever a server block sets */
        if (we_conf_mode(&mcf->cfg.floor_conf) != WE_MODE_DENY && context_denies > 0) {
            we_ngx_line(cf->log, NGX_LOG_WARN, "the floor will not deny: its mode is the http level's (%s); add "
                        "\"whisper_edge_mode deny\" at http level", we_ngx_mode_word(&mcf->cfg.floor_conf));
        }
        if (context_status > 0) {
            we_ngx_line(cf->log, NGX_LOG_NOTICE, "a whisper_edge_deny_status set in a server or location applies to that "
                        "context's own rules only; the floor and the pre-stage deny with the http level's %u",
                        (unsigned) mcf->cfg.floor_status);
        }
    }
    for (i = 0; i < mcf->nctx; i++) {
        ngx_http_whisper_edge_loc_conf_t *lcf = mcf->contexts[i];
        const we_mod_ctx_t *x = &mcf->ctxs[i];
        char esc[512];
        const we_ngx_directive_t *first = we_ngx_find_directive(mcf, WE_DIR_POLICY, lcf->path, 1);

        we_mod_escape(lcf->human, esc, sizeof esc);
        we_ngx_digest16(x->prog, d16);
        if (x->prog != NULL && i == 0 && inject) {
            we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s (%.*s:%lu): no lines of its own; runs the default program %s "
                        "(deny if listed >= high) under mode %s", esc, (int) lcf->place.file.len, lcf->place.file.data,
                        (unsigned long) lcf->place.line, d16, we_ngx_mode_word(&x->conf));
        } else if (x->cold != NULL && x->cold->own && x->prog != NULL) {
            /* what this context's lines replace: the nearest enclosing context with WRITTEN lines of its own,
             * never the default sugar the module wrote for the http level */
            const ngx_http_whisper_edge_loc_conf_t *anc = lcf->parent;
            const we_mod_ctx_t *px;

            while (anc != NULL && !(anc->ctx != NULL && anc->ctx->cold != NULL && anc->ctx->cold->own
                                    && anc->ctx->prog != NULL && anc->ctx->prog->rule_count > 0
                                    && !(inject && anc == mcf->http))) {
                anc = anc->parent;
            }
            px = anc != NULL ? anc->ctx : NULL;
            if (x->rule_count == 0) {
                we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s (%.*s:%lu): no rules (threshold off), program %s, mode %s%s", esc,
                            (int) lcf->place.file.len, lcf->place.file.data, (unsigned long) lcf->place.line, d16,
                            we_ngx_mode_word(&x->conf), px != NULL ? "" : ", inherits nothing");
            } else {
                we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s (%.*s:%lu): %u rule%s, program %s, mode %s%s", esc,
                            first != NULL ? (int) first->place.file.len : (int) lcf->place.file.len,
                            first != NULL ? first->place.file.data : lcf->place.file.data,
                            (unsigned long) (first != NULL ? first->place.line : lcf->place.line),
                            (unsigned) x->rule_count, x->rule_count == 1 ? "" : "s", d16, we_ngx_mode_word(&x->conf),
                            px != NULL ? "" : ", inherits nothing");
            }
            if (px != NULL && px->prog != x->prog) {
                we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s replaces %u inherited rule%s", esc, (unsigned) px->prog->rule_count,
                            px->prog->rule_count == 1 ? "" : "s");
            }
        } else if (x->prog != NULL) {
            we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s (%.*s:%lu): no lines of its own; runs program %s (%u rule%s) under mode %s",
                        esc, (int) lcf->place.file.len, lcf->place.file.data, (unsigned long) lcf->place.line, d16,
                        (unsigned) x->rule_count, x->rule_count == 1 ? "" : "s", we_ngx_mode_word(&x->conf));
        } else {
            we_ngx_line(cf->log, NGX_LOG_NOTICE, "%s (%.*s:%lu): no program (threshold off) under mode %s", esc,
                        (int) lcf->place.file.len, lcf->place.file.data, (unsigned long) lcf->place.line,
                        we_ngx_mode_word(&x->conf));
        }
    }
    if (mcf->export_lines > 0) {
        we_ngx_line(cf->log, NGX_LOG_NOTICE, "whisper_edge_export: accepted; nginx renders every attribute on demand through its "
                    "$whisper_edge_ variables, so the line names the planes the generations token covers");
    }
    {
        uint32_t own = 0, rules = 0;
        char regions[2048];
        size_t o = 0;
        const we_program_t *seen[64];
        ngx_uint_t nseen = 0, k;

        for (i = 0; i < mcf->nctx; i++) {
            if (mcf->ctxs[i].cold != NULL && mcf->ctxs[i].cold->own) {
                own++;
                rules += mcf->ctxs[i].rule_count;
            }
        }
        /* the sealed regions, for the gate's shared-pages row: each distinct block, the floor, the view */
        for (i = 0; i < mcf->nctx && o < sizeof regions - 64; i++) {
            const we_program_t *p = mcf->ctxs[i].prog;

            if (p == NULL || p == mcf->cfg.floor) {
                continue;
            }
            for (k = 0; k < nseen && seen[k] != p; k++) {
            }
            if (k < nseen) {
                continue;
            }
            if (nseen < sizeof seen / sizeof seen[0]) {
                seen[nseen++] = p;
            }
            o += (size_t) snprintf(regions + o, sizeof regions - o, " program %lx-%lx", (unsigned long) (uintptr_t) p,
                                   (unsigned long) ((uintptr_t) p + we_program_size(p)));
        }
        if (mcf->cfg.floor != NULL && o < sizeof regions - 64) {
            o += (size_t) snprintf(regions + o, sizeof regions - o, " floor %lx-%lx", (unsigned long) (uintptr_t) mcf->cfg.floor,
                                   (unsigned long) ((uintptr_t) mcf->cfg.floor + we_program_size(mcf->cfg.floor)));
        }
        if (mcf->cfg.hh != NULL && o < sizeof regions - 64) {
            snprintf(regions + o, sizeof regions - o, " hold-harmless-view %lx-%lx", (unsigned long) (uintptr_t) mcf->cfg.hh,
                     (unsigned long) ((uintptr_t) mcf->cfg.hh + sizeof *mcf->cfg.hh));
        }
        we_ngx_line(cf->log, NGX_LOG_NOTICE, "%u distinct program%s and the floor, %zu hot bytes in all (configuration-wide, "
                    "after interning); %u context%s with lines, %u rules, 8 pre-stage, 1 shard per worker, %u bytes per shard; "
                    "arena %zu pages; node %zu bytes per request; read-only regions:%s", (unsigned) we_mod_arena_blocks(mcf->arena),
                    we_mod_arena_blocks(mcf->arena) == 1 ? "" : "s", we_policy_hot_total(build), (unsigned) own,
                    own == 1 ? "" : "s", (unsigned) rules, (unsigned) mcf->stride * 8u, we_mod_arena_pages(mcf->arena),
                    sizeof(we_ngx_node_t), regions);
    }
    if (mcf->has_binding && !mcf->want_record) {
        we_ngx_line(cf->log, NGX_LOG_NOTICE, "no $whisper_edge_* variable is referenced and nothing is exported, so no record is "
                    "kept per request: a variable fetched by name at run time (njs, an SSI echo) renders the decision from the "
                    "request's node, and $whisper_edge_logged renders unknown; reference one in the configuration or set "
                    "whisper_edge_export to keep the record");
    }
    we_policy_build_free(build);

    /*
     * The writers' configuration-time facts: the counter map, one entry per context that owns
     * lines with the floor first, so a worker's thread can render its counts against the blocks that own
     * them; then the configuration file's own bytes, rendered once here, its name the digest of those
     * bytes, which every per-process file carries. A worker writes the file when it finds the name
     * absent; a configuration test renders it and writes nothing.
     */
    {
        uint32_t e = 0;
        ngx_uint_t p;
        size_t bound = 64u;

        mcf->ctrmap = ngx_pcalloc(cf->pool, (mcf->nctx + 1u) * sizeof(we_mod_ctrmap_entry_t));
        if (mcf->ctrmap == NULL) {
            return NGX_ERROR;
        }
        if (mcf->cfg.floor != NULL && mcf->cfg.floor->rule_count > 0u) {
            mcf->ctrmap[e].ctr_off = WE_MOD_CTR_FLOOR;
            mcf->ctrmap[e].rule_count = mcf->cfg.floor->rule_count;
            we_ngx_digest16(mcf->cfg.floor, mcf->ctrmap[e].digest16);
            e++;
            bound += 64u + (size_t) mcf->cfg.floor->rule_count * 32u;
            for (r = 0; r < mcf->cfg.floor->rule_count; r++) {
                bound += 4u * strlen(mcf->cfg.cold->rule_text[r]);
            }
        }
        for (i = 0; i < mcf->nctx; i++) {
            const we_mod_ctx_t *x = &mcf->ctxs[i];

            if (x->prog == NULL || x->cold == NULL) {
                continue;
            }
            /* every context with a program gets a program line in the file, the inheriting ones included (the
             * renderer names each context and the program it runs); only an owner's rule texts follow its line.
             * A bound that counted owners alone was overrun by a configuration of twenty-five contexts, most of
             * them inheriting, and the server refused to start: measured by the gate, which is why the term is
             * here for every context. */
            bound += 64u + 4u * (strlen(x->cold->name) + strlen(x->cold->path));
            if (!x->cold->own) {
                continue;                   /* an inheriting context's counts are its owner's */
            }
            mcf->ctrmap[e].ctr_off = x->ctr_off;
            mcf->ctrmap[e].rule_count = x->rule_count;
            we_ngx_digest16(x->prog, mcf->ctrmap[e].digest16);
            e++;
            bound += (size_t) x->rule_count * 32u;
            for (r = 0; r < x->rule_count; r++) {
                bound += 4u * strlen(x->cold->rule_text[r]);
            }
        }
        mcf->nctrm = e;
        /* the planes the configuration file lists, and why a file the workers cannot read is unreadable; the
         * plane lines themselves (the binding's paths, and the reason of a plane refused at configuration)
         * size the rest of the bound when the file is rendered, below */
        for (p = 0; p < 8; p++) {
            if (!we_ngx_plane_wanted(mcf, (uint32_t) p, &peek[p])) {
                continue;
            }
            if (peek[p].err == EACCES || peek[p].err == EPERM) {
                mcf->plane_unreadable[p] = strerror((int) peek[p].err);
            }
            mcf->plane_want = (uint8_t) (mcf->plane_want | (1u << p));
        }
        mcf->conf_bound_base = bound;
    }

    /* one full shard nothing reads, for a worker whose own shard cannot be allocated */
    mcf->sink = aligned_alloc(64, (size_t) mcf->stride * 8u);
    if (mcf->sink == NULL) {
        return NGX_ERROR;
    }
    memset(mcf->sink, 0, (size_t) mcf->stride * 8u);
    return we_ngx_render_conf_file(cf->log, cf->pool, mcf);
}

/*
 * The configuration file's bytes, rendered once the planes are bound (or checked, under nginx -t): its
 * plane lines name the files the binding reads and, for a plane refused at configuration, the core's reason
 * with the fix; its name is the digest of the bytes, and every per-process file carries that digest. A
 * worker writes the file when it finds the name absent; a configuration test renders it and writes nothing.
 */
static ngx_int_t we_ngx_render_conf_file(ngx_log_t *log, ngx_pool_t *pool, ngx_http_whisper_edge_main_conf_t *mcf)
{
    we_mod_text_t t;
    size_t bound = mcf->conf_bound_base;
    uint32_t p;

    for (p = 0; p < 8; p++) {
        if (((mcf->plane_want >> p) & 1u) == 0u && mcf->refused[p] == NULL) {
            mcf->plane_path[p] = NULL;
            continue;
        }
        if (mcf->plane_path[p] == NULL) {
            continue;
        }
        bound += 64u + 4u * strlen(mcf->plane_path[p]);
        if (mcf->plane_unreadable[p] != NULL) {
            bound += 4u * strlen(mcf->plane_unreadable[p]);
        }
        if (mcf->refused[p] != NULL) {
            bound += 16u + 4u * strlen(mcf->refused[p]);
        }
    }
    mcf->conf_bytes = ngx_pnalloc(pool, bound);
    if (mcf->conf_bytes == NULL) {
        return NGX_ERROR;
    }
    mcf->conf_bound = bound;
    t.buf = mcf->conf_bytes;
    t.len = 0u;
    t.cap = bound;
    t.over = 0;
    we_mod_render_conf(&t, &mcf->cfg, mcf->ctxs, mcf->nctx, mcf->plane_path, mcf->plane_unreadable, mcf->refused);
    if (t.over) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "whisper edge: the configuration file's own listing does not fit its "
                      "computed bound of %zu bytes", bound);
        return NGX_ERROR;
    }
    mcf->conf_len = t.len;
    we_mod_conf_name(&t, mcf->conf_name);
    ngx_memcpy(mcf->config16, mcf->conf_name + 5, 16u);
    mcf->config16[16] = '\0';
    we_ngx_line(log, NGX_LOG_NOTICE, "the configuration file %s, at most %zu bytes, is written once by whichever worker "
                "first finds it absent; every worker's status and counter file names its digest %s", mcf->conf_name,
                bound, mcf->config16);
    return NGX_OK;
}

/*
 * THE BINDING, at the end of postconfiguration and never in init_module. nginx treats a failing init_module as
 * fatal in every cycle, a reload's included: ngx_init_cycle exits the master, and its workers are left serving
 * without one (measured: exit_group(1) 23 ms after the reload's SIGHUP, the two workers reparented to init).
 * A postconfiguration failure only rejects the new configuration and keeps the running cycle, so a binding
 * refused here, at a reload, leaves the old workers serving the old planes; at a start or under nginx -t it
 * refuses the configuration, naming why.
 */
static ngx_int_t we_ngx_bind_planes(ngx_cycle_t *cycle, ngx_log_t *log, ngx_http_whisper_edge_main_conf_t *mcf)
{
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    char msg[1024];
    uint32_t p;
    int rc;

    for (p = 0; p < 8; p++) {
        mcf->refused[p] = NULL;
        mcf->plane_path[p] = NULL;
    }
    if (ngx_process == NGX_PROCESS_SIGNALLER || !mcf->has_binding) {
        return NGX_OK;         /* `nginx -s` parses the configuration to find the pid file; no directive, nothing */
    }
    if (we_ngx_bind_args(cycle->pool, mcf, &args) != NGX_OK) {
        return NGX_ERROR;
    }
    args.read_mask = mcf->read_mask;
    args.uid = we_ngx_worker_uid(cycle);
    mcf->bind_uid = args.uid;
    mcf->bind_done = 1;
    if (ngx_test_config) {
        /* nginx -t: the core's check-only bind, every rule the bind applies and nothing mapped; each plane
         * refused at configuration is said in the core's own sentence */
        we_mod_plane_check_t *out = ngx_pcalloc(cycle->pool, 8u * sizeof *out);

        if (out == NULL) {
            return NGX_ERROR;
        }
        rc = we_mod_bind_check(&args, out, msg, sizeof msg);
        if (rc != 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0, "whisper edge: the planes cannot be bound: %s (%s)", msg,
                          we_mod_strerror(rc));
            return NGX_ERROR;
        }
        for (p = 0; p < 8; p++) {
            mcf->plane_path[p] = out[p].path[0] != '\0' ? out[p].path : NULL;
            if (out[p].config_refused) {
                char line[1024];

                mcf->refused[p] = out[p].reason;
                we_mod_refused_sentence(line, sizeof line, p, out[p].reason);
                ngx_log_error(WE_NGX_REFUSED_LEVEL, log, 0, "%s", line);   /* error: a stock error_log keeps it */
            }
        }
        return NGX_OK;
    }
    /*
     * A single-process cycle (master_process off) runs init_process once, so a reload cannot start a
     * second thread or bind a second set of planes under the first: this configuration decides over the
     * FIRST configuration's planes until a restart, logged once, and the status line says
     * single-process-stale. Development only, and it says so.
     */
    if (g_worker != NULL) {
        we_mod_cfg_t *first = (we_mod_cfg_t *) g_worker->planes_cfg;

        ngx_memcpy(mcf->cfg.handle, first->handle, sizeof mcf->cfg.handle);
        ngx_memcpy(mcf->cfg.standin, first->standin, sizeof mcf->cfg.standin);
        ngx_memcpy(mcf->cfg.static_reason, first->static_reason, sizeof mcf->cfg.static_reason);
        mcf->cfg.bound_mask = first->bound_mask;
        mcf->cfg.null_reason = first->null_reason;
        mcf->planes = g_worker->planes;
        mcf->stale_single = 1;
        g_worker->single_stale = 1;
        g_worker->planes_cfg = &mcf->cfg;    /* the next reload copies from this cycle's, which outlives the old pool */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "whisper edge: master_process is off, so this reload keeps the first configuration's planes until a "
                      "restart (single-process-stale); master_process off is for development");
    } else {
        mcf->bind_lines = ngx_array_create(cycle->pool, 16, sizeof(ngx_str_t));
        if (mcf->bind_lines == NULL) {
            return NGX_ERROR;
        }
        args.log = we_ngx_bind_log;
        args.log_ud = mcf;
        rc = we_mod_bind(&mcf->cfg, &args, &mcf->planes, msg, sizeof msg);
#ifndef WE_MOD_TEST_CONFLICT_CLOSED
        if (rc == WE_MOD_ERR_CONFIG && ngx_is_init_cycle(cycle->old_cycle)) {
            /*
             * A FIRST START THAT SKIPPED nginx -t, on the one configuration the binding refuses whole (two files
             * named for one plane): fail open, as Apache and OpenLiteSpeed do. The server comes up with no plane
             * bound, every rule reads unknown and the module denies nothing, and the error log says so at error,
             * the level a stock error_log keeps. nginx -t refuses it (above), and a reload into it is refused
             * below, so the running configuration keeps its planes: only a start with nothing running opens.
             */
            ngx_log_error(NGX_LOG_ERR, log, 0, "whisper edge: the planes are not bound: %s (%s); nginx -t refuses this "
                          "configuration, and this start serves with no plane bound: every rule reads unknown and the "
                          "module denies nothing until the configuration is fixed and reloaded", msg, we_mod_strerror(rc));
            {
                /* and into the error log itself: at a first start this log is the starting stderr, so the line
                 * is queued with the binding's, which init_module writes into the cycle's own log at error */
                ngx_str_t *l = ngx_array_push(mcf->bind_lines);
                u_char *e;

                if (l == NULL || (l->data = ngx_pnalloc(cycle->pool, 1536)) == NULL) {
                    return NGX_ERROR;
                }
                e = ngx_snprintf(l->data, 1536, "whisper edge: the planes are not bound: %s (%s); nginx -t refuses this "
                                 "configuration, and this start serves with no plane bound: every rule reads unknown and "
                                 "the module denies nothing until the configuration is fixed and reloaded", msg,
                                 we_mod_strerror(rc));
                l->len = (size_t) (e - l->data);
            }
            mcf->planes = NULL;
            rc = 0;
        }
#endif
        if (rc != 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0, "whisper edge: the planes cannot be bound: %s (%s)", msg,
                          we_mod_strerror(rc));
            return NGX_ERROR;
        }
    }
    for (p = 0; p < 8; p++) {
        mcf->plane_path[p] = we_mod_plane_path(mcf->planes, p);
        mcf->refused[p] = we_mod_plane_config_refusal(mcf->planes, p);
    }
    return NGX_OK;
}

/*
 * THE WORKERS' FINAL USER. The binding runs at postconfiguration, before nginx applies a `user` line that
 * comes after the http block, so it may have trusted the default uid rather than the workers' own. Once
 * init_module knows the final uid, a binding made for another one is made again for it: under nginx -t the
 * core's check runs again and names each plane refused for the final uid; otherwise the planes are bound
 * anew with the final uid and the first binding released, so a plane whose directory only the default uid
 * could trust is refused alone, reads unknown and is named in the core's sentence. Per-plane refusals are
 * not fatal, so this never fails init_module for them.
 */
static ngx_int_t we_ngx_bind_for_final_uid(ngx_cycle_t *cycle, ngx_http_whisper_edge_main_conf_t *mcf)
{
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    unsigned uid = we_ngx_worker_uid(cycle);
    char msg[1024];
    uint32_t p;
    int rc;

    if (!mcf->bind_done || uid == mcf->bind_uid || g_worker != NULL || ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_OK;
    }
#ifdef WE_MOD_TEST_NO_FINAL_UID
    return NGX_OK;                           /* the control: the binding keeps the uid it was made for */
#endif
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "whisper edge: policy: the workers' user (uid %ud) is set after the "
                  "http block, so the planes checked for uid %ud are checked again for it", uid, mcf->bind_uid);
    if (we_ngx_bind_args(cycle->pool, mcf, &args) != NGX_OK) {
        return NGX_ERROR;
    }
    args.read_mask = mcf->read_mask;
    args.uid = uid;
    mcf->bind_uid = uid;
    if (ngx_test_config) {
        we_mod_plane_check_t *out = ngx_pcalloc(cycle->pool, 8u * sizeof *out);

        if (out == NULL) {
            return NGX_ERROR;
        }
        rc = we_mod_bind_check(&args, out, msg, sizeof msg);
        if (rc != 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "whisper edge: the planes cannot be bound: %s (%s)", msg,
                          we_mod_strerror(rc));
            return NGX_ERROR;
        }
        for (p = 0; p < 8; p++) {
            mcf->plane_path[p] = out[p].path[0] != '\0' ? out[p].path : NULL;
            mcf->refused[p] = NULL;
            if (out[p].config_refused) {
                char line[1024];

                mcf->refused[p] = out[p].reason;
                we_mod_refused_sentence(line, sizeof line, p, out[p].reason);
                ngx_log_error(WE_NGX_REFUSED_LEVEL, cycle->log, 0, "%s", line);
            }
        }
    } else {
        we_mod_planes_t *old = mcf->planes, *fresh = NULL;

        mcf->bind_lines = ngx_array_create(cycle->pool, 16, sizeof(ngx_str_t));   /* the first binding's lines go */
        if (mcf->bind_lines == NULL) {
            return NGX_ERROR;
        }
        args.log = we_ngx_bind_log;
        args.log_ud = mcf;
        /* the new binding first: a refusal leaves the configuration as it was, the first binding intact */
        rc = we_mod_bind(&mcf->cfg, &args, &fresh, msg, sizeof msg);
        if (rc != 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "whisper edge: the planes cannot be bound for the workers' user "
                          "(uid %ud): %s (%s)", uid, msg, we_mod_strerror(rc));
            return NGX_ERROR;
        }
        mcf->planes = fresh;
        if (old != NULL) {
            we_mod_planes_release(old);
        }
        for (p = 0; p < 8; p++) {
            mcf->plane_path[p] = we_mod_plane_path(mcf->planes, p);
            mcf->refused[p] = we_mod_plane_config_refusal(mcf->planes, p);
        }
    }
    return we_ngx_render_conf_file(cycle->log, cycle->pool, mcf);
}

/*
 * THE PHASE ORDER, asserted where a failure refuses the configuration rather than the running server. The
 * decision must be the last PREACCESS handler and the floor's post-read handler the first to run, or a module
 * loaded after this one could rewrite the client address before the module judges it, and the policy would be
 * bypassed without a word. The phase engine is final only once every http module's postconfiguration has run,
 * so the check cannot be a postconfiguration of this module; and init_module, where it was, is fatal at a
 * reload (nginx exits the master and leaves its workers without one). It runs from the init_conf of a core
 * module this object carries beside the http one: nginx calls every core module's init_conf after the whole
 * configuration is parsed, and one that fails refuses the new cycle, so a reload into a misordered
 * configuration is refused while the running master and workers keep serving (measured on nginx 1.24 with
 * SIGHUP to the master), and nginx -t and a fresh start refuse it the same way.
 */
static ngx_int_t we_ngx_phase_order(ngx_cycle_t *cycle, ngx_http_core_main_conf_t *cmcf)
{
    ngx_http_handler_pt *e;

    e = cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers.elts;
    if (cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers.nelts == 0 || e[0] != ngx_http_whisper_edge_preaccess) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "whisper edge: the decision is no longer the last PREACCESS handler: a module loaded after this one "
                      "moved it, so a client address rewritten in PREACCESS could be judged before the rewrite; put the "
                      "load_module line for ngx_http_whisper_edge_module last (nginx -t names this, and a reload into it is "
                      "refused while the running configuration keeps serving)");
        return NGX_ERROR;
    }
    e = cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers.elts;
    if (cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers.nelts == 0
            || e[cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers.nelts - 1] != ngx_http_whisper_edge_post_read) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "whisper edge: a module loaded after this one registers a post-read handler, which could rewrite the "
                      "client address before the floor reads it; put the load_module line for ngx_http_whisper_edge_module last "
                      "(nginx -t names this, and a reload into it is refused while the running configuration keeps serving)");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* the core module's init_conf: the workers' final user, then the phase order; a failure refuses the cycle */
static char *we_ngx_order_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    ngx_http_whisper_edge_main_conf_t *mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_whisper_edge_module);

    (void) conf;
    if (cmcf == NULL || mcf == NULL) {
        return NGX_CONF_OK;                  /* no http block: nothing to assert */
    }
    if (we_ngx_bind_for_final_uid(cycle, mcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
#ifndef WE_MOD_TEST_ORDER_IN_INIT
    if (we_ngx_phase_order(cycle, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
#endif
    return NGX_CONF_OK;
}

static ngx_core_module_t ngx_http_whisper_edge_order_ctx = {
    ngx_string("whisper_edge_order"),
    NULL,                                        /* no configuration of its own */
    we_ngx_order_init_conf                       /* the final user and the phase order, after the whole parse */
};

ngx_module_t ngx_http_whisper_edge_order_module = {
    NGX_MODULE_V1,
    &ngx_http_whisper_edge_order_ctx,
    NULL,
    NGX_CORE_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/*
 * init_module runs in the process that parsed the configuration, under `nginx -t` too, once the cycle's own
 * log is open: it writes the binding's lines there and seals the configuration's blocks read-only. Nothing
 * that can refuse a configuration belongs here, because nginx makes a failing init_module fatal at a reload;
 * the phase order is asserted by the order module's init_conf above.
 */
static ngx_int_t
ngx_http_whisper_edge_init_module(ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    ngx_http_whisper_edge_main_conf_t *mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_whisper_edge_module);

    if (cmcf == NULL || mcf == NULL) {
        return NGX_OK;                           /* no http block: nothing to assert */
    }
    if (mcf->bind_lines != NULL) {
        ngx_str_t *l = mcf->bind_lines->elts;
        ngx_uint_t k;
        static const char own[] = "whisper edge: ";

        for (k = 0; k < mcf->bind_lines->nelts; k++) {
            if (l[k].len >= sizeof own - 1 && ngx_strncmp(l[k].data, own, sizeof own - 1) == 0) {
                /* the core's own sentences (a plane refused at configuration) at error: nginx's stock
                 * error_log has no level, which is error, and a refused plane must not pass in silence */
                ngx_log_error(WE_NGX_REFUSED_LEVEL, cycle->log, 0, "%V", &l[k]);
            } else {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "whisper edge: policy: %V", &l[k]);
            }
        }
        mcf->bind_lines = NULL;
    }
#ifdef WE_MOD_TEST_ORDER_IN_INIT
    if (we_ngx_phase_order(cycle, cmcf) != NGX_OK) {
        return NGX_ERROR;                    /* the control: where nginx makes the refusal fatal at a reload */
    }
#endif
    if (mcf->arena != NULL && we_mod_arena_seal(mcf->arena) != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "whisper edge: the configuration's blocks cannot be sealed read-only");
        return NGX_ERROR;
    }
#ifdef WE_MOD_TEST_BIND_IN_INIT
    /* the control: the binding where nginx makes a refusal fatal, and the file rendered again over it */
    if (we_ngx_bind_planes(cycle, cycle->log, mcf) != NGX_OK) {
        return NGX_ERROR;
    }
    return we_ngx_render_conf_file(cycle->log, cycle->pool, mcf);
#else
    return NGX_OK;
#endif
}

/* ---- the planes' lines and the master's release ---------------------------------------------------- */

/*
 * The binding's lines. The bind runs during the configuration's parse, whose log at a first start is the
 * starting stderr; the lines belong in the error log, as they did when the bind ran later, so they are kept
 * here and init_module writes them into the cycle's own log. A line that is already a whole sentence of the
 * core's (a plane refused at configuration) keeps its own words; the rest carry the policy prefix.
 */
static void we_ngx_bind_log(void *ud, const char *entry)
{
    ngx_http_whisper_edge_main_conf_t *mcf = ud;
    ngx_str_t *l;
    size_t n = strlen(entry);

    if (mcf->bind_lines == NULL || (l = ngx_array_push(mcf->bind_lines)) == NULL) {
        return;
    }
    l->data = ngx_pnalloc(mcf->bind_lines->pool, n);
    l->len = l->data != NULL ? n : 0;
    if (l->data != NULL) {
        ngx_memcpy(l->data, entry, n);
    }
}

/*
 * THE WRITERS' CLOCKS. The files an operator reads carry wall-clock epoch milliseconds (started, written,
 * snapshot), the same convention the per-range counters always wrote; the handoff between the thread and
 * the loop is measured on the monotonic clock, as every interval, deadline and retire stamp is.
 */
static uint64_t we_ngx_epoch_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return (uint64_t) ngx_time() * 1000ull;
    }
    return (uint64_t) ts.tv_sec * 1000ull + (uint64_t) ts.tv_nsec / 1000000ull;
}

/* what the status file's process line names: the server and its version, nginx's own NGINX_VER string */
static const char we_ngx_server[] = NGINX_VER;

/* the thread's and the loop's lines: the transition entries the apply hands over, and the worker's own.
 * Every entry the loop logs is also kept, with its time, in the last-16 ring the status file prints, and
 * the error-log line and the status file's transition line are the same bytes. The append runs on
 * the loop, the status writer copies the ring on the thread, and the mutex is held for one bounded copy:
 * an entry every plane generation, sixteen 512-byte slots once per tick. */
static void we_ngx_worker_log(void *ud, const char *entry)
{
    (void) ud;                               /* the core keeps the transition ring; this is the log line */
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "whisper edge: %s", entry);
}

/*
 * The cycle that bound the planes is going. In the MASTER (and under nginx -t) the mappings, the arena
 * and the sink are released with it: a reload bound new ones, and the workers hold their own copies of
 * the pages. A single process (g_worker set) keeps the first configuration's planes across a reload by
 * design and frees only the arena and the sink, which nothing references once the new cycle decides. A
 * worker's cycle pool is destroyed on its way out of the process, after its thread was stopped or
 * abandoned, so a worker releases nothing here: an abandoned thread may still touch the planes, and the
 * process is exiting anyway.
 */
static void ngx_http_whisper_edge_release(void *data)
{
    ngx_http_whisper_edge_main_conf_t *mcf = data;

    if (ngx_process == NGX_PROCESS_WORKER || ngx_process == NGX_PROCESS_HELPER) {
        return;
    }
    if (mcf->planes != NULL && g_worker == NULL) {
        we_mod_planes_release(mcf->planes);
    }
    mcf->planes = NULL;
    if (mcf->arena != NULL) {
        we_mod_arena_free(mcf->arena);
        mcf->arena = NULL;
    }
    free(mcf->sink);
    mcf->sink = NULL;
    we_mod_trust_free(&mcf->trust);
}

/* ---- the worker: the shard, the eventfd, the thread ------------------------------------------------ */

/* the thread posted: 8 bytes into the eventfd, which the loop's read handler drains. The time is stored
 * BEFORE the write, so the loop can only ever read a stamp that predates its own wake: the handoff it
 * answers is never negative. */
static void we_ngx_wake(void *ud)
{
    we_ngx_worker_t *w = ud;
    uint64_t one = 1;

    __atomic_store_n(&w->posted_mono, we_mod_monotonic_ms(), __ATOMIC_RELEASE);
    while (write(w->efd, &one, sizeof one) < 0 && errno == EINTR) {
    }
}

/*
 * The loop's end of the thread's posts. The eventfd is drained FIRST and the lists taken second, so a post
 * that lands between the two is either in the list taken or has written the counter again. Whatever
 * c->close and c->error say (the shutdown timer calls every read handler with both set), this handler
 * never closes the connection: the descriptor is the thread's to write until it is done. Draining the
 * counter is also where the handoff term is measured: the thread's stamp against the loop's own clock,
 * one event-loop iteration on this server.
 */
static void we_ngx_efd_read(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    we_ngx_worker_t *w = c->data;
    we_mod_item_t *it;
    uint64_t v, posted;

    while (read(c->fd, &v, sizeof v) == (ssize_t) sizeof v) {
    }
    posted = __atomic_load_n(&w->posted_mono, __ATOMIC_ACQUIRE);
    if (posted != 0u) {
        __atomic_store_n(&w->handoff_ms, (uint64_t) we_mod_monotonic_ms() - posted, __ATOMIC_RELEASE);
    }
    we_mod_planes_apply(w->planes, we_ngx_worker_log, w);
    /* the per-range counter sets the thread built for a new reputation map: the loop swaps pointers and
     * hands the set it was counting into back to the thread, which writes and frees it */
    for (it = we_mod_list_take(&w->sets_to_loop); it != NULL;) {
        we_ngx_set_item_t *si = (we_ngx_set_item_t *) (void *) it;
        we_counters_t *old = w->legacy;

        it = it->next;
        w->legacy = si->set;
        si->set = old;
        we_mod_list_post(&w->sets_to_thread, &si->link);
    }
}

/* the legacy copy's per-range counters: written against the map they were built for, which the thread
 * holds while that map is armed or inside its grace */
static void we_ngx_write_legacy(we_ngx_worker_t *w, we_counters_t *set, const we_map_t *m)
{
    uint64_t now = (uint64_t) ngx_time() * 1000ull;

    if (set == NULL || m == NULL || w->counters_dir == NULL) {
        return;
    }
    if (we_counters_write(set, m, w->counters_dir, now) != WE_OK && !w->counters_said) {
        char line[512];

        w->counters_said = 1;
        snprintf(line, sizeof line, "the per-range counters cannot be written under \"%.300s\"; blocking is unaffected "
                 "and whisper-edge-summary has nothing to read there (said once)", w->counters_dir);
        we_ngx_worker_log(w, line);
    }
}

/* ---- the writers: the configuration file, the status file, the rule counters -- */

/*
 * The configuration file, written by whichever worker first finds the name absent, of another kind, or of
 * another size: the name is the digest of the bytes, so a regular file of a different length cannot be
 * the file this name promises and is replaced the same way, by the same temp-and-rename every writer
 * uses, WITHOUT THE NAME EVER BEING OPENED: no worker opens it for reading, and a same-size regular
 * file is left for the summary, whose conf-mismatch is the reader's signal. A FIFO or a symlink is
 * found by fstatat with
 * AT_SYMLINK_NOFOLLOW and replaced by the rename, never drained nor followed. The workers write it and
 * the supervisor never does, so the installer's ACL'd or group-writable counters directory, which the
 * root trust rule refuses to a root writer, still receives it.
 */
static void we_ngx_write_conf(we_ngx_worker_t *w)
{
    char why[512];
    struct stat st;

    if (w->cdir_fd < 0 || w->conf_len == 0u) {
        return;
    }
    if (fstatat(w->cdir_fd, w->conf_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode)
        && (uint64_t) st.st_size == w->conf_len) {
        return;
    }
    if (we_mod_write_file(w->cdir_fd, &w->id, "conf", w->conf_name, w->conf_bytes, w->conf_len,
                          why, sizeof why) == 0) {
        return;
    }
    if (!w->said_conf) {
        char line[512];

        w->said_conf = 1;
        snprintf(line, sizeof line, "the configuration file %s cannot be written under \"%.160s\" (%.128s); "
                 "no program texts for whisper-edge-summary; blocking is unaffected (said once)",
                 w->conf_name, w->counters_dir != NULL ? w->counters_dir : "?", why);
        we_ngx_worker_log(w, line);
    }
}

/*
 * The status file: the process line is this process's own (the server, its clocks, its
 * configuration's digest, its flags), the plane lines are what the core reads from the applied state,
 * and the transitions are the last sixteen the loop logged, copied under the ring's mutex oldest first,
 * the same bytes the error log carries. The whole write runs on one thread: the module's thread on
 * every tick, or this loop once before it serves when the thread could not be started (the process
 * line then carries no-thread, and no counter file is written, so its counts are lost, section 3.3).
 */
static void we_ngx_write_status(we_ngx_worker_t *w, uint64_t tick)
{
    we_mod_text_t t;
    char why[512];
    uint64_t now = we_ngx_epoch_ms();

    if (w->cdir_fd < 0 || w->status == NULL || w->text == NULL) {
        return;
    }
    memset(w->status, 0, sizeof *w->status);
    w->status->server = we_ngx_server;
    w->status->started_ms = w->started_ms;
    w->status->written_ms = now;
    w->status->interval_ms = w->interval_ms;
    w->status->jitter_ms = w->offset_ms;
    w->status->handoff_ms = __atomic_load_n(&w->handoff_ms, __ATOMIC_ACQUIRE);
    w->status->tick = tick;
    ngx_memcpy(w->status->config16, w->config16, sizeof w->config16);
    w->status->no_thread = (uint8_t) w->no_thread;
    w->status->client_ip_from_header = (uint8_t) w->client_header;
    w->status->single_process_stale = (uint8_t) w->single_stale;
    w->status->shards = w->no_shard ? 0u : 1u;
    we_mod_planes_status(w->planes, w->status, now);   /* the transition ring included: the core fills it */
    t.buf = w->text;
    t.len = 0u;
    t.cap = w->text_cap;
    t.over = 0;
    we_mod_render_status(&t, &w->id, w->status);
    if (t.over) {
        if (!w->said_over) {
            char line[160];

            w->said_over = 1;
            snprintf(line, sizeof line, "the status file's own listing does not fit its %zu-byte buffer and is not "
                     "written; whisper-edge-summary will list this worker as gone (said once)", w->text_cap);
            we_ngx_worker_log(w, line);
        }
        return;
    }
    if (we_mod_write_file(w->cdir_fd, &w->id, "status", w->status_name, t.buf, t.len, why, sizeof why) != 0
        && !w->said_status) {
        char line[512];

        w->said_status = 1;
        snprintf(line, sizeof line, "the status file cannot be written under \"%.160s\" (%.128s); blocking is "
                 "unaffected and whisper-edge-summary has nothing to read there (said once)",
                 w->counters_dir != NULL ? w->counters_dir : "?", why);
        we_ngx_worker_log(w, line);
    }
}

/*
 * The rule counters, version 2: the shard read with one relaxed load per word, never a plain
 * load, then rendered against this process's copy of the counter map, the non-zero counts only. The
 * snapshot clock is read before the loads and the written clock after the render, both epoch
 * milliseconds, the convention the legacy per-range counters always wrote. A worker whose own shard
 * could not be allocated writes nothing here: its counts went to the sink, which every failure shares,
 * so a file of them would double-count, and its status file says shards 0 instead (section 6).
 */
static void we_ngx_write_rules(we_ngx_worker_t *w, uint64_t tick)
{
    we_mod_text_t t;
    char why[512];
    uint64_t snapshot = we_ngx_epoch_ms();
    uint32_t i;

    if (w->cdir_fd < 0 || w->no_shard || w->snap == NULL || w->text == NULL) {
        return;
    }
    for (i = 0u; i < w->stride; i++) {
        w->snap[i] = __atomic_load_n(&w->shard[i], __ATOMIC_RELAXED);
    }
    t.buf = w->text;
    t.len = 0u;
    t.cap = w->text_cap;
    t.over = 0;
    we_mod_render_rules(&t, &w->id, &w->ctrmap, w->snap, w->started_ms, tick, snapshot, we_ngx_epoch_ms(),
                        w->config16);
    if (t.over) {
        if (!w->said_over) {
            char line[160];

            w->said_over = 1;
            snprintf(line, sizeof line, "the rule counters' own listing does not fit their %zu-byte buffer and are "
                     "not written; whisper-edge-summary will list this worker as gone (said once)", w->text_cap);
            we_ngx_worker_log(w, line);
        }
        return;
    }
    if (we_mod_write_file(w->cdir_fd, &w->id, "rules", w->rules_name, t.buf, t.len, why, sizeof why) != 0
        && !w->said_rules) {
        char line[512];

        w->said_rules = 1;
        snprintf(line, sizeof line, "the rule counter file cannot be written under \"%.160s\" (%.128s); blocking is "
                 "unaffected and whisper-edge-summary has nothing to read there (said once)",
                 w->counters_dir != NULL ? w->counters_dir : "?", why);
        we_ngx_worker_log(w, line);
    }
}

/*
 * The writers' order on every tick: the configuration file first, so a fresh directory gains the
 * one file that names every program before anything refers to its digest, then the status file, then
 * the rule counters. All three run on the module's thread alone; the no-thread process calls only the
 * status writer, once, before it serves.
 */
static void we_ngx_write_files(we_ngx_worker_t *w, uint64_t tick)
{
    we_ngx_write_conf(w);
    we_ngx_write_status(w, tick);
    we_ngx_write_rules(w, tick);
}

/*
 * THE TICK, on the module's thread: the planes' own tick (the stats, the jobs, the posted results, the
 * retire sweep), then the legacy copy's per-range counters: when the armed reputation map changed since
 * the last tick, the counters of the old map are written while it is still mapped, a fresh set is built
 * for the new map and posted to the loop, which swaps and hands the old set back to be freed here. Then
 * the writers, which run whether or not the legacy synonym is bound: the data-directory form has no
 * per-range counters but its rule counts, its status and its configuration file are written all the same.
 */
static void we_ngx_tick(void *ud, uint64_t tick, const int *stop)
{
    we_ngx_worker_t *w = ud;
    we_mod_item_t *it;

    we_mod_planes_tick(w->planes, tick, stop);
    if (w->legacy_handle != NULL) {
        for (it = we_mod_list_take(&w->sets_to_thread); it != NULL;) {
            we_ngx_set_item_t *si = (we_ngx_set_item_t *) (void *) it;

            it = it->next;
            we_counters_free(si->set);
            free(si);
        }
        {
            const we_map_t *m = we_current(w->legacy_handle);

            if (m != NULL && m != w->thread_map) {
                we_ngx_set_item_t *si;

                we_ngx_write_legacy(w, w->thread_set, w->thread_map);
                si = calloc(1, sizeof *si);
                if (si != NULL) {
                    si->set = we_counters_new(m, (uint64_t) ngx_time() * 1000ull);
                    w->thread_set = si->set;
                    w->thread_map = m;
                    we_mod_list_post(&w->sets_to_loop, &si->link);
                    we_ngx_wake(w);
                }
            }
        }
        we_ngx_write_legacy(w, w->thread_set, w->thread_map);
    }
    we_ngx_write_files(w, tick);
}

/* the final write at the stop: what the loop counted since the last tick, then this process's own files */
static void we_ngx_final(void *ud, uint64_t tick, const int *stop)
{
    we_ngx_worker_t *w = ud;

    (void) stop;
    we_ngx_write_legacy(w, w->thread_set, w->thread_map);
    we_ngx_write_files(w, tick);
}

/* a worker's offset into the interval, from its own identity, so N workers never digest at one instant */
static uint64_t we_ngx_offset(const we_mod_procid_t *id, uint64_t interval_ms)
{
    const char *h = ((const we_procid_t *) id)->id16;
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8 && h[i] != '\0'; i++) {
        v = v * 16u + (uint64_t) (h[i] <= '9' ? h[i] - '0' : h[i] - 'a' + 10);
    }
    return interval_ms != 0 ? v % interval_ms : 0;
}

static ngx_int_t
ngx_http_whisper_edge_init_process(ngx_cycle_t *cycle)
{
    ngx_http_whisper_edge_main_conf_t *mcf;
    we_ngx_worker_t *w;
    we_mod_worker_args_t wa;
    char msg[1024];
    int rc;

    /* the cache manager and loader run every init_process and leave by exit(0): no thread, no files */
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        return NGX_OK;
    }
    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_whisper_edge_module);
    if (mcf == NULL || !mcf->has_binding || mcf->planes == NULL || g_worker != NULL) {
        return NGX_OK;
    }
    w = calloc(1, sizeof *w);
    if (w == NULL) {
        return NGX_ERROR;
    }
    w->planes = mcf->planes;
    w->planes_cfg = &mcf->cfg;
    w->legacy_handle = mcf->legacy ? mcf->cfg.handle[0] : NULL;
    w->efd = -1;
    w->cdir_fd = -1;
    w->stride = mcf->stride;
    w->started_ms = (uint64_t) ngx_time() * 1000ull;
    w->interval_ms = (uint64_t) mcf->refresh;
    if (we_mod_procid(&w->id) != 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "whisper edge: this process's identity could not be read from /proc; "
                      "its files are named by its pid alone");
    }
    w->offset_ms = we_ngx_offset(&w->id, w->interval_ms);
    w->client_header = mcf->trusted_header.len > 0;
    /* the ring's mutex, before anything that can log through it: the worker-start check below can */
    /* the worker's own counters: one array, line-aligned, this thread's alone (the sink when memory fails) */
    w->shard = aligned_alloc(64, (size_t) mcf->stride * 8u);
    if (w->shard == NULL) {
        w->shard = mcf->sink;
        w->no_shard = 1;
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "whisper edge: no memory for this worker's counters (%ud bytes); its "
                      "counts go to the sink and are lost (no-shard)", (unsigned) mcf->stride * 8u);
    } else {
        memset(w->shard, 0, (size_t) mcf->stride * 8u);
    }
    if (mcf->counters_dir.len > 0) {
        w->counters_dir = malloc(mcf->counters_dir.len + 1);
        if (w->counters_dir != NULL) {
            ngx_memcpy(w->counters_dir, mcf->counters_dir.data, mcf->counters_dir.len);
            w->counters_dir[mcf->counters_dir.len] = '\0';
            /* created here, before the first accept, so the directory is the workers' own */
            if (mkdir(w->counters_dir, 0755) != 0 && errno != EEXIST) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, errno, "whisper edge: cannot create the counters directory \"%s\"; "
                              "blocking is unaffected and whisper-edge-summary will have nothing to read", w->counters_dir);
            }
            /*
             * THE WRITERS' GROUND: one held descriptor every write is openat relative to, so a
             * replaced or renamed directory cannot send the writers elsewhere mid-process, and the
             * configuration's own bytes, name, digest and counter map are COPIED here into this process's
             * memory: a single-process reload frees the cycle pool the configuration's copies live in, and
             * this process keeps serving the first configuration until it exits, which its status file
             * says with the single-process-stale flag.
             * The file names come from this process's identity, so a reused pid never overwrites another
             * process's file; without an identity the names carry the pid alone.
             */
            w->cdir_fd = open(w->counters_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (w->cdir_fd < 0) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, errno, "whisper edge: cannot open the counters directory \"%s\"; "
                              "this worker writes no status, counter or configuration file there",
                              w->counters_dir);
            }
            if (mcf->conf_len > 0u) {
                uint32_t e, rules = 0u;
                size_t status_bound, rules_bound;

                w->conf_bytes = malloc(mcf->conf_len);
                if (mcf->nctrm > 0u) {
                    w->ctrmap_e = malloc((size_t) mcf->nctrm * sizeof *w->ctrmap_e);
                }
                w->snap = malloc((size_t) w->stride * 8u);
                w->status = malloc(sizeof *w->status);
                if (w->conf_bytes != NULL && w->snap != NULL && w->status != NULL
                    && (mcf->nctrm == 0u || w->ctrmap_e != NULL)) {
                    ngx_memcpy(w->conf_bytes, mcf->conf_bytes, mcf->conf_len);
                    w->conf_len = mcf->conf_len;
                    ngx_memcpy(w->conf_name, mcf->conf_name, sizeof w->conf_name);
                    ngx_memcpy(w->config16, mcf->config16, sizeof w->config16);
                    if (mcf->nctrm > 0u) {
                        ngx_memcpy(w->ctrmap_e, mcf->ctrmap, (size_t) mcf->nctrm * sizeof *w->ctrmap_e);
                    }
                    w->ctrmap.e = w->ctrmap_e;
                    w->ctrmap.n = mcf->nctrm;
                    for (e = 0u; e < w->ctrmap.n; e++) {
                        rules += w->ctrmap_e[e].rule_count;
                    }
                    /* one render buffer for both files, the status file's bound and the counters':
                     * a plane line's reason is escaped at most fourfold, a transition entry likewise */
                    status_bound = 2048u + 8u * 2048u + (size_t) WE_MOD_TRANSITIONS * (4u * WE_MOD_RING_ENTRY + 64u)
                                   + 256u;
                    rules_bound = 512u + 8u * 64u + (size_t) rules * 64u;
                    w->text_cap = status_bound > rules_bound ? status_bound : rules_bound;
                    w->text = malloc(w->text_cap);
                    if (w->text == NULL) {
                        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "whisper edge: no memory for this worker's render "
                                      "buffer; it writes no status or counter file (blocking is unaffected)");
                    }
                    if (w->id.id16[0] != '\0') {
                        snprintf(w->status_name, sizeof w->status_name, "%llu-%s.status",
                                 (unsigned long long) w->id.pid, w->id.id16);
                        snprintf(w->rules_name, sizeof w->rules_name, "%llu-%s.rules.cnt",
                                 (unsigned long long) w->id.pid, w->id.id16);
                    } else {
                        snprintf(w->status_name, sizeof w->status_name, "%llu.status",
                                 (unsigned long long) w->id.pid);
                        snprintf(w->rules_name, sizeof w->rules_name, "%llu.rules.cnt",
                                 (unsigned long long) w->id.pid);
                    }
                } else {
                    free(w->conf_bytes);
                    free(w->ctrmap_e);
                    free(w->snap);
                    free(w->status);
                    w->conf_bytes = NULL;
                    w->ctrmap_e = NULL;
                    w->snap = NULL;
                    w->status = NULL;
                    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "whisper edge: no memory for this worker's writers; it "
                                  "writes no status, counter or configuration file (blocking is unaffected)");
                }
            }
        }
    }
    /* the eventfd: one connection slot of worker_connections, read edge-triggered, never closed by its handler */
    w->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (w->efd >= 0) {
        ngx_connection_t *c = ngx_get_connection(w->efd, cycle->log);

        if (c != NULL) {
            c->data = w;
            c->read->handler = we_ngx_efd_read;
            c->read->log = cycle->log;
            c->write->log = cycle->log;
            if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_CLEAR_EVENT) == NGX_OK) {
                w->efd_conn = c;
            } else {
                c->fd = (ngx_socket_t) -1;
                ngx_free_connection(c);
            }
        }
        if (w->efd_conn == NULL) {
            close(w->efd);
            w->efd = -1;
        }
    }
    if (w->efd_conn == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, errno, "whisper edge: no eventfd for the module's thread; the loop applies "
                      "the thread's results at its own pace");
    }
    memset(&wa, 0, sizeof wa);
    wa.now_ms = w->started_ms;
    wa.interval_ms = w->interval_ms;
    wa.wake = w->efd_conn != NULL ? we_ngx_wake : NULL;
    wa.wake_ud = w;
    wa.log = we_ngx_worker_log;
    wa.log_ud = w;
    rc = we_mod_worker_start(w->planes, &wa, msg, sizeof msg);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "whisper edge: the worker-start check failed: %s (%s); serving with the "
                      "inherited planes", msg, we_mod_strerror(rc));
    }
    rc = we_mod_thread_start(&w->thread, w->interval_ms, w->offset_ms, we_ngx_tick, we_ngx_final, w, msg, sizeof msg);
    if (rc != 0) {
        /* the process line once, on this loop, before this process serves (3.3): no thread will write it,
         * and no counter file is written, so the counts this process serves are lost, said here once */
        w->no_thread = 1;
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "whisper edge: the module's thread could not be started: %s (%s); this "
                      "worker serves its inherited planes until each one's valid-until, writes its status line once and "
                      "no counter file, so its counts are lost (no-thread)", msg, we_mod_strerror(rc));
        we_ngx_write_status(w, 0u);
    }
    w->started = 1;
    g_worker = w;
    return NGX_OK;
}

/*
 * The stop: the eventfd detached from its connection and the connection freed (never closed: the thread may
 * still write the descriptor), then the core's bounded stop (we_mod_thread_stop_bounded): the thread is asked
 * to stop and waited for in windows of WE_MOD_STOP_WINDOW_MS (2 s), a window granted again while the thread
 * makes progress or is outside a plane job, a plane job that makes none abandoned in its window, and the
 * whole stop capped at WE_MOD_STOP_CAP_MS (6 s). On done the descriptor is closed; on an abandonment the line
 * names the stage the thread was in (we_mod_stage_text) and nothing it may write is touched. Nothing here
 * allocates, locks or joins.
 */
static void
ngx_http_whisper_edge_exit_process(ngx_cycle_t *cycle)
{
    we_ngx_worker_t *w = g_worker;

    (void) cycle;
    if (w == NULL || !w->started) {
        return;
    }
    if (w->efd_conn != NULL) {
        ngx_del_event(w->efd_conn->read, NGX_READ_EVENT, 0);
        w->efd_conn->fd = (ngx_socket_t) -1;
        ngx_free_connection(w->efd_conn);
        w->efd_conn = NULL;
    }
    /* the core's bounded stop: granted again while the thread makes progress or is outside a plane job, a
     * stuck plane read abandoned in its window, any stop capped at 6 s; the stage names what was lost */
    if (w->thread != NULL) {
        uint32_t stage = WE_MOD_STAGE_WAIT;

#ifndef WE_MOD_TEST_NGX_FLAT_STOP
        if (we_mod_thread_stop_bounded(w->thread, &stage) != 0) {
            w->abandoned = 1;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "whisper edge: the module's thread did not stop and is "
                          "abandoned%s; the counts since its last write are lost", we_mod_stage_text(stage));
            return;
        }
#else
        (void) stage;
        if (we_mod_thread_stop(w->thread, 2000) != 0) {    /* the control: the flat 2 s stop, no stage */
            w->abandoned = 1;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "whisper edge: the module's thread did not stop within 2 s "
                          "and is abandoned; the counts since its last write are lost");
            return;
        }
#endif
    }
    if (w->efd >= 0) {
        close(w->efd);
        w->efd = -1;
    }
}

/* ---- the request path ------------------------------------------------------------------------------ */

/* the socket address as the core reads it: canonical (an IPv4-mapped IPv6 unmapped); 0 for no address */
static int we_ngx_addr(const struct sockaddr *sa, we_addr_t *out)
{
    uint8_t b[16];

    memset(out, 0, sizeof *out);
    if (sa == NULL) {
        return 0;
    }
    if (sa->sa_family == AF_INET) {
        memset(b, 0, sizeof b);
        memcpy(b, &((const struct sockaddr_in *) sa)->sin_addr, 4);
        we_addr_canon(b, 4, out);
        return 1;
    }
#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        memcpy(b, ((const struct sockaddr_in6 *) sa)->sin6_addr.s6_addr, 16);
        we_addr_canon(b, 6, out);
        return 1;
    }
#endif
    return 0;
}

/* the identity marker of the per-request node's pool cleanup: it does nothing, and names the node */
WE_NGX_HANDLER void ngx_http_whisper_edge_node_cleanup(void *data)
{
    (void) data;
}

/* the main request's node: the module context, or, after an internal redirect zeroed r->ctx, the cleanup */
static we_ngx_node_t *we_ngx_node(ngx_http_request_t *r)
{
    ngx_http_request_t *m = r->main;
    we_ngx_node_t *node = ngx_http_get_module_ctx(m, ngx_http_whisper_edge_module);
    ngx_pool_cleanup_t *cln;

    if (node != NULL) {
        return node;
    }
    for (cln = m->pool->cleanup; cln != NULL; cln = cln->next) {
        if (cln->handler == ngx_http_whisper_edge_node_cleanup) {
            ngx_http_set_ctx(m, cln->data, ngx_http_whisper_edge_module);
            return cln->data;
        }
    }
    return NULL;
}

/* a node for a main request that has none yet, with its peer captured and judged by the walk */
static we_ngx_node_t *we_ngx_node_make(ngx_http_request_t *r, ngx_http_whisper_edge_main_conf_t *mcf)
{
    ngx_http_request_t *m = r->main;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(m->pool, sizeof(we_ngx_node_t));
    we_ngx_node_t *node;

    if (cln == NULL) {
        return NULL;
    }
    node = cln->data;
    memset(node, 0, sizeof *node);
    cln->handler = ngx_http_whisper_edge_node_cleanup;
    ngx_http_set_ctx(m, node, ngx_http_whisper_edge_module);
    node->has_peer = (uint8_t) we_ngx_addr(m->connection->sockaddr, &node->peer);
    /*
     * THE HEADER PASS, only when the header is configured and the peer is trusted (an untrusted peer visits
     * nothing): one pass over the lines nginx accepted, nginx's own hash and the length compared before the
     * bytes, each matching line stored at `count mod 16` of a ring, so the walk gets the newest sixteen in
     * arrival order and knows whether older ones existed. An untrusted peer, or no header, judges the peer.
     */
    {
        we_mod_line_t ring[WE_MOD_WALK_LINES], lines[WE_MOD_WALK_LINES];
        uint32_t count = 0, n = 0, searches = 0;
        int older = 0;

        if (mcf->trusted_header.len > 0
                && (node->has_peer ? we_mod_trusted(&mcf->trust, &node->peer, &searches) : mcf->trust.unix_ok != 0)) {
            ngx_list_part_t *part = &m->headers_in.headers.part;
            ngx_table_elt_t *h = part->elts;
            ngx_uint_t i;

            for (i = 0; /* void */; i++) {
                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }
                    part = part->next;
                    h = part->elts;
                    i = 0;
                }
                if (h[i].hash == mcf->trusted_header_hash && h[i].key.len == mcf->trusted_header.len
                        && ngx_strncasecmp(h[i].key.data, mcf->trusted_header.data, mcf->trusted_header.len) == 0) {
#ifdef WE_MOD_TEST_RING_OLDEST
                    if (count >= WE_MOD_WALK_LINES) {
                        continue;                    /* the control: the oldest sixteen kept, not the newest */
                    }
#endif
                    ring[count % WE_MOD_WALK_LINES].p = h[i].value.data;
                    ring[count % WE_MOD_WALK_LINES].len = h[i].value.len;
                    count++;
                }
            }
            if (count <= WE_MOD_WALK_LINES) {
                n = count;
                memcpy(lines, ring, n * sizeof lines[0]);
            } else {
                uint32_t start = count % WE_MOD_WALK_LINES;

                n = WE_MOD_WALK_LINES;
                older = 1;
                for (i = 0; i < n; i++) {
                    lines[i] = ring[(start + i) % WE_MOD_WALK_LINES];
                }
            }
        }
        we_mod_walk(&mcf->trust, (uint32_t) mcf->trusted_hops, mcf->trusted_header.len > 0,
                    node->has_peer ? &node->peer : NULL, n > 0 ? lines : NULL, n, older, &node->walk);
    }
    return node;
}

/*
 * POST_READ: the TCP peer captured before any module could rewrite it (realip rewrites c->sockaddr in its
 * own handler, which runs after this one), and the walk run once per main request. A subrequest and an
 * internal redirect never come through here: a redirect re-enters at the server rewrite phase.
 */
WE_NGX_HANDLER ngx_int_t ngx_http_whisper_edge_post_read(ngx_http_request_t *r)
{
    ngx_http_whisper_edge_main_conf_t *mcf;

    WE_NGX_ENTER();
    if (r == r->main) {
        mcf = ngx_http_get_module_main_conf(r, ngx_http_whisper_edge_module);
        if (mcf != NULL && mcf->has_binding) {
            (void) we_ngx_node_make(r, mcf);
        }
    }
    WE_NGX_EXIT();
    return NGX_DECLINED;
}

/* THE WRAPPER every evaluation site calls: the module gate disassembles exactly this symbol */
WE_NGX_WRAPPER void ngx_http_whisper_edge_decide(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s,
                                                 uint64_t *shard, const we_mod_req_t *req, uint64_t now_ms)
{
    we_mod_decide(c, x, s, shard, req, now_ms);
}

/* `Cache-Control: no-store` on every deny, whatever the status: a deny depends on the client's address,
 * which no cache keys on */
static ngx_int_t we_ngx_no_store(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Cache-Control");
    ngx_str_set(&h->value, "no-store");
#if (nginx_version >= 1023000) || defined(WE_MOD_TEST_NGX_LIST_ONLY)   /* the control: the 1.23 path only */
    /* nginx 1.23 and later: the response's Cache-Control lines are a list chained through `next` */
    h->next = NULL;
    if (r->headers_out.cache_control == NULL) {
        r->headers_out.cache_control = h;
    } else {
        ngx_table_elt_t *t = r->headers_out.cache_control;

        while (t->next != NULL) {
            t = t->next;
        }
        t->next = h;
    }
#else
    /* before 1.23 (RHEL 9 ships 1.20.1): an array of pointers to the lines, which nginx's own headers filter
     * creates on the request's pool when it first adds one, as here */
    {
        ngx_table_elt_t **cc;

        if (r->headers_out.cache_control.elts == NULL
                && ngx_array_init(&r->headers_out.cache_control, r->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK) {
            return NGX_ERROR;
        }
        cc = ngx_array_push(&r->headers_out.cache_control);
        if (cc == NULL) {
            return NGX_ERROR;
        }
        *cc = h;
    }
#endif
    return NGX_OK;
}

/* did the context's program run for this verdict (not a pre-stage step, not the floor, not mode off)? */
static int we_ngx_ctx_ran(const we_verdict_t *v, const we_mod_ctx_t *x)
{
    return v->step == WE_STEP_CONTEXT && x->prog != NULL && we_conf_mode(&x->conf) != WE_MODE_OFF;
}

/* the record, allocated from the main request's pool when a variable first needs one, keyed to the server address */
static we_mod_record_t *we_ngx_record(ngx_http_request_t *r, ngx_http_whisper_edge_main_conf_t *mcf, we_ngx_node_t *node)
{
    if (node->record == NULL) {
        void *raw = ngx_palloc(r->main->pool, WE_MOD_RECORD_ALLOC);
        const we_mod_ctx_t *x = node->ctx;

        if (raw == NULL) {
            return NULL;
        }
        if (x == NULL) {
            ngx_http_whisper_edge_loc_conf_t *lcf = ngx_http_get_module_loc_conf(r, ngx_http_whisper_edge_module);

            x = lcf->ctx != NULL ? lcf->ctx : &mcf->ctxs[0];
        }
        node->record = we_mod_record_at(raw);
        we_mod_record_init(node->record, x);
    }
    if (node->record->slot.key_valid == 0u) {
        we_addr_t server;

        if (we_ngx_addr(r->connection->sockaddr, &server)) {
            we_mod_record_key(node->record, &server);
        }
    }
    return node->record;
}

/*
 * The verdict the deny and WOULD DENY lines print: the core's renderer over the request's record, spelled
 * `,spamhaus-drop`, so the line is byte-identical on every server for one listing (POLICY.md's rendering
 * section; the shipped deny lines of nginx and Apache both spelled the flag so). Cold and rate-limited with
 * the line. When a variable keeps a record the frame wrote it already; when none does, the record is
 * written on this cold frame and never on the node, so a run-time fetch still reads what row V9 says it
 * reads, whether or not this second's line was written.
 */
static __attribute__((noinline, cold)) const char *
we_ngx_log_verdict(ngx_http_whisper_edge_main_conf_t *mcf, const we_ngx_node_t *node, const we_mod_ctx_t *x,
                   const we_mod_scratch_t *s, const we_addr_t *server)
{
    we_mod_record_t tmp __attribute__((aligned(64)));

    if (node->record != NULL) {
        return we_mod_render_verdict(node->record, WE_MOD_SPELL_SPAMHAUS);
    }
    ngx_memzero(&tmp, sizeof tmp);
    (void) we_mod_record_write(&tmp, &mcf->cfg, x, s, &node->walk.floor, server);
    return we_mod_render_verdict(&tmp, WE_MOD_SPELL_SPAMHAUS);
}

/*
 * THE DECISION FRAME: a noinline function of its own so the 1,024-byte scratch lives on a frame no header
 * walk shares, called once per evaluation. It builds the request, calls the one wrapper, and then, outside
 * the gated function: writes the record when a variable needs one, counts the legacy copy's range, writes
 * the rate-limited log line, and turns an enforced deny into the response.
 */
static __attribute__((noinline)) ngx_int_t
we_ngx_decide_frame(ngx_http_request_t *r, ngx_http_whisper_edge_main_conf_t *mcf, we_ngx_worker_t *w,
                    we_ngx_node_t *node, const we_mod_ctx_t *x, const we_addr_t *server, int acme)
{
    we_mod_scratch_t s;
    we_mod_req_t req;
    ngx_time_t *tp = ngx_timeofday();
    uint64_t now = (uint64_t) tp->sec * 1000ull + (uint64_t) tp->msec;
    uint64_t *shard = w != NULL && !mcf->stale_single ? w->shard : mcf->sink;
    uint32_t sev;
    int floor_decided;

    /* the record, before the decision, when a variable or an export will read it (a read before the
     * decision allocated it already); none otherwise: the node keeps the compact fields */
    if (mcf->want_record && node->record == NULL) {
        (void) we_ngx_record(r, mcf, node);
    }
    we_mod_req_build(&req, &node->walk, server, acme);
    ngx_http_whisper_edge_decide(&mcf->cfg, x, &s, shard, &req, now);

    sev = we_mod_severity(&mcf->cfg, x, &s.v);
    node->decided = 1;
    node->ctx = x;
    node->step = s.v.step;
    node->action = s.v.action;
    node->program = s.v.program;
    node->reason = s.v.reason;
    node->marks = s.v.marks;
    node->rule = s.v.rule;
    node->severity = (uint8_t) sev;
    if (node->record != NULL) {
        we_mod_record_write(node->record, &mcf->cfg, x, &s, &node->walk.floor, server);
    }
    floor_decided = s.v.program == WE_VPROG_FLOOR || s.v.step != WE_STEP_CONTEXT;
    if (sev == 0) {
        return NGX_DECLINED;
    }
    /* a deny or a would-deny: the judged address's slot is the floor's for a floor decision, the server's
     * otherwise; the log line reads it, and the legacy copy's per-range counters count BOTH. The core's
     * contract counts after the verdict, on the path that writes the log line (under mode log the WOULD DENY
     * line), every released module counted before the mode test, and Apache and OpenLiteSpeed count both:
     * the same traffic is the same number on every server, which the summary's headline reports as requests
     * denied (a would-deny under mode log was allowed, and is counted all the same) */
    {
        const we_memo_slot_t *ss = s.v.program == WE_VPROG_FLOOR ? &s.e.slot[0]
                                   : (s.v.step != WE_STEP_EXEMPT && s.v.step != WE_STEP_TENANT && s.v.sc.ss != NULL
                                      ? (const we_memo_slot_t *) s.v.sc.ss : &s.e.slot[0]);
        const we_addr_t *judged = s.v.program == WE_VPROG_FLOOR ? &node->walk.floor : server;
        const we_map_t *view = s.e.view[0].m;
        const char *program = we_ngx_ctx_ran(&s.v, x) ? x->cold->program_ctx : x->cold->program_floor;
        const char *rule = "-", *ev = NULL;
        char addr[WE_ADDR_TEXT_MAX];

#ifndef WE_MOD_TEST_COUNT_ENFORCED_ONLY
        if (w != NULL && w->legacy != NULL && view != NULL && ss->state[0] == WE_ST_FRESH_HIT) {
#else
        if (sev == 2u && w != NULL && w->legacy != NULL && view != NULL && ss->state[0] == WE_ST_FRESH_HIT) {   /* the control */
#endif
            if (judged->family == 4u) {
                we_counters_count4(w->legacy, view, (uint32_t) judged->b[0] << 24 | (uint32_t) judged->b[1] << 16
                                   | (uint32_t) judged->b[2] << 8 | judged->b[3]);
            } else if (judged->family == 6u) {
                we_counters_count6(w->legacy, view, judged->b);
            }
        }
        if (s.v.rule != 0u) {
            const char *const *tab = s.v.program == WE_VPROG_FLOOR ? mcf->cfg.cold->rule_text : x->cold->rule_text;
            uint32_t n = s.v.program == WE_VPROG_FLOOR ? mcf->cfg.cold->rule_count : x->cold->rule_count;

            rule = tab != NULL && s.v.rule <= n ? tab[s.v.rule - 1u] : "-";
        }
        if (view != NULL && ss->state[0] == WE_ST_FRESH_HIT) {
            /* the listing's citable evidence, either family, as Apache's and OpenLiteSpeed's lines read it */
            if (judged->family == 4u) {
                ev = we_evidence4(view, (uint32_t) judged->b[0] << 24 | (uint32_t) judged->b[1] << 16
                                  | (uint32_t) judged->b[2] << 8 | judged->b[3]);
            } else if (judged->family == 6u) {
                ev = we_evidence6(view, judged->b);
            }
        }
        we_addr_format(judged, addr);
        /* RATE-LIMITED: one line per second per outcome per worker, carrying what it suppressed, so a flood
         * from listed space cannot turn the module's own logging into the attack */
        if (sev == 1u) {
            if (w != NULL) {
                w->would_deny++;
            }
            if (w == NULL || ngx_time() != w->last_would_log) {
                ngx_log_error(WE_NGX_DENY_LEVEL, r->connection->log, 0,
                              "whisper edge: WOULD DENY %s, rule %ud \"%s\" of %s, verdict %s, evidence %s (mode is log, request "
                              "allowed; %ui would-deny so far, %ui since the last line)", addr, (unsigned) s.v.rule, rule,
                              program, we_ngx_log_verdict(mcf, node, x, &s, server), ev != NULL ? ev : "none carried",
                              w != NULL ? w->would_deny : 0, w != NULL ? w->would_deny - w->would_deny_at_last_log : 0);
                if (w != NULL) {
                    w->last_would_log = ngx_time();
                    w->would_deny_at_last_log = w->would_deny;
                }
            }
            return NGX_DECLINED;
        }
        if (w != NULL) {
            w->denied++;
        }
        if (w == NULL || ngx_time() != w->last_deny_log) {
            ngx_log_error(WE_NGX_DENY_LEVEL, r->connection->log, 0,
                          "whisper edge: denied %s, rule %ud \"%s\" of %s, verdict %s, evidence %s (%ui denied so far, %ui since "
                          "the last line)", addr, (unsigned) s.v.rule, rule, program, we_ngx_log_verdict(mcf, node, x, &s, server),
                          ev != NULL ? ev : "none carried", w != NULL ? w->denied : 0,
                          w != NULL ? w->denied - w->denied_at_last_log : 0);
            if (w != NULL) {
                w->last_deny_log = ngx_time();
                w->denied_at_last_log = w->denied;
            }
        }
    }
    /* the deny: the http level's status for the floor and the pre-stage, the context's for its own rules;
     * a floor deny bypasses error_page, so its body is the server's own built-in page; 444 closes */
    {
        ngx_uint_t status = floor_decided ? mcf->cfg.floor_status : x->deny_status;

        if (status == 444) {
            return NGX_HTTP_CLOSE;
        }
#ifndef WE_MOD_TEST_NO_STORE_OFF
        if (we_ngx_no_store(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
#else
        (void) we_ngx_no_store;      /* the control: the deny goes out without no-store, and the cache in front keeps it */
#endif
#ifndef WE_MOD_TEST_FLOOR_ERROR_PAGE
        if (floor_decided) {
            r->error_page = 1;
        }
#else
        (void) floor_decided;        /* the control: a floor deny reaches error_page like a context deny */
#endif
        return (ngx_int_t) status;
    }
}

/*
 * PREACCESS, last in the phase: every main request and every internal redirect decides; a subrequest never
 * does (nginx skips subrequests in the access phase, not here, so the compare is the module's own).
 */
WE_NGX_HANDLER ngx_int_t ngx_http_whisper_edge_preaccess(ngx_http_request_t *r)
{
    ngx_http_whisper_edge_loc_conf_t *lcf;
    ngx_http_whisper_edge_main_conf_t *mcf;
    we_ngx_node_t *node;
    we_addr_t server;
    ngx_int_t rc = NGX_DECLINED;
    size_t tlen;
    int acme;

    WE_NGX_ENTER();
    if (r != r->main) {
        WE_NGX_EXIT();
        return NGX_DECLINED;
    }
    mcf = ngx_http_get_module_main_conf(r, ngx_http_whisper_edge_module);
    if (mcf == NULL || !mcf->has_binding) {
        WE_NGX_EXIT();
        return NGX_DECLINED;
    }
    node = we_ngx_node(r);
    if (node == NULL) {
        node = we_ngx_node_make(r, mcf);
        if (node == NULL) {
            WE_NGX_EXIT();
            return NGX_DECLINED;             /* no pool memory: fail open */
        }
    }
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_whisper_edge_module);
#ifdef WE_MOD_TEST_MODE_OFF_RETURN
    if (lcf->mode == WE_MODE_OFF) {
        return NGX_DECLINED;             /* the control: the shipped module's early return, which the floor never reached */
    }
#endif
    (void) we_ngx_addr(r->connection->sockaddr, &server);   /* the server's own address, after its realip */
    /* ACME HTTP-01: the request-target as received up to its first `?` is the raw path; r->uri the normalised */
    for (tlen = 0; tlen < r->unparsed_uri.len && r->unparsed_uri.data[tlen] != '?'; tlen++) {
    }
    acme = we_mod_acme(r->method_name.data, r->method_name.len, r->unparsed_uri.data,
                       tlen < r->unparsed_uri.len ? r->unparsed_uri.len : tlen, r->uri.data, r->uri.len);
    rc = we_ngx_decide_frame(r, mcf, g_worker, node, lcf->ctx != NULL ? lcf->ctx : &mcf->ctxs[0], &server, acme);
    WE_NGX_EXIT();
    return rc;
}

/* ---- the variables ---------------------------------------------------------------------------------- */

/* a rendered string into the request pool, for the three variables that are not static text */
static ngx_int_t we_ngx_var_copy(ngx_http_request_t *r, ngx_http_variable_value_t *v, const char *text, size_t len)
{
    u_char *d = ngx_pnalloc(r->pool, len);

    if (d == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(d, text, len);
    v->data = d;
    v->len = (unsigned) len;
    return NGX_OK;
}

/*
 * THE VARIABLES' HANDLER. Every value renders when it is read: an attribute from the record's entry for the
 * server's address, filled lazily (through one local scratch) when the decision did not read its plane;
 * the decision's words from the record the decision wrote, or, for a request judged with no record (no
 * static reference in the configuration), from the node's compact fields copied into a record on first
 * read, so an njs or SSI fetch by name renders the decision taken and never `-`; the bitmaps are then not
 * recoverable, so $whisper_edge_logged says unknown. Before the decision the words render `-`, the
 * attributes fill lazily, and the floor's address is the walk's. A subrequest reads its main request's.
 */
WE_NGX_HANDLER ngx_int_t ngx_http_whisper_edge_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                                                        uintptr_t data)
{
    ngx_http_whisper_edge_main_conf_t *mcf;
    we_ngx_node_t *node = NULL;
    we_mod_record_t *rec = NULL;
    const char *word;
    size_t len;
    ngx_int_t rc = NGX_OK;
    int text = data < WE_MOD_ATTRS || data == WE_NGX_VAR_VERDICT;

    WE_NGX_ENTER();
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_whisper_edge_module);
    if (mcf != NULL && mcf->has_binding) {
        node = we_ngx_node(r);
        if (node == NULL) {
            node = we_ngx_node_make(r, mcf);
        }
        rec = node != NULL ? we_ngx_record(r, mcf, node) : NULL;
    }
    if (rec == NULL) {
        /* no binding, or no pool memory: the attributes and the verdict are unknown, the words absent */
        word = text ? "unknown" : "-";
        v->data = (u_char *) word;
        v->len = (unsigned) ngx_strlen(word);
        WE_NGX_EXIT();
        return NGX_OK;
    }
    if (node->decided && !rec->decided) {
        rec->step = node->step;
        rec->action = node->action;
        rec->program = node->program;
        rec->reason = node->reason;
        rec->marks = node->marks;
        rec->rule = node->rule;
        rec->severity = node->severity;
        rec->decided = 1u;
        rec->ctx = node->ctx;
        rec->floor = node->walk.floor;
        node->synth = 1u;
    }
    {
        we_mod_scratch_t local;
        ngx_time_t *tp = ngx_timeofday();
        uint64_t now = (uint64_t) tp->sec * 1000ull + (uint64_t) tp->msec;
        char out[WE_MOD_LOGGED_MAX];

        switch (data) {
        case WE_NGX_VAR_VERDICT:
            we_mod_fill(rec, &mcf->cfg, &local, 1u, now);
            word = we_mod_render_verdict(rec, WE_MOD_SPELL_NGINX);
            break;
        case WE_NGX_VAR_ACTION:
            word = we_mod_render_action(rec);
            break;
        case WE_NGX_VAR_REASON:
            word = we_mod_render_reason(rec, node->walk.walk, node->walk.note);
            break;
        case WE_NGX_VAR_RULE_ID:
            word = we_mod_render_rule(rec, &mcf->cfg, 0);
            break;
        case WE_NGX_VAR_RULE:
            word = we_mod_render_rule(rec, &mcf->cfg, 1);
            break;
        case WE_NGX_VAR_PROGRAM:
            word = we_mod_render_program(rec, &mcf->cfg);
            break;
        case WE_NGX_VAR_LOGGED:
            if (node->synth) {
                word = "unknown";
                break;
            }
            len = we_mod_render_logged(rec, out);
            rc = we_ngx_var_copy(r, v, out, len);
            word = NULL;
            break;
        case WE_NGX_VAR_GENERATIONS:
            we_mod_fill(rec, &mcf->cfg, &local, rec->ctx != NULL ? rec->ctx->gen_mask : mcf->ctxs[0].gen_mask, now);
            len = we_mod_render_generations(rec, out);
            rc = we_ngx_var_copy(r, v, out, len);
            word = NULL;
            break;
        case WE_NGX_VAR_FLOOR_ADDR:
            if (node->walk.floor.family == 0u) {
                word = "-";
                break;
            }
            len = we_addr_format(&node->walk.floor, out);
            rc = we_ngx_var_copy(r, v, out, len);
            word = NULL;
            break;
        default: {
            const we_mod_attr_t *a = we_mod_attr((uint32_t) data);

            if (a == NULL) {
                word = "unknown";
                break;
            }
            we_mod_fill(rec, &mcf->cfg, &local, 1u << a->plane, now);
            if (we_mod_render_attr(rec, (uint32_t) data, &word, &len) != 0) {
                word = "unknown";
                break;
            }
            v->data = (u_char *) word;
            v->len = (unsigned) len;
            word = NULL;
            break;
        }
        }
        if (word != NULL) {
            v->data = (u_char *) word;
            v->len = (unsigned) ngx_strlen(word);
        }
    }
    WE_NGX_EXIT();
    return rc;
}
