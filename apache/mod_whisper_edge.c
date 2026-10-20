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
 * mod_whisper_edge.c - the Apache httpd module over the edge policy core.
 *
 * The module speaks the policy language. Every directive below is recorded while httpd parses its
 * configuration and compiled ONCE, in check_config, by the core's compiler (we_policy_build): the
 * floor, every context's rules, the sets, and the old directives as sugar over the same program. A
 * refusal is a configuration error, so `apachectl configtest` refuses exactly what the server would
 * refuse. The request path then calls ONE function, the core's we_mod_decide(), through one wrapper of
 * this file's own (apache_whisper_edge_decide), from every place it evaluates: the access checker and
 * the two fixups functions. Nothing on that path allocates, locks or makes a system call of this
 * module's own except on two counted, cold, first-request branches (the thread's counter shard, and
 * the per-range sub-block that follows a legacy snapshot publish), each a symbol of its own that the
 * gate disassembles.
 *
 * THE TWO PROPERTIES THE MODULE EXISTS TO PRESERVE.
 *
 * 1. It defaults to NOT BLOCKING. With no mode directive a context runs `deny if listed >= high`
 *    under mode `log`: the verdict it WOULD have acted on is written to the error log and the notes,
 *    and nothing is denied until somebody writes `deny`.
 *
 * 2. THE DECISION makes no syscall, takes no lock and allocates nothing: the view pointers of the
 *    planes the two programs read, the evaluator, and relaxed counts into the calling thread's own
 *    shard. The claim is about the decision; the handler around it writes a log line on a fired rule
 *    and the notes, and both cost what any Apache log line and note cost.
 *
 * WHAT IS APACHE-SPECIFIC, AND WHY.
 *
 * - THE FLOOR JUDGES THE SOCKET'S PEER. The primary connection's remote address, reached through
 *   c->master for an HTTP/2 stream (a secondary connection's socket is one never-connected dummy),
 *   read from the socket itself so that no module rewriting the connection's address can choose the
 *   floor's; a trusted proxy is honoured through the module's own http-level directives
 *   (WhisperEdgeTrustedProxy and WhisperEdgeTrustedHeader) and never through mod_remoteip, whose
 *   trust list a virtual host can redefine. The raw header is snapshotted in post_read_request at
 *   APR_HOOK_REALLY_FIRST, before mod_remoteip and mod_headers rewrite it, on the first request of a
 *   chain only (2.4.58 runs post_read_request again on an internal redirect, over a header table
 *   those modules have already edited). The context's rules judge r->useragent_addr, the server's
 *   own realip result, exactly as the nginx module judges the address its realip left.
 *
 * - THE DECISION IS IN access_checker AT APR_HOOK_FIRST, so under `Satisfy All` a deny ends the
 *   request before authentication; a fixups function at APR_HOOK_REALLY_FIRST evaluates a redirect
 *   hop whose access checker httpd skipped and enforces a deny that `Satisfy Any` voted away, and one
 *   at APR_HOOK_REALLY_LAST evaluates once more when mod_dir or mod_negotiation adopted a candidate
 *   (moved per_dir_config and uri) and enforces that. A subrequest is never evaluated: every hook
 *   returns DECLINED at once when r->main is set.
 *
 * - EVERY MPM. The counters are sharded per OS thread (prefork, worker, event and mod_http2's workers
 *   alike), allocated on a thread's first judged request and folded into a per-child retired total
 *   when the thread ends. The module's own thread per child runs the planes' verification, applies
 *   the results (on Apache the refresher IS the planes' writer, so the handoff is zero) and writes the
 *   status and counter files; it is a raw detached pthread with malloc'd state, stopped from a
 *   pre-cleanup on the child pool by an atomic flag, a pipe write and a bounded poll, which is what
 *   prefork's signal handler permits. The parent verifies and maps the planes once, in post_config,
 *   so children start armed.
 *
 * A child that cannot bind a plane serves normally and says so once. There is no configuration, and
 * no failure, that makes this module deny on absent or unreadable data.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"
#include "ap_config.h"
#include "ap_expr.h"
#include "ap_mpm.h"
#include "mpm_common.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "unixd.h"

#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(WE_MOD_TEST_SHARD_OWNER) || defined(WE_MOD_TEST_MPM_SLOT)
#include <sys/syscall.h>          /* the trap controls' tid read: SYS_gettid */
#endif
#ifdef WE_MOD_TEST_MPM_SLOT
#include "scoreboard.h"           /* the control's wrong key: the MPM slot the connection's handle names */
#endif
#if defined(WE_MOD_TEST_RANGES_UNCHECKED) && !defined(WE_MOD_CONTROL_BUILD)
#error "WE_MOD_TEST_RANGES_UNCHECKED exists only in a gate's control build (WE_MOD_CONTROL_BUILD)"
#endif
#if (defined(WE_MOD_TEST_PID_ONLY_NAMES) || defined(WE_MOD_TEST_FOLD_IN_SERVER) || defined(WE_MOD_TEST_MU_FLAG) \
        || defined(WE_MOD_TEST_LOCKED_WRITE) || defined(WE_MOD_TEST_PLANT_FRAME)) && !defined(WE_MOD_CONTROL_BUILD)
#error "WE_MOD_TEST_PID_ONLY_NAMES, WE_MOD_TEST_FOLD_IN_SERVER, WE_MOD_TEST_MU_FLAG, WE_MOD_TEST_LOCKED_WRITE and WE_MOD_TEST_PLANT_FRAME exist only in a gate's control build"
#endif
#if defined(WE_MOD_TEST_MU_FLAG) || defined(WE_MOD_TEST_SHARD_OWNER) || defined(WE_MOD_TEST_MPM_SLOT)
#include <sys/syscall.h>
#endif
#ifdef WE_MOD_TEST_MU_FLAG
#include <time.h>
#include "http_main.h"            /* ap_server_conf, for the registration-wait line */
#endif
#ifdef WE_MOD_TEST_FOLD_IN_SERVER
#include <dirent.h>
#endif

#include "we_module.h"
#include "we_procid.h"

module AP_MODULE_DECLARE_DATA whisper_edge_module;

#ifdef WE_MOD_DEBUG
/* THE DEBUG BUILD: the core's debug counters and checks on (WE_MOD_DEBUG), built by apache-gate.sh for its M3 row
 * and nothing else; build.sh never defines it and nothing ships it. The marker lets the gate tell the two objects
 * apart by their bytes, and every child says what it is at start */
__attribute__((used, visibility("default"))) const char we_mod_debug_build[] = "whisper edge: the WE_MOD_DEBUG build";
#endif

#define WE_DEFAULT_REFRESH_SEC 60
#define WE_DEFAULT_DENY_STATUS 403u
#define WE_SERVER_WORD AP_SERVER_BASEVERSION

/* the cold functions the gate pins as symbols of their own (noinline, hidden; gcc also noclone, noipa) */
#if defined(__clang__)
#define WE_COLD_SYMBOL __attribute__((noinline, cold, visibility("hidden")))
#else
#define WE_COLD_SYMBOL __attribute__((noinline, noclone, noipa, cold, visibility("hidden")))
#endif
/* the one decide wrapper, kept as one symbol with no clone: what the gate disassembles */
#if defined(WE_MOD_TEST_DECIDE_INLINED)
#define WE_DECIDE_SYMBOL __attribute__((always_inline)) inline   /* the control: the evaluation inlined into its caller */
#elif defined(__clang__)
#define WE_DECIDE_SYMBOL __attribute__((noinline, used))
#else
#define WE_DECIDE_SYMBOL __attribute__((noinline, noipa, used))
#endif

/* ---------------------------------------------------------------------------------------------- */
/* The directives: kinds, names, and what is recorded                                               */
/* ---------------------------------------------------------------------------------------------- */

/* the compiler's kinds are WE_DIR_* (1..6); the module's own follow */
#define WE_LINE_DENY_STATUS    10u
#define WE_LINE_EXPORT         11u
#define WE_LINE_DATA           12u
#define WE_LINE_SNAPSHOT       13u
#define WE_LINE_TRUSTED_PROXY  14u
#define WE_LINE_TRUSTED_HEADER 15u
#define WE_LINE_TRUSTED_HOPS   16u
#define WE_LINE_REFRESH        17u
#define WE_LINE_SUMMARY        18u
#define WE_LINE_KINDS          19u

/* one recorded directive, in file order */
typedef struct {
    uint8_t     kind;
    const char *name;         /* the directive as written (CamelCase or snake_case) */
    const char *arg;          /* the argument bytes the compiler sees (one surrounding quote pair removed) */
    size_t      len;
    const char *file;         /* cmd->directive->filename */
    int         line;
    const char *use_file;     /* the file being read when the directive ran (a mod_macro use site) */
    int         http;         /* 1: http level (the main server, outside every section) */
    void       *dirv;         /* the section's we_dir_conf_t */
} we_line_t;

typedef struct {
    const char *file;
    int         line;
} we_place_t;

/* the per-child lifecycle state, declared below */
struct we_child;

/* the configuration build: everything the request path and the child read, pconf lifetime */
typedef struct {
    we_mod_arena_t     *arena;
    we_mod_cfg_t        cfg;
    we_mod_ctx_t       *ctxs;
    size_t              nctx;
    uint32_t            stride;
    we_mod_trust_t      trust;
    int                 trust_ok;
    uint32_t            hops;
    const char         *header;     /* WhisperEdgeTrustedHeader, or NULL */
    size_t              header_len;
    we_mod_planes_t    *planes;     /* bound in post_config (the real pass), NULL under configtest */
    const char         *data_dir;
    const char         *snapshot;
    const char         *plane_file[8];   /* WhisperEdgeData <plane> <file>: the plane's own file, over the directory */
    const char         *legacy;     /* the snapshot when it is the one data directive (the legacy copy), else NULL */
    const char         *unreadable[8];   /* the configuration file's unreadable notes, kept for the post-bind render */
    const char         *refused[8];      /* each plane refused at configuration, with its reason and fix */
    const char         *counters_dir;
    int                 counters_off;
    uint64_t            interval_ms;
    char                config16[17];
    char                conf_name[29];
    char               *conf_text;  /* the conf-<16 hex>.status file's bytes */
    size_t              conf_len;
    we_mod_ctrmap_t     ctrmap;
    uint32_t           *attr_mask;  /* per ctx: the attributes its export pass writes (25 bits) */
    uint32_t           *env_mask;   /* per ctx: the attributes also copied into subprocess_env */
    uint32_t            http_ctx;   /* the index of the http context in ctxs */
    uint8_t             bound_before_fork;
    uint8_t             mod_cache_loaded;
    uint8_t             proxy_protocol_seen;
} we_build_t;

/* per server_rec; the base server's carries the http level and the build */
typedef struct {
    apr_array_header_t *lines;       /* we_line_t, file order (base only) */
    we_place_t          first[WE_LINE_KINDS];   /* the first http-level definition per single-valued kind */
    apr_array_header_t *trusted;     /* const char *: WhisperEdgeTrustedProxy's items */
    const char         *trusted_header;
    int                 trusted_hops;
    const char         *data_dir;
    const char         *snapshot;
    const char         *data_at;              /* "file:line" of the directory line */
    const char         *snapshot_at;          /* "file:line" of the snapshot line, for a refusal that names both */
    const char         *plane_file[8];        /* WhisperEdgeData <plane> <file>, http level */
    const char         *plane_at[8];          /* "file:line" of each */
    const char         *counters_dir;
    int                 counters_off;
    apr_interval_time_t refresh;
    int                 refresh_set;
    we_build_t         *build;       /* the base's; every vhost points at it after check_config */
    apr_array_header_t *said;        /* the configuration-time lines, printed under -t and into the error log at start */
    int                 is_base;
} we_srv_conf_t;

/* per section (and per server's lookup_defaults): what the request path reads is `ctx` */
typedef struct {
    const we_mod_ctx_t *ctx;         /* the context's program, conf and counters; merged nearest-wins */
    uint32_t            attr_mask;   /* the export pass's attributes */
    uint32_t            env_mask;    /* the environment copy's */
    int                 deny_status; /* 0 unset */
    const char         *export_arg;  /* NULL unset */
    int                 has_lines;   /* a module directive appeared in this section */
    const char         *sec_kind;    /* "server", "virtualhost", "directory", "directorymatch", "location", "locationmatch" */
    const char         *sec_arg;     /* the section's argument */
    const char         *file;        /* the first directive's place */
    int                 line;
    const char         *path;        /* the ordinal path, assigned at check_config */
    struct we_dir_conf *orig;        /* the handler-written conf, through the merges */
} we_dir_conf_t;
struct we_dir_conf { we_dir_conf_t c; };

/* per request_rec */
typedef struct we_rconf {
    struct we_rconf     *head;       /* the chain's first request's */
    we_mod_line_t        lines[WE_MOD_WALK_LINES]; /* the trusted header's lines, oldest first, first request only */
    uint32_t             nlines;     /* the lines kept: the newest WE_MOD_WALK_LINES of the header's entries */
    int                  older;      /* the header carried more lines than were kept */
    int                  walked;
    we_mod_walk_t        w;          /* the walk's result (on the head) */
    we_addr_t            peer;
    int                  peer_ok;
    we_mod_record_t     *rec;        /* this request_rec's record */
    int                  evaluated;
    uint32_t             note;
    uint8_t              walk;
    const we_map_t       *rep_map;    /* the view's reputation map the decision read, for the outcome log */
    uint8_t              log_kind;   /* 0 nothing to log, 1 a would-deny, 2 a deny: set by the decision frame */
    uint8_t              log_floor;  /* the decision judged the floor address, not the server's */
    uint8_t              gen_pending; /* the generations note is owed, rendered one frame out of the decision */
    uint8_t              count_ranges; /* the legacy copy's range count is owed, charged one frame out of the decision */
    uint8_t              ranges_floor; /* that count is charged to the floor address, not the server's */
    struct we_shard     *sh;          /* the shard the decision frame wrote, for the deferred range count */
    we_mod_req_t         req;         /* the request the decision frame judges, rebuilt per evaluation */
    we_addr_t            server;      /* the context address this evaluation judged */
    int                  have_server;
    int                  acme;
    char                 floor_buf[WE_ADDR_TEXT_MAX];  /* the floor address's staging, off the frame */
} we_rconf_t;

/* the deny statuses the module admits on Apache: registered, header-free, final codes */
static const uint16_t we_status_ok[] = { 400u, 403u, 404u, 406u, 409u, 410u, 413u, 415u, 422u, 428u, 429u, 451u };

/* the note (and environment) name of attribute i, in we_mod_attr()'s order */
static const char *const we_note_name[WE_MOD_ATTRS] = {
    "WHISPER_EDGE_INFERRED", "WHISPER_EDGE_RPKI_UNREACHABLE", "WHISPER_EDGE_TOR_EXIT", "WHISPER_EDGE_PROXY",
    "WHISPER_EDGE_VPN", "WHISPER_EDGE_C2", "WHISPER_EDGE_BRUTEFORCE", "WHISPER_EDGE_SPAM", "WHISPER_EDGE_PHISHING",
    "WHISPER_EDGE_SCANNER", "WHISPER_EDGE_STATE_ACTOR", "WHISPER_EDGE_ANYCAST", "WHISPER_EDGE_MOAS",
    "WHISPER_EDGE_NARROWED", "WHISPER_EDGE_TENANT_ALLOW", "WHISPER_EDGE_TENANT_DENY", "WHISPER_EDGE_LISTED",
    "WHISPER_EDGE_RPKI_REASON", "WHISPER_EDGE_RPKI", "WHISPER_EDGE_ASN", "WHISPER_EDGE_ASN_REP",
    "WHISPER_EDGE_COUNTRY", "WHISPER_EDGE_REGISTRY_COUNTRY", "WHISPER_EDGE_RIR", "WHISPER_EDGE_REGISTRY_RIR"
};

static const char *const we_plane_file[8] = {
    "reputation.bin", "tor.bin", "rpki-unreachable.bin", "routing.bin", "anonymizer.bin", "threat.bin",
    "registry.bin", "tenant.bin"
};

static int we_any_plane_file(const char *const f[8])
{
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        if (f[p] != NULL) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------------------------- */
/* Configuration storage                                                                           */
/* ---------------------------------------------------------------------------------------------- */

/*
 * The main server's conf, which holds the http level and the build. httpd creates it before any virtual
 * host's (init_server_config runs before the configuration is read), and a vhost's `next` never leads
 * back to the head of the list, so it is remembered here, once per configuration pass.
 */
static we_srv_conf_t *g_base;

static we_srv_conf_t *we_base_conf(server_rec *s)
{
    we_srv_conf_t *c = s != NULL ? ap_get_module_config(s->module_config, &whisper_edge_module) : NULL;

    if (c != NULL && c->is_base) {
        return c;
    }
    return g_base;
}

static void *we_create_server_conf(apr_pool_t *p, server_rec *s)
{
    we_srv_conf_t *c = apr_pcalloc(p, sizeof *c);

    c->lines = apr_array_make(p, 16, sizeof(we_line_t));
    c->trusted = apr_array_make(p, 4, sizeof(const char *));
    c->refresh = apr_time_from_sec(WE_DEFAULT_REFRESH_SEC);
    c->is_base = !s->is_virtual;
    if (c->is_base) {
        c->said = apr_array_make(p, 32, sizeof(const char *));
        g_base = c;
    }
    return c;
}

/* a vhost's conf: nothing of its own (every directive here is http level, held by the base) */
static void *we_merge_server_conf(apr_pool_t *p, void *basev, void *addv)
{
    we_srv_conf_t *base = basev;
    we_srv_conf_t *out = apr_pcalloc(p, sizeof *out);

    (void) addv;
    *out = *base;
    out->is_base = 0;
    return out;
}

static void *we_create_dir_conf(apr_pool_t *p, char *dir)
{
    struct we_dir_conf *d = apr_pcalloc(p, sizeof *d);

    d->c.sec_arg = dir;
    d->c.orig = d;
    return &d->c;
}

/*
 * The merge, per request and once per virtual host: the context pointer, the deny status and the
 * export set are nearest-wins (the last section Apache merged that set one); nothing else is
 * inherited, because `has_lines` and the section's identity are the handler-written conf's alone.
 */
static void *we_merge_dir_conf(apr_pool_t *p, void *basev, void *addv)
{
    we_dir_conf_t *base = basev, *add = addv;
    struct we_dir_conf *d = apr_pcalloc(p, sizeof *d);

    d->c.ctx = add->ctx != NULL ? add->ctx : base->ctx;
    d->c.attr_mask = add->ctx != NULL ? add->attr_mask : base->attr_mask;
    d->c.env_mask = add->ctx != NULL ? add->env_mask : base->env_mask;
    d->c.deny_status = add->deny_status != 0 ? add->deny_status : base->deny_status;
    d->c.export_arg = add->export_arg != NULL ? add->export_arg : base->export_arg;
    d->c.has_lines = add->has_lines;
    d->c.sec_kind = add->sec_kind;
    d->c.sec_arg = add->sec_arg;
    d->c.file = add->file;
    d->c.line = add->line;
    d->c.path = add->path;
    d->c.orig = add->orig != NULL ? add->orig : (struct we_dir_conf *) addv;
    return &d->c;
}

/* ---------------------------------------------------------------------------------------------- */
/* Directive handlers                                                                              */
/* ---------------------------------------------------------------------------------------------- */

/* the section a directive sits in, through the conditional containers that select nothing by path */
static const ap_directive_t *we_section_of(const ap_directive_t *d)
{
    const ap_directive_t *p = d != NULL ? d->parent : NULL;

    while (p != NULL && (strcasecmp(p->directive, "<IfModule") == 0 || strcasecmp(p->directive, "<IfDefine") == 0
                         || strcasecmp(p->directive, "<IfVersion") == 0 || strcasecmp(p->directive, "<IfFile") == 0
                         || strcasecmp(p->directive, "<IfDirective") == 0 || strcasecmp(p->directive, "<IfSection") == 0)) {
        p = p->parent;
    }
    return p;
}

/* the section allow-list: the main configuration, <VirtualHost>, <Directory>, <DirectoryMatch>, <Location>, <LocationMatch> */
static const char *we_section_kind(const ap_directive_t *sec)
{
    static const struct { const char *tag, *kind; } tab[] = {
        { "<VirtualHost", "virtualhost" }, { "<Directory", "directory" }, { "<DirectoryMatch", "directorymatch" },
        { "<Location", "location" }, { "<LocationMatch", "locationmatch" },
    };
    size_t i;

    if (sec == NULL) {
        return "server";
    }
    for (i = 0u; i < sizeof tab / sizeof tab[0]; i++) {
        if (strcasecmp(sec->directive, tab[i].tag) == 0) {
            return tab[i].kind;
        }
    }
    return NULL;
}

static int we_is_http_level(cmd_parms *cmd)
{
    return !cmd->server->is_virtual && cmd->path == NULL && we_section_of(cmd->directive) == NULL;
}

/* one surrounding pair of double or single quotes removed, nothing else rewritten */
static const char *we_unquote(apr_pool_t *p, const char *s, size_t *len)
{
    size_t n;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    n = strlen(s);
    while (n > 0u && (s[n - 1u] == ' ' || s[n - 1u] == '\t')) {
        n--;
    }
    if (n >= 2u && ((s[0] == '"' && s[n - 1u] == '"') || (s[0] == '\'' && s[n - 1u] == '\''))) {
        s++;
        n -= 2u;
    }
    *len = n;
    return apr_pstrndup(p, s, n);
}

/*
 * Record one directive. Every handler comes through here: the section is checked against the
 * section allow-list, an http-only directive outside the http level is refused, a second http-level
 * definition of a single-valued directive is refused naming both places, and the line joins the base
 * server's list in file order with the section it was written in.
 */
static const char *we_record(cmd_parms *cmd, void *dirv, uint8_t kind, const char *arg, int http_only, int single)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    we_dir_conf_t *d = dirv;
    const ap_directive_t *sec = we_section_of(cmd->directive);
    const char *kindw = we_section_kind(sec);
    we_line_t *l;
    size_t len = 0u;
    int http;

    if (base == NULL) {
        return "whisper edge: the main server has no configuration record";
    }
    if (kindw == NULL) {
        return apr_psprintf(cmd->pool, "%s is allowed in the main configuration, <VirtualHost>, <Directory>, "
                            "<DirectoryMatch>, <Location> and <LocationMatch>; it selects a policy by path, and %s "
                            "would select it on other request properties", cmd->directive->directive, sec->directive);
    }
    http = we_is_http_level(cmd);
    if (http_only && !http) {
        return apr_psprintf(cmd->pool, "%s is http level only, so that no virtual host can change the floor",
                            cmd->directive->directive);
    }
    if (single && http && kind < WE_LINE_KINDS) {
        if (base->first[kind].file != NULL) {
            return apr_psprintf(cmd->pool, "%s is defined twice at http level: %s:%d and %s:%d; on a server that "
                                "includes conf.d/*.conf at http level a tenant's line would otherwise be a first "
                                "definition, so the second is refused", cmd->directive->directive,
                                base->first[kind].file, base->first[kind].line, cmd->directive->filename,
                                cmd->directive->line_num);
        }
        base->first[kind].file = cmd->directive->filename;
        base->first[kind].line = cmd->directive->line_num;
    }
    l = apr_array_push(base->lines);
    memset(l, 0, sizeof *l);
    l->kind = kind;
    l->name = cmd->directive->directive;
    l->arg = arg != NULL ? we_unquote(cmd->pool, arg, &len) : "";
    l->len = len;
    l->file = cmd->directive->filename;
    l->line = cmd->directive->line_num;
    l->use_file = cmd->config_file != NULL ? cmd->config_file->name : NULL;
    l->http = http;
    l->dirv = d != NULL ? (void *) d->orig : NULL;
    if (d != NULL) {
        we_dir_conf_t *o = &d->orig->c;

        if (!o->has_lines) {
            o->has_lines = 1;
            o->sec_kind = sec == NULL ? (cmd->server->is_virtual ? "virtualhost" : "server") : kindw;
            o->file = l->file;
            o->line = l->line;
            if (sec != NULL && o->sec_arg == NULL) {
                o->sec_arg = cmd->path;
            }
        }
    }
    return NULL;
}

static const char *we_cmd_policy(cmd_parms *cmd, void *dirv, const char *arg)
{
    return we_record(cmd, dirv, WE_DIR_POLICY, arg, 0, 0);
}

static const char *we_cmd_set(cmd_parms *cmd, void *dirv, const char *arg)
{
    return we_record(cmd, dirv, WE_DIR_SET, arg, 0, 0);
}

static const char *we_cmd_floor(cmd_parms *cmd, void *dirv, const char *arg)
{
    return we_record(cmd, dirv, WE_DIR_FLOOR, arg, 1, 0);
}

static const char *we_cmd_mode(cmd_parms *cmd, void *dirv, const char *arg)
{
    return we_record(cmd, dirv, WE_DIR_MODE, arg, 0, 1);
}

static const char *we_cmd_threshold(cmd_parms *cmd, void *dirv, const char *arg)
{
    return we_record(cmd, dirv, WE_DIR_THRESHOLD, arg, 0, 1);
}

static const char *we_cmd_inferred(cmd_parms *cmd, void *dirv, const char *arg)
{
    return we_record(cmd, dirv, WE_DIR_ALLOW_INFERRED, arg, 0, 1);
}

/* the deny status: the allow-list, and every other code refused by its class, each ending `use 403` */
static const char *we_status_refusal(apr_pool_t *p, const char *name, long code)
{
    const char *why;

    switch (code) {
    case 401: why = "401 requires a WWW-Authenticate header, which this module does not send"; break;
    case 405: why = "405 requires an Allow header, which this module does not send"; break;
    case 407: why = "407 requires a Proxy-Authenticate header, which this module does not send"; break;
    case 426: why = "426 requires an Upgrade header, which this module does not send"; break;
    case 416: why = "416 requires a Content-Range header, which this module does not send"; break;
    case 408: why = "408 is not sent as written: a server closes the connection on it, and clients retry"; break;
    case 421: why = "421 tells the client to send the request again on another connection"; break;
    case 417: why = "417 tells the client to drop Expect and send the request again"; break;
    case 411: why = "411 tells the client to add a Content-Length and send the request again"; break;
    case 431: why = "431 tells the client to shrink its header and send the request again"; break;
    case 412: case 414: why = "a code that describes the request, not a decision"; break;
    case 511: why = "511 is another protocol role: a client reads it as a captive portal"; break;
    case 494: case 495: case 496: case 497: case 499:
        why = "an nginx-internal code that is never on the wire as written"; break;
    case 444: why = "444 is nginx's close without a response, which httpd cannot send"; break;
    case 402: why = "402 is reserved (RFC 9110 section 15.5.3)"; break;
    default:
        if (code >= 500 && code <= 599) {
            why = "a 5xx says the server failed (RFC 9110 section 15.6); balancers and health checks in front "
                  "(nginx proxy_next_upstream, HAProxy observe layer7, Envoy outlier detection) count it, retry it and "
                  "can eject this origin under denied traffic";
        } else if (code >= 400 && code <= 599 && ap_get_status_line((int) code) != NULL
                   && strncmp(ap_get_status_line((int) code), "500", 3) != 0) {
            why = "a code this module does not send as a deny";
        } else {
            why = "a code RFC 9110 does not register, which httpd sends as `NNN Status NNN` with its 500 body";
        }
        break;
    }
    return apr_psprintf(p, "%s %ld: %s; use 403", name, code, why);
}

static const char *we_cmd_deny_status(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_dir_conf_t *d = dirv;
    char *end = NULL;
    long code = strtol(arg, &end, 10);
    size_t i;
    int ok = 0;
    const char *err;

    if (end == NULL || *end != '\0' || end == arg) {
        return apr_psprintf(cmd->pool, "%s takes a status code; use 403", cmd->directive->directive);
    }
    for (i = 0u; i < sizeof we_status_ok / sizeof we_status_ok[0]; i++) {
        ok |= code == (long) we_status_ok[i];
    }
    if (!ok) {
        return we_status_refusal(cmd->pool, cmd->directive->directive, code);
    }
    err = we_record(cmd, dirv, WE_LINE_DENY_STATUS, arg, 0, 1);
    if (err != NULL) {
        return err;
    }
    d->orig->c.deny_status = (int) code;
    return NULL;
}

static const char *we_cmd_export(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_dir_conf_t *d = dirv;
    const char *err = we_record(cmd, dirv, WE_LINE_EXPORT, arg, 0, 0);
    const char *s = arg;

    if (err != NULL) {
        return err;
    }
    /* every name must be an attribute, or `all` */
    while (*s != '\0') {
        const char *w;
        size_t n;
        uint32_t i;
        int found = 0;

        while (*s == ' ' || *s == '\t') {
            s++;
        }
        if (*s == '\0') {
            break;
        }
        w = s;
        while (*s != '\0' && *s != ' ' && *s != '\t') {
            s++;
        }
        n = (size_t) (s - w);
        if (n == 3u && strncasecmp(w, "all", 3) == 0) {
            continue;
        }
        for (i = 0u; i < WE_MOD_ATTRS; i++) {
            const we_mod_attr_t *a = we_mod_attr(i);

            found |= strlen(a->name) == n && strncmp(a->name, w, n) == 0;
        }
        if (!found) {
            return apr_psprintf(cmd->pool, "%s: \"%.*s\" is not an attribute; the attributes are inferred, listed, "
                                "tor_exit, rpki_unreachable, rpki_reason, proxy, vpn, c2, bruteforce, spam, phishing, "
                                "scanner, state_actor, anycast, moas, narrowed, rpki, asn, asn_rep, country, rir, "
                                "registry_country, registry_rir, tenant_allow, tenant_deny, or all",
                                cmd->directive->directive, (int) n, w);
        }
    }
    d->orig->c.export_arg = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *we_cmd_data(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_DATA, arg, 1, 0);   /* several lines: one directory, plane files */
    const char *a, *b = NULL;
    size_t n;

    if (err != NULL) {
        return err;
    }
    a = we_unquote(cmd->pool, arg, &n);
    b = strchr(a, ' ');
    if (b != NULL) {
        /* the per-plane form, <plane> <absolute file>: the plane's own file, over the directory for that plane */
        const char *word = apr_pstrndup(cmd->pool, a, (apr_size_t) (b - a));
        const char *file = b;
        uint32_t p;

        while (*file == ' ' || *file == '\t') {
            file++;
        }
        for (p = 0u; p < 8u; p++) {
            if (strcmp(word, we_mod_plane_word(p)) == 0) {
                break;
            }
        }
        if (p == 8u) {
            return apr_psprintf(cmd->pool, "%s %s: \"%s\" is not a plane; the planes are reputation, tor, "
                                "rpki-unreachable, routing, anonymizer, threat, registry, tenant",
                                cmd->directive->directive, a, word);
        }
        if (file[0] != '/' || strchr(file, ' ') != NULL || file[strlen(file) - 1u] == '/') {
            return apr_psprintf(cmd->pool, "%s %s needs an absolute path to the plane's file", cmd->directive->directive, word);
        }
        if (base->plane_file[p] != NULL) {
            return apr_psprintf(cmd->pool, "%s %s is defined twice at http level: %s and %s:%d",
                                cmd->directive->directive, word, base->plane_at[p], cmd->directive->filename,
                                cmd->directive->line_num);
        }
        base->plane_file[p] = file;
        base->plane_at[p] = apr_psprintf(cmd->pool, "%s:%d", cmd->directive->filename, cmd->directive->line_num);
        return NULL;
    }
    if (a[0] != '/') {
        return apr_psprintf(cmd->pool, "%s needs an absolute directory path", cmd->directive->directive);
    }
    if (base->data_dir != NULL) {
        return apr_psprintf(cmd->pool, "%s <directory> is defined twice at http level: %s and %s:%d",
                            cmd->directive->directive, base->data_at, cmd->directive->filename, cmd->directive->line_num);
    }
    base->data_dir = a;
    base->data_at = apr_psprintf(cmd->pool, "%s:%d", cmd->directive->filename, cmd->directive->line_num);
    return NULL;
}

static const char *we_cmd_snapshot(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_SNAPSHOT, arg, 1, 1);

    if (err != NULL) {
        return err;
    }
    if (arg == NULL || *arg != '/') {
        return apr_psprintf(cmd->pool, "%s needs an absolute path to snapshot.bin", cmd->directive->directive);
    }
    base->snapshot = arg;
    base->snapshot_at = apr_psprintf(cmd->pool, "%s:%d", cmd->directive->filename, cmd->directive->line_num);
    return NULL;
}

static const char *we_cmd_summary(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_SUMMARY, arg, 1, 1);

    if (err != NULL) {
        return err;
    }
    if (arg == NULL || (*arg != '/' && strcasecmp(arg, "off") != 0)) {
        return apr_psprintf(cmd->pool, "%s needs an absolute directory path, or off", cmd->directive->directive);
    }
    base->counters_off = strcasecmp(arg, "off") == 0;
    base->counters_dir = base->counters_off ? NULL : arg;
    return NULL;
}

static const char *we_cmd_refresh(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_REFRESH, arg, 1, 1);
    char *end = NULL;
    long secs;

    if (err != NULL) {
        return err;
    }
    secs = strtol(arg, &end, 10);
    if (end == NULL || *end != '\0' || end == arg || secs < 10 || secs > 86400) {
        return apr_psprintf(cmd->pool, "%s takes a number of seconds between 10 and 86400", cmd->directive->directive);
    }
    base->refresh = apr_time_from_sec(secs);
    base->refresh_set = 1;
    return NULL;
}

static const char *we_cmd_trusted_proxy(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_TRUSTED_PROXY, arg, 1, 1);
    const char *s = arg;

    if (err != NULL) {
        return err;
    }
    while (*s != '\0') {
        const char *w;

        while (*s == ' ' || *s == '\t') {
            s++;
        }
        if (*s == '\0') {
            break;
        }
        w = s;
        while (*s != '\0' && *s != ' ' && *s != '\t') {
            s++;
        }
        *(const char **) apr_array_push(base->trusted) = apr_pstrndup(cmd->pool, w, (size_t) (s - w));
    }
    if (base->trusted->nelts == 0) {
        return apr_psprintf(cmd->pool, "%s takes addresses, CIDR prefixes or unix:", cmd->directive->directive);
    }
    return NULL;
}

/* RFC 9110 section 5.1: a field name is a token */
static int we_is_tchar(unsigned char c)
{
    return isalnum(c) || strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static const char *we_cmd_trusted_header(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_TRUSTED_HEADER, arg, 1, 1);
    const char *s;

    if (err != NULL) {
        return err;
    }
    if (arg == NULL || *arg == '\0') {
        return apr_psprintf(cmd->pool, "%s takes a header name", cmd->directive->directive);
    }
    for (s = arg; *s != '\0'; s++) {
        if (!we_is_tchar((unsigned char) *s)) {
            return apr_psprintf(cmd->pool, "a header name is a token (RFC 9110 section 5.1); \"%s\" contains a %s",
                                arg, *s == ' ' ? "space" : "character outside the token alphabet");
        }
    }
    if (strcasecmp(arg, "Forwarded") == 0) {
        return "Forwarded uses the RFC 7239 syntax, which this module does not read; name X-Forwarded-For, or a "
               "single-address header such as X-Real-IP";
    }
    base->trusted_header = arg;
    return NULL;
}

static const char *we_cmd_trusted_hops(cmd_parms *cmd, void *dirv, const char *arg)
{
    we_srv_conf_t *base = we_base_conf(cmd->server);
    const char *err = we_record(cmd, dirv, WE_LINE_TRUSTED_HOPS, arg, 1, 1);
    char *end = NULL;
    long n;

    if (err != NULL) {
        return err;
    }
    n = strtol(arg, &end, 10);
    if (end == NULL || *end != '\0' || end == arg || n < 1 || n > (long) WE_MOD_HOPS_MAX) {
        return apr_psprintf(cmd->pool, "%s takes a number of hops between 1 and %u", cmd->directive->directive,
                            (unsigned) WE_MOD_HOPS_MAX);
    }
    base->trusted_hops = (int) n;
    return NULL;
}

/*
 * Each directive under its CamelCase name and its snake_case spelling, one handler. NOT OR_*: none of
 * this is settable from .htaccess, where a tenant could otherwise switch blocking on for a neighbour's
 * traffic or off for their own. ACCESS_CONF|RSRC_CONF admits the sections the allow-list names; the handler
 * refuses the rest by name.
 */
#define WE_DIRECTIVE(camel, snake, fn, where, help) \
    AP_INIT_RAW_ARGS(camel, fn, NULL, where, help), AP_INIT_RAW_ARGS(snake, fn, NULL, where, help)
#define WE_DIRECTIVE1(camel, snake, fn, where, help) \
    AP_INIT_TAKE1(camel, fn, NULL, where, help), AP_INIT_TAKE1(snake, fn, NULL, where, help)

static const command_rec we_commands[] = {
    WE_DIRECTIVE("WhisperEdgePolicy", "whisper_edge_policy", we_cmd_policy, ACCESS_CONF | RSRC_CONF,
                 "one rule: allow|deny|log if <expression>"),
    WE_DIRECTIVE("WhisperEdgeSet", "whisper_edge_set", we_cmd_set, ACCESS_CONF | RSRC_CONF,
                 "a set declaration: @name member..."),
    WE_DIRECTIVE("WhisperEdgePolicyFloor", "whisper_edge_policy_floor", we_cmd_floor, RSRC_CONF,
                 "one deny or log rule every context runs first; http level only"),
    WE_DIRECTIVE1("WhisperEdgeMode", "whisper_edge_mode", we_cmd_mode, ACCESS_CONF | RSRC_CONF,
                  "off, log (the default) or deny"),
    WE_DIRECTIVE1("WhisperEdgeThreshold", "whisper_edge_threshold", we_cmd_threshold, ACCESS_CONF | RSRC_CONF,
                  "off, low, medium, high or critical: sugar for deny if listed >= <level>"),
    WE_DIRECTIVE1("WhisperEdgeAllowInferred", "whisper_edge_allow_inferred", we_cmd_inferred, ACCESS_CONF | RSRC_CONF,
                  "on or off: act on verdicts with no citable listing behind them"),
    WE_DIRECTIVE1("WhisperEdgeDenyStatus", "whisper_edge_deny_status", we_cmd_deny_status, ACCESS_CONF | RSRC_CONF,
                  "the status a deny sends (default 403)"),
    WE_DIRECTIVE("WhisperEdgeExport", "whisper_edge_export", we_cmd_export, ACCESS_CONF | RSRC_CONF,
                 "attribute names, or all: more notes, and the environment copy"),
    WE_DIRECTIVE("WhisperEdgeData", "whisper_edge_data", we_cmd_data, RSRC_CONF,
                 "the directory of <plane>.bin files; http level only"),
    WE_DIRECTIVE1("WhisperEdgeSnapshot", "whisper_edge_snapshot", we_cmd_snapshot, RSRC_CONF,
                  "absolute path to snapshot.bin (the reputation plane, legacy form); http level only"),
    WE_DIRECTIVE1("WhisperEdgeRefresh", "whisper_edge_refresh", we_cmd_refresh, RSRC_CONF,
                  "seconds between the module thread's ticks (default 60)"),
    WE_DIRECTIVE1("WhisperEdgeSummary", "whisper_edge_summary", we_cmd_summary, RSRC_CONF,
                  "directory for the counter and status files whisper-edge-summary reads, or off"),
    WE_DIRECTIVE("WhisperEdgeTrustedProxy", "whisper_edge_trusted_proxy", we_cmd_trusted_proxy, RSRC_CONF,
                 "addresses, CIDR prefixes, unix: the peers whose trusted header the floor reads"),
    WE_DIRECTIVE1("WhisperEdgeTrustedHeader", "whisper_edge_trusted_header", we_cmd_trusted_header, RSRC_CONF,
                  "the header a trusted proxy appends the client to (X-Forwarded-For)"),
    WE_DIRECTIVE1("WhisperEdgeTrustedHops", "whisper_edge_trusted_hops", we_cmd_trusted_hops, RSRC_CONF,
                  "judge exactly the Nth entry from the right, 1..16"),
    { NULL, { NULL }, NULL, 0, RAW_ARGS, NULL }
};

/* ---------------------------------------------------------------------------------------------- */
/* The compile: check_config                                                                        */
/* ---------------------------------------------------------------------------------------------- */

typedef struct {
    apr_pool_t *p;
    server_rec *s;
    we_srv_conf_t *base;
    const we_line_t *lines;
    int nlines;
} we_report_ud_t;

static void we_say(we_srv_conf_t *base, int level, const char *fmt, ...);

/* the compiler's reports: one line each, with the directive's own place */
static void we_report_line(void *ud, const we_policy_report_line_t *r)
{
    we_report_ud_t *u = ud;
    const char *place = "";
    int i;

    for (i = 0; i < u->nlines; i++) {
        const we_line_t *l = &u->lines[i];
        const we_dir_conf_t *d = l->dirv != NULL ? &((struct we_dir_conf *) l->dirv)->c : NULL;
        const char *path = d != NULL && d->path != NULL ? d->path : "http";

        if (l->kind == r->kind && strcmp(path, r->context) == 0) {
            place = apr_psprintf(u->p, "%s:%d: ", l->file, l->line);
            break;
        }
    }
    we_say(u->base, APLOG_NOTICE, "whisper edge: policy: report %s%s", place, r->msg);
}

static apr_status_t we_arena_cleanup(void *data)
{
    we_mod_arena_free(data);
    return APR_SUCCESS;
}

static apr_status_t we_trust_cleanup(void *data)
{
    we_mod_trust_free(data);
    return APR_SUCCESS;
}

static apr_status_t we_planes_cleanup(void *data)
{
    we_mod_planes_release(data);
    return APR_SUCCESS;
}

/*
 * STRICTMODES FOR A CONFIGURATION FILE. "http level" is not "operator only" where a panel includes
 * `conf.d/` at the http level: a tenant's `WhisperEdgeMode off` in such a file would be a first
 * definition and would disarm the floor. So the file that defines any http-level whisper_edge_* directive
 * must be owned by root or by the configuration reader and writable by neither group nor world, and so
 * must every directory above its resolved path, with one exception sshd makes too: a root-owned sticky
 * directory (/tmp above a key file) is allowed, because a configuration file is found by an explicit path
 * the operator wrote. 0, or -1 with `why` naming the file, its owner and mode, and the fix.
 */
static int we_strict_file(const char *path, char *why, size_t n)
{
    char real[PATH_MAX];
    struct stat st;
    unsigned me = (unsigned) geteuid();
    char *slash;

#ifdef WE_MOD_TEST_LEXICAL
    /* the control: the path as written, so a symbolic link's target is never looked at */
    if (strlen(path) >= sizeof real) {
        snprintf(why, n, "%s: the path is too long", path);
        return -1;
    }
    snprintf(real, sizeof real, "%s", path);
#else
    if (realpath(path, real) == NULL) {
        snprintf(why, n, "%s: %s", path, strerror(errno));
        return -1;
    }
#endif
    if (stat(real, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(why, n, "%s is not a regular file", real);
        return -1;
    }
    if ((st.st_uid != 0u && st.st_uid != me) || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
        snprintf(why, n, "%s is owned by uid %u, mode %04o; a file that defines an http-level directive must be owned by "
                 "root or by uid %u (the configuration reader) and writable by neither group nor world: chown it to root "
                 "and chmod go-w it", real, (unsigned) st.st_uid, (unsigned) (st.st_mode & 07777u), me);
        return -1;
    }
    for (slash = strrchr(real, '/'); slash != NULL; slash = strrchr(real, '/')) {
        const char *dir;

        *slash = '\0';
        dir = real[0] != '\0' ? real : "/";
        if (stat(dir, &st) != 0) {
            snprintf(why, n, "%s: %s", dir, strerror(errno));
            return -1;
        }
        if (!(S_ISDIR(st.st_mode) && (st.st_uid == 0u || st.st_uid == me) && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0u)
                && !(S_ISDIR(st.st_mode) && st.st_uid == 0u && (st.st_mode & S_ISVTX) != 0u)) {
            snprintf(why, n, "%s, above the file, is owned by uid %u, mode %04o; every directory above a file that defines an "
                     "http-level directive must be owned by root or by uid %u (the configuration reader) and writable by "
                     "neither group nor world (a root-owned sticky directory is allowed): chmod go-w that directory", dir,
                     (unsigned) st.st_uid, (unsigned) (st.st_mode & 07777u), me);
            return -1;
        }
        if (real[0] == '\0') {
            break;
        }
    }
    return 0;
}

/*
 * The owner the trust checks accept beside root: the workers' uid when the configuration reader is root
 * (mod_unixd's User), else the reader's own effective uid, which is then also the workers'.
 */
static unsigned we_trusted_uid(void)
{
    uid_t e = geteuid();

    if (e != 0u) {
        return (unsigned) e;
    }
    return ap_unixd_config.user_id != (uid_t) -1 ? (unsigned) ap_unixd_config.user_id : 0u;
}

/*
 * A configuration-time line. check_config runs before httpd opens its error log, so under `apachectl
 * configtest` the lines are printed there and then (stderr, the test's own output), while at a normal
 * start they are kept and written into the error log by post_config's real pass, once. A refusal is
 * always logged at once, because it stops the start.
 */
static void we_say(we_srv_conf_t *base, int level, const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    const char **slot;

    va_start(ap, fmt);
    apr_vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    slot = apr_array_push(base->said);
    *slot = apr_psprintf(base->said->pool, "%d\t%s", level, buf);
}

static void we_say_flush(we_srv_conf_t *base, server_rec *s)
{
    int i;

    for (i = 0; i < base->said->nelts; i++) {
        const char *l = ((const char **) base->said->elts)[i];
        int level = atoi(l);
        const char *text = strchr(l, '\t');

        ap_log_error(APLOG_MARK, level, 0, s, "%s", text != NULL ? text + 1 : l);
    }
}

static const char *we_mode_word(uint32_t m)
{
    return m == WE_MODE_DENY ? "deny" : m == WE_MODE_OFF ? "off" : "log";
}

static void we_iso_time(uint64_t ms, char out[32])
{
    time_t t = (time_t) (ms / 1000u);
    struct tm tm;

    if (gmtime_r(&t, &tm) == NULL || strftime(out, 32, "%Y-%m-%dT%H:%MZ", &tm) == 0) {
        snprintf(out, 32, "%llu", (unsigned long long) ms);
    }
}

/* the attributes of the planes in `mask` */
static uint32_t we_attrs_of_planes(uint32_t mask)
{
    uint32_t i, out = 0u;

    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        if (((mask >> we_mod_attr(i)->plane) & 1u) != 0u) {
            out |= 1u << i;
        }
    }
    return out;
}

/* `whisper_edge_export`'s names as an attribute mask, and the planes they name */
static void we_export_parse(const char *arg, uint32_t *attrs, uint8_t *planes)
{
    const char *s = arg;

    *attrs = 0u;
    *planes = 0u;
    if (arg == NULL) {
        return;
    }
    while (*s != '\0') {
        const char *w;
        size_t n;
        uint32_t i;

        while (*s == ' ' || *s == '\t') {
            s++;
        }
        if (*s == '\0') {
            break;
        }
        w = s;
        while (*s != '\0' && *s != ' ' && *s != '\t') {
            s++;
        }
        n = (size_t) (s - w);
        if (n == 3u && strncasecmp(w, "all", 3) == 0) {
            *attrs = (1u << WE_MOD_ATTRS) - 1u;
            *planes = 0xffu;
            continue;
        }
        for (i = 0u; i < WE_MOD_ATTRS; i++) {
            const we_mod_attr_t *a = we_mod_attr(i);

            if (strlen(a->name) == n && strncmp(a->name, w, n) == 0) {
                *attrs |= 1u << i;
                *planes = (uint8_t) (*planes | (1u << a->plane));
            }
        }
    }
}

/* one context's spec entry and its dir conf, gathered by the walk below */
typedef struct {
    we_dir_conf_t *d;          /* the conf object the request path reads (merged lookup_defaults, or the section's) */
    we_dir_conf_t *o;          /* the handler-written conf */
    const char    *path;
    const char    *human;
    server_rec    *s;
    int            http;
} we_ctx_item_t;

static const char *we_human_name(apr_pool_t *p, const we_dir_conf_t *o, server_rec *s)
{
    if (o->sec_kind == NULL || strcmp(o->sec_kind, "server") == 0) {
        return apr_psprintf(p, "server \"%s\"", s->server_hostname != NULL ? s->server_hostname : "");
    }
    if (strcmp(o->sec_kind, "virtualhost") == 0) {
        return apr_psprintf(p, "server \"%s\"", s->server_hostname != NULL ? s->server_hostname : "");
    }
    return apr_psprintf(p, "%s \"%s\"", o->sec_kind, o->sec_arg != NULL ? o->sec_arg : "");
}

/* a section vector's module conf, or NULL */
static we_dir_conf_t *we_sec_conf(ap_conf_vector_t *sec)
{
    return sec != NULL ? ap_get_module_config(sec, &whisper_edge_module) : NULL;
}

static int we_in_base_sections(const core_server_config *base, ap_conf_vector_t *sec)
{
    int i;

    for (i = 0; base->sec_dir != NULL && i < base->sec_dir->nelts; i++) {
        if (((ap_conf_vector_t **) base->sec_dir->elts)[i] == sec) {
            return 1;
        }
    }
    for (i = 0; base->sec_url != NULL && i < base->sec_url->nelts; i++) {
        if (((ap_conf_vector_t **) base->sec_url->elts)[i] == sec) {
            return 1;
        }
    }
    return 0;
}

/* does the earlier section `anc` cover `path`? Location: a URL prefix, as httpd matches one; Directory: whole components */
static int we_covers(int location, const char *anc, const char *path)
{
    size_t n;

    if (anc == NULL || path == NULL) {
        return 0;
    }
    n = strlen(anc);
    if (strncmp(anc, path, n) != 0) {
        return 0;
    }
    return location || n == 0 || anc[n - 1] == '/' || path[n] == '\0' || path[n] == '/';
}

/*
 * The contexts, in one order: the http level, the main server's sections with lines, then each
 * virtual host and its own sections with lines. Every server is a context (so a request in a vhost
 * with no lines of its own still finds its program); a section is one only when a module directive
 * appeared in it. Ordinal paths name them, never an operator's text, and carry httpd's own nesting: a section's parent is the
 * nearest EARLIER section of the same kind that covers it (<Directory> sections arrive shortest path
 * first, <Location> sections in configuration order, which is how httpd merges them), a regex section
 * is never a parent, and a section nothing covers hangs from its server: http, http/l1, http/l1/l1,
 * http/s1, http/s1/l2.
 */
static apr_array_header_t *we_gather_contexts(apr_pool_t *p, server_rec *s)
{
    apr_array_header_t *items = apr_array_make(p, 16, sizeof(we_ctx_item_t));
    core_server_config *base_sc = ap_get_core_module_config(s->module_config);
    server_rec *v;
    we_dir_conf_t *main_d = NULL;
    int sn = 0;

    for (v = s; v != NULL; v = v->next) {
        we_dir_conf_t *d = ap_get_module_config(v->lookup_defaults, &whisper_edge_module);
        core_server_config *sc = ap_get_core_module_config(v->module_config);
        const apr_array_header_t *secs[2];
        we_ctx_item_t *it;
        const char *spath;
        int k, i, srv_children = 0;

        if (d == NULL) {
            continue;
        }
        if (v == s) {
            spath = "http";
            main_d = d;
        } else {
            spath = apr_psprintf(p, "http/s%d", ++sn);
        }
        it = apr_array_push(items);
        it->d = d;
        it->o = &d->orig->c;
        it->path = spath;
        it->s = v;
        it->http = v == s;
        it->human = we_human_name(p, it->o, v);
        if (v == s || d != main_d) {
            /*
             * A virtual host with no module line of its own never gets a per-dir conf of its own:
             * its slot in lookup_defaults is the main server's object, shared. Numbering the shared
             * object here would re-attribute every http-level line to this virtual host's context
             * (each line's dirv is that same object), which disarms the floor's mode at the http
             * level, so the shared object keeps the http level's name.
             */
            it->o->path = spath;
            d->path = spath;
        }
        secs[0] = sc != NULL ? sc->sec_dir : NULL;
        secs[1] = sc != NULL ? sc->sec_url : NULL;
        for (k = 0; k < 2; k++) {
            int *children = apr_pcalloc(p, (size_t) (secs[k] != NULL && secs[k]->nelts > 0 ? secs[k]->nelts : 1) * sizeof *children);

            for (i = 0; secs[k] != NULL && i < secs[k]->nelts; i++) {
                ap_conf_vector_t *sec = ((ap_conf_vector_t **) secs[k]->elts)[i];
                we_dir_conf_t *sd = we_sec_conf(sec);
                const core_dir_config *cd = ap_get_core_module_config(sec);
                const char *parent = spath;
                int *pcount = &srv_children, j;

                if (sd == NULL || !sd->orig->c.has_lines || (v != s && we_in_base_sections(base_sc, sec))) {
                    continue;
                }
                if (sd->path != NULL) {
                    continue;                  /* a section already numbered (shared vectors) */
                }
                /* the parent: the nearest earlier covering section of this kind with lines; never a regex one */
                for (j = i - 1; cd != NULL && cd->r == NULL && j >= 0; j--) {
                    ap_conf_vector_t *as = ((ap_conf_vector_t **) secs[k]->elts)[j];
                    we_dir_conf_t *ad = we_sec_conf(as);
                    const core_dir_config *acd = ap_get_core_module_config(as);

                    if (ad == NULL || ad->path == NULL || acd == NULL || acd->r != NULL || !we_covers(k == 1, acd->d, cd->d)) {
                        continue;
                    }
                    parent = ad->path;
                    pcount = &children[j];
                    break;
                }
                it = apr_array_push(items);
                it->d = sd;
                it->o = &sd->orig->c;
                it->path = apr_psprintf(p, "%s/l%d", parent, ++*pcount);
                it->s = v;
                it->http = 0;
                it->human = we_human_name(p, it->o, v);
                it->o->path = it->path;
                sd->path = it->path;
            }
        }
    }
    return items;
}

/* the deny status a context's own rules use: its own, else the nearest enclosing one's, else the http level's */
static uint16_t we_nearest_status(const apr_array_header_t *items, int idx)
{
    const we_ctx_item_t *it = &((const we_ctx_item_t *) items->elts)[idx];
    int i;

    if (it->o->deny_status != 0) {
        return (uint16_t) it->o->deny_status;
    }
    /* the enclosing server's: the item whose path is the longest proper prefix */
    for (i = idx - 1; i >= 0; i--) {
        const we_ctx_item_t *a = &((const we_ctx_item_t *) items->elts)[i];
        size_t n = strlen(a->path);

        if (strncmp(a->path, it->path, n) == 0 && it->path[n] == '/' && a->o->deny_status != 0) {
            return (uint16_t) a->o->deny_status;
        }
    }
    return 0u;
}

static const char *we_nearest_export(const apr_array_header_t *items, int idx)
{
    const we_ctx_item_t *it = &((const we_ctx_item_t *) items->elts)[idx];
    int i;

    if (it->o->export_arg != NULL) {
        return it->o->export_arg;
    }
    for (i = idx - 1; i >= 0; i--) {
        const we_ctx_item_t *a = &((const we_ctx_item_t *) items->elts)[i];
        size_t n = strlen(a->path);

        if (strncmp(a->path, it->path, n) == 0 && it->path[n] == '/' && a->o->export_arg != NULL) {
            return a->o->export_arg;
        }
    }
    return NULL;
}

/* a plane's state at configuration time, from the peek: for the data line and the environment */
typedef struct {
    int      present, ok, unreadable, err;
    we_mod_peek_t pk;
    char     why[128];
} we_plane_cfg_t;

static void we_peek_planes(const we_build_t *b, we_plane_cfg_t out[8], unsigned uid)
{
    uint32_t p;
    int dirfd = -1;
    char why[128];

    memset(out, 0, 8u * sizeof out[0]);
    if (b->data_dir != NULL && we_mod_dir_open(b->data_dir, uid, &dirfd, why, sizeof why) != 0) {
        dirfd = -1;
    }
    for (p = 0u; p < 8u; p++) {
        we_plane_cfg_t *o = &out[p];
        int rc;

        const char *own = b->plane_file[p] != NULL ? b->plane_file[p] : p == 0u ? b->snapshot : NULL;

        if (own != NULL) {
            char dir[1024];
            const char *slash = strrchr(own, '/');
            int sfd;

            snprintf(dir, sizeof dir, "%.*s", (int) (slash - own), own);
            sfd = we_openat_cloexec(AT_FDCWD, dir[0] != '\0' ? dir : "/", O_RDONLY | O_DIRECTORY, 0);
            if (sfd >= 0) {
                rc = we_plane_peek(sfd, slash + 1, p + 1u, &o->pk, o->why, sizeof o->why);
                close(sfd);
            } else {
                o->pk.absent = 1u;
                rc = -1;
            }
        } else if (dirfd >= 0) {
            rc = we_plane_peek(dirfd, we_plane_file[p], p + 1u, &o->pk, o->why, sizeof o->why);
        } else {
            o->pk.absent = 1u;
            rc = -1;
        }
        o->present = !o->pk.absent;
        o->ok = rc == 0;
        o->err = (int) o->pk.err;
        o->unreadable = o->present && !o->ok && (o->err == EACCES || o->err == EPERM);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
}

/*
 * The whole configuration compiled, once, where `apachectl configtest` runs it. Every refusal is the compiler's
 * line at APLOG_CRIT and fails the test; nothing partial ever loads.
 */
/*
 * RemoteIPProxyProtocol, found in the parsed tree the configuration test already holds: the floor
 * judges the socket's peer, which under the PROXY protocol is the load balancer itself, and the source
 * the PROXY header names is read only by the header walk, so a balancer that does not append lets the
 * client choose the judged address. The line names the virtual host the directive sits in.
 */
static void we_proxy_line(const ap_directive_t *d, const char *vhost, we_srv_conf_t *base, we_build_t *b)
{
    for (; d != NULL; d = d->next) {
        if (d->directive != NULL && strcasecmp(d->directive, "<VirtualHost") == 0) {
            char label[256];
            const char *a = d->args != NULL ? d->args : "";
            size_t n = strlen(a);

            while (n > 0u && (a[n - 1u] == '>' || a[n - 1u] == ' ' || a[n - 1u] == '\t')) {
                n--;               /* the block's closing '>' is not part of its address list */
            }
            if (n >= sizeof label) {
                n = sizeof label - 1u;
            }
            memcpy(label, a, n);
            label[n] = '\0';
            we_proxy_line(d->first_child, label, base, b);
        } else if (d->directive != NULL && strcasecmp(d->directive, "RemoteIPProxyProtocol") == 0) {
            const char *a = d->args != NULL ? d->args : "";

            while (*a == ' ' || *a == '\t') {
                a++;
            }
            if ((strncasecmp(a, "on", 2) == 0) && (a[2] == '\0' || a[2] == ' ' || a[2] == '\t')) {
                b->proxy_protocol_seen = 1;
                we_say(base, APLOG_NOTICE, "whisper edge: policy: the floor judges the PROXY-protocol load "
                             "balancer on %s, not the client; the PROXY header's source is not read%s %s%s",
                             vhost != NULL ? vhost : "the main configuration",
                             b->header != NULL ? "; a balancer that does not append to" : "",
                             b->header != NULL ? b->header : "", b->header != NULL ? " lets the client choose the judged address" : "");
            }
        } else {
            we_proxy_line(d->first_child, vhost, base, b);
        }
    }
}

static int we_check_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    we_srv_conf_t *base = ap_get_module_config(s->module_config, &whisper_edge_module);
    we_build_t *b;
    apr_array_header_t *items;
    we_policy_directive_t *dirs;
    we_policy_source_t src;
    we_policy_env_t env;
    we_policy_error_t err;
    we_policy_report_t rep;
    we_report_ud_t rud;
    we_policy_build_t *pb = NULL;
    we_mod_ctx_spec_t *spec;
    const char *const *plane_path;
    we_plane_cfg_t pcfg[8];
    char msg[1024], why[256];
    uint32_t p, i, read_mask = 0u, http_mask = 0u;
    uint16_t http_status = WE_DEFAULT_DENY_STATUS;
    int n, rc, synthetic = 0;
    unsigned uid = we_trusted_uid();
    server_rec *v;

    (void) plog;
    (void) ptemp;
    if (base == NULL) {
        return OK;
    }
    if (geteuid() != 0u && (base->data_dir != NULL || base->snapshot != NULL || we_any_plane_file(base->plane_file))) {
        we_say(base, APLOG_WARNING, "whisper edge: policy: the configuration is read as uid %u, not root, "
                     "so the trusted owner of every plane and directory is that uid, which is also the uid the workers run "
                     "as; code running as the workers can then replace a plane", uid);
    }
    b = apr_pcalloc(pconf, sizeof *b);
    base->build = b;
    for (v = s->next; v != NULL; v = v->next) {
        we_srv_conf_t *c = ap_get_module_config(v->module_config, &whisper_edge_module);

        if (c != NULL) {
            c->build = b;
        }
    }
    b->data_dir = base->data_dir;
    b->snapshot = base->snapshot;
    memcpy(b->plane_file, base->plane_file, sizeof b->plane_file);
    /* the snapshot is the legacy copy only as the configuration's one data directive; beside a directory or a
     * plane's own file it is the reputation plane's file, mapped as every other plane is */
    b->legacy = b->snapshot != NULL && b->data_dir == NULL && !we_any_plane_file(b->plane_file) ? b->snapshot : NULL;
    b->counters_off = base->counters_off;
    b->counters_dir = base->counters_dir;
    b->interval_ms = (uint64_t) apr_time_as_msec(base->refresh);
    b->hops = base->trusted_hops > 0 ? (uint32_t) base->trusted_hops : 0u;
    b->header = base->trusted_header;
    b->header_len = b->header != NULL ? strlen(b->header) : 0u;
    if (b->counters_dir == NULL && !b->counters_off) {
        /* the core's rule (we_mod_bind_counters_dir): `counters` inside the data directory, or beside the snapshot,
         * or beside the per-plane files when they share one directory. Files in two directories have no one place
         * beside them: the configuration test fails naming the counters directive, and a real start serves on with
         * no counter files, the refusal at error level (the counts are not on the serving path) */
        we_mod_bind_args_t ca = WE_MOD_BIND_ARGS_INIT;
        char cdir[PATH_MAX], cwhy[512];
        int crc;

        ca.data_dir = b->data_dir;
        ca.legacy_file = b->snapshot;
        memcpy(ca.plane_file, b->plane_file, sizeof ca.plane_file);
        crc = we_mod_bind_counters_dir(&ca, cdir, sizeof cdir, cwhy, sizeof cwhy);
        if (crc == 1) {
            b->counters_dir = apr_pstrdup(pconf, cdir);
        } else if (crc != 0) {
            if (ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_TEST) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: %s", crc == -1 ? cwhy
                             : "the counters directory's path is too long; name it with WhisperEdgeSummary <dir>");
                return DONE;
            }
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "whisper edge: %s; serving on with no counter files",
                         crc == -1 ? cwhy : "the counters directory's path is too long");
            b->counters_off = 1;
        }
    }
    /* StrictModes on every file that defines an http-level directive: the file httpd read it from, and for a
     * mod_macro expansion both the macro's defining file and the file that used it; a command-line directive
     * (-c, -C) comes from root's own invocation and is trusted */
    {
        const char *checked[64];
        char swhy[PATH_MAX + 512];
        int nchecked = 0, j;

        for (j = 0; j < base->lines->nelts; j++) {
            const we_line_t *l = &((we_line_t *) base->lines->elts)[j];
            const char *files[2] = { NULL, NULL };
            char macro_file[PATH_MAX];
            int k;

            (void) macro_file;

            if (!l->http) {
                continue;
            }
            if (l->file != NULL && strncmp(l->file, "macro '", 7) == 0) {
                /* mod_macro: `macro 'x' (defined on line N of "DEF") used on line M of "USE"`: both files */
                const char *q = strstr(l->file, " of \"");
                int nf = 0;

                while (q != NULL && nf < 2) {
                    const char *e = strchr(q + 5, '"');

                    if (e == NULL) {
                        break;
                    }
                    if ((size_t) (e - (q + 5)) < sizeof macro_file) {
                        char *copy = apr_pstrndup(pconf, q + 5, (apr_size_t) (e - (q + 5)));

                        files[nf++] = copy;
                    }
                    q = strstr(e, " of \"");
                }
                if (nf < 2) {
                    files[nf] = l->use_file;
                }
            } else if (l->file != NULL && l->file[0] == '/') {
                files[0] = l->file;
            }
            for (k = 0; k < 2; k++) {
                int seen = 0, m;

                if (files[k] == NULL || files[k][0] != '/') {
                    continue;
                }
                for (m = 0; m < nchecked; m++) {
                    seen |= strcmp(checked[m], files[k]) == 0;
                }
                if (seen) {
                    continue;
                }
                if (nchecked < 64) {
                    checked[nchecked++] = apr_pstrdup(pconf, files[k]);
                }
                if (we_strict_file(files[k], swhy, sizeof swhy) != 0) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: %s at %s:%d: StrictModes: %s",
                                 l->name, l->file, l->line, swhy);
                    return DONE;
                }
            }
        }
    }

    /* the trusted-proxy table, with its configuration-time report */
    if (base->trusted->nelts > 0) {
        we_mod_trust_report_t tr;

        if (we_mod_trust_build((const char *const *) base->trusted->elts, (size_t) base->trusted->nelts, &b->trust,
                               &tr, why, sizeof why) != 0) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: WhisperEdgeTrustedProxy: %s", why);
            return DONE;
        }
        b->trust_ok = 1;
        apr_pool_cleanup_register(pconf, &b->trust, we_trust_cleanup, apr_pool_cleanup_null);
        if (tr.broad != 0u) {
            we_say(base, APLOG_WARNING, "whisper edge: policy: WhisperEdgeTrustedProxy: %u prefix%s "
                         "broader than /16 (IPv4) or /32 (IPv6): a shared range lets anyone in it choose the next "
                         "entry; prefer WhisperEdgeTrustedHops for a CDN", tr.broad, tr.broad == 1u ? "" : "es");
        }
        if (tr.covers_mapped != 0u) {
            we_say(base, APLOG_WARNING, "whisper edge: policy: WhisperEdgeTrustedProxy: an IPv6 "
                         "prefix shorter than /96 covers ::ffff:0:0/96, which never matches an IPv4 peer after "
                         "canonicalisation; add the IPv4 prefix it means");
        }
        we_say(base, APLOG_NOTICE, "whisper edge: policy: trusted proxies: %u IPv4 and %u IPv6 "
                     "entries as written, %u and %u intervals after merging%s%s", tr.configured4, tr.configured6,
                     b->trust.n4, b->trust.n6, b->trust.unix_ok ? ", unix: trusted" : "",
                     b->header != NULL ? "" : "; no WhisperEdgeTrustedHeader, so the header is never read");
    } else if (b->header != NULL) {
        we_say(base, APLOG_WARNING, "whisper edge: policy: WhisperEdgeTrustedHeader is set with no "
                     "WhisperEdgeTrustedProxy, so no peer is trusted and the header is never read");
    }

    /* RemoteIPProxyProtocol in the parsed tree: the PROXY line, once per virtual host that turns it on */
    b->proxy_protocol_seen = 0;
    we_proxy_line(ap_conftree, NULL, base, b);

    /* the contexts and the directives the compiler sees, in file order */
    items = we_gather_contexts(pconf, s);
    n = base->lines->nelts;
    dirs = apr_pcalloc(pconf, (size_t) (n + 1) * sizeof *dirs);
    {
        int k = 0, j, http_has_program = 0;

        /*
         * THE SUGAR DEFAULT: a context with no policy lines and no threshold line runs
         * `deny if listed >= high` under mode log. Every context inherits its nearest ancestor's program,
         * so the default is written once, at the http level, when nothing there sets one.
         */
        for (j = 0; j < n; j++) {
            const we_line_t *l = &((we_line_t *) base->lines->elts)[j];

            http_has_program |= l->http && (l->kind == WE_DIR_POLICY || l->kind == WE_DIR_THRESHOLD);
        }
        if (!http_has_program) {
            dirs[k].kind = WE_DIR_THRESHOLD;
            dirs[k].context = "http";
            dirs[k].arg = (const uint8_t *) "high";
            dirs[k].len = 4u;
            k++;
            synthetic = 1;
        }
        for (j = 0; j < n; j++) {
            const we_line_t *l = &((we_line_t *) base->lines->elts)[j];
            const we_dir_conf_t *d = l->dirv != NULL ? &((struct we_dir_conf *) l->dirv)->c : NULL;

            if (l->kind > WE_DIR_ALLOW_INFERRED) {
                continue;                      /* the module's own: not the compiler's */
            }
            dirs[k].kind = l->kind;
            dirs[k].context = l->kind == WE_DIR_FLOOR ? "http" : (d != NULL && d->path != NULL ? d->path : "http");
            dirs[k].arg = (const uint8_t *) l->arg;
            dirs[k].len = l->len;
            k++;
        }
        src.d = dirs;
        src.n = (size_t) k;
        src.context = NULL;
        src.floor = 0;
    }

    /* the environment: the planes present and well-formed where the configuration reads them */
    we_peek_planes(b, pcfg, uid);
    memset(&env, 0, sizeof env);
    for (p = 0u; p < 8u; p++) {
        if (pcfg[p].present) {
            env.present = (uint8_t) (env.present | (1u << p));
        }
        if (pcfg[p].ok) {
            env.schema_ok = (uint8_t) (env.schema_ok | (1u << p));
        }
    }
    env.legacy = (uint8_t) (b->legacy != NULL);

    memset(&err, 0, sizeof err);
    rud.p = pconf;
    rud.s = s;
    rud.base = base;
    rud.lines = (const we_line_t *) base->lines->elts;
    rud.nlines = n;
    rep.line = we_report_line;
    rep.ud = &rud;
    rc = we_policy_build(&src, &env, NULL, &pb, &err, &rep);
    if (rc != WE_POLICY_OK || pb == NULL) {
        char text[1536];
        const we_line_t *bad = NULL;
        int j, k = 0;

        /* the directive the refusal points at, by its index among the compiler's lines */
        k = synthetic;                         /* the default's own line precedes the operator's */
        for (j = 0; j < n; j++) {
            const we_line_t *l = &((we_line_t *) base->lines->elts)[j];

            if (l->kind > WE_DIR_ALLOW_INFERRED) {
                continue;
            }
            if ((uint32_t) k == err.directive) {
                bad = l;
                break;
            }
            k++;
        }
        we_policy_error_format(&err, text, sizeof text);
        if (rc == WE_POLICY_NOMEM) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: out of memory compiling the policy");
        } else if (bad != NULL) {
            const we_dir_conf_t *d = bad->dirv != NULL ? &((struct we_dir_conf *) bad->dirv)->c : NULL;

            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: %s:%d: %s (%s): %s", bad->file,
                         bad->line, bad->name, d != NULL && d->path != NULL ? d->path : "http", text);
        } else {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: %s", text);
        }
        return DONE;
    }

    /* the http level's deny status, the spec, the export sets */
    {
        const we_ctx_item_t *it0 = &((const we_ctx_item_t *) items->elts)[0];

        if (it0->o->deny_status != 0) {
            http_status = (uint16_t) it0->o->deny_status;
        }
    }
    spec = apr_pcalloc(pconf, (size_t) items->nelts * sizeof *spec);
    b->attr_mask = apr_pcalloc(pconf, (size_t) items->nelts * sizeof *b->attr_mask);
    b->env_mask = apr_pcalloc(pconf, (size_t) items->nelts * sizeof *b->env_mask);
    for (i = 0u; i < (uint32_t) items->nelts; i++) {
        const we_ctx_item_t *it = &((const we_ctx_item_t *) items->elts)[i];
        const we_program_t *prog = we_policy_program(pb, it->path);
        const we_program_t *floor = we_policy_floor(pb);
        uint32_t attrs, def;
        uint8_t planes, pmask;
        const char *ex = we_nearest_export(items, (int) i);

        pmask = (uint8_t) ((floor != NULL ? floor->plane_mask : 0u) | (prog != NULL ? prog->plane_mask : 0u) | 0x80u);
        def = we_attrs_of_planes(pmask);
        we_export_parse(ex, &attrs, &planes);
        spec[i].path = it->path;
        spec[i].name = it->human;
        spec[i].deny_status = we_nearest_status(items, (int) i);
        spec[i].export_mask = (uint8_t) (pmask | planes);
        spec[i].gen_mask = spec[i].export_mask;
        b->attr_mask[i] = def | attrs;
        b->env_mask[i] = attrs;
        if (prog != NULL) {
            uint32_t m = prog->plane_mask;

            /* a keyed plane (routing, registry) binds only from http-level configuration */
            read_mask |= it->http ? m : (m & ~((1u << 3) | (1u << 6)));
            if (it->http) {
                http_mask |= m;
            }
        }
        read_mask |= it->http ? planes : (planes & ~((1u << 3) | (1u << 6)));
    }
    read_mask |= we_policy_floor(pb) != NULL ? we_policy_floor(pb)->plane_mask : 0u;
    b->http_ctx = 0u;

    /* the arena and the request path's configuration */
    b->arena = we_mod_arena_new();
    if (b->arena == NULL) {
        we_policy_build_free(pb);
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: out of memory (the arena)");
        return DONE;
    }
    apr_pool_cleanup_register(pconf, b->arena, we_arena_cleanup, apr_pool_cleanup_null);
    rc = we_mod_config_build(WE_MODULE_ABI_VERSION, b->arena, pb, &src, spec, (size_t) items->nelts, http_status,
                             &b->cfg, &b->ctxs, &b->stride, msg, sizeof msg);
    if (rc != 0) {
        we_policy_build_free(pb);
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: %s (%s)", msg, we_mod_strerror(rc));
        return DONE;
    }
    b->nctx = (size_t) items->nelts;
    for (i = 0u; i < (uint32_t) items->nelts; i++) {
        we_ctx_item_t *it = &((we_ctx_item_t *) items->elts)[i];

        if (i > 0u && it->d == ((const we_ctx_item_t *) items->elts)[0].d) {
            continue;                  /* a line-less virtual host shares the main's object; writing through it would hand the main server this context */
        }
        it->d->ctx = &b->ctxs[i];
        it->d->attr_mask = b->attr_mask[i];
        it->d->env_mask = b->env_mask[i];
        it->o->ctx = &b->ctxs[i];
        it->o->attr_mask = b->attr_mask[i];
        it->o->env_mask = b->env_mask[i];
    }

    /* the configuration-time lines, one per context (section 2.5) */
    for (i = 0u; i < (uint32_t) items->nelts; i++) {
        const we_ctx_item_t *it = &((const we_ctx_item_t *) items->elts)[i];
        const we_mod_ctx_t *x = &b->ctxs[i];
        const char *d16 = x->cold != NULL && x->prog != NULL ? x->cold->program_ctx + 6u : NULL;   /* after `floor:` */
        const char *ctxd = d16 != NULL ? strstr(d16, "ctx:") : NULL;
        char place[1024];

        if (it->o->file != NULL && (i == 0u || it->o != ((const we_ctx_item_t *) items->elts)[0].o)) {
            /* a line-less virtual host shares the main's marker: its context has no line of its own to point at */
            snprintf(place, sizeof place, " (%s:%d)", it->o->file, it->o->line);
        } else {
            place[0] = '\0';
        }
        if (x->prog == NULL) {
            we_say(base, APLOG_NOTICE, "whisper edge: policy: %s%s: no rules; the default allow under "
                         "mode %s", it->human, place, we_mode_word(we_conf_mode(&x->conf)));
        } else if (x->cold != NULL && x->cold->own) {
            we_say(base, APLOG_NOTICE, "whisper edge: policy: %s%s: %u rule%s, program %s, mode %s%s, "
                         "deny status %u, inherits nothing", it->human, place, x->rule_count, x->rule_count == 1u ? "" : "s",
                         ctxd != NULL ? ctxd + 4 : "-", we_mode_word(we_conf_mode(&x->conf)),
                         we_conf_inferred(&x->conf) ? " with inferred listings" : "", x->deny_status);
        } else {
            we_say(base, APLOG_NOTICE, "whisper edge: policy: %s%s: no lines of its own; runs program "
                         "%s under mode %s%s, deny status %u", it->human, place, ctxd != NULL ? ctxd + 4 : "-",
                         we_mode_word(we_conf_mode(&x->conf)), we_conf_inferred(&x->conf) ? " with inferred listings" : "",
                         x->deny_status);
        }
    }
    {
        const we_program_t *floor = b->cfg.floor;
        uint32_t fm = we_conf_mode(&b->cfg.floor_conf);
        int any_deny = 0;

        if (floor != NULL && floor->rule_count > 0u) {
            const char *fd = b->cfg.cold != NULL ? b->cfg.cold->program_none + 6u : "-";

            we_say(base, APLOG_NOTICE, "whisper edge: policy: floor: %u rule%s, program %.16s, mode %s "
                         "and deny status %u from the http level", floor->rule_count, floor->rule_count == 1u ? "" : "s",
                         fd, we_mode_word(fm), http_status);
            for (i = 0u; i < (uint32_t) items->nelts; i++) {
                any_deny |= we_conf_mode(&b->ctxs[i].conf) == WE_MODE_DENY;
            }
            if (fm != WE_MODE_DENY && any_deny) {
                we_say(base, APLOG_NOTICE, "whisper edge: policy: the floor will not deny: its mode is "
                             "the http level's (%s); add \"WhisperEdgeMode deny\" at http level", we_mode_word(fm));
            }
        }
    }
    /* mod_cache: its quick handler (on by default) serves a cached response before every access hook,
     * so with the floor or any rule a listed client can be handed a page this module never judged; the
     * warning names the setting that puts the judgment back in front of the cache, and a quick handler
     * of this module's own is deferred (section 17) */
    {
        int any_rule = 0;
        module *modp;

        for (i = 0u; i < b->nctx; i++) {
            any_rule |= b->ctxs[i].prog != NULL;
        }
        /* ap_find_linked_module compares against the module struct's own name field, which this httpd
         * fills with the module's source file (mod_cache.c), so asking it for "cache_module" never
         * matches, warning or not. The short-name table holds the LoadModule names without their
         * _module suffix (mod_cache's is "cache"; -M prints it back with the suffix), so the walk
         * asks that one, entry by entry. */
        b->mod_cache_loaded = 0u;
        for (modp = ap_top_module; modp != NULL; modp = modp->next) {
            const char *mn = ap_find_module_short_name(modp->module_index);

            if (mn != NULL && strcmp(mn, "cache") == 0) {
                b->mod_cache_loaded = 1u;
                break;
            }
        }
        if (b->mod_cache_loaded && (b->cfg.floor != NULL || any_rule)) {
            we_say(base, APLOG_WARNING, "whisper edge: policy: mod_cache's quick handler serves cached responses "
                         "before this module judges them; set CacheQuickHandler off");
        }
    }
    /* the data line: what each plane is at configuration time */
    {
        char line[2048];
        size_t o = 0u;
        const char *where = b->data_dir != NULL ? b->data_dir : b->legacy;

        o += (size_t) snprintf(line + o, sizeof line - o, "whisper edge: policy: %s \"%s\":",
                               b->data_dir != NULL || b->legacy == NULL ? "data" : "snapshot",
                               where != NULL ? where : "(no directory)");
        for (p = 0u; p < 8u && o < sizeof line; p++) {
            const we_plane_cfg_t *c = &pcfg[p];
            const char *nm = we_mod_plane_word(p);
            char d16[17], until[32];

            const char *own = b->plane_file[p] != NULL ? b->plane_file[p] : p == 0u ? b->snapshot : NULL;

            if (b->data_dir == NULL && own == NULL) {
                continue;
            }
            if (own != NULL && b->legacy == NULL) {
                o += (size_t) snprintf(line + o, sizeof line - o, " %s file \"%s\"%s", nm, own,
                                       b->plane_file[p] != NULL ? "" : " (the snapshot)");
            }
            if (!c->present) {
                if (((read_mask >> p) & 1u) != 0u || p == 7u || b->plane_file[p] != NULL) {
                    o += (size_t) snprintf(line + o, sizeof line - o, " %s absent;", nm);
                }
                continue;
            }
            if (c->unreadable) {
                o += (size_t) snprintf(line + o, sizeof line - o, " %s present, unreadable by uid %u (%s): rules on it are "
                                       "inert;", nm, uid, strerror(c->err));
                continue;
            }
            if (!c->ok) {
                o += (size_t) snprintf(line + o, sizeof line - o, " %s present, refused (%s);", nm, c->why);
                continue;
            }
            we_digest16(c->pk.digest, d16);
            we_iso_time(c->pk.valid_until_ms, until);
            if (((read_mask >> p) & 1u) == 0u && p != 7u && b->plane_file[p] == NULL) {   /* a plane's own line binds it */
                o += (size_t) snprintf(line + o, sizeof line - o, " %s present, not bound: nothing in this configuration "
                                       "reads it;", nm);
            } else {
                o += (size_t) snprintf(line + o, sizeof line - o, " %s generation %llu digest %s valid until %s, format %u%s, "
                                       "owner %u mode %04o;", nm, (unsigned long long) c->pk.generation, d16, until,
                                       (unsigned) c->pk.format, env.legacy && p == 0u ? ", legacy" : "", c->pk.uid, c->pk.mode);
            }
        }
        if (b->data_dir != NULL && b->snapshot == NULL && b->plane_file[0] == NULL && !pcfg[0].present) {
            /* reputation absent: say where snapshot.bin is if it is here, with the fix */
            char sp[1024], w[128];
            we_mod_peek_t pk;
            int dfd = -1;

            snprintf(sp, sizeof sp, "%s", b->data_dir);
            if (we_mod_dir_open(sp, uid, &dfd, w, sizeof w) == 0) {
                if (we_plane_peek(dfd, "snapshot.bin", 1u, &pk, w, sizeof w) == 0) {
                    char until[32];

                    we_iso_time(pk.valid_until_ms, until);
                    o += (size_t) snprintf(line + o, sizeof line - o, " (snapshot.bin is here, generation %llu, valid "
                                           "until %s: add \"WhisperEdgeSnapshot %s/snapshot.bin\" to read it, or install "
                                           "it as reputation.bin)", (unsigned long long) pk.generation, until, b->data_dir);
                }
                close(dfd);
            }
        }
        we_say(base, APLOG_NOTICE, "%s", line);
    }
    /* the summary line: the blocks and the counters, and where the read-only pages lie (the gate reads them) */
    {
        char regions[2048];
        size_t o = 0u, hot = 0u;
        uint32_t k, slots = 0u;
        const we_program_t *seen[64];
        uint32_t nseen = 0u;

        for (i = 0u; i < (uint32_t) items->nelts; i++) {
            const we_program_t *pr = b->ctxs[i].prog;

            if (pr == NULL) {
                continue;
            }
            for (k = 0u; k < nseen && seen[k] != pr; k++) {
            }
            if (k == nseen && nseen < 64u) {
                seen[nseen++] = pr;
                hot += pr->hot_len;
                if (o < sizeof regions) {
                    o += (size_t) snprintf(regions + o, sizeof regions - o, " program %lx-%lx", (unsigned long) (uintptr_t) pr,
                                           (unsigned long) ((uintptr_t) pr + we_program_size(pr)));
                }
            }
            if (b->ctxs[i].cold != NULL && b->ctxs[i].cold->own) {
                slots += b->ctxs[i].rule_count;
            }
        }
        if (b->cfg.floor != NULL) {
            hot += b->cfg.floor->hot_len;
            if (o < sizeof regions) {
                o += (size_t) snprintf(regions + o, sizeof regions - o, " floor %lx-%lx", (unsigned long) (uintptr_t) b->cfg.floor,
                                       (unsigned long) ((uintptr_t) b->cfg.floor + we_program_size(b->cfg.floor)));
            }
        }
        if (b->cfg.hh != NULL && o < sizeof regions) {
            o += (size_t) snprintf(regions + o, sizeof regions - o, " hold-harmless-view %lx-%lx",
                                   (unsigned long) (uintptr_t) b->cfg.hh, (unsigned long) ((uintptr_t) b->cfg.hh + sizeof *b->cfg.hh));
        }
        we_say(base, APLOG_NOTICE, "whisper edge: policy: %u distinct program%s and the floor, %lu hot "
                     "bytes in all (configuration-wide, after interning); counters %d context%s, %u rules, %u floor rules, "
                     "8 pre-stage, %u bytes per shard; %lu arena pages; read-only regions:%s", nseen, nseen == 1u ? "" : "s",
                     (unsigned long) hot, items->nelts, items->nelts == 1 ? "" : "s", slots,
                     b->cfg.floor != NULL ? b->cfg.floor->rule_count : 0u, b->stride * 8u,
                     (unsigned long) we_mod_arena_pages(b->arena), regions);
    }

    /* the counter map and the configuration file's bytes, which the workers write once */
    {
        we_mod_ctrmap_entry_t *e = apr_pcalloc(pconf, (size_t) (items->nelts + 1) * sizeof *e);
        uint32_t ne = 0u;
        const char *unreadable[8];
        const char **pp = apr_pcalloc(pconf, 8u * sizeof *pp);
        we_mod_text_t t;
        size_t cap = 4096u;

        if (b->cfg.floor != NULL && b->cfg.floor->rule_count > 0u && b->cfg.cold != NULL) {
            e[ne].ctr_off = WE_MOD_CTR_FLOOR;
            e[ne].rule_count = b->cfg.floor->rule_count;
            memcpy(e[ne].digest16, b->cfg.cold->program_none + 6u, 16u);
            e[ne].digest16[16] = '\0';
            ne++;
        }
        for (i = 0u; i < (uint32_t) items->nelts; i++) {
            const we_mod_ctx_t *x = &b->ctxs[i];
            const char *cd;

            if (x->prog == NULL || x->cold == NULL || !x->cold->own) {
                continue;
            }
            cd = strstr(x->cold->program_ctx, "ctx:");
            if (cd == NULL) {
                continue;
            }
            e[ne].ctr_off = x->ctr_off;
            e[ne].rule_count = x->rule_count;
            memcpy(e[ne].digest16, cd + 4, 16u);
            e[ne].digest16[16] = '\0';
            ne++;
            for (p = 0u; p < x->rule_count; p++) {
                cap += 64u + 4u * strlen(x->cold->rule_text[p]);
            }
            cap += 64u + 4u * strlen(x->cold->name) + 4u * strlen(x->cold->path);
        }
        if (b->cfg.floor != NULL && b->cfg.cold != NULL) {
            for (p = 0u; p < b->cfg.floor->rule_count; p++) {
                cap += 64u + 4u * strlen(b->cfg.cold->rule_text[p]);
            }
        }
        b->ctrmap.e = e;
        b->ctrmap.n = ne;
        /* the core's check-only bind (we_mod_bind_check): every check the bind makes, nothing mapped, armed or logged.
         * Its results name each plane's path, its unreadable text and its refusal at configuration, so the
         * configuration test and the bound file can never disagree; the configuration test fails on the whole
         * refusal (the snapshot and a reputation line) and on every plane refused at configuration, by the core's
         * own sentence. A real start only reads the paths here: the bind's refusals are served fail open */
        {
            we_mod_bind_args_t ca = WE_MOD_BIND_ARGS_INIT;
            we_mod_plane_check_t *chk = apr_pcalloc(ptemp, 8u * sizeof *chk);
            char cmsg[512];
            int crc, test = ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_TEST, nref = 0;

            ca.data_dir = b->data_dir;
            ca.legacy_file = b->snapshot;
            memcpy(ca.plane_file, b->plane_file, sizeof ca.plane_file);
            ca.read_mask = (uint8_t) (read_mask & 0xffu);
            ca.uid = uid;
            crc = (b->data_dir != NULL || b->snapshot != NULL || we_any_plane_file(b->plane_file))
                ? we_mod_bind_check(&ca, chk, cmsg, sizeof cmsg) : 0;
            if (crc != 0) {
                if (test) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: %s (WhisperEdgeSnapshot at %s, "
                                 "WhisperEdgeData reputation at %s)", cmsg, base->snapshot_at != NULL ? base->snapshot_at : "-",
                                 base->plane_at[0] != NULL ? base->plane_at[0] : "-");
                    we_policy_build_free(pb);
                    return DONE;
                }
                memset(chk, 0, 8u * sizeof *chk);   /* a real start: the bind refuses the same and is served fail open */
            }
            for (p = 0u; p < 8u; p++) {
                unreadable[p] = strcmp(chk[p].state, "unreadable") == 0 ? apr_pstrdup(pconf, chk[p].reason) : NULL;
                b->unreadable[p] = unreadable[p];
                b->refused[p] = chk[p].config_refused ? apr_pstrdup(pconf, chk[p].reason) : NULL;
                pp[p] = chk[p].path[0] != '\0' ? apr_pstrdup(pconf, chk[p].path) : NULL;
                if (pp[p] != NULL) {
                    cap += 128u + 4u * strlen(pp[p]) + (b->refused[p] != NULL ? 4u * strlen(b->refused[p]) : 0u);
                }
                if (test && chk[p].config_refused) {
                    char sent[1024];

                    (void) we_mod_refused_sentence(sent, sizeof sent, p, chk[p].reason);
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "%s", sent);
                    nref++;
                }
            }
            if (nref != 0) {
                we_policy_build_free(pb);
                return DONE;
            }
        }
        plane_path = pp;
        t.buf = apr_palloc(pconf, cap);
        t.len = 0u;
        t.cap = cap;
        t.over = 0;
        we_mod_render_conf(&t, &b->cfg, b->ctxs, b->nctx, plane_path, unreadable, (const char *const *) b->refused);
        if (t.over) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: the configuration file does not fit "
                         "its computed size (%lu bytes)", (unsigned long) cap);
            we_policy_build_free(pb);
            return DONE;
        }
        b->conf_text = t.buf;
        b->conf_len = t.len;
        we_mod_conf_name(&t, b->conf_name);
        memcpy(b->config16, b->conf_name + 5, 16u);
        b->config16[16] = '\0';
    }
    (void) http_mask;
    we_policy_build_free(pb);
    if (we_mod_arena_seal(b->arena) != 0) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: the arena cannot be made read-only");
        return DONE;
    }
    /* the planes some program reads, for the binding (the tenant plane binds whenever present) */
    b->cfg.bound_mask = 0u;
    b->bound_before_fork = 0u;
    {
        /* remembered for post_config through the build: the read mask rides in the trust struct's padding-free field */
        b->cfg.static_reason[0] = 0u;
    }
    apr_pool_userdata_set((void *) (uintptr_t) (read_mask | 0x100u), "whisper_edge_read_mask", apr_pool_cleanup_null, pconf);
    if (ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_TEST) {
        we_say_flush(base, s);                 /* the configuration test: the lines are its output */
    }
    return OK;
}

/* ---------------------------------------------------------------------------------------------- */
/* post_config: the parent binds the planes once, in the real pass                                 */
/* ---------------------------------------------------------------------------------------------- */

static void we_bind_log(void *ud, const char *entry)
{
    /* the core's sentence for a plane refused at configuration (we_mod_refused_sentence) carries its own prefix and is
     * an error: the plane reads unknown until the configuration is fixed */
    if (strncmp(entry, "whisper edge: ", 14) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, (server_rec *) ud, "%s", entry);
        return;
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, (server_rec *) ud, "whisper edge: %s", entry);
}

static int we_monitor(apr_pool_t *p, server_rec *s);

/*
 * The configuration file's bytes again after the bind, with each `plane <p> path` line taken from the core
 * (we_mod_plane_path), the file the binding actually names. The rest of the file is what check_config rendered,
 * so its size bound is that file's length plus the new paths' worst-case escaping.
 */
static int we_render_bound_conf(we_build_t *b, apr_pool_t *pconf)
{
    const char *pp[8];
    we_mod_text_t t;
    size_t cap = b->conf_len + 4096u;
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        pp[p] = we_mod_plane_path(b->planes, p);
        b->refused[p] = we_mod_plane_config_refusal(b->planes, p);
        if (pp[p] != NULL) {
            cap += 128u + 4u * strlen(pp[p]) + (b->refused[p] != NULL ? 4u * strlen(b->refused[p]) : 0u);
        }
    }
    t.buf = apr_palloc(pconf, cap);
    t.len = 0u;
    t.cap = cap;
    t.over = 0;
    we_mod_render_conf(&t, &b->cfg, b->ctxs, b->nctx, pp, b->unreadable, (const char *const *) b->refused);
    if (t.over) {
        return -1;
    }
    b->conf_text = t.buf;
    b->conf_len = t.len;
    we_mod_conf_name(&t, b->conf_name);
    memcpy(b->config16, b->conf_name + 5, 16u);
    b->config16[16] = '\0';
    return 0;
}

static int we_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    we_srv_conf_t *base = ap_get_module_config(s->module_config, &whisper_edge_module);
    we_build_t *b = base != NULL ? base->build : NULL;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    void *data = NULL;
    char msg[512];
    int rc;

    (void) plog;
    (void) ptemp;
    ap_add_version_component(pconf, "whisper-edge/2");
    if (b == NULL) {
        return OK;
    }
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;                             /* the first of httpd's two passes: nothing is bound twice */
    }
    we_say_flush(base, s);                     /* the configuration-time lines, once, into the opened error log */
#ifdef WE_MOD_TEST_KEY_IN_PARENT
    {   /* the control build: a thread key created in the parent, one per config pass, the defect the
         * graceful-restart row exists to catch (the shipped build creates the key in child_init only,
         * so the parent's count stays 0 across every graceful) */
        pthread_key_t k;

        if (pthread_key_create(&k, NULL) == 0) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "whisper edge: thread key created");
        }
    }
#endif
    if (b->data_dir == NULL && b->snapshot == NULL && !we_any_plane_file(b->plane_file)) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "whisper edge: no WhisperEdgeData or WhisperEdgeSnapshot: every rule "
                     "on a plane is inert, and only the fixed exemptions and the default allow run");
        return OK;
    }
    apr_pool_userdata_get(&data, "whisper_edge_read_mask", pconf);
    args.data_dir = b->data_dir;
    args.legacy_file = b->snapshot;            /* the core decides: legacy alone, the reputation plane's file beside others */
    memcpy(args.plane_file, b->plane_file, sizeof args.plane_file);
    args.read_mask = (uint8_t) ((uintptr_t) data & 0xffu);
    args.uid = we_trusted_uid();
    args.log = we_bind_log;
    args.log_ud = s;
    rc = we_mod_bind(&b->cfg, &args, &b->planes, msg, sizeof msg);
    if (rc != 0) {
        /* fail open, never an exit: the configuration test names this refusal (check_config's trust walks); a server
         * started on it anyway binds nothing and answers every request, every rule on a plane reading unknown */
        b->planes = NULL;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "whisper edge: policy refused: %s (%s); serving with no plane bound, "
                     "every rule on a plane reads unknown, until a reload binds", msg, we_mod_strerror(rc));
        return OK;
    }
    b->bound_before_fork = 1u;
    apr_pool_cleanup_register(pconf, b->planes, we_planes_cleanup, apr_pool_cleanup_null);
    if (we_render_bound_conf(b, pconf) != 0) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: policy refused: the configuration file does not fit "
                     "its computed size after the bind");
        return DONE;
    }
    if (b->cfg.bound_mask == 0u) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "whisper edge: no plane is bound: every rule on a plane reads unknown "
                     "and is inert, and only the fixed exemptions and the default allow run");
    }
    return OK;
}

/* ---------------------------------------------------------------------------------------------- */
/* The child: shards, the module thread, the writers                                               */
/* ---------------------------------------------------------------------------------------------- */

/* one thread's counters: the shard, and the legacy copy's per-range sub-block */
typedef struct we_shard {
    struct we_shard *next;
    uint64_t        *ctr;          /* stride words, 64-byte aligned, this thread's alone */
    we_counters_t   *ranges;       /* the legacy reputation copy's per-range counts, this thread's */
    uint64_t         ranges_gen;
    uint32_t         ranges_v4, ranges_v6;
#if defined(WE_MOD_TEST_SHARD_OWNER) || defined(WE_MOD_TEST_MPM_SLOT)
    uint64_t         owner_tid;    /* the trap controls: the registering thread, so a build that hands a second
                                    * thread the same shard is caught writing it, loudly, at the write itself */
#endif
} we_shard_t;

typedef struct we_child {
    server_rec        *s;
    we_build_t        *b;
    pthread_key_t      key;
    int                key_ok;
    pthread_mutex_t    mu;
    we_shard_t        *shards;     /* live, under mu */
    uint64_t          *retired;    /* stride: the folded counts of ended threads, under mu */
    uint64_t          *sink;       /* stride, aligned: a thread with no shard counts here */
    uint64_t          *sum;        /* stride: the writer's scratch */
    we_counters_t     *ranges_retired;  /* ended threads' range counts for the current generation */
    uint64_t           ranges_retired_gen;
    uint32_t           live, retired_n;
    uint32_t           registrations, subblock_swaps;
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    uint32_t           dbg_dtor;   /* destructor entries, counted apart from retired_n so the export proves the two agree */
    uint64_t           dbg_alloc, dbg_freed;   /* the shard memory ledger: every byte the shard paths allocated and freed */
#endif
#ifdef WE_MOD_TEST_MPM_SLOT
    /* the control's wrong keying: one shard per MPM slot (the scoreboard worker the connection's handle
     * names), which under HTTP/1.1 is the slot's one thread but under h2 is written by every worker
     * that picks up one of the master connection's streams */
#define WE_SLOT_ROWS 256u
    const void        *slot_key[WE_SLOT_ROWS];
    we_shard_t        *slot_shard[WE_SLOT_ROWS];
#endif
    uint64_t           last_log_sec[2];   /* would-deny, deny: the per-process rate limit's last second */
    int                no_shard_said, no_ranges_said;
    we_mod_thread_t   *thr;
    int                no_thread;
    we_mod_procid_t    id;
    int                dirfd;
    int                dir_said;
    uint64_t           started_ms, offset_ms;
    we_mod_status_t   *st;
    we_mod_text_t      text;
    char               status_name[80], rules_name[80];
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    char               sharddbg_name[80];   /* the export's own file, <pid>-<id16>.shard, beside the status file */
#endif
    char               abandon_line[4][320];   /* one whole line per stage, formatted at child start */
    char               held_line[256];         /* the final write's line when the mutex stays held, likewise */
    size_t             held_len;
    size_t             abandon_len[4];         /* measured there too: the stop path calls no strlen */
    uint32_t           ntrans;
    uint64_t           trans_ms[WE_MOD_TRANSITIONS];
    char               trans[WE_MOD_TRANSITIONS][WE_MOD_RING_ENTRY];
    we_counters_t     *ranges_sum;
} we_child_t;

static we_child_t *g_child;      /* the one per process; NULL in the parent */


static uint64_t we_boottime_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u;
}

static uint64_t we_epoch_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u;
}

/* a zero fill no compiler turns into a memset call: the cold symbols' rows list no memset */
static void we_zero_words(uint64_t *p, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        p[i] = 0u;
        __asm__ __volatile__("" : : : "memory");
    }
}

/* the shard-list mutex is taken through one pair, so the gate's debug build can mark the held span: the holder's
 * thread id sits in an exported word the preloaded interposer reads, and an I/O call made by the thread that
 * holds the mutex is a fault it counts (the production rule: no file I/O under the shard-list mutex) */
#ifdef WE_MOD_TEST_MU_FLAG
__attribute__((visibility("default"))) volatile unsigned long we_mod_test_mu_holder;
#endif
static inline void we_mu_lock(we_child_t *ch)
{
    pthread_mutex_lock(&ch->mu);
#ifdef WE_MOD_TEST_MU_FLAG
    we_mod_test_mu_holder = (unsigned long) syscall(SYS_gettid);
#endif
}
/* the final write's bounded try: 200 tries 5 ms apart, one second at most, well inside the stop's first window */
static int we_final_lock(we_child_t *ch)
{
    struct timespec ts = { 0, 5000000 };
    int k;

#ifdef WE_MOD_TEST_FINAL_BLOCKING
    we_mu_lock(ch);                            /* the control: the blocking lock the try-lock replaced */
    return 1;
#endif
    for (k = 0; k < 200; k++) {
        if (pthread_mutex_trylock(&ch->mu) == 0) {
#ifdef WE_MOD_TEST_MU_FLAG
            we_mod_test_mu_holder = (unsigned long) syscall(SYS_gettid);
#endif
            return 1;
        }
        nanosleep(&ts, NULL);
    }
    return 0;
}
#ifdef WE_MOD_TEST_TICK_AT_STOP
static int we_test_tick_waiting;               /* the row's setup: set by a tick about to take the mutex */
#endif
/*
 * A tick's lock: blocking, as long as no stop has been asked for. A stop that lands while a request thread holds the
 * mutex (prefork's SIGTERM handler interrupting a first request's registration) and while this thread is inside a
 * tick waiting for that same mutex would otherwise hold the tick until the stop's 6 s cap abandons it, as "a tick's
 * own work" (measured on a loaded walk: 4 abandonments in a tick's own work against a held mutex). So the wait is in
 * 5 ms slices, each checking the stop word; on a stop it gives the tick up, the counts stay for the final write, and
 * the final write's bounded try decides them. Returns 1 holding the mutex, 0 on a stop.
 */
static int we_tick_lock_wait(we_child_t *ch, const int *stop);
static int we_tick_lock(we_child_t *ch, const int *stop)
{
    int got;

#ifdef WE_MOD_TEST_TICK_AT_STOP
    __atomic_store_n(&we_test_tick_waiting, 1, __ATOMIC_RELEASE);   /* 1 only while this thread waits */
#endif
    got = we_tick_lock_wait(ch, stop);
#ifdef WE_MOD_TEST_TICK_AT_STOP
    __atomic_store_n(&we_test_tick_waiting, 0, __ATOMIC_RELEASE);
#endif
    return got;
}
static int we_tick_lock_wait(we_child_t *ch, const int *stop)
{
#ifdef WE_MOD_TEST_TICK_BLOCKING
    (void) stop;
    we_mu_lock(ch);                            /* the control: the blocking tick lock this replaced */
    return 1;
#else
    for (;;) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 5000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        if (pthread_mutex_timedlock(&ch->mu, &ts) == 0) {
#ifdef WE_MOD_TEST_MU_FLAG
            we_mod_test_mu_holder = (unsigned long) syscall(SYS_gettid);
#endif
            return 1;
        }
        if (stop != NULL && __atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
            return 0;
        }
    }
#endif
}
static inline void we_mu_unlock(we_child_t *ch)
{
#ifdef WE_MOD_TEST_MU_FLAG
    we_mod_test_mu_holder = 0u;
#endif
    pthread_mutex_unlock(&ch->mu);
}
#ifdef WE_MOD_TEST_GLOBAL_SHARD
/* the control's one shared array: every thread's load-and-store lands here, so concurrent writers lose
 * counts; the tick writer sums it as one more source, which is what the row's control reads */
uint64_t we_mod_test_shard[4096];
#endif

/* every aligned_alloc(64) here asks for a multiple of 64 bytes: C11 requires the size to be a multiple of the
 * alignment, and ASan reports the call otherwise (invalid-aligned-alloc-alignment), which the sanitizer row
 * measured on a 16-word stride and a 4-range sub-block before this rounding */
#define WE_ROUND64(n) (((size_t) (n) + 63u) & ~(size_t) 63u)
#define WE_SHARD_HDR_BYTES WE_ROUND64(sizeof(we_shard_t))
#define WE_SHARD_CTR_BYTES(stride) WE_ROUND64((size_t) (stride) * 8u)
/* the ranges sub-block's exact allocation size, the one arithmetic the swap allocates by and the ledger counts */
static size_t we_ranges_bytes(uint32_t v4, uint32_t v6)
{
    return WE_ROUND64(WE_ROUND64(sizeof(we_counters_t)) + ((size_t) v4 + (size_t) v6) * 8u + 64u);
}

/* a thread ended: its shard's counts join the child's retired total, its sub-block the retired ranges */
static void we_shard_destructor(void *v)
{
    we_shard_t *sh = v;
    we_child_t *ch = g_child;
    uint32_t i;

    if (sh == NULL || ch == NULL) {
        return;
    }
    we_mu_lock(ch);
    for (i = 0u; i < ch->b->stride; i++) {
        ch->retired[i] += __atomic_load_n(&sh->ctr[i], __ATOMIC_RELAXED);
    }
    if (sh->ranges != NULL && ch->ranges_retired != NULL && ch->ranges_retired_gen == sh->ranges_gen) {
        for (i = 0u; i < sh->ranges_v4; i++) {
            ch->ranges_retired->v4_hits[i] += sh->ranges->v4_hits[i];
        }
        for (i = 0u; i < sh->ranges_v6; i++) {
            ch->ranges_retired->v6_hits[i] += sh->ranges->v6_hits[i];
        }
        ch->ranges_retired->denied += sh->ranges->denied;
    }
    {
        we_shard_t **pp = &ch->shards;

        while (*pp != NULL && *pp != sh) {
            pp = &(*pp)->next;
        }
        if (*pp == sh) {
            *pp = sh->next;
            ch->live--;
            ch->retired_n++;
        }
    }
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    ch->dbg_dtor++;
#ifndef WE_MOD_TEST_NO_RELEASE
    ch->dbg_freed += WE_SHARD_HDR_BYTES + WE_SHARD_CTR_BYTES(ch->b->stride);
    if (sh->ranges != NULL) {
        ch->dbg_freed += we_ranges_bytes(sh->ranges_v4, sh->ranges_v6);
    }
#endif
#endif
    we_mu_unlock(ch);
#ifndef WE_MOD_TEST_NO_RELEASE
    free(sh->ctr);
    free(sh->ranges);
    free(sh);
#endif
}

/*
 * THE FIRST JUDGED REQUEST ON A THREAD: its shard, aligned_alloc(64), zeroed, registered under the
 * child's mutex for the tick writer, and bound to the thread's key with the destructor above. A
 * symbol of its own, so the gate can show that the access hook's only locking call sits here.
 * NULL when the child has no key or no memory: the caller counts into the sink.
 */
WE_COLD_SYMBOL we_shard_t *we_apache_shard_register(we_child_t *ch)
{
    we_shard_t *sh;
    uint64_t *ctr;

    if (ch == NULL || !ch->key_ok) {
        return NULL;
    }
#ifdef WE_MOD_TEST_SHARD_OWNER
    {   /* the control's wrong keying: every thread shares the first thread's shard, so the ownership
         * trap at the write catches the second writer; the sharers' keys stay unset, so no destructor
         * ever runs on a shard another thread is still writing */
        we_shard_t *first;

        we_mu_lock(ch);
        first = ch->shards;
        we_mu_unlock(ch);
        if (first != NULL) {
            return first;
        }
    }
#endif
    sh = (we_shard_t *) aligned_alloc(64u, WE_SHARD_HDR_BYTES);
    ctr = (uint64_t *) aligned_alloc(64u, WE_SHARD_CTR_BYTES(ch->b->stride));
    if (sh == NULL || ctr == NULL) {
        free(sh);
        free(ctr);
        return NULL;
    }
    we_zero_words((uint64_t *) (void *) sh, WE_SHARD_HDR_BYTES / 8u);
    we_zero_words(ctr, WE_SHARD_CTR_BYTES(ch->b->stride) / 8u);
    sh->ctr = ctr;
#if defined(WE_MOD_TEST_SHARD_OWNER) || defined(WE_MOD_TEST_MPM_SLOT)
    sh->owner_tid = (uint64_t) syscall(SYS_gettid);   /* the trap's owner: the thread that registered */
#endif
#ifdef WE_MOD_TEST_MU_FLAG
    {   /* the debug build times the wait for the mutex at a registration, and prints every wait over 1 ms: the
         * writer's I/O runs outside the mutex, so a new worker's first request should never wait on it */
        struct timespec t0, t1;
        unsigned long us;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        we_mu_lock(ch);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        us = (unsigned long) ((t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000L);
        if (us > 1000u) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, "whisper edge: a registration waited %lu us for the shard mutex", us);
        }
    }
#else
    we_mu_lock(ch);
#endif
    sh->next = ch->shards;
    ch->shards = sh;
    ch->live++;
    ch->registrations++;
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    ch->dbg_alloc += WE_SHARD_HDR_BYTES + WE_SHARD_CTR_BYTES(ch->b->stride);
#endif
    we_mu_unlock(ch);
    if (pthread_setspecific(ch->key, sh) != 0) {
        return sh;                             /* the shard stays registered; the next request registers again */
    }
    return sh;
}

/*
 * THE LEGACY COPY'S RANGE COUNTERS: a sub-block per thread, tagged with the generation and counts of the
 * map it indexes, replaced on the thread's first judged request after a publish; the old one is folded
 * into the child's retired ranges under the mutex. A symbol of its own, like the registration.
 */
WE_COLD_SYMBOL void we_apache_subblock_swap(we_child_t *ch, we_shard_t *sh, const we_map_t *m)
{
    size_t bytes;
    we_counters_t *c;
    uint64_t *hits;
    uint32_t i;

    if (ch == NULL || sh == NULL || m == NULL) {
        return;
    }
    bytes = WE_ROUND64(sizeof *c);
    c = (we_counters_t *) aligned_alloc(64u, we_ranges_bytes(m->v4_count, m->v6_count));
    if (c != NULL) {
        /* the new block is filled while it is still this thread's alone, and published below under the mutex the
         * module thread sums it under, so the tick never sees the pointer before the fields it leads to */
        we_zero_words((uint64_t *) (void *) c, we_ranges_bytes(m->v4_count, m->v6_count) / 8u);
        hits = (uint64_t *) (void *) ((uint8_t *) c + bytes);
        c->generation = m->generation;
        c->v4_count = m->v4_count;
        c->v6_count = m->v6_count;
        c->v4_hits = m->v4_count != 0u ? hits : NULL;
        c->v6_hits = m->v6_count != 0u ? hits + m->v4_count : NULL;
    }
    we_mu_lock(ch);
    if (sh->ranges != NULL) {
        if (ch->ranges_retired != NULL && ch->ranges_retired_gen == sh->ranges_gen) {
            for (i = 0u; i < sh->ranges_v4; i++) {
                ch->ranges_retired->v4_hits[i] += sh->ranges->v4_hits[i];
            }
            for (i = 0u; i < sh->ranges_v6; i++) {
                ch->ranges_retired->v6_hits[i] += sh->ranges->v6_hits[i];
            }
            ch->ranges_retired->denied += sh->ranges->denied;
        }
        free(sh->ranges);
        sh->ranges = NULL;
#ifdef WE_MOD_TEST_EXPORT_SHARDS
        ch->dbg_freed += we_ranges_bytes(sh->ranges_v4, sh->ranges_v6);
#endif
    }
    ch->subblock_swaps++;
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    if (c != NULL) {
        ch->dbg_alloc += we_ranges_bytes(m->v4_count, m->v6_count);
    }
#endif
#ifndef WE_MOD_TEST_SUBBLOCK_UNLOCKED
    if (c != NULL) {
        sh->ranges_gen = m->generation;
        sh->ranges_v4 = m->v4_count;
        sh->ranges_v6 = m->v6_count;
        sh->ranges = c;
    }
    we_mu_unlock(ch);
#else
    /* the control: the block published after the unlock with plain stores, the order the candidate had */
    we_mu_unlock(ch);
    if (c != NULL) {
        sh->ranges = c;
        sh->ranges_gen = m->generation;
        sh->ranges_v4 = m->v4_count;
        sh->ranges_v6 = m->v6_count;
    }
#endif
}

static void we_child_log(void *ud, const char *entry)
{
    we_child_t *ch = ud;

#ifdef WE_MOD_TEST_DROP_LOG
    return;                            /* the control build: the refresher's line never reaches the logger,
                                        * so a row that greps the file or the socket can fail, not pass vacuously */
#endif
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ch->s, "whisper edge: %s", entry);
    if (strncmp(entry, "plane ", 6) == 0) {
        uint32_t k = ch->ntrans < WE_MOD_TRANSITIONS ? ch->ntrans : WE_MOD_TRANSITIONS - 1u;

        if (ch->ntrans >= WE_MOD_TRANSITIONS) {
            memmove(ch->trans[0], ch->trans[1], (WE_MOD_TRANSITIONS - 1u) * WE_MOD_RING_ENTRY);
            memmove(ch->trans_ms, ch->trans_ms + 1, (WE_MOD_TRANSITIONS - 1u) * sizeof ch->trans_ms[0]);
        }
        snprintf(ch->trans[k], WE_MOD_RING_ENTRY, "%s", entry);
        ch->trans_ms[k] = we_boottime_ms();
        if (ch->ntrans < WE_MOD_TRANSITIONS) {
            ch->ntrans++;
        }
    }
}

static int we_write_text(we_child_t *ch, const char *kind, const char *name)
{
    char why[256];
    int rc;

    if (ch->dirfd < 0 || ch->text.over) {
        return -1;
    }
    rc = we_mod_write_file(ch->dirfd, &ch->id, kind, name, ch->text.buf, ch->text.len, why, sizeof why);
    if (rc != 0 && rc != WE_ERR_PERMISSIONS && !ch->dir_said) {
        ch->dir_said = 1;
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ch->s, "whisper edge: cannot write %s into %s (%s); blocking is "
                     "unaffected and whisper-edge-summary will have nothing to read from this process", name,
                     ch->b->counters_dir, why);
    }
    return rc;
}

/* the tick, on the module's thread: the planes, their results applied here (the refresher is the writer), the files */
#ifdef WE_MOD_TEST_EXPORT_SHARDS
/* the shard export's one append: the text buffer's own over flag carries the cut */
static void we_dbg_append(we_mod_text_t *t, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (t->over || t->len >= t->cap) {
        t->over = 1;
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(t->buf + t->len, t->cap - t->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t) n >= t->cap - t->len) {
        t->over = 1;
        return;
    }
    t->len += (size_t) n;
}
#endif

static void we_tick_write(we_child_t *ch, uint64_t tick, int final, const int *stop)
{
    we_build_t *b = ch->b;
    uint64_t now = we_epoch_ms(), boot = we_boottime_ms();
    uint32_t i, live = 0u;
    int counted = 1;
    we_shard_t *sh;
    const we_map_t *rep = b->cfg.handle[0] != NULL ? we_current(b->cfg.handle[0]) : NULL;
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    uintptr_t dbg_base[128];
    size_t dbg_rng[128];
    uint32_t dbg_n = 0u, dbg_trunc = 0u;
    uint64_t dbg_alloc = 0u, dbg_freed = 0u;   /* snapshotted under the mutex, so the head and the shard lines
                                               * describe one instant and a registration between them cannot
                                               * make the ledger disagree with the lines it names */
    uint32_t dbg_dtor = 0u, dbg_reg = 0u, dbg_swaps = 0u, dbg_retired = 0u;
#endif

    /* the counters: live shards and the retired total, summed into the scratch under the mutex, no I/O inside. The
     * final write takes the mutex by a bounded try: prefork runs the stop inside its SIGTERM handler on the main
     * thread, which may hold the mutex where the signal interrupted it (a first request's registration, a sub-block
     * swap), and a blocking lock would hold the final write until the stop's 6 s cap abandons it. When the try runs
     * out, the status file is written and the rule counts are not: the last tick's file stands, and one line says the
     * counts since it are not written */
    if (final) {
        if (!we_final_lock(ch)) {
            ssize_t w;

            do {
                w = write(STDERR_FILENO, ch->held_line, ch->held_len);
            } while (w < 0 && errno == EINTR);
            counted = 0;
        }
    } else if (!we_tick_lock(ch, stop)) {
        counted = 0;                           /* a stop: this tick's counts are the final write's */
    }
    if (!counted) {
        goto no_count;
    }
    for (i = 0u; i < b->stride; i++) {
        ch->sum[i] = ch->retired[i];
    }
    for (sh = ch->shards; sh != NULL; sh = sh->next) {
        live++;
        for (i = 0u; i < b->stride; i++) {
            ch->sum[i] += __atomic_load_n(&sh->ctr[i], __ATOMIC_RELAXED);
        }
#ifdef WE_MOD_TEST_EXPORT_SHARDS
        if (dbg_n < (uint32_t) (sizeof dbg_base / sizeof dbg_base[0])) {
            dbg_base[dbg_n] = (uintptr_t) sh->ctr;
            dbg_rng[dbg_n] = sh->ranges != NULL ? we_ranges_bytes(sh->ranges_v4, sh->ranges_v6) : (size_t) 0u;
            dbg_n++;
        } else {
            dbg_trunc++;
        }
#endif
    }
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    dbg_alloc = ch->dbg_alloc;
    dbg_freed = ch->dbg_freed;
    dbg_dtor = ch->dbg_dtor;
    dbg_reg = ch->registrations;
    dbg_swaps = ch->subblock_swaps;
    dbg_retired = ch->retired_n;
#endif
#ifdef WE_MOD_TEST_GLOBAL_SHARD
    /* the control: the shared array is one more source, so its lost counts are what the file carries */
    for (i = 0u; i < b->stride; i++) {
        ch->sum[i] += __atomic_load_n(&we_mod_test_shard[i], __ATOMIC_RELAXED);
    }
#endif
    /* the legacy copy's per-range counts, summed the same way for the range-counter file */
    /* the final write allocates nothing: a generation it has no block for keeps the last tick's range file */
    if (rep != NULL && b->planes != NULL && b->legacy != NULL
            && (!final || (ch->ranges_sum != NULL && ch->ranges_sum->generation == rep->generation))) {
        if (ch->ranges_sum == NULL || ch->ranges_sum->generation != rep->generation) {
            we_counters_free(ch->ranges_sum);
            ch->ranges_sum = we_counters_new(rep, now);
            we_counters_free(ch->ranges_retired);
            ch->ranges_retired = we_counters_new(rep, now);
            ch->ranges_retired_gen = rep->generation;
        }
        if (ch->ranges_sum != NULL) {
            we_counters_t *sum = ch->ranges_sum;

            for (i = 0u; i < sum->v4_count; i++) {
                sum->v4_hits[i] = ch->ranges_retired != NULL ? ch->ranges_retired->v4_hits[i] : 0u;
            }
            for (i = 0u; i < sum->v6_count; i++) {
                sum->v6_hits[i] = ch->ranges_retired != NULL ? ch->ranges_retired->v6_hits[i] : 0u;
            }
            sum->denied = ch->ranges_retired != NULL ? ch->ranges_retired->denied : 0u;
            for (sh = ch->shards; sh != NULL; sh = sh->next) {
#ifdef WE_MOD_TEST_RANGES_UNCHECKED
                if (sh->ranges == NULL) {          /* the control sums a stale block as the current map's */
                    continue;
                }
#else
                if (sh->ranges == NULL || sh->ranges_gen != rep->generation) {
                    continue;
                }
#endif
                for (i = 0u; i < sum->v4_count && i < sh->ranges_v4; i++) {
                    sum->v4_hits[i] += __atomic_load_n(&sh->ranges->v4_hits[i], __ATOMIC_RELAXED);
                }
                for (i = 0u; i < sum->v6_count && i < sh->ranges_v6; i++) {
                    sum->v6_hits[i] += __atomic_load_n(&sh->ranges->v6_hits[i], __ATOMIC_RELAXED);
                }
                sum->denied += __atomic_load_n(&sh->ranges->denied, __ATOMIC_RELAXED);
            }
        }
    }
    we_mu_unlock(ch);
no_count:

    if (ch->dirfd < 0) {
        return;
    }
#ifdef WE_MOD_TEST_LOCKED_WRITE
    we_mu_lock(ch);                            /* the control: the writer's file I/O runs under the shard-list mutex */
#endif
    /* the status file */
    {
        we_mod_status_t *st = ch->st;

        memset(st, 0, sizeof *st);
        st->server = WE_SERVER_WORD;
        st->started_ms = ch->started_ms;
        st->written_ms = boot;
        st->interval_ms = b->interval_ms;
        st->jitter_ms = ch->offset_ms;
        st->handoff_ms = 0u;
        st->tick = tick;
        memcpy(st->config16, b->config16, sizeof st->config16);
        st->no_thread = (uint8_t) ch->no_thread;
        st->shards = live;
        st->retired = ch->retired_n;
        if (b->planes != NULL) {
            we_mod_planes_status(b->planes, st, now);   /* fills the transition ring too (ABI 4): the module's own copy went */
        }
        ch->text.len = 0u;
        ch->text.over = 0;
        we_mod_render_status(&ch->text, &ch->id, st);
        we_write_text(ch, "status", ch->status_name);
    }
    /* the rule counters, when the sum above was taken */
    if (counted) {
        ch->text.len = 0u;
        ch->text.over = 0;
        we_mod_render_rules(&ch->text, &ch->id, &b->ctrmap, ch->sum, ch->started_ms, tick, boot, boot, b->config16);
        we_write_text(ch, "rules", ch->rules_name);
    }
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    /* the shard ledger, one file per child per tick: the bases the gate checks for distinctness,
     * alignment and disjointment, the live and retired counts beside the destructor's own, and the
     * byte ledger whose difference is the live shards' exact footprint */
    ch->text.len = 0u;
    ch->text.over = 0;
    we_dbg_append(&ch->text, "whisper-edge-shards 1\n");
    we_dbg_append(&ch->text, "pid %lu tick %lu live %u retired %u dtor %u registrations %u swaps %u alloc %lu "
                             "freed %lu hdr %lu ctr %lu truncated %u\n",
                  (unsigned long) getpid(), (unsigned long) tick, live, dbg_retired, dbg_dtor,
                  dbg_reg, dbg_swaps, (unsigned long) dbg_alloc,
                  (unsigned long) dbg_freed, (unsigned long) WE_SHARD_HDR_BYTES,
                  (unsigned long) WE_SHARD_CTR_BYTES(b->stride), dbg_trunc);
    for (i = 0u; i < dbg_n; i++) {
        we_dbg_append(&ch->text, "shard %lx ranges %lu\n",
                      (unsigned long) dbg_base[i], (unsigned long) dbg_rng[i]);
    }
    we_write_text(ch, "shards", ch->sharddbg_name);
#endif
#ifdef WE_MOD_TEST_FOLD_IN_SERVER
    {   /* the control: the server folds the other processes' counter files itself, opening each one */
        DIR *d = opendir(b->counters_dir);

        if (d != NULL) {
            struct dirent *e;

            while ((e = readdir(d)) != NULL) {
                size_t len = strlen(e->d_name);

                if (len > 10u && strcmp(e->d_name + len - 10u, ".rules.cnt") == 0 && strcmp(e->d_name, ch->rules_name) != 0) {
                    int fd = openat(ch->dirfd, e->d_name, O_RDONLY | O_CLOEXEC);

                    if (fd >= 0) {
                        char one;

                        (void) !read(fd, &one, 1u);
                        close(fd);
                    }
                }
            }
            closedir(d);
        }
    }
#endif
#ifdef WE_MOD_TEST_LOCKED_WRITE
    we_mu_unlock(ch);
#endif
    /* the configuration file, when absent or not a regular file */
    {
        struct stat st;

        if (fstatat(ch->dirfd, b->conf_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
            char why[256];

            we_mod_write_file(ch->dirfd, &ch->id, "conf", b->conf_name, b->conf_text, b->conf_len, why, sizeof why);
        }
    }
    /* the legacy copy's range-counter file, the summary's headline */
    if (ch->ranges_sum != NULL && rep != NULL) {
        we_counters_write(ch->ranges_sum, rep, b->counters_dir, now);
    }
}

static void we_on_tick(void *ud, uint64_t tick, const int *stop)
{
    we_child_t *ch = ud;

#ifdef WE_MOD_TEST_STALL_STOP
    /* the control: a plane job that runs until the stop and is then stuck 5 s, as a pread on a file system that
     * stopped answering is, making no progress after its one mark. 5 s, past two windows: a thread whose first tick
     * starts only after the stop makes its mark inside the first window, which earns it a second one (measured: one
     * child in eight on a full walk, its thread waking 3 s later and writing its count) */
    we_mod_thread_stage(WE_MOD_STAGE_PLANES);
    while (!__atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
        usleep(10000);
    }
    usleep(5000000);
#endif
    if (ch->b->planes != NULL) {
        we_mod_planes_tick(ch->b->planes, tick, stop);   /* marks its plane jobs itself */
        we_mod_planes_apply(ch->b->planes, we_child_log, ch);
    }
    we_tick_write(ch, tick, 0, stop);
}

static void we_on_final(void *ud, uint64_t tick, const int *stop)
{
    we_child_t *ch = ud;

    (void) stop;
#if defined(WE_MOD_TEST_SLOW_STOP)
    /* the control: a final write slower than the stop's 2 s window, but running: four 800 ms steps, as a thread
     * starved of the CPU or held by a slow disk takes them, each one marked as progress */
    {
        int k;

        for (k = 0; k < 4; k++) {
            usleep(800000);
            we_mod_thread_stage(WE_MOD_STAGE_FINAL);
        }
    }
#elif defined(WE_MOD_TEST_STALL_WRITE)
    /* the control: the final write held WE_MOD_TEST_STALL_WRITE ms in one piece, no progress, as a rename into a
     * counters directory on a disk held by other writers is (measured on the gate's host at load 20: 27 of 34
     * abandoned children left a temp file, so their threads were inside a write) */
    usleep((useconds_t) (WE_MOD_TEST_STALL_WRITE) * 1000u);
#endif
    if (ch->b->planes != NULL) {
        we_mod_planes_apply(ch->b->planes, we_child_log, ch);
    }
    we_tick_write(ch, tick, 1, NULL);
}

/*
 * THE STOP, from a pre-cleanup on the child pool, which prefork runs inside its SIGTERM and SIGHUP
 * handler: the core's bounded stop (we_mod_thread_stop_bounded: windows of 2 s while the thread makes
 * progress or works outside a plane job, 6 s in all; a plane job with no progress for a window is
 * abandoned), then, on an abandonment, ONE write(2) of the line formatted at child start for the stage
 * the thread was in. One write, because children stopping together write to the same error log: a line in
 * three writes interleaved with its neighbours' and lost its stage (measured, three runs in ten of the
 * stalled-plane-job arm). Nothing here allocates, locks, logs, joins or measures a string.
 */
static apr_status_t we_child_stop(void *data)
{
    we_child_t *ch = data;
    uint32_t stage = WE_MOD_STAGE_WAIT;
    ssize_t w;

    if (ch->thr == NULL) {
        return APR_SUCCESS;
    }
#ifdef WE_MOD_TEST_HOLD_MU_AT_STOP
    pthread_mutex_lock(&ch->mu);               /* the row's setup: the stop arrives with the shard-list mutex held, as a
                                                * signal landing inside a registration leaves it (never in a release) */
#ifdef WE_MOD_TEST_TICK_AT_STOP
    {   /* and with the module thread inside a tick waiting for that mutex: the stop waits (at most 15 s, past one
         * interval) until the thread's next tick reaches the lock, so the arm is that case every time */
        struct timespec ts = { 0, 10000000 };
        int k;

        for (k = 0; k < 1500 && !__atomic_load_n(&we_test_tick_waiting, __ATOMIC_ACQUIRE); k++) {
            nanosleep(&ts, NULL);
        }
        nanosleep(&ts, NULL);                  /* past the store, into the wait */
    }
#endif
#endif
    if (we_mod_thread_stop_bounded(ch->thr, &stage) == 0) {
        return APR_SUCCESS;
    }
    if (stage > WE_MOD_STAGE_FINAL) {
        stage = WE_MOD_STAGE_TICK;
    }
    do {
        w = write(STDERR_FILENO, ch->abandon_line[stage], ch->abandon_len[stage]);
    } while (w < 0 && errno == EINTR);
    return APR_SUCCESS;
}

static void we_child_init(apr_pool_t *pchild, server_rec *s)
{
    we_srv_conf_t *base = we_base_conf(s);
    we_build_t *b = base != NULL ? base->build : NULL;
    we_child_t *ch;
    we_mod_worker_args_t w;
    char msg[512], why[256];
    int rc;

    if (b == NULL) {
        return;
    }
    ch = calloc(1, sizeof *ch);
    if (ch == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: out of memory at child start; serving with no counters");
        return;
    }
    g_child = ch;
#ifdef WE_MOD_DEBUG
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "whisper edge: this child runs the WE_MOD_DEBUG build (the core's debug "
                 "counters on), the gate's M3 build; it is not a release build");
#endif
    ch->s = s;
    ch->b = b;
    ch->dirfd = -1;
    ch->started_ms = we_boottime_ms();
    pthread_mutex_init(&ch->mu, NULL);
    ch->key_ok = pthread_key_create(&ch->key, we_shard_destructor) == 0;
#if defined(WE_MOD_TEST_COUNT_KEY_CREATE) || defined(WE_MOD_TEST_KEY_IN_PARENT)
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "whisper edge: thread key created");   /* counted by pid */
#endif
    ch->retired = calloc(b->stride, sizeof *ch->retired);
    ch->sum = calloc(b->stride, sizeof *ch->sum);
    ch->sink = aligned_alloc(64u, WE_SHARD_CTR_BYTES(b->stride));
    ch->st = calloc(1, sizeof *ch->st);
    ch->text.cap = 65536u + (size_t) b->stride * 48u;
    ch->text.buf = malloc(ch->text.cap);
    if (ch->retired == NULL || ch->sum == NULL || ch->sink == NULL || ch->st == NULL || ch->text.buf == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: out of memory at child start; serving, counting into "
                     "nothing, writing no file");
        ch->key_ok = 0;
        ch->dirfd = -1;
        if (ch->sink != NULL) {
            we_zero_words(ch->sink, b->stride);
        }
        return;
    }
    we_zero_words(ch->sink, b->stride);
    if (!ch->key_ok) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "whisper edge: no thread key (pthread_key_create failed): every "
                     "thread counts into the sink, and the counter file holds no rule counts from this process");
    }
    if (we_mod_procid(&ch->id) != 0) {
        snprintf(ch->id.id16, sizeof ch->id.id16, "%016llx", (unsigned long long) getpid());
    }
#ifdef WE_MOD_TEST_PID_ONLY_NAMES
    /* the control: files named by the pid alone, so a child respawned into a gone child's pid writes over
     * that child's files and its counts are gone */
    snprintf(ch->status_name, sizeof ch->status_name, "%llu.status", (unsigned long long) getpid());
    snprintf(ch->rules_name, sizeof ch->rules_name, "%llu.rules.cnt", (unsigned long long) getpid());
#else
    snprintf(ch->status_name, sizeof ch->status_name, "%llu-%s.status", (unsigned long long) getpid(), ch->id.id16);
    snprintf(ch->rules_name, sizeof ch->rules_name, "%llu-%s.rules.cnt", (unsigned long long) getpid(), ch->id.id16);
#endif
#ifdef WE_MOD_TEST_EXPORT_SHARDS
    snprintf(ch->sharddbg_name, sizeof ch->sharddbg_name, "%llu-%s.shard", (unsigned long long) getpid(), ch->id.id16);
#endif
#ifdef WE_MOD_TEST_GLOBAL_SHARD
    if (b->stride > (uint32_t) (sizeof we_mod_test_shard / sizeof we_mod_test_shard[0])) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "whisper edge: the shared-shard control's array is smaller than "
                     "this configuration's stride; the control refuses to run");
        ch->key_ok = 0;
    }
#endif
    {
        uint32_t k;

        for (k = 0u; k <= WE_MOD_STAGE_FINAL; k++) {
            snprintf(ch->abandon_line[k], sizeof ch->abandon_line[k], "[whisper edge] pid %llu: the module thread did not "
                     "stop within %u ms of its last progress (%u ms at most); the counts since its last write are not "
                     "written (no file was touched at exit)%s\n", (unsigned long long) getpid(),
                     (unsigned) WE_MOD_STOP_WINDOW_MS, (unsigned) WE_MOD_STOP_CAP_MS, we_mod_stage_text(k));
            ch->abandon_len[k] = strlen(ch->abandon_line[k]);
        }
    }
    snprintf(ch->held_line, sizeof ch->held_line, "[whisper edge] pid %llu: the final write found the shard-list mutex "
             "held for 1 s; the status file is written and the rule counts since the last tick are not\n",
             (unsigned long long) getpid());
    ch->held_len = strlen(ch->held_line);
    ch->offset_ms = b->interval_ms != 0u ? strtoull(ch->id.id16, NULL, 16) % b->interval_ms : 0u;

    /* the counters directory, held as a descriptor; created when absent */
    if (b->counters_dir != NULL && !b->counters_off) {
        ch->dirfd = we_openat_cloexec(AT_FDCWD, b->counters_dir, O_RDONLY | O_DIRECTORY, 0);
        if (ch->dirfd < 0 && errno == ENOENT) {
            if (mkdir(b->counters_dir, 0755) == 0 || errno == EEXIST) {
                ch->dirfd = we_openat_cloexec(AT_FDCWD, b->counters_dir, O_RDONLY | O_DIRECTORY, 0);
            }
        }
        if (ch->dirfd < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "whisper edge: cannot open the counters directory %s (%s); "
                         "blocking is unaffected and whisper-edge-summary will have nothing to read. Set WhisperEdgeSummary "
                         "to a writable directory, or to off", b->counters_dir, strerror(errno));
        }
    }

    /* the worker-start check and the arm-time mlock, before the first accept; then the thread */
    if (b->planes != NULL) {
        memset(&w, 0, sizeof w);
        w.interval_ms = b->interval_ms;
        w.log = we_child_log;
        w.log_ud = ch;
        rc = we_mod_worker_start(b->planes, &w, msg, sizeof msg);
        if (rc != 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "whisper edge: the worker-start check was refused: %s", msg);
        }
    }
    rc = we_mod_thread_start(&ch->thr, b->interval_ms, ch->offset_ms, we_on_tick, we_on_final, ch, why, sizeof why);
    if (rc != 0) {
        ch->no_thread = 1;
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "whisper edge: no module thread (%s): the inherited planes serve "
                     "until each one's validity ends and then read unknown; this process writes its status once, with "
                     "no-thread, and no counter file", why);
        we_tick_write(ch, 0u, 1, NULL);
    }
    /* the stop, before mod_http2's pre-cleanup (child_init is ordered before its), never in a forked CGI child */
    apr_pool_pre_cleanup_register(pchild, ch, we_child_stop);
}

/* the parent's budgeted verification, about every ten seconds; the core's monitor is declared ahead of its body */
static int we_monitor(apr_pool_t *p, server_rec *s)
{
    we_srv_conf_t *base = we_base_conf(s);
    static int said;
    uint32_t armed = 0u;
    int rc;

    (void) p;
    if (base == NULL || base->build == NULL || base->build->planes == NULL || g_child != NULL) {
        return DECLINED;
    }
    rc = we_mod_planes_monitor(base->build->planes, 50u, &armed);
    if (rc == 1 && armed != 0u) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "whisper edge: the parent armed planes 0x%02x; children spawned from "
                     "now inherit them", armed);
    } else if (rc == WE_MOD_ERR_ARG && !said) {
        said = 1;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "whisper edge: the parent's budgeted verification is not built in this "
                     "core; a child spawned after a new generation verifies it itself");
    }
    return DECLINED;
}

/* ---------------------------------------------------------------------------------------------- */
/* The request path                                                                                */
/* ---------------------------------------------------------------------------------------------- */

static we_rconf_t *we_rconf_get(request_rec *r)
{
    return ap_get_module_config(r->request_config, &whisper_edge_module);
}

static we_rconf_t *we_rconf_make(request_rec *r)
{
    we_rconf_t *rc = we_rconf_get(r);

    if (rc == NULL) {
        rc = apr_pcalloc(r->pool, sizeof *rc);
        rc->head = rc;
        ap_set_module_config(r->request_config, &whisper_edge_module, rc);
    }
    return rc;
}

/* the chain's first request's config, reached through r->prev (an internal redirect's predecessor) */
static we_rconf_t *we_rconf_head(request_rec *r)
{
    request_rec *h = r;

    while (h->prev != NULL) {
        h = h->prev;
    }
    while (h->main != NULL) {
        h = h->main;
    }
    return h != r ? we_rconf_get(h) : NULL;
}

/* an APR socket address as the core's canonical address; 0 when it is not an IP address */
static int we_addr_of(const apr_sockaddr_t *sa, we_addr_t *out)
{
    uint8_t b[16];

    if (sa == NULL) {
        return 0;
    }
    if (sa->family == APR_INET) {
        memcpy(b, &sa->sa.sin.sin_addr, 4);
        memset(b + 4, 0, 12);
        we_addr_canon(b, 4, out);
        return 1;
    }
#if APR_HAVE_IPV6
    if (sa->family == APR_INET6) {
        memcpy(b, &sa->sa.sin6.sin6_addr, 16);
        we_addr_canon(b, 6, out);
        return 1;
    }
#endif
    return 0;
}

/*
 * THE RAW HEADER SNAPSHOT, at APR_HOOK_REALLY_FIRST before mod_remoteip and mod_headers: the table's
 * value pointer, never a copy, on the first request of a chain only; a redirect links to it.
 */
#ifdef WE_MOD_TEST_COUNT_HDR_BYTES
/* the debug build's header-bytes counter: one pass over the merged value of the trusted header, every
 * line's bytes and the merge's ", " gaps, exported as the WHISPER_EDGE_TEST_HEADER_BYTES note so the gate
 * reads the aggregate a request left behind; the production build counts nothing and exports no note */
static uint64_t we_test_hdr_bytes;
#endif
#ifdef WE_MOD_TEST_COUNT_UNSET_ADDR
/* the debug build's no-address counter: requests judged as having no address at all (neither the primary
 * connection's peer nor mod_remoteip's rewrite produced one), the shape the HTTP/2 dummy socket would
 * produce; exported as the WHISPER_EDGE_TEST_UNSET_ADDR note, and 0 under a correct read */
static uint64_t we_test_unset_addr;
#endif

static int we_post_read_request(request_rec *r)
{
    we_srv_conf_t *base = we_base_conf(r->server);
    we_build_t *b = base != NULL ? base->build : NULL;
    we_rconf_t *rc;

    if (b == NULL || r->main != NULL) {
        return DECLINED;
    }
    rc = we_rconf_make(r);
    if (r->prev != NULL) {
        we_rconf_t *h = we_rconf_head(r);

        rc->head = h != NULL ? h->head : rc;
        return DECLINED;
    }
    rc->head = rc;
    if (b->header != NULL) {
        /* every entry of the trusted header, one pass: a proxy may append the client on a line of its
         * own rather than into the line it received, and the walk's contract is over the header's lines
         * in arrival order, newest walked first. The newest WE_MOD_WALK_LINES are kept; the walk treats
         * the rest as older lines not kept, and the bytes counter below reads every line exactly once. */
        const apr_array_header_t *elts = apr_table_elts(r->headers_in);
        const apr_table_entry_t *e = (const apr_table_entry_t *) elts->elts;
        uint32_t i, total = 0u;

        for (i = 0u; i < (uint32_t) elts->nelts; i++) {
            size_t len;

            if (e[i].key == NULL || strcasecmp(e[i].key, b->header) != 0 || e[i].val == NULL) {
                continue;
            }
            len = strlen(e[i].val);
#ifdef WE_MOD_TEST_COUNT_HDR_BYTES
            we_test_hdr_bytes += (uint64_t) len + (total != 0u ? 2u : 0u); /* the merged value: the gaps are ", " */
#endif
            total++;
            if (total <= WE_MOD_WALK_LINES) {
                rc->lines[total - 1u].p = (const uint8_t *) e[i].val;
                rc->lines[total - 1u].len = len;
            } else {
                memmove(rc->lines, rc->lines + 1u, (WE_MOD_WALK_LINES - 1u) * sizeof rc->lines[0]);
                rc->lines[WE_MOD_WALK_LINES - 1u].p = (const uint8_t *) e[i].val;
                rc->lines[WE_MOD_WALK_LINES - 1u].len = len;
                rc->older = 1;
            }
        }
        rc->nlines = total > WE_MOD_WALK_LINES ? WE_MOD_WALK_LINES : total;
    }
    return DECLINED;
}

/* the one decide wrapper every evaluation site calls: what the gate disassembles out of the built module */
WE_DECIDE_SYMBOL static void apache_whisper_edge_decide(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s,
                                                        uint64_t *shard, const we_mod_req_t *req, uint64_t now_ms)
{
    we_mod_decide(c, x, s, shard, req, now_ms);
}

static const char *we_pool_str(apr_pool_t *p, const char *s, size_t n)
{
    char *out = apr_palloc(p, n + 1u);

    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

/*
 * The exact lengths the logged and generations renders will write over the same record, counted with
 * the renderer's own primitives (we_mod_put_u64, we_mod_plane_word, we_mod_nomap_get), so each value
 * is rendered straight into ONE request-pool allocation with no per-request staging buffer beside the
 * scratch: the frame's budget holds the scratch, the handler's locals and the wrapper, nothing else.
 * The counts mirror the public grammar (POLICY.md's rendering section), which the gate's content rows
 * pin; a grammar change that outgrew its count would fail those rows before any release. noinline, so
 * a helper's own few bytes never fold into the decision frame.
 */
static __attribute__((noinline)) size_t we_logged_len(const we_mod_record_t *rec)
{
    char t[24];                     /* the digit writer's own scratch, the renderer's primitive */
    size_t o = 0u;
    uint32_t k, r;

    for (k = 0u; k < 2u; k++) {
        int any = 0;

        for (r = 0u; r < 256u; r++) {
            if (((rec->log_fired[k][r >> 3] >> (r & 7u)) & 1u) == 0u) {
                continue;
            }
            if (!any) {
                o += (o != 0u ? 1u : 0u) + (k == 0u ? 6u : 4u);   /* the space and "floor:"/"ctx:" */
                any = 1;
            } else {
                o += 1u;                                           /* ',' */
            }
            o += we_mod_put_u64(t, r + 1u);
        }
    }
    return o != 0u ? o : 1u;                                       /* the renderer's '-' when nothing fired */
}

static __attribute__((noinline)) size_t we_generations_len(const we_mod_record_t *rec)
{
    char t[24];
    size_t o = 0u;
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        uint32_t st, code;

        if (((rec->gen_mask >> p) & 1u) == 0u) {
            continue;
        }
        if (o != 0u) {
            o += 1u;                                               /* ' ' */
        }
        o += strlen(we_mod_plane_word(p)) + 1u;                   /* the plane's name and ':' */
        if (((rec->disarmed_mask >> p) & 1u) != 0u) {
            o += 2u;                                               /* "-d" */
        } else {
            st = rec->slot.state[p];
            code = we_mod_nomap_get(rec, p);
            if (st == WE_ST_NONE || code != WE_MOD_NOMAP_NONE) {
                o += 2u;                                           /* the dash and its state letter */
            } else if (st == WE_ST_REVOKED) {
                o += 1u;                                           /* '0' */
            } else {
                o += we_mod_put_u64(t, rec->slot.e[p].generation) + 1u + 8u;  /* the digits, '.', eight hex */
                if (st == WE_ST_STALE_HIT || st == WE_ST_STALE_NR
                        || (st == WE_ST_UNKNOWN && rec->slot.e[p].generation != 0u)) {
                    o += 1u;                                       /* '~', or '^' for the lapsed tenant: one byte either way */
                }
            }
        }
        if (((rec->lazy_mask >> p) & 1u) != 0u) {
            o += 1u;                                               /* '*' */
        }
    }
    return o;
}

/* the export pass: the decision's notes, the floor address, the generations, the verdict, the attributes */
static void we_export(request_rec *r, we_rconf_t *rc, const we_build_t *b, const we_dir_conf_t *d, we_mod_scratch_t *s,
                      uint64_t now_ms)
{
    we_mod_record_t *rec = rc->rec;
    const we_mod_ctx_t *x = d->ctx;
    int again = (rec->flags & WE_MOD_FLAG_NOTES_WRITTEN) != 0u;
    char *const buf = rc->floor_buf;    /* the floor address's staging lives in the per-request rconf */
    size_t n;
    uint32_t i;

    /* addn on a fresh notes table (the keys are new and every WHISPER_EDGE_ key shares one bucket, so a
     * setn would scan them all); setn on an adopted-candidate hop, whose notes this request_rec already holds */
#define put(t, k, v) do { if (again) { apr_table_setn((t), (k), (v)); } else { apr_table_addn((t), (k), (v)); } } while (0)

    /* reputation always: the verdict note is written on every judged request */
    we_mod_fill(rec, &b->cfg, s, (uint32_t) x->export_mask | (uint32_t) x->gen_mask | 1u, now_ms);
    put(r->notes, "WHISPER_EDGE_ACTION", we_mod_render_action(rec));
#ifdef WE_MOD_TEST_COUNT_HDR_BYTES
    put(r->notes, "WHISPER_EDGE_TEST_HEADER_BYTES",
        apr_psprintf(r->pool, "%lu", (unsigned long) we_test_hdr_bytes));
#endif
#ifdef WE_MOD_TEST_COUNT_UNSET_ADDR
    put(r->notes, "WHISPER_EDGE_TEST_UNSET_ADDR",
        apr_psprintf(r->pool, "%lu", (unsigned long) we_test_unset_addr));
#endif
    put(r->notes, "WHISPER_EDGE_RULE", we_mod_render_rule(rec, &b->cfg, 1));
    put(r->notes, "WHISPER_EDGE_RULE_ID", we_mod_render_rule(rec, &b->cfg, 0));
    put(r->notes, "WHISPER_EDGE_REASON", we_mod_render_reason(rec, rc->walk, rc->note));
    put(r->notes, "WHISPER_EDGE_PROGRAM", we_mod_render_program(rec, &b->cfg));
    /* the logged list: one exact pool string, rendered straight into it; the dash is static, no allocation */
    n = we_logged_len(rec);
    if (n == 1u) {
        put(r->notes, "WHISPER_EDGE_LOGGED", "-");
    } else {
        char *lg = apr_palloc(r->pool, n + 1u);

        (void) we_mod_render_logged(rec, lg);
        put(r->notes, "WHISPER_EDGE_LOGGED", lg);
    }
    n = we_mod_render_floor(rec, buf);
    put(r->notes, "WHISPER_EDGE_FLOOR_ADDR", we_pool_str(r->pool, buf, n));
    /* the generations token is rendered one frame out of the decision (we_export_generations): the core's
     * renderer runs in an outlined frame of its own, which here would stack on the scratch's */
    rc->gen_pending = 1u;
    put(r->notes, "WHISPER_EDGE_VERDICT", we_mod_render_verdict(rec, WE_MOD_SPELL_SPAMHAUS));
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        const char *v;
        size_t vl;

        if (((d->attr_mask >> i) & 1u) == 0u) {
            continue;
        }
        if (we_mod_render_attr(rec, i, &v, &vl) == 0) {
            put(r->notes, we_note_name[i], v);
            if (((d->env_mask >> i) & 1u) != 0u) {
                apr_table_setn(r->subprocess_env, we_note_name[i], v);
            }
        }
    }
    rec->flags |= WE_MOD_FLAG_NOTES_WRITTEN;
#undef put
}

/*
 * At most one line per second per outcome per process, so a flood from a listed address cannot turn the
 * log into the attack. The last-logged second is one relaxed load and one relaxed store on a per-process
 * word, never a compare-and-swap: a locked instruction has no place on the request path (N5), and the
 * race it leaves is benign, two threads crossing the same second boundary write two lines instead of one.
 */
static void we_log_outcome(request_rec *r, we_child_t *ch, const we_mod_record_t *rec, const we_build_t *b, int deny,
                           uint64_t now_sec, const we_addr_t *a, const we_map_t *rep)
{
    uint64_t *last = ch != NULL ? &ch->last_log_sec[deny ? 1 : 0] : NULL;
    const char *ev = NULL;
    char addr[WE_ADDR_TEXT_MAX];

    if (last != NULL) {
        if (__atomic_load_n(last, __ATOMIC_RELAXED) == now_sec) {
            return;
        }
        __atomic_store_n(last, now_sec, __ATOMIC_RELAXED);
    }
    we_addr_format(a, addr);
    /* the citable evidence of a reputation hit, through the view the decision used, inside its grace */
    if (rep != NULL && rep != b->cfg.standin[0] && rec->slot.state[0] == WE_ST_FRESH_HIT) {
        if (a->family == 4u) {
            ev = we_evidence4(rep, (uint32_t) a->b[0] << 24 | (uint32_t) a->b[1] << 16 | (uint32_t) a->b[2] << 8 | a->b[3]);
        } else {
            ev = we_evidence6(rep, a->b);
        }
    }
    /* at error, httpd's own level for a denial (AH01797, "client denied by server configuration"), the deny
     * and the log mode's WOULD DENY alike, so the README's promise that log mode writes what it would deny
     * into the error log holds under any LogLevel that keeps httpd's own denials */
#ifndef WE_MOD_TEST_DENY_AT_WARN
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
#else
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,   /* the control: at warn, under a LogLevel error */
#endif
                  "whisper edge: %s %s: rule %s (%s), program %s, verdict %s, evidence %s%s",
                  deny ? "denied" : "WOULD DENY", addr, we_mod_render_rule(rec, &b->cfg, 0), we_mod_render_rule(rec, &b->cfg, 1),
                  we_mod_render_program(rec, &b->cfg), we_mod_render_verdict(rec, WE_MOD_SPELL_SPAMHAUS),
                  ev != NULL ? ev : "none carried", deny ? "" : " (mode is log, request allowed)");
}

/*
 * The legacy copy's range count, charged to the judged address, taken out of the decision frame as its
 * own noinline step so its locals never sit beside the scratch (the frame budget). Runs only on a
 * would-deny or a deny with no data directory: cold.
 */
static __attribute__((noinline)) void we_legacy_ranges(we_child_t *ch, we_shard_t *sh, const we_build_t *b,
                                                       const we_map_t *m, int floor_pgm, const we_mod_req_t *req)
{
    if (m == NULL || m == b->cfg.standin[0]) {
        return;
    }
    {
        const we_addr_t *a = floor_pgm ? &req->r.floor : &req->r.server;
        int idx;

#ifdef WE_MOD_TEST_RANGES_UNCHECKED
        /* the control: the sub-block is never checked against the map it is written under, and the hit is
         * bounded by the map's count rather than the block's own, so a thread keeps writing the block it
         * allocated under generation G with generation G + 1's indices */
        if (sh->ranges == NULL) {
            we_apache_subblock_swap(ch, sh, m);
        }
#else
        if (sh->ranges == NULL || sh->ranges_gen != m->generation || sh->ranges_v4 != m->v4_count
                || sh->ranges_v6 != m->v6_count) {
            we_apache_subblock_swap(ch, sh, m);   /* the first request after a publish: cold, counted */
        }
#endif
        if (sh->ranges != NULL) {
            uint64_t *hit = NULL;
#ifdef WE_MOD_TEST_RANGES_UNCHECKED
            const uint32_t bound4 = m->v4_count, bound6 = m->v6_count;
#else
            const uint32_t bound4 = sh->ranges_v4, bound6 = sh->ranges_v6;
#endif

            if (a->family == 4u) {
                uint32_t v = (uint32_t) a->b[0] << 24 | (uint32_t) a->b[1] << 16 | (uint32_t) a->b[2] << 8 | a->b[3];

                idx = we_range4(m, v);
                hit = idx >= 0 && (uint32_t) idx < bound4 ? &sh->ranges->v4_hits[idx] : NULL;
            } else {
                idx = we_range6(m, a->b);
                hit = idx >= 0 && (uint32_t) idx < bound6 ? &sh->ranges->v6_hits[idx] : NULL;
            }
            if (hit != NULL) {
                __atomic_store_n(hit, __atomic_load_n(hit, __ATOMIC_RELAXED) + 1u, __ATOMIC_RELAXED);
                __atomic_store_n(&sh->ranges->denied, __atomic_load_n(&sh->ranges->denied, __ATOMIC_RELAXED) + 1u,
                                 __ATOMIC_RELAXED);
            }
        }
    }
}

#ifdef WE_MOD_TEST_PLANT_FRAME
/* the control: a 512-byte frame called from inside the decision frame, which the frame row's chain
 * decomposition must name beneath we_decide_frame instead of the export fill */
static __attribute__((noinline)) void we_test_planted_callee(void)
{
#ifndef WE_MOD_TEST_PLANT_FRAME_BYTES
#define WE_MOD_TEST_PLANT_FRAME_BYTES 512   /* the frame rows choose the size: past the bound, or just past the ratchet */
#endif
    volatile unsigned char we_test_plant[WE_MOD_TEST_PLANT_FRAME_BYTES];

    we_test_plant[0] = 1u;
    we_test_plant[WE_MOD_TEST_PLANT_FRAME_BYTES - 1] = we_test_plant[0];
}
#endif

/*
 * THE GENERATIONS NOTE, one frame out of the decision: the core's renderer is outlined by the compiler into a
 * frame of its own (128 bytes), and inside the decision frame that frame stacked on the scratch's and carried
 * the segment to 1,504 bytes (measured once the stack-usage table folded the compiler's clone names); rendered
 * after the frame returns, like the outcome log, it never stacks on the scratch. One exact pool string, the
 * dash static when no plane is named; set-or-add, so a hop that rewrites the notes rewrites this one too.
 */
static __attribute__((noinline)) void we_export_generations(request_rec *r, we_rconf_t *rc)
{
    const we_mod_record_t *rec = rc->rec;
    size_t n;

    rc->gen_pending = 0u;
    if (rec == NULL) {
        return;
    }
    n = we_generations_len(rec);
    if (n == 0u) {
        apr_table_setn(r->notes, "WHISPER_EDGE_GENERATIONS", "-");
    } else {
        char *gn = apr_palloc(r->pool, n + 1u);

        (void) we_mod_render_generations(rec, gn);
        apr_table_setn(r->notes, "WHISPER_EDGE_GENERATIONS", gn);
    }
}

/*
 * THE DECISION FRAME: owns the scratch (1,024 bytes, 64-byte aligned, dead after the record write), calls
 * the wrapper, writes the record, runs the export pass through the same scratch, and returns the status to
 * send (0 to continue). noinline, so the walk and the handler's own locals never share its frame.
 */
static __attribute__((noinline)) int we_decide_frame(request_rec *r, we_rconf_t *rc, we_build_t *b, we_dir_conf_t *d,
                                                     uint64_t now_ms)
{
    we_mod_scratch_t s;
    const we_mod_req_t *req = &rc->req;
    we_child_t *ch = g_child;
    we_shard_t *sh = NULL;
    uint64_t *shard;
    const we_mod_ctx_t *x = d->ctx;
    we_mod_record_t *rec;
    int status = 0;
    int enforce, floor_pgm;

    rc->log_kind = 0u;                             /* a re-evaluated hop must not inherit its earlier outcome */

    if (ch != NULL && ch->key_ok) {
#ifdef WE_MOD_TEST_MPM_SLOT
        {   /* the control's wrong keying: the MPM slot, read from the scoreboard worker the connection's
             * handle names (an h2 stream's own connection carries no handle; its master's names the
             * slot). Under HTTP/1.1 the slot is the thread processing the connection, so one writer; an
             * h2 stream runs on a worker of its own against the master's slot, so the trap trips there.
             * (Keying on the connection itself was tried first and trips under HTTP/1.1 too: a closed
             * connection's address is reused by the next one, measured, 13 traps in 1,024 requests.) */
            conn_rec *c1 = r->connection;
            const void *key;
            uint32_t k, found = 0xffffffffu;

            while (c1->sbh == NULL && c1->master != NULL) {
                c1 = c1->master;
            }
            key = c1->sbh != NULL ? (const void *) ap_get_scoreboard_worker(c1->sbh) : NULL;
            we_mu_lock(ch);
            for (k = 0u; key != NULL && k < WE_SLOT_ROWS; k++) {
                if (ch->slot_key[k] == key) {
                    found = k;
                    break;
                }
                if (ch->slot_key[k] == NULL) {
                    ch->slot_key[k] = key;             /* the row is claimed before its shard exists */
                    found = k;
                    break;
                }
            }
            we_mu_unlock(ch);
            if (found != 0xffffffffu) {
                sh = ch->slot_shard[found];
                if (sh == NULL) {
                    sh = we_apache_shard_register(ch);
                    we_mu_lock(ch);
                    if (ch->slot_shard[found] == NULL) {
                        ch->slot_shard[found] = sh;    /* only the first registrant: the rest trip the trap */
                    }
                    we_mu_unlock(ch);
                    if (sh == NULL) {
                        sh = pthread_getspecific(ch->key);   /* no memory: the thread's own shard or the sink */
                    }
                }
            } else {
                sh = pthread_getspecific(ch->key);
                if (sh == NULL) {
                    sh = we_apache_shard_register(ch);
                }
            }
        }
#else
        sh = pthread_getspecific(ch->key);
        if (sh == NULL) {
            sh = we_apache_shard_register(ch);  /* the first judged request on this thread: cold, counted */
            if (sh == NULL && !ch->no_shard_said) {
                ch->no_shard_said = 1;
            }
        }
#endif
    }
#if defined(WE_MOD_TEST_SHARD_OWNER) || defined(WE_MOD_TEST_MPM_SLOT)
    if (sh != NULL && sh->owner_tid != 0u && sh->owner_tid != (uint64_t) syscall(SYS_gettid)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "whisper edge: the shard ownership trap: pid %lu, thread %lu "
                     "writes a shard owned by thread %lu", (unsigned long) getpid(),
                     (unsigned long) syscall(SYS_gettid), (unsigned long) sh->owner_tid);
        abort();
    }
#endif
    shard = sh != NULL ? sh->ctr : (ch != NULL && ch->sink != NULL ? ch->sink : NULL);
    if (shard == NULL) {
        return 0;                              /* no memory at all: judge nothing, serve */
    }
    apache_whisper_edge_decide(&b->cfg, x, &s, shard, req, now_ms);

    /* the record: this request_rec's own; a hop starts from its predecessor's chain view */
    if (rc->rec == NULL) {
        rec = we_mod_record_at(apr_palloc(r->pool, WE_MOD_RECORD_ALLOC));
        we_mod_record_init(rec, x);
        if (r->prev != NULL) {
            we_rconf_t *pc = we_rconf_get(r->prev);

            if (pc != NULL && pc->rec != NULL) {
                memcpy(rec, pc->rec, sizeof *rec);
                rec->flags = 0u;
                rec->chain = pc->rec;
            }
        }
        rc->rec = rec;
    }
    rec = rc->rec;
    we_mod_record_write(rec, &b->cfg, x, &s, &req->r.floor, &req->r.server);
    /* this request_rec's own evaluation slot, never copied along the chain */
    rec->per_dir_config = r->per_dir_config;
    rec->uri = r->uri;
    rec->eval_action = s.v.action;
    rec->eval_mode = (uint8_t) (s.v.program == WE_VPROG_FLOOR || s.v.step != WE_STEP_CONTEXT
                                ? we_conf_mode(&b->cfg.floor_conf) : we_conf_mode(&x->conf));
    rec->eval_status = s.v.enforce ? (s.v.program == WE_VPROG_FLOOR || s.v.step != WE_STEP_CONTEXT ? b->cfg.floor_status
                                                                                                    : x->deny_status) : 0u;
    rc->evaluated = 1;

    /* the legacy copy's range count, on a would-deny or deny, charged to the judged address: owed here,
     * charged one frame out (we_legacy_ranges runs in a frame of its own with the sub-block swap beneath
     * it, 128 bytes that stacked on the scratch's frame and carried the segment to 1,504, measured) */
    rc->sh = sh;
    rc->count_ranges = ch != NULL && sh != NULL && b->legacy != NULL && (s.v.enforce || we_mod_severity(&b->cfg, x, &s.v) != 0u);
    rc->ranges_floor = s.v.program == WE_VPROG_FLOOR;
#ifdef WE_MOD_TEST_PLANT_FRAME
    we_test_planted_callee();                  /* the control: a frame planted beneath the decision frame */
#endif

    /* the verdict's tail reads are taken BEFORE the export: the export fills a cold plane through
     * this very scratch, and the fill's documented contract clears the verdict area of the local
     * it borrows, so a verdict read after the export reads a wiped one; a deny that loses its
     * verdict there is enforced only by the fixup backstop, with no outcome line at all */
    enforce = s.v.enforce != 0;
    floor_pgm = s.v.program == WE_VPROG_FLOOR;
    rc->rep_map = s.e.view[0].m;               /* the reputation view the decision used, before any fill replaces it */

    /* the export pass, once per request_rec (an adopted-candidate hop rewrites) */
    we_export(r, rc, b, d, &s, now_ms);

    /* the outcome: what to log is recorded here, the log itself is written one frame out, so the
     * log line's own buffers never stack on the scratch's frame */
    if (enforce) {
        status = rec->eval_status;
        rc->log_kind = 2u;
        apr_table_setn(r->err_headers_out, "Cache-Control", "no-store");
        if (floor_pgm) {
            ap_custom_response(r, status, WE_MOD_DENY_TEXT);   /* the module's own text: no error document below the floor */
        }
    } else if (rec->severity == 1u && rec->decided) {
        rc->log_kind = 1u;
    }
    rc->log_floor = floor_pgm;
    return status;
}

/*
 * The peer and the trusted-header walk, once per chain (the head request's). Its own noinline step, so
 * the walk's locals run in a frame that has returned before the decision frame owns the scratch: the
 * two never share a stack, and neither stacks on the other.
 */
static __attribute__((noinline)) void we_walk_head(request_rec *r, we_rconf_t *h, const we_build_t *b)
{
    conn_rec *c = r->connection;
    apr_socket_t *sock;
    apr_sockaddr_t *sa = NULL;

    /* the primary connection's socket: an HTTP/2 stream's secondary connection has a dummy */
    while (c->master != NULL) {
        c = c->master;
    }
    sock = ap_get_conn_socket(c);
    h->peer_ok = sock != NULL && apr_socket_addr_get(&sa, APR_REMOTE, sock) == APR_SUCCESS && we_addr_of(sa, &h->peer);
    if (!h->peer_ok && !b->trust.unix_ok) {
        /* not an IP address and not a trusted unix peer: no address, counted, logged once per process */
        static int said;

        if (!said) {
            said = 1;
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "whisper edge: the connection's peer is not an IP address; "
                          "such requests are judged as having no address (allow-by-no-address)");
        }
    }
    we_mod_walk(&b->trust, b->hops, b->header != NULL, h->peer_ok ? &h->peer : NULL, h->lines, h->nlines, h->older,
                &h->w);
    h->walked = 1;
    h->walk = h->w.walk;
    h->note = h->w.note;
}

/*
 * The request the decision frame judges: the context address, ACME, and the core's request struct,
 * built into the per-request rconf so no part of it lives on the handler chain's frames. Its own
 * noinline step, a sibling of the decision frame, so its locals never stack on the scratch.
 */
static __attribute__((noinline)) void we_build_head(request_rec *r, we_rconf_t *h, we_rconf_t *rc)
{
    const char *norm = r->parsed_uri.path != NULL ? r->parsed_uri.path : r->uri;

    rc->have_server = we_addr_of(r->useragent_addr, &rc->server);
    rc->acme = we_mod_acme((const uint8_t *) r->method, strlen(r->method), (const uint8_t *) r->unparsed_uri,
                           r->unparsed_uri != NULL ? strlen(r->unparsed_uri) : 0u, (const uint8_t *) norm,
                           norm != NULL ? strlen(norm) : 0u);
    we_mod_req_build(&rc->req, &h->w, rc->have_server ? &rc->server : (h->peer_ok ? &h->peer : NULL), rc->acme);
    if (!rc->have_server && !h->peer_ok) {
        rc->req.r.walk = WE_WALK_NO_ADDRESS;
#ifdef WE_MOD_TEST_COUNT_UNSET_ADDR
        we_test_unset_addr++;
#endif
    }
}

/* one evaluation of a main request or a redirect hop: the walk, the request, the frame, the log */
static int we_evaluate(request_rec *r)
{
    we_srv_conf_t *base = we_base_conf(r->server);
    we_build_t *b = base != NULL ? base->build : NULL;
    we_dir_conf_t *d = ap_get_module_config(r->per_dir_config, &whisper_edge_module);
    we_rconf_t *rc, *h;
    int status;
    uint64_t now_ms = (uint64_t) (r->request_time / 1000);

    if (b == NULL || d == NULL || d->ctx == NULL || b->ctxs == NULL) {
        return 0;
    }
    rc = we_rconf_make(r);
    h = rc->head != NULL ? rc->head : rc;
    if (!h->walked) {
        we_walk_head(r, h, b);
    }
    rc->walk = h->walk;
    rc->note = h->note;
    we_build_head(r, h, rc);
    status = we_decide_frame(r, rc, b, d, now_ms);
    if (rc->count_ranges) {
        rc->count_ranges = 0u;                 /* the legacy copy's range count, one frame out of the decision */
        we_legacy_ranges(g_child, rc->sh, b, rc->rep_map, rc->ranges_floor, &rc->req);
    }
    if (rc->gen_pending) {
        we_export_generations(r, rc);          /* the generations note, one frame out of the decision */
    }
    /* the outcome log, one frame out of the decision: the record, the request and the frame's own
     * findings carry everything the line needs */
    if (rc->log_kind != 0u) {
        we_log_outcome(r, g_child, rc->rec, b, rc->log_kind == 2u, now_ms / 1000u,
                       rc->log_floor ? &rc->req.r.floor : &rc->req.r.server, rc->rep_map);
    }
    return status;
}

static int we_access_checker(request_rec *r)
{
    int status;

    if (r->main != NULL) {
        return DECLINED;                       /* a subrequest is never evaluated */
    }
    status = we_evaluate(r);
    return status != 0 ? status : DECLINED;
}

/* a hop the access checker skipped (an equal per_dir_config) is evaluated here; a deny voted away by Satisfy Any is enforced */
static int we_fixups_first(request_rec *r)
{
    we_rconf_t *rc;

    if (r->main != NULL) {
        return DECLINED;
    }
    rc = we_rconf_get(r);
    if (rc == NULL || !rc->evaluated) {
        int status = we_evaluate(r);

        if (status != 0) {
            return status;
        }
        rc = we_rconf_get(r);
    }
    if (rc != NULL && rc->rec != NULL && rc->rec->eval_status != 0u && rc->rec->eval_mode == WE_MODE_DENY) {
        apr_table_setn(r->err_headers_out, "Cache-Control", "no-store");
        if (rc->rec->program == WE_VPROG_FLOOR) {
            ap_custom_response(r, rc->rec->eval_status, WE_MOD_DENY_TEXT);
        }
        return rc->rec->eval_status;
    }
    return DECLINED;
}

/* an adopted candidate (mod_dir, mod_negotiation) moved per_dir_config or uri: the main request is evaluated once more */
static int we_fixups_last(request_rec *r)
{
    we_rconf_t *rc;

    if (r->main != NULL) {
        return DECLINED;
    }
    rc = we_rconf_get(r);
    if (rc == NULL || rc->rec == NULL || !rc->evaluated) {
        return DECLINED;
    }
    if (rc->rec->per_dir_config != (const void *) r->per_dir_config || rc->rec->uri != (const void *) r->uri) {
        int status = we_evaluate(r);

        if (status != 0) {
            return status;
        }
    }
    return DECLINED;
}

/* %{WHISPER_EDGE_<NAME>} in ap_expr: the attribute, lazily filled, before or after the decision */
static const char *we_expr_var(ap_expr_eval_ctx_t *ctx, const void *data)
{
    request_rec *r = ctx->r;
    uintptr_t which = (uintptr_t) data;
    we_srv_conf_t *base;
    we_build_t *b;
    we_dir_conf_t *d;
    we_rconf_t *rc;
    we_mod_record_t *rec;
    const char *v;
    size_t vl;

    if (r == NULL) {
        return "";
    }
    while (r->main != NULL) {
        r = r->main;                           /* a subrequest reads the main request's record */
    }
    base = we_base_conf(r->server);
    b = base != NULL ? base->build : NULL;
    d = ap_get_module_config(r->per_dir_config, &whisper_edge_module);
    if (b == NULL || d == NULL || d->ctx == NULL) {
        return "";
    }
    rc = we_rconf_make(r);
    if (rc->rec == NULL) {
        we_addr_t server;

        rec = we_mod_record_at(apr_palloc(r->pool, WE_MOD_RECORD_ALLOC));
        we_mod_record_init(rec, d->ctx);
        if (we_addr_of(r->useragent_addr, &server)) {
            we_mod_record_key(rec, &server);
        }
        rc->rec = rec;
    }
    rec = rc->rec;
    if (which >= 100u) {
        switch (which) {
        case 100u: return we_mod_render_action(rec);
        case 101u: return we_mod_render_rule(rec, &b->cfg, 1);
        case 102u: return we_mod_render_rule(rec, &b->cfg, 0);
        case 103u: return we_mod_render_reason(rec, rc->walk, rc->note);
        case 104u: return we_mod_render_program(rec, &b->cfg);
        case 105u: return we_mod_render_verdict(rec, WE_MOD_SPELL_SPAMHAUS);
        default: break;
        }
        {
            size_t n;

            if (which == 107u) {
                char buf[WE_ADDR_TEXT_MAX];       /* the floor address fits: 46 bytes of staging */

                n = we_mod_render_floor(rec, buf);
                return we_pool_str(r->pool, buf, n);
            }
            if (which == 106u) {
                n = we_logged_len(rec);
                if (n == 1u) {
                    return "-";                   /* nothing fired: the static dash, no pool string */
                }
            } else {
                we_mod_scratch_t local;           /* the lazy fill's own 1,024-byte local, the designed cold path */

                we_mod_fill(rec, &b->cfg, &local, rec->gen_mask, (uint64_t) (r->request_time / 1000));
                n = we_generations_len(rec);
                if (n == 0u) {
                    return "-";
                }
            }
            {
                char *out = apr_palloc(r->pool, n + 1u);

                if (which == 106u) {
                    (void) we_mod_render_logged(rec, out);
                } else {
                    (void) we_mod_render_generations(rec, out);
                }
                return out;
            }
        }
    }
    {
        const we_mod_attr_t *a = we_mod_attr((uint32_t) which);
        we_mod_scratch_t local;

        if (a == NULL) {
            return "";
        }
        if (rec->slot.state[a->plane] == WE_ST_NONE && rec->slot.key_valid) {
            we_mod_fill(rec, &b->cfg, &local, 1u << a->plane, (uint64_t) (r->request_time / 1000));
        }
        if (we_mod_render_attr(rec, (uint32_t) which, &v, &vl) != 0) {
            return "";
        }
        return v;
    }
}

static int we_expr_lookup(ap_expr_lookup_parms *parms)
{
    static const struct { const char *name; uintptr_t which; } dec[] = {
        { "WHISPER_EDGE_ACTION", 100u }, { "WHISPER_EDGE_RULE", 101u }, { "WHISPER_EDGE_RULE_ID", 102u },
        { "WHISPER_EDGE_REASON", 103u }, { "WHISPER_EDGE_PROGRAM", 104u }, { "WHISPER_EDGE_VERDICT", 105u },
        { "WHISPER_EDGE_LOGGED", 106u }, { "WHISPER_EDGE_FLOOR_ADDR", 107u }, { "WHISPER_EDGE_GENERATIONS", 108u },
    };
    uint32_t i;

    if (parms->type != AP_EXPR_FUNC_VAR || parms->name == NULL || strncmp(parms->name, "WHISPER_EDGE_", 13) != 0) {
        return DECLINED;
    }
    for (i = 0u; i < sizeof dec / sizeof dec[0]; i++) {
        if (strcmp(parms->name, dec[i].name) == 0) {
            *parms->func = (const void *) we_expr_var;
            *parms->data = (const void *) dec[i].which;
            return OK;
        }
    }
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        if (strcmp(parms->name, we_note_name[i]) == 0) {
            *parms->func = (const void *) we_expr_var;
            *parms->data = (const void *) (uintptr_t) i;
            return OK;
        }
    }
    return DECLINED;
}

static void we_register_hooks(apr_pool_t *p)
{
    static const char *const after_remoteip[] = { "mod_remoteip.c", "mod_headers.c", NULL };
    static const char *const before_http2[] = { "mod_http2.c", NULL };

    (void) p;
    ap_hook_check_config(we_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(we_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(we_child_init, NULL, before_http2, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(we_post_read_request, NULL, after_remoteip, APR_HOOK_REALLY_FIRST);
    ap_hook_access_checker(we_access_checker, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(we_fixups_first, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(we_fixups_last, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_hook_expr_lookup(we_expr_lookup, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_monitor(we_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA whisper_edge_module = {
    STANDARD20_MODULE_STUFF,
    we_create_dir_conf,
    we_merge_dir_conf,
    we_create_server_conf,
    we_merge_server_conf,
    we_commands,
    we_register_hooks
#ifdef AP_MODULE_FLAG_NONE
    /*
     * httpd grew a trailing `flags` field; initialising it explicitly keeps the build clean under
     * -Wextra, and the guard keeps it compiling against an httpd that predates the field. We want no
     * warnings in somebody else's build, because a warning from a vendored file is a reason to
     * delete the vendored file.
     */
    , AP_MODULE_FLAG_NONE
#endif
};
