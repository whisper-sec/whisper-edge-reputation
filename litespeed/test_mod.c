/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * test_mod.c - the LiteSpeed module's own unit test, against a stub of the server's API.
 *
 * The gate proves the module inside a real OpenLiteSpeed, and it can only see what the server lets it
 * see. This proves, deterministically and in one process, what the gate cannot pin down by timing: the
 * parameters and the words each refusal prints; the whole-configuration build with a refused virtual
 * host beside good ones; the request path through the one wrapper, with a listed client behind the
 * trusted proxy, the hold-harmless loopback, an unparsable entry, the ACME forms and a mode-off host;
 * the exported environment values; the shard's counts; the thread's first status write and the exit
 * flush that reaches the rule-counter file.
 *
 *   test_mod <reputation.bin> <scratch-dir> <listed-high-ipv4> <unlisted-ipv4> <listed-critical-ipv4>
 *
 * The plane is the shared generator's synthetic reputation plane (make-test-snapshot.py --plane
 * reputation --synthetic), and the three addresses come from its --expect file: one inside a HIGH range,
 * one in no range, one inside a CRITICAL range (the floor's rule). Neither may be a documentation or otherwise reserved address, because those are in
 * the hold-harmless table and the pre-stage exempts them before any rule runs. The scratch directory is
 * only used when it lies under a chain the trust walk accepts; otherwise the test picks
 * $XDG_RUNTIME_DIR, /run/user/<uid> or $HOME, as test_module does, and says which.
 *
 * The module source is INCLUDED, so the statics are reachable. WE_MODULE_SRC names another copy of it,
 * which is how the gate runs this test against a control build.
 */
#ifndef WE_MODULE_SRC
#define WE_MODULE_SRC "mod_whisper_edge.c"
#endif
#include WE_MODULE_SRC

#include <ftw.h>
#include <sys/time.h>
#include <time.h>

__thread const lsi_api_t *g_api;

/* the server's session pool, outside the server: plain malloc, freed with the test's request */
#define STUB_POOL_MAX 64
static void *stub_pool[STUB_POOL_MAX];
static int stub_npool;
void *ls_xpool_alloc(ls_xpool_t *pool, uint32_t size)
{
    void *p = malloc(size);

    (void) pool;
    if (stub_npool < STUB_POOL_MAX) {
        stub_pool[stub_npool++] = p;
    }
    return p;
}
static void stub_pool_free(void)
{
    while (stub_npool > 0) {
        free(stub_pool[--stub_npool]);
    }
}

static int checks, failed;

#define CHECK(cond, ...) do {                                   \
        checks++;                                               \
        if (!(cond)) {                                          \
            failed++;                                           \
            printf("  FAIL  ");                                 \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
        }                                                       \
    } while (0)

/* ---- the stub server ------------------------------------------------------------------------- */

static int stub_level = LSI_LOG_DEBUG;
static char stub_root[PATH_MAX];
static we_conf_t *stub_conf;
static const char *stub_ip = "127.0.0.1";
static const char *stub_uri = "/index.html";
static const char *stub_target = "/index.html";
static int stub_method = LSI_METHOD_GET;
static int stub_status;
static int stub_timer_calls;
static char stub_body[256];
static int stub_body_len, stub_ended, stub_nostore;
static struct { const char *k, *v; } stub_hdr[40];
static int stub_nhdr;
#define LOG_KEEP 256
static char stub_log_lines[LOG_KEEP][1024];
static int stub_nlog;
static struct { char name[48]; char val[2200]; } stub_env[48];
static int stub_nenv;

static void stub_log(const lsi_session_t *s, int level, const char *fmt, ...)
{
    va_list ap;
    char *dst = stub_log_lines[stub_nlog % LOG_KEEP];

    (void) s;
    (void) level;
    va_start(ap, fmt);
    vsnprintf(dst, sizeof stub_log_lines[0], fmt, ap);
    va_end(ap);
    dst[strcspn(dst, "\n")] = '\0';
    stub_nlog++;
    if (getenv("WE_TEST_VERBOSE") != NULL) {
        puts(dst);
    }
}
static int log_has(const char *frag)
{
    int i, n = stub_nlog < LOG_KEEP ? stub_nlog : LOG_KEEP;

    for (i = 0; i < n; i++) {
        if (strstr(stub_log_lines[i], frag) != NULL) {
            return 1;
        }
    }
    return 0;
}
static int log_count(const char *frag)
{
    int i, c = 0, n = stub_nlog < LOG_KEEP ? stub_nlog : LOG_KEEP;

    for (i = 0; i < n; i++) {
        c += strstr(stub_log_lines[i], frag) != NULL;
    }
    return c;
}
static int stub_set_timer(unsigned int ms, int repeat, lsi_timercb_pf cb, const void *arg)
{
    (void) ms; (void) repeat; (void) cb; (void) arg;
    stub_timer_calls++;
    return 1;
}
static void *stub_get_config(const lsi_session_t *s, const lsi_module_t *m) { (void) s; (void) m; return stub_conf; }
static const char *stub_client_ip(const lsi_session_t *s, int *len) { (void) s; *len = (int) strlen(stub_ip); return stub_ip; }
static void stub_set_req_env(const lsi_session_t *s, const char *name, unsigned int nl, const char *val, int vl)
{
    (void) s;
    if (stub_nenv < 48) {
        snprintf(stub_env[stub_nenv].name, sizeof stub_env[0].name, "%.*s", (int) nl, name);
        snprintf(stub_env[stub_nenv].val, sizeof stub_env[0].val, "%.*s", vl, val);
        stub_nenv++;
    }
}
static const char *env_of(const char *name)
{
    int i;

    for (i = 0; i < stub_nenv; i++) {
        if (strcmp(stub_env[i].name, name) == 0) {
            return stub_env[i].val;
        }
    }
    return NULL;
}
static void stub_set_status(const lsi_session_t *s, int code) { (void) s; stub_status = code; }
static time_t stub_time = 1700000000;   /* the server's cached clock: advanced by the test where a second must pass */
static time_t stub_cur_time(int32_t *usec) { if (usec != NULL) { *usec = 0; } return stub_time; }
/* how many of the language's attributes live on the planes of `mask`: the default export set's size, from the table */
static int attrs_in(uint32_t mask)
{
    uint32_t i;
    int n = 0;

    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        n += ((mask >> we_mod_attr(i)->plane) & 1u) != 0u;
    }
    return n;
}
static const char *stub_server_root(void) { return stub_root; }
static int stub_hdr_count(const lsi_session_t *s) { (void) s; return stub_nhdr; }
static int stub_get_headers(const lsi_session_t *s, struct iovec *k, struct iovec *v, int max)
{
    int i;

    (void) s;
    for (i = 0; i < stub_nhdr && i < max; i++) {
        k[i].iov_base = (void *) stub_hdr[i].k;
        k[i].iov_len = strlen(stub_hdr[i].k);
        v[i].iov_base = (void *) stub_hdr[i].v;
        v[i].iov_len = strlen(stub_hdr[i].v);
    }
    return i;
}
static const char *stub_get_uri(const lsi_session_t *s, int *len) { (void) s; *len = (int) strlen(stub_uri); return stub_uri; }
/* the original path and the query as the server parses them from the request line: the path up to the `?`,
 * and a non-NULL (possibly empty) query pointer when a `?` is present, NULL when it is not (measured) */
static int stub_org_uri(const lsi_session_t *s, char *buf, int max)
{
    const char *q = strchr(stub_target, '?');
    int n = q != NULL ? (int) (q - stub_target) : (int) strlen(stub_target);

    (void) s;
    return snprintf(buf, (size_t) max, "%.*s", n, stub_target);
}
static const char *stub_query(const lsi_session_t *s, int *len)
{
    const char *q = strchr(stub_target, '?');

    (void) s;
    *len = q != NULL ? (int) strlen(q + 1) : 0;
    return q != NULL ? q + 1 : NULL;
}
static enum LSI_REQ_METHOD stub_get_method(const lsi_session_t *s) { (void) s; return (enum LSI_REQ_METHOD) stub_method; }
static ls_xpool_t *stub_session_pool(const lsi_session_t *s) { static int dummy; (void) s; return (ls_xpool_t *) (void *) &dummy; }
static int stub_set_resp_header(const lsi_session_t *s, unsigned int id, const char *name, int nl, const char *val, int vl, int op)
{
    (void) s; (void) name; (void) nl; (void) op;
    if (id == LSI_RSPHDR_CACHE_CTRL && vl == 8 && memcmp(val, "no-store", 8) == 0) {
        stub_nostore = 1;
    }
    return 0;
}
static int stub_append_body(const lsi_session_t *s, const char *buf, int len)
{
    (void) s;
    stub_body_len = len < (int) sizeof stub_body - 1 ? len : (int) sizeof stub_body - 1;
    memcpy(stub_body, buf, (size_t) stub_body_len);
    stub_body[stub_body_len] = '\0';
    return len;
}
static void stub_end_resp(const lsi_session_t *s) { (void) s; stub_ended = 1; }

/* ---- scaffolding ----------------------------------------------------------------------------- */

static char g_base[PATH_MAX];

static void trusted_base(const char *arg, char *out, size_t n)
{
    const char *c[4];
    char run[64], why[256];
    size_t i;

    snprintf(run, sizeof run, "/run/user/%u", (unsigned) getuid());
    c[0] = arg;
    c[1] = getenv("XDG_RUNTIME_DIR");
    c[2] = run;
    c[3] = getenv("HOME");
    for (i = 0u; i < 4u; i++) {
        int fd;

        /* the planes' own walk (no sticky exception), not the configuration files' chain check, which admits a
         * /tmp-chained candidate the planes' walk would then refuse */
        if (c[i] != NULL && c[i][0] == '/' && we_mod_dir_open(c[i], (unsigned) geteuid(), &fd, why, sizeof why) == 0) {
            close(fd);
            snprintf(out, n, "%.4000s/we-test-litespeed.%ld", c[i], (long) getpid());
            return;
        }
    }
    out[0] = '\0';
}

static int rm_one(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void) st; (void) flag; (void) ftw;
    return remove(path);
}

static int copy_file(const char *from, const char *to, mode_t mode)
{
    FILE *a = fopen(from, "rb"), *b;
    char buf[8192];
    size_t n;

    if (a == NULL) {
        return -1;
    }
    b = fopen(to, "wb");
    if (b == NULL) {
        fclose(a);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof buf, a)) > 0u) {
        fwrite(buf, 1, n, b);
    }
    fclose(a);
    fclose(b);
    return chmod(to, mode);
}

static module_param_info_t *params(const char *const *kv, int n, char ***hold)
{
    module_param_info_t *p = calloc((size_t) n, sizeof *p);
    char **h = calloc((size_t) n, sizeof *h);
    int i, k;

    for (i = 0; i < n; i++) {
        const char *key = kv[2 * i], *val = kv[2 * i + 1];

        for (k = 0; k < K_COUNT && strcmp(ls_key_name[k], key) != 0; k++) {
        }
        p[i].key_index = (uint16_t) k;
        h[i] = strdup(val);
        p[i].val = h[i];
        p[i].val_len = (uint16_t) strlen(val);
    }
    *hold = h;
    return p;
}

static we_conf_t *parse(int level, const char *name, const char *const *kv, int n, void *parent)
{
    char **hold;
    module_param_info_t *p = params(kv, n, &hold);
    we_conf_t *c = we_parse_config(p, n, parent, level, name);
    int i;

    for (i = 0; i < n; i++) {
        free(hold[i]);
    }
    free(hold);
    free(p);
    return c;
}

static int one_request(we_conf_t *conf, const char *ip, const char *xff, const char *uri, const char *target)
{
    lsi_param_t p;

    memset(&p, 0, sizeof p);
    p.session = (const lsi_session_t *) &p;
    stub_conf = conf;
    stub_ip = ip;
    stub_uri = uri;
    stub_target = target;
    stub_nhdr = 0;
    stub_hdr[stub_nhdr].k = "host"; stub_hdr[stub_nhdr++].v = "test";
    if (xff != NULL) {
        stub_hdr[stub_nhdr].k = "x-forwarded-for"; stub_hdr[stub_nhdr++].v = xff;
    }
    stub_status = 0;
    stub_body_len = 0;
    stub_body[0] = '\0';
    stub_ended = 0;
    stub_nostore = 0;
    stub_nenv = 0;
    stub_pool_free();
    return we_check(&p);
}

static lsi_callback_pf hook_of(int index)
{
    const lsi_serverhook_t *h;

    for (h = MNAME.serverhook; h != NULL && h->cb != NULL; h++) {
        if (h->index == index && (h->flag & LSI_FLAG_ENABLED)) {
            return h->cb;
        }
    }
    return NULL;
}

static int wait_file(const char *dir, const char *suffix, char *out, size_t n, int secs)
{
    int i;

    for (i = 0; i < secs * 20; i++) {
        char cmd[PATH_MAX + 64];
        FILE *f;

        snprintf(cmd, sizeof cmd, "ls %.4000s 2>/dev/null", dir);
        f = popen(cmd, "r");
        if (f != NULL) {
            char line[512];

            while (fgets(line, sizeof line, f) != NULL) {
                line[strcspn(line, "\n")] = '\0';
                if (strlen(line) > strlen(suffix) && strcmp(line + strlen(line) - strlen(suffix), suffix) == 0) {
                    snprintf(out, n, "%.3500s/%.500s", dir, line);
                    pclose(f);
                    return 0;
                }
            }
            pclose(f);
        }
        usleep(50000);
    }
    return -1;
}

static int file_has(const char *path, const char *frag)
{
    FILE *f = fopen(path, "r");
    char line[4096];
    int found = 0;

    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        found |= strstr(line, frag) != NULL;
    }
    fclose(f);
    return found;
}

#ifdef WE_MOD_TEST_LEGACY_HOLD
static we_map_t *g_hold_m1, *g_hold_m2;

/* the seam's hook: the loop publishes twice while the writer holds the set it loaded */
static void test_two_publishes(void)
{
    ls_legacy_publish(g_hold_m1);
    ls_legacy_publish(g_hold_m2);
}
#endif

int main(int argc, char **argv)
{
    static lsi_api_t api;
    char planes[PATH_MAX], counters[PATH_MAX], confdir[PATH_MAX], path[PATH_MAX], out[PATH_MAX + 64];
    char d16[17];
    lsi_callback_pf main_inited, worker_init, worker_atexit;
    lsi_param_t none;
    we_conf_t *srv, *vdeny, *voff, *vbad, *vinh, *vhttp, *vall;
    uint32_t off_deny;
    FILE *f;

    const char *listed, *unlisted, *critical;
    char mapped[64], junked[80];

    /* the fixture's files must pass the module's trust rule whatever umask the caller runs under (this box runs
     * 0002, which would make the fake main file 0664 and refused as group-writable); and the output is line
     * buffered, so a check's FAIL line reaches the caller even if a later dereference crashes the test */
    umask(022);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 6) {
        fprintf(stderr, "usage: test_mod <reputation.bin> <scratch-dir> <listed-high-ipv4> <unlisted-ipv4> <listed-critical-ipv4>\n");
        return 2;
    }
    listed = argv[3];
    unlisted = argv[4];
    critical = argv[5];
    snprintf(mapped, sizeof mapped, "::ffff:%.40s", listed);
    snprintf(junked, sizeof junked, "%.40s, junk, 127.0.0.1", listed);
    api.log = stub_log;
    api.set_timer = stub_set_timer;
    api.get_config = stub_get_config;
    api.get_client_ip = stub_client_ip;
    api.set_req_env = stub_set_req_env;
    api.set_status_code = stub_set_status;
    api.get_cur_time = stub_cur_time;
    api.get_server_root = stub_server_root;
    api.get_req_headers_count = stub_hdr_count;
    api.get_req_headers = stub_get_headers;
    api.get_req_uri = stub_get_uri;
    api.get_req_org_uri = stub_org_uri;
    api.get_req_query_string = stub_query;
    api.get_req_method = stub_get_method;
    api.get_session_pool = stub_session_pool;
    api.set_resp_header = stub_set_resp_header;
    api.append_resp_body = stub_append_body;
    api.end_resp = stub_end_resp;
    api._log_level_ptr = &stub_level;
    g_api = &api;
    memset(&none, 0, sizeof none);

    trusted_base(argv[2], g_base, sizeof g_base);
    if (g_base[0] == '\0') {
        printf("  FAIL  no directory this process owns under a root-owned chain (XDG_RUNTIME_DIR, /run/user/<uid>, HOME): "
               "the planes cannot be placed where the trust walk accepts them\n");
        return 1;
    }
    printf("scratch %s\n", g_base);
    mkdir(g_base, 0700);
    snprintf(planes, sizeof planes, "%.4000s/planes", g_base);
    snprintf(counters, sizeof counters, "%.4000s/counters", g_base);
    snprintf(confdir, sizeof confdir, "%.4000s/lsws/conf", g_base);
    snprintf(stub_root, sizeof stub_root, "%.4000s/lsws/", g_base);
    mkdir(planes, 0755);
    mkdir(counters, 0755);
    snprintf(path, sizeof path, "%.4000s/lsws", g_base);
    mkdir(path, 0755);
    mkdir(confdir, 0755);
    snprintf(path, sizeof path, "%.4000s/reputation.bin", planes);
    CHECK(copy_file(argv[1], path, 0444) == 0, "the snapshot %s cannot be copied to %s", argv[1], path);
    snprintf(path, sizeof path, "%.4000s/httpd_config.conf", confdir);
    f = fopen(path, "w");
    if (f != NULL) {
        fputs("serverName test\nuseIpInProxyHeader 0\ntuning {\n    maxReqHeaderSize 65536\n}\n", f);
        fclose(f);
    }

    /* 1. the server level: the parameters, what is kept and what is refused with which words */
    {
        char refresh[16];
        const char *kv[] = {
            "whisper_edge_data", planes,
            "whisper_edge_summary", counters,
            "whisper_edge_refresh", refresh,
            "whisper_edge_policy_floor", "deny if listed >= critical",
            "whisper_edge_mode", "log",
            "whisper_edge_mode", "deny",                 /* a second definition: refused naming both */
            "whisper_edge_trusted_proxy", "127.0.0.1 ::1",
            "whisper_edge_trusted_header", "X-Forwarded-For",
            "whisper_edge_policy", "deny if listed >= high",
            "whisper_edge_policy", "log if country in @embargo",
            "whisper_edge_set", "@embargo KP SY",
            "whisper_edge_deny_status", "401",            /* refused: needs WWW-Authenticate */
            "whisper_edge_trusted_hops", "17",            /* refused: 1..16 */
        };

        snprintf(refresh, sizeof refresh, "10");
        we_init(&MNAME);
        srv = parse(LSI_CFG_SERVER, "httpServerConfig", kv, (int) (sizeof kv / sizeof kv[0] / 2u), NULL);
        CHECK(srv != NULL && srv->c == &g_server, "the server block's configuration does not name the server context");
        CHECK(log_has("whisper_edge_mode #6 is a second definition at the server level (the first is #5)"),
              "a second whisper_edge_mode at the server level was not refused naming both ordinals");
        CHECK(log_has("401 requires a WWW-Authenticate header, which this module does not send; use 403"),
              "deny_status 401 was not refused with its class's reason");
        CHECK(log_has("whisper_edge_trusted_hops #13 takes 1 to 16; \"17\" is refused; the configuration is refused and the "
                      "module runs no program until it is fixed") && g_http.trust_refused,
              "trusted_hops 17 was not refused as a configuration refusal");
        CHECK(g_http.refresh_ms == 10000u && strcmp(g_http.data_dir, planes) == 0 && g_http.ntrusted == 2u
              && strcmp(g_http.trusted_header, "X-Forwarded-For") == 0, "the server-level values were not kept");
        CHECK(g_server.n == 5u, "the server level carries %zu compiler directives, not the 5 written (floor, mode, 2 policy, set)",
              g_server.n);
    }
    /* the trust directives parse as Apache and nginx parse them: the proxy list split on whitespace alone (a comma
     * stays inside its entry, which the table then refuses), no cap on the entries, and the hops value read whole */
    {
        static char many[257 * 16];
        const char *kv1[] = { "whisper_edge_trusted_proxy", many };
        const char *kv2[] = { "whisper_edge_trusted_proxy", "10.0.0.1,10.0.0.2" };
        const char *kv3[] = { "whisper_edge_trusted_hops", "000000000000002garbage" };
        size_t o = 0u, k;
        uint32_t hops0 = g_http.trusted_hops;
        we_conf_t *t;

        for (k = 0u; k < 257u; k++) {
            o += (size_t) snprintf(many + o, sizeof many - o, "%s10.%u.%u.0/24", k ? " " : "", (unsigned) (k / 256u),
                                   (unsigned) (k % 256u));
        }
        g_http.ntrusted = 0u;
        g_http.first_ordinal[K_TRUSTED_PROXY] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv1, 1, NULL); free(t);
        CHECK(g_http.ntrusted == 257u, "a trusted_proxy line of 257 prefixes kept %zu of them (a silent cap)", g_http.ntrusted);
        g_http.ntrusted = 0u;
        g_http.first_ordinal[K_TRUSTED_PROXY] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv2, 1, NULL); free(t);
        CHECK(g_http.ntrusted == 1u, "\"10.0.0.1,10.0.0.2\" became %zu entries; Apache keeps one (whitespace splits, a comma "
              "does not)", g_http.ntrusted);
        g_http.first_ordinal[K_TRUSTED_HOPS] = 0u;
        g_http.trusted_hops = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv3, 1, NULL); free(t);
        CHECK(g_http.trusted_hops == 0u && log_has("whisper_edge_trusted_hops #1 takes 1 to 16; \"000000000000002garbage\""),
              "trusted_hops \"000000000000002garbage\" was read as %u, not refused (the value cut to 15 bytes)",
              g_http.trusted_hops);
        CHECK(g_http.trust_refused, "a refused hops value did not refuse the configuration");
        g_http.trusted_hops = hops0;
        /* the first block's trusted line again, for the build below */
        {
            const char *kv4[] = { "whisper_edge_trusted_proxy", "127.0.0.1 ::1" };

            g_http.ntrusted = 0u;
            g_http.first_ordinal[K_TRUSTED_PROXY] = 0u;
            t = parse(LSI_CFG_SERVER, "httpServerConfig", kv4, 1, NULL); free(t);
        }
        g_http.first_ordinal[K_TRUSTED_HOPS] = 0u;
    }
    /* more refusals, each with its words */
    {
        const char *kv1[] = { "whisper_edge_trusted_header", "X Forwarded" };
        const char *kv2[] = { "whisper_edge_trusted_header", "FORWARDED" };
        const char *kv3[] = { "whisper_edge_deny_status", "503" };
        const char *kv4[] = { "whisper_edge_deny_status", "444" };
        const char *kv5[] = { "whisper_edge_export", "asn nonsense tor_exit" };
        const char *kv6[] = { "whisper_edge_data", "routing /var/lib/x.bin" };
        const char *kv7[] = { "whisper_edge_data", "routing var/lib/x.bin" };
        const char *kv8[] = { "whisper_edge_data", "nonsense /var/lib/x.bin" };
        const char *kv9[] = { "whisper_edge_data", "routing /var/lib/y.bin" };
        we_conf_t *t;

        g_http.first_ordinal[K_TRUSTED_HEADER] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv1, 1, NULL); free(t);
        CHECK(log_has("a header name is a token (RFC 9110 section 5.1); \"X Forwarded\" is refused"),
              "a header name with a space was not refused as not a token");
        g_http.first_ordinal[K_TRUSTED_HEADER] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv2, 1, NULL); free(t);
        CHECK(log_has("Forwarded uses the RFC 7239 syntax, which this module does not read"),
              "FORWARDED was not refused (field names are case-insensitive)");
        CHECK(strcmp(g_http.trusted_header, "X-Forwarded-For") == 0, "a refused header name replaced the accepted one");
        g_http.first_ordinal[K_DENY_STATUS] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv3, 1, NULL); free(t);
        CHECK(log_has("a 5xx says the server failed (RFC 9110 section 15.6)"), "deny_status 503 was not refused as a 5xx");
        g_http.first_ordinal[K_DENY_STATUS] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv4, 1, NULL); free(t);
        CHECK(log_has("444 is nginx's close without a response"), "deny_status 444 was not refused on this server");
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv5, 1, NULL); free(t);
        CHECK(log_has("names \"nonsense\", which is not an attribute of the language"), "an unknown export name was not refused");
        CHECK(g_server.export_set && (g_server.export_attrs & (1u << 19)) && (g_server.export_attrs & (1u << 2)),
              "the known export names (asn, tor_exit) were not kept beside the refused one (mask %08x)", g_server.export_attrs);
        g_server.export_set = 0u;
        g_server.export_attrs = 0u;
        /* ABI 5: the per-plane form binds that plane's own file beside the directory, which it does not replace;
         * a relative path, an unknown plane and a second line for one plane are refused */
        g_http.first_ordinal[K_DATA] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv6, 1, NULL); free(t);
        CHECK(strcmp(g_http.plane_file[3], "/var/lib/x.bin") == 0 && strcmp(g_http.data_dir, planes) == 0,
              "whisper_edge_data routing <file> did not bind routing's file beside the directory (\"%s\", \"%s\")",
              g_http.plane_file[3], g_http.data_dir);
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv9, 1, NULL); free(t);
        CHECK(log_has("is a second definition of plane routing at the server level")
              && strcmp(g_http.plane_file[3], "/var/lib/x.bin") == 0,
              "a second routing line was not refused, or it replaced the first (\"%s\")", g_http.plane_file[3]);
        g_http.plane_file[3][0] = '\0';
        g_http.plane_file_ordinal[3] = 0u;
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv7, 1, NULL); free(t);
        CHECK(log_has("the routing file needs an absolute path; \"var/lib/x.bin\" is refused") && g_http.plane_file[3][0] == '\0',
              "a relative per-plane path was not refused");
        t = parse(LSI_CFG_SERVER, "httpServerConfig", kv8, 1, NULL); free(t);
        CHECK(log_has("\"nonsense\" names no plane"), "a per-plane line naming no plane was not refused");
        memset(g_http.plane_file, 0, sizeof g_http.plane_file);
        memset(g_http.plane_file_ordinal, 0, sizeof g_http.plane_file_ordinal);
    }

    /* 2. the virtual hosts */
    {
        const char *deny[] = { "whisper_edge_mode", "deny", "whisper_edge_deny_status", "451",
                               "whisper_edge_policy", "deny if listed >= low", "whisper_edge_policy", "log if listed >= low" };
        const char *off[] = { "whisper_edge_mode", "off" };
        const char *bad[] = { "whisper_edge_mode", "deny", "whisper_edge_policy", "deny if tor_exit garbage" };
        const char *inh[] = { "whisper_edge_allow_inferred", "no" };
        const char *http[] = { "whisper_edge_data", "/nowhere", "whisper_edge_mode", "DENY" };
        const char *all[] = { "whisper_edge_mode", "deny", "whisper_edge_export", "all",
                              "whisper_edge_policy", "deny if listed >= medium" };

        vdeny = parse(LSI_CFG_VHOST, "VDeny", deny, 4, srv);
        voff = parse(LSI_CFG_VHOST, "VOff", off, 1, srv);
        vbad = parse(LSI_CFG_VHOST, "VBad", bad, 2, srv);
        vinh = parse(LSI_CFG_VHOST, "VInherit", inh, 1, srv);
        vhttp = parse(LSI_CFG_VHOST, "VHttpOnly", http, 2, srv);
        vall = parse(LSI_CFG_VHOST, "VAll", all, 3, srv);
        CHECK(g_nvhost == 6u && vdeny->c->index == 1u && strcmp(vdeny->c->path, "http/v1") == 0,
              "the virtual hosts are not numbered in parse order");
        CHECK(log_has("vhost \"VHttpOnly\": whisper_edge_data #1: whisper_edge_data is http level only"),
              "an http-only directive in a virtual host was not refused with the documented words");
        CHECK(vhttp->c->n == 1u, "the refused http-only line was kept beside the host's mode line");
        CHECK(vinh->c->n == 1u && memcmp(vinh->c->d[0].arg, "off", 3) == 0, "allow_inferred no was not read as off");
        CHECK(vdeny->c->deny_status == 451u, "deny_status 451 was not kept on the virtual host");
    }

    /* the trust refusals above refused the configuration, as they must; the build below is about everything else */
    g_http.trust_refused = 0;
    /* 3. the whole build at MAIN_INITED */
    main_inited = hook_of(LSI_HKPT_MAIN_INITED);
    worker_init = hook_of(LSI_HKPT_WORKER_INIT);
    worker_atexit = hook_of(LSI_HKPT_WORKER_ATEXIT);
    CHECK(main_inited != NULL && worker_init != NULL && worker_atexit != NULL && hook_of(LSI_HKPT_HTTP_AUTH) == we_check,
          "the hook table lacks MAIN_INITED, WORKER_INIT, HTTP_AUTH or WORKER_ATEXIT");
    CHECK(main_inited(&none) == LSI_OK && g_built, "the configuration did not build");
    if (!g_built) {
        printf("=== litespeed module unit test: %d checks, %d failed (the configuration did not build; the rest cannot run) ===\n",
               checks, failed);
        return 1;
    }
    CHECK(log_has("policy refused: \"VBad\": policy #2: rule 1, line 1, column 18: near \"garbage\""),
          "the refused host's line does not name the host, the directive's ordinal and the refusal");
    CHECK(vbad->c->refused && vbad->c->ctx != NULL && vbad->c->ctx->prog != NULL && vbad->c->ctx->prog->rule_count == 0u,
          "a refused host does not run the empty program");
    CHECK(vdeny->c->ctx != NULL && vdeny->c->ctx->prog != NULL && vdeny->c->ctx->prog->rule_count == 2u
          && we_conf_mode(&vdeny->c->ctx->conf) == WE_MODE_DENY && vdeny->c->ctx->deny_status == 451u,
          "the deny host's program, mode or status is wrong");
    CHECK(vinh->c->ctx != NULL && vinh->c->ctx->prog == g_server.ctx->prog && we_conf_mode(&vinh->c->ctx->conf) == WE_MODE_LOG,
          "a host with no lines of its own does not run the server's program under its own mode");
    CHECK(g_cfg.floor != NULL && g_cfg.floor->rule_count == 1u && we_conf_mode(&g_cfg.floor_conf) == WE_MODE_LOG
          && g_cfg.floor_status == 403u, "the floor is not the one line under the http level's log mode and 403");
    CHECK((g_cfg.bound_mask & 0x01u) != 0u && we_current(g_cfg.handle[0]) != NULL, "reputation is not bound and armed");
    CHECK(log_has("floor: 1 rules, program ") && log_has("vhost \"VDeny\": 2 rules, program ")
          && log_has("vhost \"VDeny\" replaces 2 inherited rules") && log_has("vhost \"VInherit\": no lines of its own; runs program ")
          && log_has("vhost \"VBad\": refused (policy #2:"), "the configuration-time lines are not the documented ones");
    CHECK(log_has("report http: rule 2: rule 2 references plane \"routing\", which is not installed here"),
          "the inert rule on the absent routing plane was not reported");
    CHECK(log_has("the floor will not deny: its mode is the http level's (log)"), "the silent dry run of the floor was not named");
    CHECK(g_stride == 16u, "the stride is %u, not 16 (8 pre-stage + 1 floor + 2 server + 2 deny + 1 all + 0 refused, rounded to 8)", g_stride);
    /* the server's own settings file says useIpInProxyHeader 0, so nothing is said */
    CHECK(g_srv.use_ip_in_proxy_header == 0 && !ls_client_ip_from_header()
          && !log_has("the floor does not trust the client address"), "useIpInProxyHeader 0 was read as %d, or the distrust warning fired",
          g_srv.use_ip_in_proxy_header);
    {
        /* the mapping the ERROR line and the status flag rest on: every value but 0, and none (-1), is not
         * trusted: the module trusts only an explicit 0 */
        int saved = g_srv.use_ip_in_proxy_header, v, bad_map = 0;
        static const int want[6] = { 1, 1, 0, 1, 1, 1 };  /* for -1, 1, 0, 2, 3, 4 */
        static const int vals[6] = { -1, 1, 0, 2, 3, 4 };

        for (v = 0; v < 6; v++) {
            g_srv.use_ip_in_proxy_header = vals[v];
            bad_map |= ls_client_ip_from_header() != want[v];
        }
        g_srv.use_ip_in_proxy_header = saved;
        CHECK(!bad_map, "ls_client_ip_from_header does not distrust every value but 0, and none");
    }
    CHECK(g_conf_text.buf != NULL && strstr(g_conf_text.buf, "refused \"http/v3\" \"policy #2:") != NULL,
          "the configuration file carries no refused line for the refused host");
    CHECK(strlen(g_config16) == 16u && strncmp(g_conf_name, "conf-", 5) == 0, "the configuration digest is not named");
    CHECK(g_hdr_line_bound == 65536u / 4u, "the header-line bound is %u, not 16384 from the file's maxReqHeaderSize", g_hdr_line_bound);
    CHECK(g_trust_built && g_trust.n4 == 1u && g_trust.n6 == 1u, "the trusted-proxy table was not built");
    ls_program_digest(vdeny->c->ctx->prog, d16);
    off_deny = vdeny->c->ctx->ctr_off;
    /* a late build: a host whose block arrives after the build runs the server's program and is said */
    {
        const char *late[] = { "whisper_edge_mode", "deny" };
        we_conf_t *l = parse(LSI_CFG_VHOST, "VLate", late, 1, srv);

        CHECK(l != NULL && l->c == &g_server && log_has("vhost VLate: its module block arrived after the configuration was built"),
              "a late virtual host was not refused with the server's configuration handed back");
        free(l);
    }

    /* 4. the worker: the start check, the shard, the thread's first write */
    CHECK(worker_init(&none) == LSI_OK && g_shard != NULL && g_shard != g_sink && g_thread != NULL && stub_timer_calls == 1,
          "the worker start did not allocate the shard, start the thread and register the poll");
    CHECK(wait_file(counters, ".status", out, sizeof out, 3) == 0, "no status file appeared within 3 s of the worker start");
    CHECK(file_has(out, "plane reputation armed generation 1 digest ") && file_has(out, "whisper-edge-status 2"),
          "the first status write does not report reputation armed: %s", out);
    snprintf(path, sizeof path, "%.4000s/%s", counters, g_conf_name);
    CHECK(access(path, R_OK) == 0 && file_has(path, "refused \"http/v3\""), "the configuration file was not written by the first tick");

    /* 5. the request path */
    CHECK(one_request(vdeny, "127.0.0.1", NULL, "/index.html", "/index.html") == LSI_OK && stub_status == 0,
          "the loopback peer (hold-harmless) was not allowed");
    CHECK(env_of("WHISPER_EDGE_ACTION") != NULL && strcmp(env_of("WHISPER_EDGE_ACTION"), "allow") == 0
          && strcmp(env_of("WHISPER_EDGE_REASON"), "hold-harmless,floor-header-missing") == 0,
          "the loopback decision renders action %s, reason %s", env_of("WHISPER_EDGE_ACTION"), env_of("WHISPER_EDGE_REASON"));
    CHECK(strncmp(env_of("WHISPER_EDGE_PROGRAM"), "floor:", 6) == 0 && strstr(env_of("WHISPER_EDGE_PROGRAM"), " ctx:-") != NULL,
          "a pre-stage decision does not render ctx:- (%s)", env_of("WHISPER_EDGE_PROGRAM"));
    CHECK(strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), "127.0.0.1") == 0, "the floor address is %s", env_of("WHISPER_EDGE_FLOOR_ADDR"));
    CHECK(stub_nenv == 9 + attrs_in(0x81u), "%d environment values exported; %d expected: 9 decision values and the attributes of "
          "the deny host's default export set, reputation (its program's and the floor's) and the tenant plane (in every set, "
          "unbound here, so unknown)", stub_nenv, 9 + attrs_in(0x81u));
    CHECK(strcmp(env_of("WHISPER_EDGE_TENANT_ALLOW"), "unknown") == 0, "the unbound tenant plane's attribute renders %s, not unknown",
          env_of("WHISPER_EDGE_TENANT_ALLOW"));

    CHECK(one_request(vdeny, "127.0.0.1", listed, "/index.html", "/index.html") == LSI_DENY,
          "a listed client behind the trusted proxy was not denied on the deny host");
    CHECK(stub_status == 451 && stub_nostore && stub_ended && strcmp(stub_body, WE_MOD_DENY_TEXT) == 0,
          "the deny response is status %d, no-store %d, ended %d, body \"%s\"", stub_status, stub_nostore, stub_ended, stub_body);
    CHECK(strcmp(env_of("WHISPER_EDGE_ACTION"), "deny") == 0 && strcmp(env_of("WHISPER_EDGE_RULE_ID"), "ctx:1") == 0
          && strcmp(env_of("WHISPER_EDGE_RULE"), "deny if listed >= low") == 0
          && strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), listed) == 0
          && strcmp(env_of("WHISPER_EDGE_VERDICT"), "high") == 0 && strcmp(env_of("WHISPER_EDGE_LISTED"), "high") == 0,
          "the deny renders action %s rule_id %s rule \"%s\" floor %s verdict %s listed %s", env_of("WHISPER_EDGE_ACTION"),
          env_of("WHISPER_EDGE_RULE_ID"), env_of("WHISPER_EDGE_RULE"), env_of("WHISPER_EDGE_FLOOR_ADDR"),
          env_of("WHISPER_EDGE_VERDICT"), env_of("WHISPER_EDGE_LISTED"));
    {
        char want[64];

        snprintf(want, sizeof want, "floor:%s ctx:%s", "", d16);
        CHECK(strstr(env_of("WHISPER_EDGE_PROGRAM"), " ctx:") != NULL && strstr(env_of("WHISPER_EDGE_PROGRAM"), d16) != NULL,
              "the program renders %s, which does not name the deny host's block %s", env_of("WHISPER_EDGE_PROGRAM"), d16);
        CHECK(strcmp(env_of("WHISPER_EDGE_REASON"), "-") == 0, "a rule's deny renders reason %s, not -", env_of("WHISPER_EDGE_REASON"));
        CHECK(strncmp(env_of("WHISPER_EDGE_GENERATIONS"), "reputation:1.", 13) == 0 && strchr(env_of("WHISPER_EDGE_GENERATIONS"), '*') == NULL,
              "the generations token is %s", env_of("WHISPER_EDGE_GENERATIONS"));
        CHECK(strcmp(env_of("WHISPER_EDGE_LOGGED"), "-") == 0, "logged renders %s after a deny by rule 1 (rule 2 never ran)",
              env_of("WHISPER_EDGE_LOGGED"));
    }
    CHECK(__atomic_load_n(&g_shard[off_deny], __ATOMIC_RELAXED) == 1u, "the deny host's rule 1 counts %llu, not 1",
          (unsigned long long) g_shard[off_deny]);
    CHECK(__atomic_load_n(&g_shard[WE_MOD_CTR_HOLD_HARMLESS], __ATOMIC_RELAXED) == 1u
          && __atomic_load_n(&g_shard[WE_MOD_CTR_FLOOR_HEADER_MISSING], __ATOMIC_RELAXED) == 1u,
          "the pre-stage counters read hold-harmless %llu, floor-header-missing %llu", (unsigned long long) g_shard[0],
          (unsigned long long) g_shard[WE_MOD_CTR_FLOOR_HEADER_MISSING]);

    CHECK(one_request(vinh, "127.0.0.1", listed, "/index.html", "/index.html") == LSI_OK && stub_status == 0,
          "the inheriting host under mode log enforced a deny");
    /* the server's program names the routing plane (log if country in @embargo), which is not bound here: its three
     * attributes are in the default export set, rendered unknown without a fill, and the token says why */
    CHECK(stub_nenv == 9 + attrs_in(0x89u) && strcmp(env_of("WHISPER_EDGE_COUNTRY"), "unknown") == 0
          && strcmp(env_of("WHISPER_EDGE_ASN"), "unknown") == 0 && strstr(env_of("WHISPER_EDGE_GENERATIONS"), "routing:-a") != NULL,
          "the inheriting host exports %d values (%d expected: 9 and the attributes of reputation, routing and tenant) with country %s "
          "asn %s generations %s", stub_nenv, 9 + attrs_in(0x89u), env_of("WHISPER_EDGE_COUNTRY"), env_of("WHISPER_EDGE_ASN"),
          env_of("WHISPER_EDGE_GENERATIONS"));
    CHECK(strcmp(env_of("WHISPER_EDGE_ACTION"), "would-deny") == 0 && strcmp(env_of("WHISPER_EDGE_RULE_ID"), "-") == 0
          && strcmp(env_of("WHISPER_EDGE_LOGGED"), "ctx:1") == 0,
          "the inheriting host renders action %s rule_id %s logged %s, not would-deny - ctx:1 (a downgraded deny decides "
          "nothing: the default allow does, and the fired rule is in logged)", env_of("WHISPER_EDGE_ACTION"),
          env_of("WHISPER_EDGE_RULE_ID"), env_of("WHISPER_EDGE_LOGGED"));
    CHECK(one_request(voff, "127.0.0.1", listed, "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_ACTION"), "allow") == 0 && strstr(env_of("WHISPER_EDGE_PROGRAM"), " ctx:-") != NULL
          && strcmp(env_of("WHISPER_EDGE_VERDICT"), "high") == 0,
          "mode off: action %s program %s verdict %s (the floor judged, the context skipped, the verdict still written)",
          env_of("WHISPER_EDGE_ACTION"), env_of("WHISPER_EDGE_PROGRAM"), env_of("WHISPER_EDGE_VERDICT"));
    CHECK(one_request(vbad, "127.0.0.1", listed, "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_ACTION"), "allow") == 0, "the refused host judged by a rule: action %s",
          env_of("WHISPER_EDGE_ACTION"));
    {
        /* the floor under the http level's deny mode (the public pair flipped for these requests), on the mode-off host:
         * the floor's deny fires before any rule reads another plane, so the export fill after the decision has planes
         * to fill and clears the scratch verdict; a frame that read the scratch served a 200 with a log line saying deny */
        uint8_t saved = g_cfg.floor_conf.mode;
        char line[96];

        g_cfg.floor_conf.mode = WE_MODE_DENY;
        stub_time += 1;                     /* a new second: the deny line's rate limit admits one line per second */
        CHECK(one_request(voff, "127.0.0.1", critical, "/index.html", "/index.html") == LSI_DENY
              && stub_status == 403 && stub_nostore && stub_ended && strcmp(stub_body, WE_MOD_DENY_TEXT) == 0
              && strcmp(env_of("WHISPER_EDGE_ACTION"), "deny") == 0 && strcmp(env_of("WHISPER_EDGE_RULE_ID"), "floor:1") == 0,
              "a floor deny on the mode-off host under the http level's deny: rc status %d nostore %d ended %d action %s rule_id %s",
              stub_status, stub_nostore, stub_ended, env_of("WHISPER_EDGE_ACTION"), env_of("WHISPER_EDGE_RULE_ID"));
        snprintf(line, sizeof line, "denied %.40s by floor:1 \"deny if listed >= critical\"", critical);
        CHECK(log_has(line), "the floor deny's log line is missing");
        CHECK(one_request(vdeny, "127.0.0.1", critical, "/index.html", "/index.html") == LSI_DENY && stub_status == 403,
              "a floor deny on the deny host uses the http level's status, not the host's 451 (status %d)", stub_status);
        g_cfg.floor_conf.mode = saved;
    }
    CHECK(one_request(vall, "127.0.0.1", critical, "/index.html", "/index.html") == LSI_DENY
          && strcmp(env_of("WHISPER_EDGE_RULE_ID"), "ctx:1") == 0 && strcmp(env_of("WHISPER_EDGE_ASN"), "unknown") == 0
          && strcmp(env_of("WHISPER_EDGE_TOR_EXIT"), "unknown") == 0 && strstr(env_of("WHISPER_EDGE_GENERATIONS"), "tor:-a") != NULL
          && strstr(env_of("WHISPER_EDGE_GENERATIONS"), "routing:-a") != NULL,
          "export all: rule_id %s asn %s tor_exit %s generations %s (every attribute exported, the unbound planes unknown and -a)",
          env_of("WHISPER_EDGE_RULE_ID"), env_of("WHISPER_EDGE_ASN"), env_of("WHISPER_EDGE_TOR_EXIT"), env_of("WHISPER_EDGE_GENERATIONS"));
    /* right to left: the trusted proxy's own entry is skipped, `junk` ends the walk, and the last entry that parsed
     * (the proxy's, the bad one's right neighbour) is judged with eligibility cleared and the unparsed note */
    CHECK(one_request(vdeny, "127.0.0.1", junked, "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), "127.0.0.1") == 0
          && strcmp(env_of("WHISPER_EDGE_REASON"), "floor-header-unparsed") == 0,
          "a bad entry after a parsed one: the last parsed is judged, not eligible (floor %s, reason %s)",
          env_of("WHISPER_EDGE_FLOOR_ADDR"), env_of("WHISPER_EDGE_REASON"));
    /* the rightmost element bad: nothing in the header vouches for an address, so the peer, marked, not eligible */
    CHECK(one_request(vdeny, "127.0.0.1", "junk", "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), "127.0.0.1") == 0
          && strcmp(env_of("WHISPER_EDGE_REASON"), "floor-header-unparsed") == 0,
          "no entry parsed: the peer with the unparsed note and no hold-harmless (floor %s, reason %s)",
          env_of("WHISPER_EDGE_FLOOR_ADDR"), env_of("WHISPER_EDGE_REASON"));
    CHECK(__atomic_load_n(&g_shard[WE_MOD_CTR_FLOOR_HEADER_UNPARSED], __ATOMIC_RELAXED) == 2u
          && __atomic_load_n(&g_shard[WE_MOD_CTR_FLOOR_HEADER_MISSING], __ATOMIC_RELAXED) == 1u,
          "unparsed counts %llu (2 expected) and header-missing %llu (1 expected): an unparsed request must count once",
          (unsigned long long) g_shard[WE_MOD_CTR_FLOOR_HEADER_UNPARSED], (unsigned long long) g_shard[WE_MOD_CTR_FLOOR_HEADER_MISSING]);
    CHECK(one_request(vdeny, "127.0.0.1", unlisted, "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_VERDICT"), "none") == 0 && strcmp(env_of("WHISPER_EDGE_LISTED"), "none") == 0,
          "an unlisted client renders verdict %s listed %s", env_of("WHISPER_EDGE_VERDICT"), env_of("WHISPER_EDGE_LISTED"));
    CHECK(one_request(vdeny, "127.0.0.1", listed, "/.well-known/acme-challenge/tok", "/.well-known/acme-challenge/tok") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_REASON"), "acme") == 0, "the ACME exact form was not exempt (reason %s)",
          env_of("WHISPER_EDGE_REASON"));
    CHECK(one_request(vdeny, "127.0.0.1", listed, "/.well-known/acme-challenge/tok", "/.well-known/acme-challenge/tok?") == LSI_DENY,
          "an ACME path with an empty query was exempt");
    CHECK(one_request(vdeny, "127.0.0.1", listed, "/.well-known/acme-challenge/tok", "/.well-known/acme-challenge/%74ok") == LSI_DENY,
          "a percent-encoded token character was exempt");
    CHECK(one_request(vdeny, "127.0.0.1", listed, "/.well-known/acme-challenge/tok", "//.well-known/acme-challenge/tok") == LSI_DENY,
          "a leading // was exempt");
    stub_method = LSI_METHOD_POST;
    CHECK(one_request(vdeny, "127.0.0.1", listed, "/.well-known/acme-challenge/tok", "/.well-known/acme-challenge/tok") == LSI_DENY,
          "a POST to the ACME path was exempt");
    stub_method = LSI_METHOD_GET;
    CHECK(one_request(vdeny, "2001:db8::1", listed, "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), "2001:db8::1") == 0,
          "an untrusted IPv6 peer's header was read (floor %s)", env_of("WHISPER_EDGE_FLOOR_ADDR"));
    CHECK(one_request(vdeny, mapped, NULL, "/index.html", "/index.html") == LSI_DENY
          && strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), listed) == 0,
          "a mapped IPv4 peer was not canonicalised to IPv4 (floor %s)", env_of("WHISPER_EDGE_FLOOR_ADDR"));
    CHECK(one_request(vdeny, "not-an-address", NULL, "/index.html", "/index.html") == LSI_OK
          && strcmp(env_of("WHISPER_EDGE_REASON"), "no-address") == 0 && strcmp(env_of("WHISPER_EDGE_FLOOR_ADDR"), "-") == 0,
          "an unparsable peer was not allow-by-no-address (reason %s floor %s)", env_of("WHISPER_EDGE_REASON"),
          env_of("WHISPER_EDGE_FLOOR_ADDR"));
    {
        char line[96];

        snprintf(line, sizeof line, "denied %.40s by ctx:1", listed);
        CHECK(log_count(line) == 1, "the deny log line appeared %d times, not once per second", log_count(line));
        CHECK(log_has("evidence "), "the deny log line carries no citable evidence");
    }
    CHECK(__atomic_load_n(&g_shard[off_deny], __ATOMIC_RELAXED) == 6u, "the deny host's rule 1 counts %llu, not 6",
          (unsigned long long) g_shard[off_deny]);

    /* 6. the exit: the thread's final write carries the counts since the last tick */
    CHECK(worker_atexit(&none) == LSI_OK, "the exit hook failed");
    CHECK(wait_file(counters, ".rules.cnt", out, sizeof out, 3) == 0, "no rule-counter file after the exit flush");
    {
        char want[64];

        snprintf(want, sizeof want, "r %s 1 6", d16);
        CHECK(file_has(out, want) && file_has(out, "pre hold-harmless 2") && file_has(out, "pre floor-header-unparsed 2")
              && file_has(out, "pre no-address 1") && file_has(out, "pre acme 1"),
              "the rule-counter file lacks the counts (want \"%s\", hold-harmless 2, unparsed 2, no-address 1, acme 1): %s", want, out);
    }

#ifdef WE_MOD_TEST_LEGACY_HOLD
    /* 7. two legacy publishes inside one write (the seam): the writer has loaded the live set S0 when the loop
     * publishes twice, retiring S0 and then S1. S0 must stay alive until the writer's next tick, which frees both.
     * Under AddressSanitizer the one-slot handoff this replaced (WE_MOD_TEST_LEGACY_LOOP_FREES) freed S0 on the
     * second publish and the write read it after the free: a heap-use-after-free, deterministic here. */
    {
        static we_map_t m0, m1, m2;
        ls_retired_t *r;
        int n = 0;

        CHECK(we_map_open(argv[1], &m0) == 0 && we_map_open(argv[1], &m1) == 0 && we_map_open(argv[1], &m2) == 0,
              "legacy hold: the three maps of %s did not open", argv[1]);
        g_legacy_map = &m0;
        __atomic_store_n(&g_legacy_counters, we_counters_new(&m0, 1u), __ATOMIC_RELEASE);
        ls_test_legacy_hold = test_two_publishes;
        g_hold_m1 = &m1;
        g_hold_m2 = &m2;
        ls_write_files(1u, 0);                   /* holds S0, the hook publishes twice, then the write reads S0 */
        ls_test_legacy_hold = NULL;
        for (r = __atomic_load_n(&g_legacy_retired, __ATOMIC_ACQUIRE); r != NULL; r = r->next) {
            n++;
        }
        CHECK(n == 2 && g_legacy_map == &m2, "legacy hold: two publishes inside one write left %d retired sets, not 2 "
              "held for the thread", n);
        ls_write_files(2u, 0);                   /* the thread's next tick frees them */
        CHECK(__atomic_load_n(&g_legacy_retired, __ATOMIC_ACQUIRE) == NULL, "legacy hold: the next tick did not free the "
              "retired sets");
        we_counters_free(__atomic_exchange_n(&g_legacy_counters, NULL, __ATOMIC_ACQ_REL));
        g_legacy_map = NULL;
        we_map_close(&m0);
        we_map_close(&m1);
        we_map_close(&m2);
    }
#endif

    stub_pool_free();
    nftw(g_base, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    printf("=== litespeed module unit test: %d checks, %d failed ===\n", checks, failed);
    return failed == 0 ? 0 : 1;
}
