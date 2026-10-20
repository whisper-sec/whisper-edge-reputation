/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * fuzz_manifest.c - whisper-edge-lookup's manifest reader, driven on its own.
 *
 * It includes the tool's one source file with WE_LOOKUP_READER_ONLY, so the reader exercised here is the
 * reader the tool runs, byte for byte, and nothing else of the tool is compiled.
 *
 *   fuzz_manifest_replay <file>...   one dump per file, in the format `lookup-check.py manifest` prints,
 *                                    so the C reader and the reference reader compare line for line
 *
 * Built with -DFZ_LIBFUZZER it is a libFuzzer target instead: every input is parsed and its fields
 * extracted under the sanitizers, and nothing is printed. `make check-lookup` runs the replay under
 * ASan and UBSan when the toolchain has them; a libFuzzer run is a by-hand step.
 */
#define WE_LOOKUP_READER_ONLY 1
#include "we_lookup_cli.c"

#ifndef FZ_LIBFUZZER
static void put_s(const char *s)
{
    sb_t r = {0};

    if (s == NULL) {
        fputs("-", stdout);
        return;
    }
    render(&r, s, strlen(s));
    fputs(r.p ? r.p : "", stdout);
    free(r.p);
}

static void put_t(tval_t t)
{
    switch (t.st) {
    case T_ABSENT:  fputs("absent", stdout); break;
    case T_NULL:    fputs("null", stdout); break;
    case T_REFUSED: fputs("refused", stdout); break;
    default:        printf("ms:%" PRId64, t.ms); break;
    }
}

static void dump(const manifest_t *m)
{
    uint32_t i, k;

    if (m->state != M_READ) {
        printf("result refuse:%s\n", m->why);
        return;
    }
    fputs("result accept\ntop generation=", stdout);
    put_s(m->generation);
    fputs(" builtAt=", stdout);
    put_t(m->built);
    fputs(" builder=", stdout);
    put_s(m->builder);
    fputs(" tier=", stdout);
    put_s(m->tier);
    fputs("\n", stdout);
    for (i = 0; i < m->nplanes; i++) {
        const pentry_t *p = &m->planes[i];

        printf("plane %u name=", i);
        put_s(p->name);
        printf(" sha256=%s bytes=", p->sha_ok ? p->sha : "-");
        if (p->bytes_ok) {
            printf("%" PRIu64, p->bytes);
        } else {
            fputs("-", stdout);
        }
        fputs(" generation=", stdout);
        put_s(p->generation);
        fputs(" headerGeneration=", stdout);
        put_s(p->hgen);
        fputs(" builtAt=", stdout);
        put_t(p->built);
        fputs(" validUntil=", stdout);
        put_t(p->valid);
        fputs(" coverage=", stdout);
        if (!p->cov_obj) {
            fputs("null", stdout);
        } else {
            put_s(p->cov_v4);
            fputs("/", stdout);
            put_s(p->cov_v6);
            fputs("/", stdout);
            put_s(p->cov_s32);
        }
        printf(" sources=%u\n", p->nsrc);
        for (k = 0; k < p->nsrc; k++) {
            const src_t *s = &p->src[k];

            printf("source %u %u name=", i, k);
            put_s(s->name);
            fputs(" kind=", stdout);
            put_s(s->kind);
            fputs(" count=", stdout);
            put_s(s->count);
            fputs(" observedAt=", stdout);
            put_t(s->observed);
            fputs(" recall=", stdout);
            put_s(s->recall);
            fputs(" precision=", stdout);
            put_s(s->precision);
            fputs("\n", stdout);
        }
    }
    for (i = 0; i < m->nlegacy; i++) {
        const lentry_t *l = &m->legacy[i];

        printf("legacy %u name=", i);
        put_s(l->name);
        printf(" sha256=%s bytes=", l->sha_ok ? l->sha : "-");
        if (l->bytes_ok) {
            printf("%" PRIu64, l->bytes);
        } else {
            fputs("-", stdout);
        }
        fputs(" headerGeneration=", stdout);
        put_s(l->hgen);
        fputs("\n", stdout);
    }
    for (i = 0; i < m->nwithheld; i++) {
        const wentry_t *w = &m->withheld[i];
        int r;

        printf("withheld %u name=", i);
        put_s(w->name);
        fputs(" reasons=", stdout);
        if (w->reasons_state == 0) {
            fputs("not-stated", stdout);
        } else if (w->reasons_state == 2) {
            fputs("refused", stdout);
        } else if (w->nreasons == 0) {
            fputs("-", stdout);
        } else {
            for (r = 0; r < w->nreasons; r++) {
                if (r) {
                    fputs(",", stdout);
                }
                put_s(w->reasons[r]);
            }
        }
        fputs(" reason=", stdout);
        put_s(w->reason);
        fputs(" detail=", stdout);
        put_s(w->detail);
        fputs(" since=", stdout);
        put_t(w->since);
        fputs(" builtGeneration=", stdout);
        put_s(w->built_gen);
        fputs(" lastPublishedValidUntil=", stdout);
        put_t(w->lpvu);
        fputs("\n", stdout);
    }
    for (i = 0; i < m->nfnotes; i++) {
        /* stored as "<file> <path>: <rule>"; printed as "fieldnote <path> <rule>" */
        const char *n = m->fnotes[i], *sp = strchr(n, ' '), *colon = strstr(n, ": ");

        if (sp != NULL && colon != NULL) {
            printf("fieldnote %.*s %s\n", (int)(colon - sp - 1), sp + 1, colon + 2);
        }
    }
}

int main(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        uint8_t *buf = NULL;
        size_t n = 0, cap = 0;
        manifest_t m;
        const char *base = strrchr(argv[i], '/');

        if (f == NULL) {
            fprintf(stderr, "fuzz_manifest: cannot read %s\n", argv[i]);
            return 2;
        }
        for (;;) {
            size_t got;

            if (n == cap) {
                uint8_t *nb;

                cap = cap ? cap * 2 : 65536;
                nb = (uint8_t *)realloc(buf, cap);
                if (nb == NULL) {
                    die_oom();
                }
                buf = nb;
            }
            got = fread(buf + n, 1, cap - n, f);
            n += got;
            if (got == 0) {
                break;
            }
        }
        fclose(f);
        memset(&m, 0, sizeof m);
        m.file = "manifest.json";
        manifest_from_bytes(&m, buf, n);
        printf("seed %s\n", base ? base + 1 : argv[i]);
        dump(&m);
        manifest_free(&m);
        free(buf);
    }
    return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    manifest_t m;

    memset(&m, 0, sizeof m);
    m.file = "manifest.json";
    manifest_from_bytes(&m, data, size);
    manifest_free(&m);
    return 0;
}
#endif
