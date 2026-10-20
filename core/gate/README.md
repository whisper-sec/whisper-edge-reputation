# gate/

`straight-64.policy` and `straight-128.policy` are the straight-line family: N rules of one atom each
(`log if c2`, a BOOL on the threat plane, TRUE in the gate's world, so every rule runs and none
decides), one address, one plane, in the corpus record format of `testdata/policy/README.md`. Measured
through both evaluators: 2 operations per rule (the atom and the rule's end; `ops` 128 at 64 rules and
256 at 128), no jump, and one lookup of the threat plane besides the tenant pre-stage. They exist so the
cachegrind gate can hold the evaluator's data references per rule to a fixed count: the cost of rule N+1
over rule N, at 64 and at 128 rules, must not move by more than one reference.

## Baselines, per architecture and compiler

`cachegrind-baseline.tsv`, `cost-constants.tsv` and `dataref-baseline.tsv` hold one row per architecture
and compiler (`aarch64` and `x86_64`, `gcc` and `clang`), and their headers name the toolchain each
architecture's rows were measured with; `cachegrind-gate.sh` refuses a run whose compiler or valgrind
release is not the one named, so a count is never compared across toolchains. `residency-baseline.tsv` is
keyed by cache geometry instead, since the LRU model does not depend on the host. A slot with no row for
the architecture the gate runs on FAILS by name and prints what it measured; nothing is inferred from the
other architecture.

How a new architecture, compiler release or evaluator row gets its rows: run the gate with
`--write-baseline` on a host of that architecture with the pinned toolchain, read the diff (only that
architecture's rows and its header lines may move: the toolchain, the driver layout, and the vantage
line recording the load, CPU count and time the write run measured), and commit. The write is refused
while any control above it fails, or from a noisy host: the launch probe's own row is timed three
times, its counts must be identical and its wall time within 1.5x of its fastest. Each architecture's rows
are written on a host of that architecture, and the committed header records the gcc, clang and valgrind
releases of the run that wrote them; an ordinary run then holds every row within its band.

**Two D1 models.** The rows' D1 is 32 KiB of 64-byte lines, fully associative: it counts the code's
footprint, every line first touched and every line touched again after capacity pushed it out, and no
conflict, so no placement of any object can move it. The hardware's 8-way geometry is kept where a
conflict is the point: the launch probe below, the link-order arm, and the 8-way conflict row (below).

Why a count does not depend on how the gate was started: the 8-way model indexes its sets on bits 6 to 11
of an address, inside the page offset, so its count is exact only if every address the measured region
touches has the same page offset on every run. The arrays always did (they are 4096-byte aligned); the
stack did not. The kernel copies the environment and argv above `main`'s frame, so their size set the
page offset of the evaluator's stack objects (`cg_eval`'s `ev_run_t` with the floor's conf and the plane
views, the verdict, and the frames of `ev_one` and `we_decide`), and where those lines shared a set with
the program block and the hold-harmless table they evicted each other on every request. One gcc binary
read 13.961, 15.934, 16.906 or 17.906 D1 misses per request on `evaluator-basis-rules-4@floor` as the
environment alone grew, with the instructions and the data references identical; that is how three hosts
of the two architectures each disagreed with rows written under another launch. The driver
now runs every `cg` measurement on a stack of its own, an `aligned_alloc(4096)` block entered at its top
(`cg_on_own_stack`), whose lowest page is a guard page; the heap objects the run touches keep their
offsets because the heap's allocation history before the switch is the same on every launch. The gate starts every valgrind client under `env -i` with a fixed environment. The launch probe holds
it on every run: `evaluator-basis-rules-4@floor` under 34 launches that differ only in environment size
(0 to 3968 bytes, one page of offsets), the inherited environment and the data directory reached through a 97-character directory name must
give one figure per compiler. Its control, `WE_CG_PLANT_UNALIGNED=1`, puts the measured loop back on the
launch stack and must give more than one, so a probe that could not see the drift fails the gate too.

The fixed stack position makes a D1 row a different quantity from one measured on the launch stack, so
rows from before and after this change are not comparable. The aarch64 rows were rewritten with the
launch probe in place and are the new reference. The x86_64 rows remain the old measurement until the
`lookup costs, x86_64` job rewrites them through its `write_baseline` dispatch, and until then they
can disagree with an x86_64 run by a line per request.

**The link order, and what the rows do not cover.** The core's and the evaluator's read-only and data
tables are placed by the link, and a D1 row moves with their page offsets: on aarch64, linking the driver
first and page-aligning two of its strings that no measured loop reads moved every evaluator row from
1.23 to 7.1 D1 misses per request, with the instructions unchanged. So the gate links the driver LAST,
after the core and the evaluator, and nothing of the driver's can move them. The gate
holds that by the placement itself, on every architecture: 1,000 read-only bytes in an object of their
own (`gate/cg_plant.c`) leave the page offset of every data object the core and the evaluator define
unchanged when linked after the driver, and move some of them when linked before the core (13 of 30 on
gcc aarch64 and on x86_64 gcc 13, 14 of 27 on clang aarch64); then a row is measured equal with and
without the plant. An earlier plant inside the driver was blind on x86_64, because the driver's
page-aligned statics re-align whatever follows them.

Linked last, the driver's own strings and tables follow the core's sizes, the module renderers' words
among them (they are compiled into the driver from `we_module.h`). On an 8-way D1 any size change in the
core moved their conflict sets: one 1,000-byte plant linked before the core moved gcc aarch64
`module-export` from 26.135 to 23.422 misses a request with every instruction the same, and the six x86_64
module rows of write run 38669743015 moved in D1 alone. That is why the rows are fully associative
(`WE_CG_LAYOUT 4`): under the same plants `module-export` reads 5.987 to 5.998. The gate holds it: **the D1
layout row** measures each module row and the link-order row on the production build and with the
plant of 1,000, 2,000 and 3,500 bytes linked before the core, must find every placement within 1% at equal
instructions, and must find some placement moving some row by more than 1% on the 8-way geometry, or it
is blind and the gate NOT PROVEN (one plant alone moved nothing that far on x86_64 clang, run 38697985954). `WE_CG_D1_HW=1` measures the rows on the
8-way geometry, as before, and fails it by name; `--write-baseline` refuses that control.

**The 8-way conflict row.** A fully associative D1 cannot see two hot objects landing in one set, and
planes are mapped page-aligned, so a page stride between hot lines is real. Every module request path is
measured on the 8-way geometry at four placements (the plant at 0, 1,000, 2,000 and 3,500 bytes before
the core): `module-default`, `-tenant`, `module-export`, `-prestage`, `module-export-all`, both
`module-var-prerewrite` rows and `module-worst`, the last two of which read 45 and 5.4 misses a request on
the old 8-way rows and about 1 fully associative, so nearly all of their old cost was conflict. Two figures
per row are held to `gate/conflict-baseline.tsv`:
- the minimum over the four placements. The plants move objects by amounts that are not a page, so every
  page-aligned object keeps its set: a conflict among page-aligned objects (the planes, the driver's
  arrays, set 0 where each starts) is the same at every placement, and the minimum is its floor. It is not
  a floor for an object the link places: a hot static that collides at the production link can leave its
  set at some plant, and the minimum would read the cured placement. So the row also holds
- placement 0, the production link, with its own bound.

Each is refused above its committed figure plus exactly three misses a request. The bound is flat
because one that grows with the figure is weakest where the floor is already high: the first version's
`2b + 1` let the control's own twelve-line conflict pass on four of the eight gcc aarch64 rows, among them
`module-export` (39.093 at the best placement against a bound of 53.030), whose floor already carries
about twenty conflict misses; the second, `b + max(3, b/5)`, was fitted to the tightest row of the day,
let an 8.24-miss regression on `module-export-all` at the production link read green, and goes blind once
a figure nears 65. The figures repeat to 0.000 run to run (this box against the x86_64 runner, a write
against a push, on all 16 x86_64 rows), so three misses is far above the noise, and the control's smallest
step, 13.08 misses on gcc `module-export-all` at the production link (49.740 to 62.819), clears it by
10.08 however far the figures grow. The cure mirrors the bound: a figure more than three misses under its
committed one fails as a cured conflict and asks for `--write-baseline`, so the same conflict coming back
later is never read green, on a high-floor row as on a low one.

The rows are held by identity: `CF_SLOTS` in the gate names each once, and `gate/conflict-baseline.tsv`
holds exactly those rows for each architecture and compiler, each once. A row committed but not named
(removed from the gate, or misspelt there), a row named twice and a name the driver does not have each
fail by name, in the gate for its own architecture and in `cachegrind-target.sh` for both; a named row
with no figures is NOT PROVEN until `--write-baseline` writes it.

The control is `WE_CG_PLANT_CONFLICT`, run on every row against that row's own figures in the same run,
at the minimum and at placement 0: twelve volatile loads a request at a 4,096-byte stride (twelve lines in
one set) must cross the bound on every row, and the same loads at a stride of 0 (a line the request already
reads) must cross it on none. The loads' sum is stored on the request's own stack frame. The first
version summed them into the page-aligned `sink`, so its twin wrote a line into set 0 every request and
`module-worst` read 9.205 against 5.252 (gcc aarch64), past the additive bound; a version that cast the
loads to void let clang load into the zero register, and valgrind dropped the dead loads, so the conflict
added 0.08 misses on every clang row. The twin now reads each row's production figure to 0.007. The
runs are made once, `WE_CG_JOBS` at a time (default `nproc`), and the D1 layout row reads the same cache.

What this does NOT make true:
- A D1 row counts footprint, not the conflicts of a real cache. An 8-way conflict of the code is caught
  only on the module rows and only past the conflict row's bound of exactly three misses a request: one
  more hot line in set 0, where every page-aligned array of the driver starts, costs about four on
  `module-worst` (the first twin's sink, above) and less on the rows whose set 0 is not full, so it can
  pass. The evaluator rows have no 8-way row.
- The nginx, Apache and LiteSpeed modules link the core among their own objects, wherever their builds
  put it. A row is the code's footprint, and the conflict row the code's floor at the gate's four
  placements; a module build's own placement, and the conflicts it brings, is unmeasured.

## The module rows

`cg_driver.c` measures the modules' request path beside the evaluator's. Every module row has an
evaluator TWIN: the same programs, world, armed planes and request stream measured through `ev_one`
(the harness fills the eight views before each request and nulls them after, `we_decide` runs). The
module row runs the same requests through `we_mod_decide`, which fills its own views from the handles
and counts, so the row less its twin, plus the harness's own view stores, is the module's work and
nothing of the evaluator's. The configuration is built by hand from the twin's run, as `test_module`'s
fixture builds its own; the module's cold half (`we_module.c`) is not linked, so the link layout of every
evaluator row is what it was, and the maps are published into the handles with the one release store
`we_handle_set_view` ends in. Every plane has a handle, NULL on the unbound ones, so a mutant that reads
every view pays an acquire load per plane and never a NULL-handle branch. A module slot's cases and
reference verdicts are its twin's under its own name (`cases` aliases them), and `verdicts` also holds
the module's counters to the recount of the verdicts it printed, so a module that miscounts is never
priced.

**One compiled copy of the decision.** The module rows and their twins call ONE noinline function,
`cg_decide`, which runs `we_decide`: `ev_one` and `ev_one_sv` call it, and `we_mod_decide` calls it
through `WE_MOD_DECIDE_COPY`, a name `we_module.h` admits in this driver alone (a server module inlines
`we_decide` there). So the decision's instructions are the same instructions in a module row and in its
twin, and the row less its twin is the module's own work by construction: its views, parks, counts and
renders, plus nothing of how the decision compiled. Each row now measures the decision plus the call into
the copy, one inlining fewer than before; the evaluator constants (`c_prestage` and the rest) carry that
call, a constant per request. Before the copy each harness function inlined the decision into itself, the
two compiled one instruction apart on some paths, and the module basis read that difference as the
module's cost; the paragraphs below record the shapes that worked around it while it held. No cachegrind
row measures the module's inlined copy of the decision any more: `hotpath-gate.sh`'s `hpmod` holds that
shape, and the evaluator rows hold the decision's cost. Three controls run every time:
- CS: the decision's hold-harmless search run twice inside the copy (`WE_CG_PLANT_SEARCH`): every row sees
  it, and `c_prestage` must leave its band;
- CM: 128 instructions of the module's own work before the decision, outside the copy
  (`WE_CG_MODWORK`): `module-allow` must rise, `evaluator-allow` must not move by one instruction, and
  `c_mod_fixed` must leave its band;
- CX: this run's own rows with `module-worst` one instruction a request dearer: the module basis must
  refuse that row by name.

The model (`cost-model.py`, the module half): `c_harness_view` is `evaluator-views@1` less its
static-views twin `evaluator-views@1-sv`, one program and one path, where the figure is exact. The
default stream's own pair, `evaluator-default` less `evaluator-default-sv`, is printed as a note and not
used: the evaluator is inlined into each harness function and compiled differently in each, so over that
stream's many request shapes the two differ by more than the view stores (48.047 instructions a request
on gcc 13.3 aarch64, not an integer). Then each row carrying a `twin:` term is reduced to the module's
work alone and the module basis is solved from the rows not marked held and held exactly on the rest:
`c_mod_fixed` (the wrapper, the parking, the mask, the scan of the eight bitmap words with every word
empty), `c_view` per bound plane a program references and `c_view@tenant` for the tenant's view (its mask
bit is a constant the compiler may fold: clang 18 on x86_64 reads it 2 instructions cheaper than a
program's view, where gcc there and both compilers on aarch64 read it equal), and for each of the eight
bitmap words `w`, `floor0` to `floor3` and `ctx0` to `ctx3`, `c_word@w` for the word non-empty over
empty and `c_count@w` per bit set in it, because the scan over the words is unrolled and each word's
copy has a cost of its own: on x86_64 gcc 13.3 the floor's words 1 to 3 cost 15 instructions over what
word 0's figure predicted (the first x86_64 write run, `module-worst` 6331 against 6316), and on clang
18 there the eight words missed by 3. The words are measured through rules that FIRE only: a rule that
ends FALSE costs the module's inlined evaluator one instruction less than the harness's copy on gcc
13.3 aarch64, so leading FALSE rules put evaluator code into the twin difference (a first shape of these
rows solved `c_word@floor1` to -63, `floor2` to -127, `floor3` to -191, exactly -64 a word), where
leading firing rules are priced by the words they set; so the count rows are cumulative, `module-count@n-<pass>`
with n in 1, 64, 65, 96, 128, 129, 192, 193, 224 and 256, each pass's 64(w + 1) and 64w + 1 rows solving
word w, and 96 and 224 held out. Finally `c_cnt_rule` and `c_cnt_exempt` price the decision's one direct
count, two code paths. On gcc 13.3 aarch64 the view rows read 759.5, 762.5, 765.5 and 768.5 instructions
a request for one to four views against a twin at 606.5 for every k, exactly 3 a view; the context's
first-word rows 770.5 and 9590.5 against 609.5 and 8736.5, 11 a bit; the floor's 905.5 and 9725.5
against 746.5 and 8999.5, 9 a bit; and every word's constants are the same as its pass's first word's:
`c_mod_fixed` 194, `c_view` 3, `c_view@tenant` 3, `c_word@*` 1, `c_count@floor*` 9, `c_count@ctx*` 11,
`c_cnt_rule` 4 (clang 18: 152, 2, 2, floor words 0 and context words 1, every bit 10, and 4).
`module-allow`, `module-views@1`, `@2`, `@4`, `module-default-tenant`, the sixteen solving count rows and
`module-default` solve it; `module-views@3`, `@5`, `@6`, `@7`, `@8` (the one view row that reads the
tenant), the four half-word count rows and `module-worst` (four full words of each bitmap and the deny)
are held out and predicted exactly, `module-worst` 5318 a request on gcc and 5272 on clang. One per-bit
constant for both bitmaps, the first shape tried, predicted the worst row 504 high on gcc and 4 low on
clang, and per-pass terms without the per-word ones left +8 and +5 here and +15 and +3 on x86_64. The remainders
follow, each a row less every term it names: `c_export` (`module-export` over `module-default`, the
record write, the default set's lazy fills and nine decision values plus five attributes rendered),
`c_export_all` (`module-export-all` over `module-default-full`, every bound plane filled and all 25
attributes, the two countries among them), `c_lazy` (`module-export-prestage` over
`module-default-prestage` and `c_export`, divided by the 5/2 lazy fills a request of its alternating
hold-harmless and critical-listed stream), `c_prerewrite` and `c_prerewrite@1` (nginx's pre-decision
variable path reading three planes, and one, over `module-default`). Measured on an aarch64 test host
(gcc 13.3, then clang 18): `c_export` 7983.84 and 6600.28 instructions a request, `c_export_all` 11923 and
10128, `c_lazy` 60.07 and 83.22 a lazily filled plane, `c_prerewrite` 1720.24 and 1453.92, `c_prerewrite@1`
1209.30 and 960.51; `c_cnt_exempt`, the one constant solved from the default stream's single equation,
9.06 and 9.08, the fraction being that stream's inlining variance. `c_mod_fixed`'s band is the wider of
the tolerance and the spread of its committed values across the toolchains, printed as a `band` line.

The controls, each a build of the driver with one planted defect mapped from a `-DWE_CG_*` the gate
passes to that unit alone, judged against the production run's own figures: `WE_TEST_MOD_ALL_VIEWS`
(every view read; on each held-out row it must cost more instructions, which the exact production
prediction refuses by name, and at least 8 - k data reads more a request, `Dr` counted on its own;
`control blind` when `c_view` is not above 0), `WE_MOD_TEST_LOCKED_COUNT` (a read-modify-write per
increment must move `c_count` outside its band), `WE_MOD_TEST_EAGER_EXPORT` (all 25 attributes on the
default export path must move `c_export` outside its band), `WE_MOD_TEST_LAZY_PER_PLANE` (the local
context rebuilt per lazily filled plane must add at least 600 bytes / 64 = 75/8 data writes a request on
`module-export-prestage`: 3/2 rebuilds of 400 bytes, the 80-byte verdict clear and the 320-byte slot copy,
over the widest store any current ISA issues; cachegrind counts store instructions, and a store's width is
the code generation's, 41 and 39 writes measured on aarch64 gcc and clang, 69.5 and 29.5 on x86_64, so the
bound is in bytes, the implied bytes a store printed; `Dw` on its own, `lazy control blind` when the delta
is not above 0; the instruction delta is printed, not judged), `WE_MOD_TEST_COUNTRY_SCAN` (the pin's linear country scan
must move `module-export-all` outside its own band), `WE_CG_VAR_PER_READ` (a variable handler that
rebuilds its local context per read must move `c_prerewrite` outside its band), C6 in the traced build
(`views <slot> <n>`: the `we_current()` reads of the decision, counted at the call, equal
`popcount((floor | context | tenant) & bound)` on every request, and `WE_CG_PLANT_NINTH=1`, a ninth read,
is refused), and the guard: `hp_mod.c` compiled with `WE_TEST_MOD_ALL_VIEWS` must stop at
`we_module.h`'s `#error`, so the mutant stays the driver's alone. The rows get their baselines as every
other row does, by `--write-baseline` on each architecture; `make cachegrind` names every slot of the
cost rows that has none, per architecture and compiler.

**C5+'s module half, in the trace build** (`cg_driver.c` `mbound <slot> <n>` and `mlayout`, the gate's
trace section beside C6). Two sets of 64-byte lines are traced per request: the handle lines
`we_current()` reads (the counting wrapper C6 uses records the handle's `current` field) and the shard
lines `we_mod_count()` writes (`we_module.h`'s `WE_TRACE_COUNT` hook, a no-op outside the trace build).
The model never calls the module: one handle line per referenced bound plane (C6's popcount, by address),
and for the counters the lines the LAYOUT RULE gives the indices the decision counts, computed from the
shard's base and index / 8, never from the pointer the module took (the pre-stage's eight named counters
at 0..7, the floor's rules from 8, the context's right after the floor's, `we_mod_config_build`'s order);
the counted indices are what `we_mod_decide` counts (the walk's note or header-missing mark, the deciding
rule or the pre-stage step, every log bit of both bitmaps). Before any request the shard base and stride
are whole lines, the scratch and the lazy-fill local are 64-byte aligned and the eight view stores are one
line (the layout rule: shard bases and the scratch 64-byte aligned, strides a multiple of 64). Three planted layouts are each refused by name: `WE_CG_PLANT_STRIDE` (the base eight bytes into
its line, the stride one counter over), `WE_CG_PLANT_SCRATCH` (the scratch 32 bytes into its line: the
view stores span two lines), `WE_CG_PLANT_SPLIT` (the context's counters eight slots past the floor's,
off the layout rule: the traced lines move, the model's do not). `mlayout`, on each compiler's production
build, prints and holds the layout figures the header's ABI asserts state: the scratch 1,024 bytes on a
64-byte boundary with the views first, the record 576 bytes with `disarmed_mask` at 465, `digest4` at 512
and `gen_mask` at 547, the handle's `current` first. The servers' own halves of C5+ (W's visit counter,
Apache's byte counter, LiteSpeed's iov count, the `-fstack-usage` sum over each handler's call chains) are
the module gates'.
