#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# hotpath-gate.sh - prove the per-request path makes no call, no syscall, no atomic, no fence and no
# store outside the caller's context, on two architectures and four optimisation levels.
#
# Zero allocations per request and no network call in the request path are claims about compiled
# code, so this checks the compiled code. It builds wrappers that the compiler cannot inline away
# (hp.c, over the lookup in whisper_edge.h and nothing else), compiles each with
# -ffunction-sections so every wrapper has a section of its own, and refuses the build if any wrapper:
#
#   reloc    has a relocation table of its own (.rela.text.<sym>), which is a call, an outline atomic, a
#            global, the GOT, the PLT or a jump table, all in one check. The section must EXIST first
#            (check "section"), or the absence of its relocations would prove nothing.
#   branch   contains, on aarch64, bl|blr|br|svc|hvc|smc|brk|hlt|eret in any suffixed form; on x86,
#            call|syscall|int|ud2 in any form, an indirect `jmp *`, `ljmp`, or the CET `notrack` prefix
#   ret-reg  returns through a register other than the link register (aarch64 `ret xN`)
#   class    matches the aarch64 atomic CLASS, as a class rather than a list of mnemonics:
#              \b(ld|st)(add|clr|eor|set|smax|smin|umax|umin)[a-z]*\b      LSE arithmetic and stores
#              \b(ld|st)[a-z]*x[rp][bh]?\b                                 exclusive pairs
#              \b(stl|lda|ldla|stll|swp|cas|ldiap|stil)[a-z]*\b            acquire/release, LORegion,
#                                                                          swap, CAS, the RCpc3 pair
#   barrier  contains dmb|dsb|isb (aarch64)
#   lock     contains `lock`, which llvm-objdump prints alone on its line (x86)
#   fence    contains lfence|mfence|sfence (x86; a seq_cst fence is mfence)
#   xchg     contains an xchg whose memory operand is ANYWHERE on the line (x86, AT&T syntax puts it
#            after the comma: `xchgl %ecx, (%rdx)` is a seq_cst store)
#   string   contains a string instruction: x86's rep-prefixed movs/stos/cmps/scas/lods/ins/outs, or
#            aarch64's FEAT_MOPS cpy*/set* triples. A fixed-width copy never compiles to one, so a
#            string instruction in a hot wrapper is a copy or a fill whose LENGTH the data decides, and
#            it is neither a call nor a relocation: gcc inlines a variable-length memcpy as `rep movsb`
#            at -Os on x86_64, and gcc and clang inline it as cpyfp/cpyfm/cpyfe under +mops (measured)
#   tail     branches to a symbol other than itself, however the branch is spelled
#   band     is outside its instruction band (below: the lookup was not inlined; above: something large
#            was inlined into it)
#   stack    needs more stack than its bound, refused at compile time by -Wstack-usage (gcc) or
#            -Wframe-larger-than (clang) and checked per function from -fstack-usage: the backstop
#   locals   keeps any byte of locals on the stack (register saves are not locals): the structural
#            stack guard, named so a local array fails as what it is
#   undef    leaves an undefined symbol in the object (corroboration of reloc, whole object)
#
# and two checks per translation unit on the read-trace hook, WE_TRACE_READ(p):
#
#   trace-pp         the production preprocessor output (-UWE_TRACE) contains no we_trace_read and
#                    no we_trace_eval (the evaluator's hook, WE_TRACE_EVAL(p), placed the same way)
#   trace-identical  `objdump -d -r` of the production object is identical with the hook sites in the
#                    source and with them removed. The hook is an expression that is ((void)0) in
#                    production, and this is the check that it really costs nothing: the if/return form
#                    of the same hook moved gcc's block layout at three levels. The comparison is
#                    against the sites REMOVED, not against -DWE_TRACE, because a traced build calls
#                    we_trace_read by design and could never be identical; hp.c carries
#                    #error under WE_TRACE so a traced build cannot be checked by mistake. Both hooks,
#                    WE_TRACE_READ and WE_TRACE_EVAL, are removed for the comparison.
#
# THE POLICY EVALUATOR'S WRAPPERS live in hp_eval.c, over we_eval.h. Until that header is in the tree
# every one of their rows is reported DARK by name and nothing is claimed for it; the moment the header
# lands the rows run, with no edit to this file, and a row that then fails, or whose band has not been
# derived yet, fails the gate. They carry no locals-ok allowance (decision D9: scratch moves into *ctx
# before a local is allowed), and the gate refuses one that asks for it.
#
# THE NEGATIVE CONTROLS RUN ON EVERY INVOCATION. Each gate/ctl-*.c injects one hazard into a wrapper
# and names, in its own `@expect` lines, the check that must refuse it on each architecture. The gate
# prints CLEAR only when the clean code passes every check AND every control was refused by its named
# check at every level on every toolchain. A control marked `@fold` carries a hazard the compiler
# creates or not by its own choice (an equality chain folded into a jump table): at a level where it
# did not, the object must build CLEAN and is reported n/a, and the control must still be refused at
# some level on some toolchain of each architecture. A gate whose checks have stopped seeing what they claim to
# see then fails, instead of passing quietly, which is the failure mode every earlier version of this
# file had: it missed an inlined LSE atomic, a seq_cst store, a seq_cst fence and an indirect tail call
# while printing "ok".
#
# TOOLCHAINS. gcc and clang for aarch64, gcc and clang for x86_64. The host's own are native; the other
# architecture is a cross build (clang --target with the declaration-only headers in gate/shim, gcc as
# the distribution's cross package). Three are required: gcc-aarch64, clang-aarch64,
# clang-x86_64; gcc-x86_64 runs whenever it is installed (CI installs it). A missing toolchain is
# reported by name and the result is INCOMPLETE, never CLEAR. With WE_GATE_STRICT=1, as CI runs it,
# INCOMPLETE exits non-zero, and so does a missing apxs or nginx (the shims' flag sources).
#
# Usage: hotpath-gate.sh [workdir]
# Environment: WE_GATE_LEVELS (default "-O -O2 -Os -O3"; -O0 is refused, nothing ships at -O0),
#              WE_GATE_STRICT, WE_GATE_CLANG, WE_GATE_GCC_A64, WE_GATE_GCC_X86.
set -euo pipefail

cd "$(dirname "$0")"
HERE=$(pwd)
OUT="${1:-$(mktemp -d)}"
# mkdir, because the first version of this script did not: handed a path that did not exist it failed
# at the first redirect, printed one line of shell noise, and, piped into tail by its caller, looked
# like a pass. A gate that cannot run must not be mistakable for a gate that ran.
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
STRICT="${WE_GATE_STRICT:-0}"

LEVELS="${WE_GATE_LEVELS:--O -O2 -Os -O3}"
for L in $LEVELS; do
    case "$L" in
        -O|-O1|-O2|-O3|-Os|-Oz) ;;
        *) echo "GATE FAIL: optimisation level '$L' is not one a module ships at (-O0 never is)"; exit 1 ;;
    esac
done

# STACK BOUNDS, per wrapper, and TWO GUARDS.
#
# The lookup the shims call is the two-armed one (radix or rank, chosen by the arm-time kind byte) with
# every index-derived position clamped against arm-time copies, and that holds more values live than
# x86_64's caller-saved registers carry: the lookup wrappers push callee-saved registers (rbx, rbp, r12
# to r15) and keep NO locals and make no other stack store; on aarch64 they use no stack at all. The
# gate prints the frame it saw, below.
#
# The LOCALS check (check "locals", in check_symbol) is the structural guard: a lookup wrapper may
# save registers and keep nothing else on the stack, so a local array, a spilled struct or a red-zone
# buffer fails by name at 8 bytes, which no byte bound tuned to the push count could do. The byte bound
# is the BACKSTOP: 64, the next 16-byte boundary above the measured maxima (56 under gcc with Ubuntu's
# x86_64 module flags, hp6, six pushes and the return address; 48 under clang), so that a compiler
# saving one more register does not fail a build that holds no locals, while a frame that grows past
# that is still refused. UNITS: the bound is compared with -fstack-usage as each compiler states it,
# and the two state it differently on x86_64: gcc's figure counts the 8-byte return address the call
# pushed, clang's does not (a leaf with no pushes is 8 under gcc and 0 under clang; on aarch64 the
# return address is in a register and both say 0). So 48 under gcc is five pushes and the return
# address, 48 under clang is six pushes, and the frame line below prints each compiler's figures
# separately rather than one range that mixes the two. hpcur is one acquire load and keeps 16.
# The evaluator wrappers' bound is the performance budget's (FORMAT.md §7)
# STACK_MAX_EVAL, in the same per-compiler units, and their frames are printed for all four toolchains
# because the bound applies on aarch64 as much as on x86_64; the controls are compiled against it so
# that the 544-byte frame is shown to be refused even by the larger bound.
#
STACK_MAX_CURRENT=16
STACK_MAX_LOOKUP=64
STACK_MAX_EVAL=256

#
# THE HOT SYMBOLS. name : source : stack bound : instruction band min : max : allowance
#
# ONE METHOD FOR EVERY BAND: the range of instruction counts this script prints for the wrapper, over
# four toolchains, four levels and every flag set, widened by a quarter on each side (floor of 0.75 x
# the lowest, ceiling of 1.25 x the highest). That leaves room for a compiler upgrade but not for a
# lookup that stopped being inlined (it collapses to a handful of instructions) or for an inlined
# memcpy or loop blowup. Re-derive a band the same way when the code it covers changes.
#
# hpcur is the one acquire load of the published map. On aarch64 it is ldar (or ldapr under RCpc),
# which the class pattern matches on purpose; its allowance is EXACTLY ONE such load and nothing else.
# On x86 an acquire load is a plain mov and nothing is allowed at all.
#
# THE EVALUATOR'S EIGHT, in hp_eval.c, under STACK_MAX_EVAL and with no allowance. Their bands follow
# the same method, from the evaluator's own counts over four toolchains, four levels and every flag
# set, measured by its author over the evaluator as it stood for this commit (and confirmed here on
# aarch64: hpfill4 483 and hpeval 2,691 instructions under gcc -O2 fall inside). A "-" band still
# fails a row and prints the derived band.
#
# Their locals are held at zero: every value lives in a register or in *ctx (decision D9). Measured
# with this script against the evaluator, every frame is callee-saved registers only (48 to 96 bytes
# against 256 under -fstack-usage, the fill wrappers 0 to 48) under gcc 13 and 14 and clang 18 on both
# architectures. clang 19 and 20 on x86_64 kept one 8-byte spill in hpeval and hpeval_ops at all four
# levels, `mov %rdi,-0x8(%rsp)` in the red zone below a frame of pushes only, which a frame size cannot
# show and the locals check refuses; the evaluator was changed to keep that value in a register.
# The claim is only as wide as the flag sets run, and the base set was not what distributions build
# with. Measured over the distribution and target sets below: under -mtune=znver3/znver4 clang spilled
# in hpfloor, the fill rows and the lookup wrapper hpdeny until the evaluator's rank descent took an
# unroll(disable) hint (0 since); under the Ubuntu and Fedora module sets clang 18 to 20 on x86_64 keep
# a spill in hpeval and hpeval_ops (-fno-omit-frame-pointer takes %rbp from the allocator), and clang 20
# under -march=x86-64-v3 packs the K3 bit stacks into an xmm register with constant-pool loads. Those
# two are held EXACTLY by the expected-locals and expected-relocations tables below, and every other
# leg must read 0 of both; gcc and every aarch64 build read 0 everywhere.
#
SYMS=(
    "hpcur:hp.c:$STACK_MAX_CURRENT:2:15:acquire-one"
    # seen, over four toolchains, four levels and every flag set including the Ubuntu cross sets:
    # hpcur 3..12, hp4 93..127, hp6 94..155, hpdeny 111..152, hpf4 90..121, hpf4_radix 37..113,
    # hpf4_rank 76..113, hp6w 87..115, hp6w_radix 39..106, hp6w_rank 73..106
    "hp4:hp.c:$STACK_MAX_LOOKUP:69:159:"
    "hp6:hp.c:$STACK_MAX_LOOKUP:70:194:"
    "hpdeny:hp.c:$STACK_MAX_LOOKUP:83:190:"
    "hpf4:hp.c:$STACK_MAX_LOOKUP:67:152:"
    "hpf4_radix:hp.c:$STACK_MAX_LOOKUP:27:142:"
    "hpf4_rank:hp.c:$STACK_MAX_LOOKUP:57:142:"
    "hp6w:hp.c:$STACK_MAX_LOOKUP:65:144:"
    "hp6w_radix:hp.c:$STACK_MAX_LOOKUP:29:133:"
    "hp6w_rank:hp.c:$STACK_MAX_LOOKUP:54:133:"
    "hpeval:hp_eval.c:$STACK_MAX_EVAL:1764:4562:"
    "hpeval_ops:hp_eval.c:$STACK_MAX_EVAL:592:1742:"
    "hpfill4:hp_eval.c:$STACK_MAX_EVAL:175:689:"
    "hpfill6w:hp_eval.c:$STACK_MAX_EVAL:240:689:"
    "hpfill6:hp_eval.c:$STACK_MAX_EVAL:240:689:"
    "hpfill1:hp_eval.c:$STACK_MAX_EVAL:307:689:"
    "hpfloor:hp_eval.c:$STACK_MAX_EVAL:496:1072:"
    "hpaddr:hp_eval.c:$STACK_MAX_EVAL:13:39:"
    # THE MODULES' DECISION, in hp_mod.c over we_module.h: the views of exactly the planes the two
    # programs read, the evaluator, the counts. The evaluator's rules (STACK_MAX_EVAL, no locals) plus
    # `acquire-views`: on aarch64 between one and eight acquire loads of a 64-bit register and nothing
    # else in the atomic class, a SHAPE (a loop over the mask emits one ldar however many views it
    # fills; the per-request count is the trace build's). On x86_64 an acquire load is a plain mov and
    # nothing is claimed beyond the atomic class. Band by the one method, from this script's counts over
    # four toolchains, four levels and every flag set: seen 2593..3507, so 1944..4384.
    "hpmod:hp_mod.c:$STACK_MAX_EVAL:1944:4384:acquire-views"
)

#
# THE TARGET SETS' BANDS. Under -mtune=znver3/znver4 clang if-converts the searches (setbe, cmov and
# lea where the baseline branches), so a lookup wrapper runs to two or three times its baseline count:
# a compiler choice, not a blowup. Widening the rows above to hold it would blind them to the blowup
# they exist for, so the x86_64 target sets get bands of their own, derived by the same method from
# those sets alone, and every other check (locals, calls, atomics, relocations, frames) is the same
# for them as for every set. A "-" fails the row and prints the band the run derives.
#
#
# THE EXPECTED LOCALS. The zero-locals claim holds on every leg but these, where clang on x86_64 with
# -fno-omit-frame-pointer keeps a spill in the evaluator's two big wrappers that the evaluator cannot
# remove without giving up a register it needs. The claim is narrowed to exactly this table and the
# gate holds each entry EXACTLY: a byte more or a byte fewer fails by name, so the published reading
# and the gate cannot drift apart. A leg or row not in the table expects 0. Key:
# <compiler>-<major>|<flag set>|<symbol> at every level, or <compiler>-<major>|<flag set>|<level>|<symbol>
# for one level, which wins. The compiler may carry its target, <compiler>-<major>@<arch>, for a flag set
# both architectures share (base); a key with the target wins over one without. Measured with this script against the evaluator at all four levels.
#
declare -A EXPECT_LOCALS=(
    ["clang-18|ubuntu-x86_64|hpeval"]=8
    ["clang-18|ubuntu-x86_64|hpeval_ops"]=12
    ["clang-18|ubuntu-x86_64|-O|hpeval_ops"]=8
    ["clang-19|ubuntu-x86_64|hpeval"]=8
    ["clang-19|ubuntu-x86_64|hpeval_ops"]=4
    ["clang-19|ubuntu-x86_64|-O|hpeval_ops"]=16
    ["clang-19|fedora-x86_64|hpeval"]=8
    ["clang-19|fedora-x86_64|hpeval_ops"]=4
    ["clang-19|fedora-x86_64|-O|hpeval_ops"]=16
    ["clang-20|ubuntu-x86_64|hpeval"]=8
    ["clang-20|ubuntu-x86_64|hpeval_ops"]=4
    ["clang-20|ubuntu-x86_64|-O|hpeval_ops"]=16
    ["clang-20|fedora-x86_64|hpeval"]=8
    ["clang-20|fedora-x86_64|hpeval_ops"]=4
    ["clang-20|fedora-x86_64|-O|hpeval_ops"]=16
    # THE MODULES' DECISION. hpmod keeps no local on aarch64 under either compiler and on x86_64 at -O2,
    # -Os and -O3, every operand parked in the scratch. Two x86_64 legs keep one, measured with this script:
    # gcc 13 at -O spills the verdict pointer once across the rule loop, on every flag set, where hpeval
    # holds the same pointer in its incoming argument slot (its ninth argument arrives on the stack, and an
    # argument slot is not a local); clang 18 under the Ubuntu set (-fno-omit-frame-pointer takes %rbp)
    # keeps 16 bytes, the leg the evaluator's own rows hold above. Held exactly, like those. The gcc keys
    # name x86_64, because gcc 13 builds the base set for aarch64 too and keeps no local there.
    ["gcc-13@x86_64|base|-O|hpmod"]=8
    ["gcc-13@x86_64|ubuntu-x86_64|-O|hpmod"]=8
    ["gcc-13@x86_64|fedora-x86_64|-O|hpmod"]=8
    ["gcc-13@x86_64|x86-64-v3|-O|hpmod"]=8
    ["gcc-13@x86_64|znver3|-O|hpmod"]=8
    ["gcc-13@x86_64|znver4|-O|hpmod"]=8
    # gcc 13 on the shims' own sets, which only the host's own gcc reads (apxs -q CFLAGS and nginx -V on
    # the machine the modules are built for): the same spill, measured with this script under the flags
    # apxs and nginx print there, and caught by the push gates on that host's native run
    ["gcc-13@x86_64|apxs|-O|hpmod"]=8
    ["gcc-13@x86_64|nginx|-O|hpmod"]=8
    # gcc 14 spills the same pointer under the same condition, on every x86_64 flag set and at no other
    # level, measured with this script under gcc 14 on the same eight sets; on aarch64 gcc 14 keeps no
    # local, so its keys name x86_64 like gcc 13's
    ["gcc-14@x86_64|base|-O|hpmod"]=8
    ["gcc-14@x86_64|ubuntu-x86_64|-O|hpmod"]=8
    ["gcc-14@x86_64|fedora-x86_64|-O|hpmod"]=8
    ["gcc-14@x86_64|x86-64-v3|-O|hpmod"]=8
    ["gcc-14@x86_64|znver3|-O|hpmod"]=8
    ["gcc-14@x86_64|znver4|-O|hpmod"]=8
    ["gcc-14@x86_64|apxs|-O|hpmod"]=8
    ["gcc-14@x86_64|nginx|-O|hpmod"]=8
    ["clang-18|ubuntu-x86_64|hpmod"]=16
    # clang 19 and 20 keep the same 16 bytes on both x86_64 distribution sets (each takes %rbp with
    # -fno-omit-frame-pointer), at every level; measured with this script under each, and the decision's
    # code is byte-identical with and without the we_slot_key guard, so the spill predates it
    ["clang-19|ubuntu-x86_64|hpmod"]=16
    ["clang-19|fedora-x86_64|hpmod"]=16
    ["clang-20|ubuntu-x86_64|hpmod"]=16
    ["clang-20|fedora-x86_64|hpmod"]=16
)
expected_locals_key() { # compiler-id[@arch] set level symbol -> the table key that applies, or nothing
    local k base=${1%@*}
    for k in "$1|$2|$3|$4" "$1|$2|$4" "$base|$2|$3|$4" "$base|$2|$4"; do
        if [ -n "${EXPECT_LOCALS[$k]:-}" ]; then echo "$k"; return; fi
    done
}
expected_locals() { # compiler-id[@arch] set level symbol -> the bytes the table expects (0 when not tabled)
    local k
    k=$(expected_locals_key "$@")
    if [ -n "$k" ]; then echo "${EXPECT_LOCALS[$k]}"; else echo 0; fi
}
locals_verdict() { # measured expected -> the failure's text, nothing when they are equal
    [ "$1" = "$2" ] && return 0
    if [ "$2" = 0 ]; then
        echo "$1 bytes of locals on the stack"
    else
        echo "$1 bytes of locals on the stack, where the expected-locals table holds exactly $2 for this leg"
    fi
}
declare -A LOCALS_HELD=()
#
# THE EXPECTED RELOCATIONS, the same way and for one leg: clang 20 at -march=x86-64-v3 packs the
# evaluator's two 64-bit K3 bit stacks into one xmm register (the SLP vectoriser; no loop is vectorised)
# and loads its lane masks from a constant pool, so hpeval and hpeval_ops carry relocations into .rodata
# and its .LCPI entries at -O2, -Os and -O3 (none at -O; none on clang 18 or 19 or any other leg); hpmod,
# which inlines the same evaluator, carries 14 at the same three levels, measured the same way. The
# count per wrapper and level is held exactly, and every one of them must point into the constant pool:
# one more, one fewer, or one anywhere else fails by name. Measured against the evaluator.
#
declare -A EXPECT_RELOCS=(
    ["clang-20|x86-64-v3|-O2|hpeval"]=14
    ["clang-20|x86-64-v3|-O2|hpeval_ops"]=7
    ["clang-20|x86-64-v3|-Os|hpeval"]=14
    ["clang-20|x86-64-v3|-Os|hpeval_ops"]=7
    ["clang-20|x86-64-v3|-O3|hpeval"]=14
    ["clang-20|x86-64-v3|-O3|hpeval_ops"]=7
    ["clang-20|x86-64-v3|-O2|hpmod"]=14
    ["clang-20|x86-64-v3|-Os|hpmod"]=14
    ["clang-20|x86-64-v3|-O3|hpmod"]=14
)
expected_relocs() { # compiler-id set level symbol -> the constant-pool relocations the table expects
    echo "${EXPECT_RELOCS["$1|$2|$3|$4"]:-0}"
}
reloc_verdict() { # count non-pool expected names -> the failure's text, nothing when held
    if [ "$3" = 0 ]; then
        [ "$1" = 0 ] || echo "$4"
        return 0
    fi
    [ "$1" = "$3" ] && [ "$2" = 0 ] && return 0
    echo "$1 relocations ($2 outside the constant pool): $4; the expected-relocations table holds exactly $3 constant-pool relocations for this leg"
}

TUNED_SETS=" x86-64-v3 znver3 znver4 "
# measured with this script over gcc 13 and 14 and clang 18, 19 and 20, every level, the three sets
declare -A TUNED_BAND=(
    [hp4]=75:414
    [hp6]=87:400
    [hp6w]=71:334
    [hp6w_radix]=33:127
    [hp6w_rank]=56:309
    [hpaddr]=16:44
    [hpcur]=4:10
    [hpdeny]=93:443
    [hpeval]=2057:6677
    [hpeval_ops]=710:2183
    [hpf4]=72:410
    [hpf4_radix]=30:130
    [hpf4_rank]=59:388
    [hpfill1]=345:1315
    [hpfill4]=196:670
    [hpfill6]=275:923
    [hpfill6w]=275:923
    [hpfloor]=538:2169
    [hpmod]=2138:4303
)

# every translation unit of hot wrappers; each SYMS row names its own. hp_eval.c joins when the
# evaluator's header is in the tree; until then its rows are DARK, reported by name below.
GATE_SOURCES=(hp.c)
EVAL_DARK=""
if [ -f we_eval.h ]; then
    GATE_SOURCES+=(hp_eval.c)
    if [ -f we_module.h ] && [ -f hp_mod.c ]; then
        GATE_SOURCES+=(hp_mod.c)
    else
        EVAL_DARK_MOD="we_module.h is not in this tree"
    fi
else
    EVAL_DARK="we_eval.h is not in this tree"
fi
EVAL_DARK_MOD=${EVAL_DARK_MOD:-$EVAL_DARK}
# the evaluator's rows and the modules' decision row are held to the same rules (STACK_MAX_EVAL, D9)
is_eval_file() { [ "$1" = hp_eval.c ] || [ "$1" = hp_mod.c ]; }
eval_dark_of() { # file -> why its rows are dark, nothing when they run
    case "$1" in
        hp_eval.c) printf '%s' "$EVAL_DARK" ;;
        hp_mod.c)  printf '%s' "$EVAL_DARK_MOD" ;;
    esac
}
eval_rows() {
    local row sym file
    for row in "${SYMS[@]}"; do
        IFS=: read -r sym file _ <<<"$row"
        is_eval_file "$file" && printf '%s ' "$sym"
    done
}

# ---- the patterns: the instruction classes the hot path may not contain -----------------------------
A64_CLASS='\b(ld|st)(add|clr|eor|set|smax|smin|umax|umin)[a-z]*\b|\b(ld|st)[a-z]*x[rp][bh]?\b|\b(stl|lda|ldla|stll|swp|cas|ldiap|stil)[a-z]*\b'
A64_BRANCH='\b(bl|blr|br|svc|hvc|smc|brk|hlt|eret)[a-z]*\b'
A64_RETREG='\bret[a-z]*[[:space:]]+x([0-9]|[12][0-9])\b'
A64_BARRIER='\b(dmb|dsb|isb)\b'
X86_BRANCH='\b(call[a-z]*|lcall[a-z]*|syscall|sysenter|int|int[0-9]|into|ud[0-9a-z]*)\b|\b(jmp[a-z]*|ljmp[a-z]*)[[:space:]]+\*|\bljmp[a-z]*\b|\bnotrack\b'
X86_LOCK='\block\b'
X86_FENCE='\b[lms]fence\b'
X86_XCHG='\bxchg[a-z]*[[:space:]].*\('
# THE STRING CHECK, and where its proof stands. x86_64: a rep-prefixed string instruction is a copy loop
# the relocation check never sees. Only one toolchain this gate runs emits one for a variable copy with
# no relocation beside it: gcc for x86_64 at -Os (measured on ctl-eval-memcpy: rep movsb); clang calls
# memcpy at every level, which the relocation check refuses instead. So on x86 the string check is
# exercised where the cross gcc is installed, which it always is in CI. aarch64: the MOPS families
# (cpyf*, set*) under -march=armv8.8-a+mops, which gcc 13 and clang 18 both inline at all four levels
# (ctl-eval-mops: cpyfp, cpyfm, cpyfe), so the check is exercised on both aarch64 compilers.
X86_STRING='\brep[a-z]*[[:space:]]+(movs|stos|cmps|scas|lods|ins|outs)[a-z]*\b'
A64_STRING='\b(cpyf?|setg?)[pme][a-z]*\b'
A64_ACQUIRE_ONE='^[[:space:]]*ld(a|ap)r[[:space:]]+x[0-9]+,[[:space:]]*\[x[0-9]+\]$'

# ---- toolchains ----------------------------------------------------------------------------------
HOST=$(uname -m)
case "$HOST" in
    aarch64|arm64) HOST=aarch64 ;;
    x86_64|amd64)  HOST=x86_64 ;;
    *) echo "GATE FAIL: unknown host architecture $HOST; refusing to report a pass I cannot check"; exit 1 ;;
esac
CLANG="${WE_GATE_CLANG:-clang}"
SHIM="$HERE/gate/shim"

# tc_setup NAME: sets TC_CC (array), TC_OD, TC_ARCH, TC_KIND (gcc|clang), TC_NATIVE; returns 1 if the
# toolchain is not installed.
tc_setup() {
    local name=$1 res
    TC_ARCH=${name#*-}
    TC_KIND=${name%%-*}
    TC_NATIVE=0
    [ "$TC_ARCH" = "$HOST" ] && TC_NATIVE=1
    case "$TC_KIND" in
        gcc)
            local g
            if [ "$TC_ARCH" = aarch64 ]; then
                if [ "$TC_NATIVE" = 1 ]; then g="${WE_GATE_GCC_A64:-gcc}"; else g="${WE_GATE_GCC_A64:-aarch64-linux-gnu-gcc}"; fi
            else
                if [ "$TC_NATIVE" = 1 ]; then g="${WE_GATE_GCC_X86:-gcc}"; else g="${WE_GATE_GCC_X86:-x86_64-linux-gnu-gcc}"; fi
            fi
            command -v "$g" >/dev/null 2>&1 || return 1
            TC_CC=("$g")
            if [ "$TC_NATIVE" = 1 ]; then
                TC_OD=objdump
            elif command -v "${TC_ARCH}-linux-gnu-objdump" >/dev/null 2>&1; then
                TC_OD="${TC_ARCH}-linux-gnu-objdump"
            else
                TC_OD=llvm-objdump
            fi
            ;;
        clang)
            command -v "$CLANG" >/dev/null 2>&1 || return 1
            if [ "$TC_NATIVE" = 1 ]; then
                TC_CC=("$CLANG")
                TC_OD=objdump
            else
                res=$("$CLANG" -print-resource-dir)
                TC_CC=("$CLANG" "--target=${TC_ARCH}-linux-gnu" -nostdinc -isystem "$SHIM" -isystem "$res/include")
                TC_OD=llvm-objdump
            fi
            ;;
    esac
    command -v "$TC_OD" >/dev/null 2>&1 || return 1
    return 0
}

stack_flag() { # bound -> the compiler's own stack warning
    if [ "$TC_KIND" = gcc ]; then echo "-Wstack-usage=$1"; else echo "-Wframe-larger-than=$1"; fi
}

# ---- the shims' real flags ------------------------------------------------------------------------
# Read from the installed servers, never typed in here: a gate that pins its own flags proves a
# property of a binary nobody ships (this one used to hardcode -O2 while nginx builds at -O).
BASE_FLAGS=(-std=c11 -fPIC -ffunction-sections -D_FORTIFY_SOURCE=2 -Wall -Wextra -Werror -Wvla -Walloca)
APXS_FLAGS=""
NGINX_FLAGS=""
APXS_NOTE="apxs not installed: the Apache module's flags are NOT checked here"
NGINX_NOTE="nginx not installed: the nginx module's flags are NOT checked here"
if command -v apxs >/dev/null 2>&1 && APXS_FLAGS=$(apxs -q CFLAGS 2>/dev/null) && [ -n "$APXS_FLAGS" ]; then
    APXS_NOTE="apxs -q CFLAGS: $APXS_FLAGS"
else
    APXS_FLAGS=""
fi
if command -v nginx >/dev/null 2>&1; then
    ngv=$(nginx -V 2>&1 || true)
    NGINX_FLAGS=$(printf '%s\n' "$ngv" | sed -n "s/.*--with-cc-opt='\([^']*\)'.*/\1/p" | sed -n 1,1p)
    [ -z "$NGINX_FLAGS" ] && NGINX_FLAGS=$(printf '%s\n' "$ngv" | sed -n 's/.*--with-cc-opt=\([^ ]*\).*/\1/p' | sed -n 1,1p)
    if [ -n "$NGINX_FLAGS" ]; then
        NGINX_NOTE="nginx --with-cc-opt: $NGINX_FLAGS"
    else
        NGINX_NOTE="nginx -V has no --with-cc-opt; the module is built with nginx's defaults, which the base set covers"
    fi
fi

#
# THE OTHER ARCHITECTURE'S MODULE FLAGS, as a fixture. apxs and nginx report the flags of the host's
# own architecture only, so an aarch64 host could never see what Ubuntu's x86_64 module build adds
# (-fcf-protection) and what that does to a frame: under these flags gcc puts hp6 at 56 bytes against
# 48 under the base set, and only the x86_64 CI job saw it. So the cross gcc also runs with the other
# architecture's set, typed in here because it cannot be read here, with its source:
# `DEB_HOST_ARCH=amd64 dpkg-buildflags --get CFLAGS` (and arm64) from dpkg 1.22.6 on Ubuntu 24.04,
# which is what `apxs -q CFLAGS` prints on that system, less the build-path -ffile-prefix-map; plus
# nginx's own additions from its `nginx -V` (-fPIC -Wdate-time -D_FORTIFY_SOURCE=3), so the set is the
# nginx one, which contains the Apache one.
#
UBUNTU_X86_64_FLAGS="-g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -flto=auto -ffat-lto-objects -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -fPIC -Wdate-time -D_FORTIFY_SOURCE=3"
UBUNTU_AARCH64_FLAGS="-g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -flto=auto -ffat-lto-objects -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -mbranch-protection=standard -fPIC -Wdate-time -D_FORTIFY_SOURCE=3"
#
# FEDORA'S MODULE FLAGS, also a fixture: `rpm --target <arch> -E '%{optflags}'` from
# redhat-rpm-config-294-1.fc41 on Fedora 41, which is what an RPM build of a module compiles with.
# Kept as Fedora prints them except for four words that change no code here and cannot be given on
# this host: the two -specs files (redhat-hardened-cc1 adds -fPIE only where no -fpic/-fPIC is given,
# and a module is always -fPIC; redhat-annobin-cc1 loads a plugin that writes notes), and
# -grecord-gcc-switches and -Wno-complain-wrong-lang (a note section, and a gcc-14-only option name).
# `-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3` is given as the two plain words it passes to the
# preprocessor. -fPIC is the module build's own.
#
FEDORA_X86_64_FLAGS="-O2 -flto=auto -ffat-lto-objects -fexceptions -g -pipe -Wall -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -m64 -march=x86-64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -mtls-dialect=gnu2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fPIC"
FEDORA_AARCH64_FLAGS="-O2 -flto=auto -ffat-lto-objects -fexceptions -g -pipe -Wall -Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -mbranch-protection=standard -fasynchronous-unwind-tables -fstack-clash-protection -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fPIC"
#
# THE x86_64 TARGETS a site builds for when it does not take the distribution baseline: the v3 level
# (RHEL 10's baseline, and what -march=haswell implies) and AMD Zen 3 and Zen 4 tuning. Each changes
# register allocation enough to spill where the baseline does not, so each is a set of its own.
#
X86_64_V3_FLAGS="-march=x86-64-v3"
ZNVER3_FLAGS="-mtune=znver3"
ZNVER4_FLAGS="-mtune=znver4"

# shim_flags SET -> the words of that flag set on top of what every build needs. The shims' own
# _FORTIFY_SOURCE wins over ours (defining it twice to different values is an error under -Werror).
shim_flags() {
    local set=$1 words=""
    case "$set" in
        base)  printf '%s\n' "${BASE_FLAGS[@]}"; return ;;
        apxs)  words=$APXS_FLAGS ;;
        nginx) words=$NGINX_FLAGS ;;
        ubuntu-x86_64)  words=$UBUNTU_X86_64_FLAGS ;;
        ubuntu-aarch64) words=$UBUNTU_AARCH64_FLAGS ;;
        fedora-x86_64)  words=$FEDORA_X86_64_FLAGS ;;
        fedora-aarch64) words=$FEDORA_AARCH64_FLAGS ;;
        x86-64-v3)      words=$X86_64_V3_FLAGS ;;
        znver3)         words=$ZNVER3_FLAGS ;;
        znver4)         words=$ZNVER4_FLAGS ;;
        *) echo "shim_flags: no flag set named $set" >&2; return 1 ;;
    esac
    local w fort=0
    for w in $words; do
        case "$w" in -D_FORTIFY_SOURCE*|-U_FORTIFY_SOURCE) fort=1 ;; esac
        printf '%s\n' "$w"
    done
    for w in "${BASE_FLAGS[@]}"; do
        case "$w" in -D_FORTIFY_SOURCE*) [ "$fort" = 1 ] && continue ;; esac
        printf '%s\n' "$w"
    done
}

# undef_syms OBJ -> the undefined symbols of OBJ from its ELF symbol table, space-separated; returns 1
# (with the reason on stdout) when the table cannot be read. readelf, never nm: on a fat LTO object
# binutils nm loads the system LLVM plugin, which, older than clang 20, prints "Invalid record" and
# "no symbols", and a parse of that once read the word "record" as a symbol.
undef_syms() {
    local tab
    if ! tab=$(readelf -sW "$1" 2>&1); then
        echo "readelf could not read the symbol table: $(printf '%s' "$tab" | head -c 160)"
        return 1
    fi
    if [[ "$tab" != *"Symbol table '.symtab'"* ]]; then
        echo "the object has no .symtab, so no symbol could be checked"
        return 1
    fi
    printf '%s\n' "$tab" | awk '$7 == "UND" && $8 != "" { print $8 }' | sort -u | tr '\n' ' '
}

# ---- one object, every check ----------------------------------------------------------------------
# check_symbol OBJ SYM STACKBOUND BANDMIN BANDMAX ALLOW -> prints the names of the checks that fired,
# one per line, each followed by a TAB and the evidence. Prints nothing when the symbol is clean.
check_symbol() {
    local obj=$1 sym=$2 bound=$3 bmin=$4 bmax=$5 allow=$6 body n bad su
    # Never `producer | grep -q` under pipefail: grep -q exits at the first match, the producer dies of
    # SIGPIPE, the pipeline returns 141 and the `if` reads a match as no match. On the relocation check
    # that is a silent pass. So the producer's output is captured first and searched as a string.
    local sections relocs
    sections=$(readelf -SW "$obj")
    relocs=$(readelf -rW "$obj")
    if [[ "$sections" != *" .text.$sym "* ]]; then
        printf 'section\tno .text.%s section, so the relocation check would be vacuous\n' "$sym"
        return
    fi
    if [[ "$relocs" == *"'.rela.text.$sym'"* || "$relocs" == *"'.rel.text.$sym'"* ]]; then
        local rl rcount rpool rexp rmsg
        rl=$(printf '%s\n' "$relocs" | sed -n "/'\.rela\{0,1\}\.text\.$sym'/,/^\$/p" \
              | grep -oE 'R_[A-Z0-9_]+[[:space:]]+[0-9a-f]+[[:space:]]+[^ ]+' | awk '{print $1":"$3}' || true)
        bad=$(printf '%s\n' "$rl" | sort -u | tr '\n' ' ')
        rcount=$(printf '%s\n' "$rl" | grep -c . || true)
        rpool=$(printf '%s\n' "$rl" | grep -vcE ':(\.rodata(\.cst[0-9]+)?|\.LCPI[0-9]+_[0-9]+)$' || true)
        rexp=$(expected_relocs "$TC_ID" "${SET:-base}" "${L:-}" "$sym")
        rmsg=$(reloc_verdict "$rcount" "$rpool" "$rexp" "$bad")
        [ -n "$rmsg" ] && printf 'reloc\t%s\n' "$rmsg"
        [ -z "$rmsg" ] && printf 'held\t%s\n' "$TC_ID|${SET:-base}|${L:-}|$sym=$rexp constant-pool relocations"
    elif [ "$(expected_relocs "$TC_ID" "${SET:-base}" "${L:-}" "$sym")" != 0 ]; then
        printf 'reloc\t0 relocations, where the expected-relocations table holds exactly %s for this leg\n' \
            "$(expected_relocs "$TC_ID" "${SET:-base}" "${L:-}" "$sym")"
    fi
    body=$("$TC_OD" -d --no-show-raw-insn "$obj" 2>/dev/null | sed -n "/<$sym>:\$/,/^\$/p" | sed '1d')
    if [ -z "$body" ]; then
        printf 'section\tcould not disassemble %s\n' "$sym"
        return
    fi
    # strip the address column: what is left is the instruction text the patterns are written for
    local insns
    insns=$(printf '%s\n' "$body" | grep -E '^[[:space:]]*[0-9a-f]+:' | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' | tr '\t' ' ')
    local fired
    if [ "$TC_ARCH" = aarch64 ]; then
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_BRANCH" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'branch\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_RETREG" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'ret-reg\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_BARRIER" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'barrier\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_STRING" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'string\t%s\n' "$fired"
        local cls
        cls=$(printf '%s\n' "$insns" | grep -E "$A64_CLASS" || true)
        if [ "$allow" = acquire-one ]; then
            local nacq
            nacq=$(printf '%s\n' "$cls" | grep -cE "$A64_ACQUIRE_ONE" || true)
            if [ "$nacq" != 1 ]; then
                printf 'acquire\texpected exactly one acquire load of the map pointer, found %s\n' "$nacq"
            fi
            cls=$(printf '%s\n' "$cls" | grep -vE "$A64_ACQUIRE_ONE" || true)
        elif [ "$allow" = acquire-views ]; then
            local nacq
            nacq=$(printf '%s\n' "$cls" | grep -cE "$A64_ACQUIRE_ONE" || true)
            if [ "$nacq" -lt 1 ] || [ "$nacq" -gt 8 ]; then
                printf 'acquire\texpected one to eight acquire loads of the view pointers, found %s\n' "$nacq"
            fi
            cls=$(printf '%s\n' "$cls" | grep -vE "$A64_ACQUIRE_ONE" || true)
        fi
        fired=$(printf '%s\n' "$cls" | grep -v '^$' | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'class\t%s\n' "$fired"
    else
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_BRANCH" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'branch\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_LOCK" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'lock\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_FENCE" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'fence\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_XCHG" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'xchg\t%s\n' "$fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_STRING" | sed -n 1,3p | tr '\n' ';' || true)
        [ -n "$fired" ] && printf 'string\t%s\n' "$fired"
    fi
    # LOCALS, the structural stack guard: a lookup wrapper may save registers and nothing else, so any
    # byte of locals fails here by name, whatever the byte bound says. Read from the instructions by
    # locals_of: the bytes below the entry sp that are read, written or have their address taken, other
    # than a callee-saved register's own save and restore (see there for why never the frame's size)
    # A symbol whose allowance is locals-ok is exempt; no row carries it today, and an evaluator row
    # may not (decision D9, refused before the run).
    local npush nloc
    npush=$(printf '%s\n' "$insns" | grep -cE '^push' || true)
    nloc=$(printf '%s\n' "$insns" | locals_of "$TC_ARCH")
    if [ "$allow" != locals-ok ]; then
        local lexp lmsg
        lexp=$(expected_locals "$TC_ID@$TC_ARCH" "${SET:-base}" "${L:-}" "$sym")
        lmsg=$(locals_verdict "${nloc:-0}" "$lexp")
        [ -n "$lmsg" ] && printf 'locals\t%s\n' "$lmsg"
        local lkey
        lkey=$(expected_locals_key "$TC_ID@$TC_ARCH" "${SET:-base}" "${L:-}" "$sym")
        [ -z "$lmsg" ] && [ "$lexp" != 0 ] && printf 'held\t%s\n' "$lkey=$lexp bytes of locals"
    fi
    # A branch that names a DIFFERENT symbol is a call however it is spelled. An internal branch
    # renders as <sym+0xNN>.
    fired=$(printf '%s\n' "$body" | grep -oE '<[A-Za-z_.][A-Za-z0-9_.]*(\+0x[0-9a-f]+)?>' \
            | grep -vE "<$sym(\+0x[0-9a-f]+)?>" | sort -u | tr '\n' ' ' || true)
    [ -n "$fired" ] && printf 'tail\t%s\n' "$fired"
    n=$(printf '%s\n' "$insns" | grep -c . || true)
    if [ "$bmin" = - ] || [ "$bmax" = - ]; then
        printf 'band\t%s instructions, and this row has no band yet: derive it from the summary below and commit it\n' "$n"
    elif [ "$n" -lt "$bmin" ] || [ "$n" -gt "$bmax" ]; then
        printf 'band\t%s instructions, outside %s..%s\n' "$n" "$bmin" "$bmax"
    fi
    printf 'count\t%s\n' "$n"
    # -fstack-usage is read in each compiler's OWN unit: gcc's figure counts the 8-byte return address
    # that x86_64's call pushes, clang's does not (a leaf with no pushes: gcc 8, clang 0; on aarch64 the
    # return address is in a register and both say 0). The bound is compared with that figure as the
    # compiler states it, so the same frame reads 8 bytes higher under gcc on x86_64.
    su="${obj%.o}.su"
    local used=""
    if [ -f "$su" ]; then
        used=$(awk -F'\t' -v s="$sym" '{ k = $1; sub(/.*:/, "", k); if (k == s) print $2 }' "$su" | sed -n 1,1p)
        [ -z "$used" ] && used=0     # a function the stack diagnostic does not name uses no stack
        if [ -n "$used" ] && [ "$used" -gt "$bound" ]; then
            printf 'stack\t%s bytes (%s'"'"'s -fstack-usage unit), over the bound of %s\n' "$used" "$TC_KIND" "$bound"
        fi
    fi
    printf 'frame\t%s %s %s\n' "$npush" "${nloc:-0}" "${used:--1}"
    return 0
}

# tu_bound SRC -> the largest stack bound of the wrappers in SRC. The compiler's warning is per
# translation unit; each wrapper's own bound is then checked from -fstack-usage in check_symbol.
tu_bound() {
    local row sym file bound max=0
    for row in "${SYMS[@]}"; do
        IFS=: read -r sym file bound _ <<<"$row"
        [ "$file" = "$1" ] && [ "$bound" -gt "$max" ] && max=$bound
    done
    echo "$max"
}

# compile TU OBJ LEVEL BOUND SET [extra...] -> 0 on success; on failure writes OBJ.err and returns 1
compile() {
    local src=$1 obj=$2 level=$3 bound=$4 set=$5
    shift 5
    local flags=()
    mapfile -t flags < <(shim_flags "$set")
    rm -f "$obj" "${obj%.o}.su"
    "${TC_CC[@]}" -c "${flags[@]}" "$level" "$(stack_flag "$bound")" -fstack-usage -UWE_TRACE "$@" \
        -I"$HERE" -I"$HERE/gate" -o "$obj" "$src" 2>"$obj.err" || return 1
    #
    # UNDER -flto, gcc writes NO .su file (the shims' flag sets all carry -flto=auto), so without this
    # the per-function bound was silently unchecked for every shim set: only the translation unit's
    # -Wstack-usage at its largest bound applied, and hpcur's 16 was not enforced there. The figure is
    # recovered from the compiler's own diagnostic at a threshold of 0, which LTO does not suppress
    # and which is in the same unit as the .su: every function with a non-zero frame is named with its
    # byte count, and a function it does not name uses 0.
    #
    if [ ! -f "${obj%.o}.su" ]; then
        local m="$obj.measure"
        if [ "$TC_KIND" = gcc ]; then
            "${TC_CC[@]}" -c "${flags[@]}" "$level" -Wstack-usage=0 -Wno-error=stack-usage= -UWE_TRACE "$@" \
                -I"$HERE" -I"$HERE/gate" -o "$m.o" "$src" 2>"$m.err" || return 1
            awk '/In function / { f = $0; sub(/.*In function [^A-Za-z_]*/, "", f); sub(/[^A-Za-z0-9_].*/, "", f) }
                 /stack usage is [0-9]+ bytes/ { n = $0; sub(/.*stack usage is /, "", n); sub(/ .*/, "", n); print "diag:" f "\t" n "\tstatic" }' \
                "$m.err" > "${obj%.o}.su"
        else
            "${TC_CC[@]}" -c "${flags[@]}" "$level" -Wframe-larger-than=0 -Wno-error=frame-larger-than -UWE_TRACE "$@" \
                -I"$HERE" -I"$HERE/gate" -o "$m.o" "$src" 2>"$m.err" || return 1
            sed -nE "s/.*stack frame size \(([0-9]+)\) exceeds limit \([0-9]+\) in '([A-Za-z0-9_]+)'.*/diag:\2\t\1\tstatic/p" \
                "$m.err" > "${obj%.o}.su"
        fi
        rm -f "$m.o"
    fi
}

# classify a compile failure: stack, not-applicable or compile
# LOCALS, read from one symbol's instructions on stdin: the number of distinct bytes BELOW the entry stack
# pointer that the code reads, writes or takes the address of, other than a callee-saved register's own
# save and restore. Derived from the accesses themselves, never from the frame's size less its saves: a
# compiler puts a local wherever there is room, in the alignment pad of a frame of saves (clang 18 at
# -O2 on aarch64 keeps an 8-byte local at [x29, #24] in a 48-byte frame) or in a slot a `push %rax`
# reserved on x86_64, and a frame-size reading sees none there. A load from at or above the entry sp is
# an incoming argument (aarch64 passes the ninth on the stack), not a local.
#
# The depth below the entry sp is walked through the listing so every offset can be placed:
#   aarch64  `[sp, #-N]!` and `sub sp, sp, #N` go down, `[sp], #N` and `add sp, sp, #N` come back up
#            (`lsl #12` honoured); `mov x29, sp` and `add x29, sp, #k` record the frame pointer, and
#            `mov sp, x29` and `sub sp, x29, #k` return to it. An access is a load or store of any width
#            (ldr, ldur, ldrb, ldrh, ldrs*, ldp, str, stur, strb, strh, stp) on [sp...] or [x29...], or an
#            `add xN, sp, #k` / `add xN, x29, #k` taking a slot's address. Each element of a pair that is a
#            callee-saved register (x19 to x30, d8 to d15) is a save or a restore and does not count.
#   x86_64   `sub $N, %rsp` and `push` go down, `add $N, %rsp` and `pop` up, N read as two's complement;
#            `push %rbp; mov %rsp, %rbp` records the frame pointer; `leave`, `mov %rbp, %rsp` and
#            `lea ...(%rbp), %rsp` tear the frame down. An access is any instruction with an operand
#            N(%rsp) or N(%rbp), with or without an index, or a `lea` of one; push and pop are the saves.
#            Its width comes from the other register operand or the mnemonic's suffix, 8 by default.
# A shrink-wrapped function has its prologue twice; the bytes are a set, so a slot used on two paths
# counts once.
locals_of() {
    awk -v arch="$1" '
        function hexu(s,   i, v) { v = 0; for (i = 3; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
        # two-s complement for a full 64-bit immediate: computed on the complement, so it stays exact
        function hexs(s,   i, v) {
            s = tolower(s)
            if (length(s) == 18 && index("89abcdef", substr(s, 3, 1)) > 0) {
                v = 0
                for (i = 3; i <= 18; i++) v = v * 16 + (15 - (index("0123456789abcdef", substr(s, i, 1)) - 1))
                return -(v + 1)
            }
            return hexu(s)
        }
        function num(s) { s = tolower(s); sub(/^#/, "", s); if (s == "") return 0
                          return substr(s, 1, 2) == "0x" ? hexs(s) : (substr(s, 1, 3) == "-0x" ? -hexu(substr(s, 2)) : s + 0) }
        function imm(line, pre,   t, v) {      # the immediate after `pre`, with an `lsl #12` honoured
            t = line; sub(pre, "", t); v = t; sub(/[^-0-9a-fx#].*/, "", v); v = num(v)
            if (t ~ /lsl #12/) v = v * 4096
            return v
        }
        # bytes [dist - size + 1, dist] below the entry sp, for an access whose lowest byte sits at depth dist
        function touch(dist, size,   j) { for (j = 0; j < size; j++) if (dist - j > 0) bytes[dist - j] = 1 }
        function a64size(r, mn) {
            if (mn ~ /^(ldrb|strb|ldrsb)/) return 1
            if (mn ~ /^(ldrh|strh|ldrsh)/) return 2
            if (mn ~ /^ldrsw/) return 4
            if (r ~ /^x/ || r ~ /^d/) return 8
            if (r ~ /^w/ || r ~ /^s/) return 4
            if (r ~ /^q/) return 16
            if (r ~ /^h/) return 2
            if (r ~ /^b/) return 1
            return 8
        }
        function callee(r) { return r ~ /^x(19|2[0-9]|30)$/ || r ~ /^d([89]|1[0-5])$/ }
        function x86size(line,   m, t) {
            if (line ~ /%xmm/) return 16
            if (line ~ /%r[0-9]+b|%[abcd]l|%[sd]il|%[bs]pl/) return 1
            if (line ~ /%r[0-9]+w|%[abcd]x[^a-z]|%[sd]i[^a-z]|%[bs]p[^a-z]/) return 2
            if (line ~ /%e[a-z][a-z]|%r[0-9]+d/) return 4
            m = line; sub(/ .*/, "", m)
            if (m ~ /b$/ && m !~ /^sub/) return 1
            if (m ~ /w$/) return 2
            if (m ~ /l$/ && m !~ /^(cal|nop)/) return 4
            return 8
        }
        arch == "x86_64" {
            line = $0
            if (line ~ /^push/) {
                d += 8
                # the push slot of a callee-saved register is its own: a mov to or from it in that register (gcc
                # restores %rbx with `mov -0x8(%rbp),%rbx` under the frame-pointer flags) is a save, not a local
                rg = line; sub(/^push[a-z]* +/, "", rg); sub(/ .*/, "", rg)
                if (rg ~ /^%(rbx|rbp|r12|r13|r14|r15)$/) slotreg[d] = rg
                next
            }
            if (line ~ /^pop/) { d -= 8; next }
            if (line ~ /^sub[a-z]* +\$/ && line ~ /%rsp *$/) { s = line; sub(/^sub[a-z]* +\$/, "", s); sub(/,.*/, "", s); d += num(s); next }
            if (line ~ /^add[a-z]* +\$/ && line ~ /%rsp *$/) { s = line; sub(/^add[a-z]* +\$/, "", s); sub(/,.*/, "", s); d -= num(s); next }
            # %rbp is the frame pointer only where the prologue makes it one; elsewhere it is an ordinary
            # register (gcc hands it out under -funroll-loops) and (%rbp) is data, not the frame. Never
            # cleared once set: a block laid out after an epilogue may still address the frame through it.
            if (line ~ /^mov[a-z]* +%rsp, *%rbp/) { fp = d; fpset = 1; next }
            # the address of the stack copied into any other register escapes where this parser cannot follow
            # it, so it counts as a local (8 bytes just below the current sp) rather than as nothing
            if (line ~ /^mov[a-z]* +%rsp, *%/) { touch(d + 8, 8); next }
            if (line ~ /^leave/ || line ~ /^mov[a-z]* +%rbp, *%rsp/ || line ~ /^lea[a-z]* .*\(%rbp\), *%rsp/) { d = fp - 8; next }
            t = line
            while (match(t, /(-?0x[0-9a-f]+|-?[0-9]+)?\(%r(sp|bp)[,)]/)) {
                m = substr(t, RSTART, RLENGTH); base = (m ~ /%rsp/) ? d : fp
                if (m ~ /%rbp/ && !fpset) { t = substr(t, RSTART + RLENGTH); continue }
                off = m; sub(/\(.*/, "", off); off = num(off)
                dist = base - off
                if ((dist in slotreg) && line ~ /^mov/ && index(line, slotreg[dist]) > 0) { t = substr(t, RSTART + RLENGTH); continue }
                touch(dist, line ~ /^lea/ ? 8 : x86size(line))
                t = substr(t, RSTART + RLENGTH)
            }
        }
        arch == "aarch64" {
            line = $0
            mn = line; sub(/ .*/, "", mn)
            # the address of a slot taken into another register
            if (match(line, /^add +x([0-9]|[12][0-9]), (sp|x29), #/)) {
                k = imm(line, "^add +x[0-9]+, (sp|x29), #")
                touch((line ~ /, sp,/ ? d : fp) - k, 8)
            }
            if (line ~ /^sub +sp, sp, #/) { d += imm(line, "^sub +sp, sp, #"); next }
            if (line ~ /^add +sp, sp, #/) { d -= imm(line, "^add +sp, sp, #"); next }
            if (line ~ /^mov +x29, sp *$/) { fp = d; next }
            if (line ~ /^add +x29, sp, #/) { fp = d - imm(line, "^add +x29, sp, #"); next }
            if (line ~ /^mov +sp, x29 *$/) { d = fp; next }
            if (line ~ /^sub +sp, x29, #/) { d = fp + imm(line, "^sub +sp, x29, #"); next }
            if (mn !~ /^(ld|st)(r|ur|p)/ || line !~ /\[(sp|x29)/) next
            ops = line; sub(/^[a-z]+ +/, "", ops); sub(/ *\[.*/, "", ops); n = split(ops, r, /[ ,]+/)
            pre = match(line, /\[(sp|x29), #-?(0x[0-9a-f]+|[0-9]+)\]!/)
            post = match(line, /\[(sp|x29)\], #-?(0x[0-9a-f]+|[0-9]+)/)
            k = 0
            if (match(line, /\[(sp|x29), #-?(0x[0-9a-f]+|[0-9]+)\]/)) { m = substr(line, RSTART, RLENGTH); sub(/.*#/, "", m); sub(/\].*/, "", m); k = num(m) }
            onfp = line ~ /\[x29/
            if (pre && !onfp) { d -= k; k = 0 }          # pre-index: sp moves first, the access is at the new sp
            base = onfp ? fp : d
            w = a64size(r[1], mn)
            for (i = 1; i <= n; i++) if (r[i] != "" && !callee(r[i]) && r[i] != "x29" && r[i] != "x30") touch(base - (k + (i - 1) * w), w)
            if (post && !onfp) { m = line; sub(/.*\], #/, "", m); d -= num(m) }
        }
        END { c = 0; for (b in bytes) c++; print c }'
}

# The parser's own controls, on listings in the shapes compilers emit: each must read the number beside
# it. Run before any symbol is judged, so a parser that has drifted stops the gate.
locals_selftest() {
    local bad=0 got want arch name listing
    while IFS='|' read -r arch want name listing; do
        [ -n "$arch" ] || continue
        got=$(printf '%b\n' "$listing" | locals_of "$arch")
        if [ "$got" != "$want" ]; then
            echo "GATE FAIL: the locals parser reads $got bytes on '$name' ($arch), not $want"
            bad=1
        fi
    done <<'CASES'
aarch64|0|a frame of twelve saved registers, saved and restored|stp x29, x30, [sp, #-96]!\nmov x29, sp\nstp x19, x20, [sp, #16]\nstp x21, x22, [sp, #32]\nstp x23, x24, [sp, #48]\nstp x25, x26, [sp, #64]\nstp x27, x28, [sp, #80]\nldp x19, x20, [sp, #16]\nldp x21, x22, [sp, #32]\nldp x23, x24, [sp, #48]\nldp x25, x26, [sp, #64]\nldp x27, x28, [sp, #80]\nldp x29, x30, [sp], #96\nret
aarch64|4|a 4-byte local in a pre-index frame (the sign once dropped it)|stp x29, x30, [sp, #-48]!\nmov x29, sp\nstr w1, [sp, #16]\nldr w1, [sp, #16]\nldp x29, x30, [sp], #48\nret
aarch64|8|an 8-byte local in the alignment pad of a frame of saves, clang 18 -O2 (frame size less saves read 0)|stp x29, x30, [sp, #-48]!\nstr x21, [sp, #16]\nstp x20, x19, [sp, #32]\nmov x29, sp\nstr x0, [x29, #24]\nldr x0, [x29, #24]\nldp x20, x19, [sp, #32]\nldr x21, [sp, #16]\nldp x29, x30, [sp], #48\nret
aarch64|8|argument spills paired with a saved register (one element of the pair is a local)|stp x29, x30, [sp, #-32]!\nmov x29, sp\nstp x7, x24, [sp, #16]\nldp x7, x24, [sp, #16]\nldp x29, x30, [sp], #32\nret
aarch64|0|the ninth argument, read from the caller's frame, is not a local|stp x29, x30, [sp, #-96]!\nmov x29, sp\nldr x8, [sp, #96]\nldp x29, x30, [sp], #96\nret
aarch64|0|a shrink-wrapped prologue, twice|cbz x0, 40\nstp x29, x30, [sp, #-32]!\nstp x19, x20, [sp, #16]\nldp x19, x20, [sp, #16]\nldp x29, x30, [sp], #32\nret\nstp x29, x30, [sp, #-32]!\nstp x19, x20, [sp, #16]\nldp x19, x20, [sp, #16]\nldp x29, x30, [sp], #32\nret
aarch64|8|a slot used on two shrink-wrapped paths counts once|sub sp, sp, #16\nstr x0, [sp, #8]\nadd sp, sp, #16\nret\nsub sp, sp, #16\nstr x0, [sp, #8]\nadd sp, sp, #16\nret
aarch64|8|a slot's address taken (a volatile array's base)|sub sp, sp, #16\nadd x8, sp, #0x8\nstrb w1, [x8, x9]\nadd sp, sp, #16\nret
aarch64|4|a byte-wide store four times, one word|sub sp, sp, #0x1, lsl #12\nstrb w0, [sp, #8]\nstrb w0, [sp, #9]\nstrb w0, [sp, #10]\nstrb w0, [sp, #11]\nadd sp, sp, #0x1, lsl #12\nret
x86_64|8|a local below a sub|sub $0x70,%rsp\nmov %rax,0x8(%rsp)\nadd $0x70,%rsp\nret
x86_64|4|a negative add allocates (unsigned, it once read 2^64)|add $0xffffffffffffff80,%rsp\nmov %eax,(%rsp)\nsub $0xffffffffffffff80,%rsp\nret
x86_64|4|a local in a slot a push %rax reserved (frame size less pushes read 0)|push %rax\nmov %edi,0x4(%rsp)\nmov 0x4(%rsp),%eax\npop %rcx\nret
x86_64|8|a leaf's red zone|mov %rax,-0x8(%rsp)\nret
x86_64|0|pushes are saves|push %rbx\npush %r12\npop %r12\npop %rbx\nret
x86_64|0|an incoming stack argument is not a local|mov 0x8(%rsp),%rax\nret
x86_64|8|a local off the frame pointer|push %rbp\nmov %rsp,%rbp\nmov %rdi,-0x8(%rbp)\nleave\nret
x86_64|8|a slot's address taken|sub $0x18,%rsp\nlea 0x8(%rsp),%rdi\nadd $0x18,%rsp\nret
x86_64|0|a pushed register restored from its own slot through the frame pointer|push %rbp\nmov %rsp,%rbp\npush %rbx\nmov -0x8(%rbp),%rbx\nleave\nret
x86_64|8|a pushed register's slot written from another register is a local|push %rbp\nmov %rsp,%rbp\npush %rbx\nmov %rax,-0x8(%rbp)\nmov -0x8(%rbp),%rbx\nleave\nret
x86_64|0|%rbp as an ordinary register, no frame pointer (gcc -funroll-loops)|push %rbp\npush %rbx\nmov %rdi,%rbp\nmovzbl 0x1(%rbp),%eax\nmov %al,(%rbp)\npop %rbx\npop %rbp\nret
x86_64|8|the stack's address copied into another register counts|mov %rsp,%rax\nmov %rdi,-0x8(%rax)\nret
CASES
    if [ "$bad" = 0 ]; then
        echo "ok   the locals parser reads every control listing right: saves and restores, a pre-index frame, a local in an alignment pad, a pair half a spill, the ninth argument, shrink-wrapped paths, an address taken, byte stores, a sub, a negative add, a push %rax slot, a red zone, pushes, an incoming argument, a frame-pointer local, a pushed register restored through the frame pointer, and its slot reused, %rbp as an ordinary register, and the stack's address copied out"
    fi
    return "$bad"
}

compile_failure() {
    local err=$1
    if grep -qE 'stack usage|stack frame size|frame size .* exceeds' "$err"; then
        echo stack
    elif grep -qE "WE_GATE_NOT_APPLICABLE|unknown value .* for .-march|unsupported argument .* to option .-march|unknown target CPU|invalid arch name|invalid feature modifier .* in .-march" "$err"; then
        echo n/a
    else
        echo compile
    fi
}

# Strip every trace-hook site, WE_TRACE_READ and the evaluator's WE_TRACE_EVAL, from a copy of the
# headers beside SRC and print how many went. The expression form `(WE_TRACE_READ(x), e)` becomes
# `(e)` and the statement form disappears; the #define lines are untouched because a definition is
# never followed by a comma or a semicolon.
strip_trace() {
    local srcdir=$1 dst=$2 h total=0 n left
    mkdir -p "$dst"
    cp "$srcdir"/*.c "$srcdir"/*.h "$dst"/
    for h in "$dst"/*.h; do
        n=$(grep -oE 'WE_TRACE_(READ|EVAL)\(' "$h" | wc -l)
        perl -0777 -i -pe 's/WE_TRACE_(?:READ|EVAL)(\((?:[^()]++|(?1))*\))\s*[,;]\s*//g' "$h"
        # what is left must be only the definitions and prose in comments
        left=$(grep -vE '^[[:space:]]*(#[[:space:]]*define|\*|/\*|//)' "$h" | grep -cE 'WE_TRACE_(READ|EVAL)\(' || true)
        if [ "$left" != 0 ]; then
            echo "GATE FAIL: $left trace-hook site(s) in $(basename "$h") are not in the expression or statement form this check can remove" >&2
            return 1
        fi
        total=$((total + n - $(grep -oE 'WE_TRACE_(READ|EVAL)\(' "$h" | wc -l)))
    done
    echo "$total"
}

dis_rel() { "$TC_OD" -d -r --no-show-raw-insn "$1" | sed '1,3d'; }

# ---- the run ------------------------------------------------------------------------------------
REQUIRED=(gcc-aarch64 clang-aarch64 clang-x86_64)
OPTIONAL=(gcc-x86_64)
# Every `@expect` line names an architecture or a toolchain the gate runs. A toolchain line overrides
# its architecture's, so a misspelt one would be ignored and the control judged by the wider line: it
# fails here by name instead, and the check is held to a planted misspelling first.
expect_names_bad() { # file -> the names on its @expect lines that are neither an architecture nor a toolchain
    sed -n 's/^ \* @expect \([^ ]*\) .*/\1/p' "$1" |
        grep -vxE '(aarch64|x86_64|gcc-aarch64|clang-aarch64|gcc-x86_64|clang-x86_64)' || true
}
expect_names_check() {
    local f bad ok=0 plant="$OUT/expect-plant.c"
    printf '/*\n * @expect gcc-aarch46 reloc\n * @expect aarch64 class\n */\n' > "$plant"
    if [ "$(expect_names_bad "$plant")" != gcc-aarch46 ]; then
        echo "GATE FAIL: the @expect name check did not refuse a planted misspelt toolchain (gcc-aarch46)"
        ok=1
    fi
    for f in gate/ctl-*.c; do
        bad=$(expect_names_bad "$f")
        if [ -n "$bad" ]; then
            echo "GATE FAIL: $f names an @expect target the gate never runs: $(echo "$bad" | tr -s "[:space:]" " ")"
            ok=1
        fi
    done
    [ "$ok" = 0 ] && echo "ok   every control's @expect lines name a known architecture or toolchain (a planted misspelling refused)"
    return $ok
}

# the expected-locals table's own control: every tabled entry is found by its lookup, held when equal,
# and refused a byte either way; an untabled leg expects 0 and refuses a single byte
expect_table_selftest() {
    local k c st y lv e bad=0
    for k in "${!EXPECT_LOCALS[@]}"; do
        e=${EXPECT_LOCALS[$k]}
        # a key names its level or holds at every level (looked up at -O2, where no row is level-keyed)
        IFS='|' read -r c st lv y <<<"$k"
        if [ -z "$y" ]; then y=$lv; lv=-O2; fi
        [ "$(expected_locals "$c" "$st" "$lv" "$y")" = "$e" ] || { echo "GATE FAIL: the expected-locals lookup misses $k"; bad=1; }
        [ -z "$(locals_verdict "$e" "$e")" ] || { echo "GATE FAIL: the expected-locals check refuses $k at its own $e bytes"; bad=1; }
        [ -n "$(locals_verdict $((e + 1)) "$e")" ] || { echo "GATE FAIL: the expected-locals check accepts $k at $((e + 1)) bytes"; bad=1; }
        [ -n "$(locals_verdict $((e - 1)) "$e")" ] || { echo "GATE FAIL: the expected-locals check accepts $k at $((e - 1)) bytes"; bad=1; }
    done
    for k in "${!EXPECT_RELOCS[@]}"; do
        e=${EXPECT_RELOCS[$k]}
        IFS='|' read -r c st lv y <<<"$k"
        [ "$(expected_relocs "$c" "$st" "$lv" "$y")" = "$e" ] || { echo "GATE FAIL: the expected-relocations lookup misses $k"; bad=1; }
        [ -z "$(reloc_verdict "$e" 0 "$e" x)" ] || { echo "GATE FAIL: the expected-relocations check refuses $k at its own $e"; bad=1; }
        [ -n "$(reloc_verdict $((e + 1)) 0 "$e" x)" ] || { echo "GATE FAIL: the expected-relocations check accepts $k at $((e + 1))"; bad=1; }
        [ -n "$(reloc_verdict $((e - 1)) 0 "$e" x)" ] || { echo "GATE FAIL: the expected-relocations check accepts $k at $((e - 1))"; bad=1; }
        [ -n "$(reloc_verdict "$e" 1 "$e" x)" ] || { echo "GATE FAIL: the expected-relocations check accepts $k with one outside the constant pool"; bad=1; }
    done
    [ "$(expected_relocs clang-20 x86-64-v3 -O hpeval)" = 0 ] || { echo "GATE FAIL: clang 20 v3 at -O does not expect 0 relocations"; bad=1; }
    [ -n "$(reloc_verdict 1 0 0 x)" ] || { echo "GATE FAIL: the relocation check accepts one relocation on an untabled leg"; bad=1; }
    [ "$(expected_locals gcc-13 base -O2 hpeval)" = 0 ] || { echo "GATE FAIL: an untabled leg does not expect 0"; bad=1; }
    [ "$(expected_locals gcc-13@aarch64 base -O hpmod)" = 0 ] || { echo "GATE FAIL: gcc 13's x86_64 entry for the base set reaches aarch64"; bad=1; }
    [ "$(expected_locals gcc-13@x86_64 base -O hpmod)" = 8 ] || { echo "GATE FAIL: gcc 13's x86_64 entry for the base set is not found with its target"; bad=1; }
    [ "$(expected_locals gcc-13@x86_64 apxs -O hpmod)" = 8 ] || { echo "GATE FAIL: gcc 13's x86_64 entry for the shims' own flag set is not found"; bad=1; }
    [ "$(expected_locals gcc-14@aarch64 base -O hpmod)" = 0 ] || { echo "GATE FAIL: gcc 14's x86_64 entry for the base set reaches aarch64"; bad=1; }
    [ "$(expected_locals gcc-14@x86_64 base -O hpmod)" = 8 ] || { echo "GATE FAIL: gcc 14's x86_64 entry for the base set is not found with its target"; bad=1; }
    [ "$(expected_locals clang-18@x86_64 ubuntu-x86_64 -O2 hpmod)" = 16 ] || { echo "GATE FAIL: a key without a target is not found from a compiler that names one"; bad=1; }
    [ -n "$(locals_verdict 1 0)" ] || { echo "GATE FAIL: the locals check accepts one byte on an untabled leg"; bad=1; }
    [ "$bad" = 0 ] && echo "ok   the expected-locals table (${#EXPECT_LOCALS[@]} entries) and the expected-relocations table (${#EXPECT_RELOCS[@]}): each held exactly and refused one either way (a relocation also anywhere outside the constant pool); an untabled leg expects 0"
    return "$bad"
}

fail=0
SETS_NA=()
locals_selftest || fail=1
expect_table_selftest || fail=1
expect_names_check || fail=1
ran=()
missing=()
unproven=()
declare -A CTL_RESULT=()
declare -A COUNTS=()
declare -A TCOUNTS=()
declare -A FRAMES=()

echo "hot-path gate, host $HOST, levels: $LEVELS"
echo "  $APXS_NOTE"
echo "  $NGINX_NOTE"
if [ -n "$EVAL_DARK" ]; then
    echo "  DARK: the policy evaluator's rows ($(eval_rows | sed 's/ $//')) are not checked: $EVAL_DARK;"
    echo "        they run, with no edit here, once it is"
fi

# Decision D9, checked before anything is compiled: no evaluator row may carry the locals-ok
# allowance. A spill moves into *ctx; a local is never the answer. The check is first shown to refuse
# a planted row, so a broken predicate cannot pass every real row by refusing nothing.
d9_refuses() { # row -> 0 when the row asks for an allowance an evaluator row may not have
    local sym file allow
    IFS=: read -r sym file _ _ _ allow <<<"$1"
    is_eval_file "$file" && [ "$allow" = locals-ok ]
}
if ! d9_refuses "hpplanted:hp_eval.c:$STACK_MAX_EVAL:-:-:locals-ok"; then
    echo "GATE FAIL: the D9 check accepted a planted evaluator row with locals-ok, so it checks nothing"
    fail=1
fi
for row in "${SYMS[@]}"; do
    if d9_refuses "$row"; then
        echo "GATE FAIL: ${row%%:*} asks for locals-ok, which an evaluator row may not (decision D9: scratch moves into *ctx)"
        fail=1
    fi
done

for TC in "${REQUIRED[@]}" "${OPTIONAL[@]}"; do
    if ! tc_setup "$TC"; then
        missing+=("$TC")
        echo
        echo "---- $TC: NOT INSTALLED, not checked ----"
        continue
    fi
    ran+=("$TC")
    TC_ID="$TC_KIND-$("${TC_CC[0]}" -dumpversion | cut -d. -f1)"
    D="$OUT/$TC"
    mkdir -p "$D"
    echo
    echo "---- $TC (${TC_CC[*]}; disassembled with $TC_OD) ----"

    # the flag sets this toolchain is checked with: the base set always; the shims' sets on the host's
    # own gcc, which is the compiler apxs and nginx report and the one a distribution builds them with
    SETS=(base)
    if [ "$TC_NATIVE" = 1 ] && [ "$TC_KIND" = gcc ]; then
        [ -n "$APXS_FLAGS" ] && SETS+=(apxs)
        [ -n "$NGINX_FLAGS" ] && SETS+=(nginx)
    fi
    # the cross gcc also runs the other architecture's Ubuntu module set, so this host measures what
    # that architecture's CI job will; clang runs it on both architectures, because a module built with
    # CC=clang gets the same CFLAGS, and -fno-omit-frame-pointer moves clang's register allocation
    if [ "$TC_NATIVE" = 0 ] || [ "$TC_KIND" = clang ]; then
        SETS+=("ubuntu-$TC_ARCH")
    fi
    # Fedora's module set on every compiler. clang 18 has no -mtls-dialect=gnu2, which Fedora's x86_64
    # set carries; Fedora 41 builds with gcc 14 and clang 19, so on clang 18 the set is not applicable
    # and is listed as such, never silently dropped
    mapfile -t probe_flags < <(shim_flags "fedora-$TC_ARCH")
    if "${TC_CC[@]}" "${probe_flags[@]}" -x c -c /dev/null -o "$D/fedora-probe.o" 2>"$D/fedora-probe.err"; then
        SETS+=("fedora-$TC_ARCH")
    else
        SETS_NA+=("fedora-$TC_ARCH on $TC (${TC_CC[0]}, $("${TC_CC[0]}" --version 2>/dev/null | sed -n 1p | cut -c1-60)): $(grep -m1 -i 'error' "$D/fedora-probe.err" | cut -c1-140)")
    fi
    if [ "$TC_ARCH" = x86_64 ]; then
        SETS+=(x86-64-v3 znver3 znver4)
    fi
    echo "  flag sets: ${SETS[*]}"
    # the undef step's control, under every set (the LTO sets are where nm misread): a planted external
    # reference must be read back by name
    uok=1
    for SET in "${SETS[@]}"; do
        printf 'extern int we_gate_planted_external(int);\nint we_gate_planted(int x) { return we_gate_planted_external(x) + 1; }\n' > "$D/undef-plant.c"
        if ! compile "$D/undef-plant.c" "$D/undef-plant-$SET.o" -O2 "$STACK_MAX_EVAL" "$SET"; then
            echo "GATE FAIL: $TC [$SET]: the undef control does not compile: $(grep -m1 -i error "$D/undef-plant-$SET.o.err" | cut -c1-140)"
            fail=1; uok=0
        elif ! got=$(undef_syms "$D/undef-plant-$SET.o") || [ "$got" != "we_gate_planted_external " ]; then
            echo "GATE FAIL: $TC [$SET]: the undef step did not read a planted external back (read: '$got')"
            fail=1; uok=0
        fi
    done
    [ "$uok" = 1 ] && echo "ok   the undef step reads a planted external back under every set on $TC"

    for SRC in "${GATE_SOURCES[@]}"; do
        tag=$(basename "$SRC" .c)
        # trace-pp: the production preprocessor output must not mention the hook
        if ! pp=$("${TC_CC[@]}" -E -std=c11 -UWE_TRACE -I"$HERE" -I"$HERE/gate" "$SRC" 2>"$D/$tag.pp.err"); then
            echo "GATE FAIL: $TC $SRC: trace-pp: the preprocessor failed:"
            sed 's/^/        /' "$D/$tag.pp.err" | sed -n 1,8p
            fail=1
        elif [[ "$pp" == *we_trace_read* || "$pp" == *we_trace_eval* ]]; then
            echo "GATE FAIL: $TC $SRC: trace-pp: the production preprocessor output contains a trace hook (we_trace_read or we_trace_eval)"
            fail=1
        fi
        # trace-identical, at every level, base flags
        if ! sites=$(strip_trace "$(dirname "$HERE/$SRC")" "$D/strip-$tag"); then
            fail=1
            sites=unknown
        fi
        same=0; diffs=0
        for L in $LEVELS; do
            rm -f "$D/$tag-hook.o.err" "$D/$tag-nohook.o.err"     # never report a previous level's error
            if compile "$SRC" "$D/$tag-hook.o" "$L" "$STACK_MAX_EVAL" base \
               && compile "$D/strip-$tag/$(basename "$SRC")" "$D/$tag-nohook.o" "$L" "$STACK_MAX_EVAL" base; then
                if diff <(dis_rel "$D/$tag-hook.o") <(dis_rel "$D/$tag-nohook.o") >"$D/$tag$L.tracediff"; then
                    same=$((same + 1))
                else
                    diffs=$((diffs + 1))
                    echo "GATE FAIL: $TC $SRC $L: trace-identical: the hook changed the production object code"
                    sed 's/^/        /' "$D/$tag$L.tracediff" | sed -n 1,20p
                    fail=1
                fi
            else
                # Name the failure and keep going. The second build runs only when the first succeeded,
                # so its .err may not exist; reading a missing file here used to end the whole gate
                # under pipefail, with the remaining toolchains and the summary never printed (a frame
                # over STACK_MAX_EVAL in the hooked build is enough to reach it).
                for e in "$D/$tag-hook.o.err" "$D/$tag-nohook.o.err"; do
                    [ -f "$e" ] || continue
                    echo "GATE FAIL: $TC $SRC $L: could not build the trace comparison ($(basename "$e" .o.err)): $(compile_failure "$e"):"
                    sed -n 's/^/        /;1,8p' "$e"
                done
                fail=1
            fi
        done
        if [ "$sites" = 0 ]; then
            echo "ok   $SRC: trace-pp clean; trace-identical $same of $same levels, trivially: the headers have no trace-hook site yet"
        else
            echo "ok   $SRC: trace-pp clean; trace-identical $same of $((same + diffs)) levels with $sites hook site(s) removed"
        fi

        for SET in "${SETS[@]}"; do
            setfail=0
            for L in $LEVELS; do
                obj="$D/$tag-$SET$L.o"
                if ! compile "$SRC" "$obj" "$L" "$(tu_bound "$SRC")" "$SET"; then
                    why=$(compile_failure "$obj.err")
                    echo "GATE FAIL: $TC $SRC [$SET $L]: $why:"
                    sed 's/^/        /' "$obj.err" | sed -n 1,8p
                    fail=1; setfail=$((setfail + 1))
                    continue
                fi
                for row in "${SYMS[@]}"; do
                    IFS=: read -r sym file bound bmin bmax allow <<<"$row"
                    [ "$file" = "$SRC" ] || continue
                    tuned=0
                    case "$TUNED_SETS" in *" $SET "*) tuned=1; IFS=: read -r bmin bmax <<<"${TUNED_BAND[$sym]:--:-}" ;; esac
                    res=$(check_symbol "$obj" "$sym" "$bound" "$bmin" "$bmax" "$allow")
                    n=$(printf '%s\n' "$res" | sed -n 's/^count\t//p')
                    if [ "$tuned" = 1 ]; then
                        TCOUNTS["$sym"]="${TCOUNTS[$sym]:-} $n"
                    else
                        COUNTS["$sym"]="${COUNTS[$sym]:-} $n"
                    fi
                    hd=$(printf '%s\n' "$res" | sed -n 's/^held\t//p')
                    [ -n "$hd" ] && LOCALS_HELD["$hd"]=1
                    fr=$(printf '%s\n' "$res" | sed -n 's/^frame\t//p')
                    [ -n "$fr" ] && FRAMES["$sym|$TC"]="${FRAMES[$sym|$TC]:-} ${fr// /:}"
                    res=$(printf '%s\n' "$res" | grep -v '^count' | grep -v '^frame' | grep -v '^held' | grep -v '^$' || true)
                    if [ -n "$res" ]; then
                        # the refusing checks named on the verdict line itself (the detail follows, indented), so a
                        # reader of that one line never sees a refusal with no reason
                        echo "GATE FAIL: $TC $SRC [$SET $L] $sym: refused by $(printf '%s\n' "$res" | cut -f1 | sort -u | tr '\n' ' ')"
                        printf '%s\n' "$res" | sed 's/^/        /'
                        fail=1; setfail=$((setfail + 1))
                    fi
                done
                # a table that cannot be read is a failure by name, never an empty list
                if ! undef=$(undef_syms "$obj"); then
                    echo "GATE FAIL: $TC $SRC [$SET $L]: undef: $undef"
                    fail=1; setfail=$((setfail + 1))
                    continue
                fi
                if [ -n "${undef// /}" ]; then
                    echo "GATE FAIL: $TC $SRC [$SET $L]: undef: the object references external symbols: $undef"
                    fail=1; setfail=$((setfail + 1))
                fi
            done
            # the set's verdict line is earned: a set with a refused level is named as such, never read as clean
            if [ "$setfail" = 0 ]; then
                echo "ok   $SRC [$SET]: every wrapper clean at $LEVELS"
            else
                echo "FAIL $SRC [$SET]: $setfail refusal(s) across $LEVELS (named above)"
            fi
        done
    done

    # ---- the negative controls ----
    for CTL in gate/ctl-*.c; do
        name=$(basename "$CTL" .c)
        # one check, or alternatives separated by | where compilers legitimately differ; an `@expect` line
        # naming the toolchain (gcc-aarch64) wins over the architecture's, so a control whose compilers
        # lower it differently holds each compiler to its own check rather than accepting either
        expect=$(sed -n "s/^ \* @expect $TC \([a-z|-]*\).*/\1/p" "$CTL" | sed -n 1,1p)
        [ -n "$expect" ] || expect=$(sed -n "s/^ \* @expect $TC_ARCH \([a-z|-]*\).*/\1/p" "$CTL" | sed -n 1,1p)
        mapfile -t cflags < <(sed -n "s/^ \* @cflags $TC_ARCH //p" "$CTL" | tr ' ' '\n' | grep -v '^$' || true)
        # @allow: the allowance the control's wrapper stands in for (a ctl-mod control keeps the
        # decision's acquire loads, so the check it names, not the allowance, is what must refuse it)
        callow=$(sed -n 's/^ \* @allow \([a-z-]*\)$/\1/p' "$CTL" | sed -n 1,1p)
        if [ -z "$expect" ]; then
            echo "GATE FAIL: $CTL names no @expect check for $TC_ARCH"
            fail=1
            continue
        fi
        # @fold: the hazard is one the compiler creates or not (a chain folded into a table), so a level
        # where it did not must build CLEAN and reads n/a; the control is still owed a refusal on some
        # toolchain of this architecture, which the proof below demands
        fold=0
        grep -qE '^ \* @fold$' "$CTL" && fold=1
        verdict=""
        nfold=0
        nocompile=""
        for L in $LEVELS; do
            obj="$D/$name$L.o"
            if ! compile "$CTL" "$obj" "$L" "$STACK_MAX_EVAL" base "${cflags[@]}"; then
                got=$(compile_failure "$obj.err")
                # a control that does not compile for any reason but not-applicable has refused nothing:
                # the check it names never saw it
                [ "$got" = compile ] && nocompile="$nocompile $L: $(grep -m1 -iE 'error' "$obj.err" | cut -c1-160);"
            else
                got=$(check_symbol "$obj" hpk "$STACK_MAX_EVAL" 1 100000 "$callow" | cut -f1 | { grep -vE '^(count|frame)$' || true; } | sort -u | tr '\n' ' ')
            fi
            hit=""
            IFS='|' read -ra alts <<<"$expect"
            for a in "${alts[@]}"; do
                case " $got " in *" $a "*) hit=$a ;; esac
            done
            if [ -n "$hit" ]; then
                verdict="$verdict ${L}:$hit"
            elif [ "$fold" = 1 ] && [ -z "${got// /}" ]; then
                verdict="$verdict ${L}:unfolded"
                nfold=$((nfold + 1))
            else
                case " $got " in
                    *" n/a "*) verdict="$verdict ${L}:n/a" ;;
                    *)         verdict="$verdict ${L}:MISSED(${got:-nothing})" ;;
                esac
            fi
            CTL_RESULT["$name|$TC|$L"]="$got"
        done
        if [ -n "$nocompile" ]; then
            echo "GATE FAIL: control $name does not COMPILE on $TC, so no check refused it:$nocompile"
            fail=1
        elif [[ "$verdict" == *MISSED* ]]; then
            echo "GATE FAIL: control $name on $TC was NOT refused by '$expect' at every level:$verdict"
            fail=1
        elif [ "$fold" = 1 ] && [[ "$verdict" == *:unfolded* ]]; then
            if [[ "$verdict" == *:n/a* ]]; then
                echo "GATE FAIL: control $name on $TC builds at some levels and not others:$verdict"
                fail=1
            elif [ "$nfold" = "$(wc -w <<<"$LEVELS")" ]; then
                echo "n/a  control $name on $TC: the compiler formed no table at any level, and the object is clean, so there is nothing here to refuse; it must be proven on another $TC_ARCH toolchain"
                CTL_RESULT["$name|$TC|na"]=1
            else
                echo "ok   control $name on $TC refused where a table formed, clean where none did:$verdict"
            fi
        elif [[ "$verdict" == *:n/a* ]]; then
            if ! [[ "$verdict" =~ ^(\ [^ ]+:n/a)+$ ]]; then
                echo "GATE FAIL: control $name on $TC builds at some levels and not others:$verdict"
                fail=1
            else
                why=$(grep -oE 'WE_GATE_NOT_APPLICABLE[^"]*|unknown value [^ ]* for [^ ]*' "$D/$name${LEVELS%% *}.o.err" | sed -n 1,1p || true)
                echo "n/a  control $name on $TC: does not build here (${why:-the compiler refused it}); it must be proven on another $TC_ARCH toolchain"
                CTL_RESULT["$name|$TC|na"]=1
            fi
        else
            echo "ok   control $name on $TC refused:$verdict"
        fi
    done
done

# ---- the controls that may be not-applicable somewhere must still be proven somewhere -------------
for CTL in gate/ctl-*.c; do
    name=$(basename "$CTL" .c)
    for arch in aarch64 x86_64; do
        proven=0
        for TC in "${ran[@]}"; do
            [ "${TC#*-}" = "$arch" ] || continue
            [ -z "${CTL_RESULT["$name|$TC|na"]:-}" ] && proven=1
        done
        [ "$proven" = 1 ] && continue
        # Not proven on this architecture. If a toolchain for it is missing, the one that could prove
        # it may be that one (clang, for min/max and RCpc3): incomplete, not failed. If every
        # toolchain for the architecture ran and none could build it, the control proves nothing.
        case " ${missing[*]:-} " in
            *"-$arch "*) unproven+=("$name on $arch") ;;
            *) echo "GATE FAIL: control $name was not shown to fail on ANY $arch toolchain"; fail=1 ;;
        esac
    done
done

echo
echo "instruction counts per wrapper, over every toolchain, level and flag set run:"
for row in "${SYMS[@]}"; do
    IFS=: read -r sym file _ bmin bmax _ <<<"$row"
    if is_eval_file "$file" && [ -n "$(eval_dark_of "$file")" ]; then
        printf '  %-10s DARK: %s\n' "$sym" "$(eval_dark_of "$file")"
        continue
    fi
    read -ra seen <<<"${COUNTS[$sym]:-}"
    c=$(printf '%s\n' "${seen[@]}" | sort -n | uniq | tr '\n' ' ')
    lo=$(printf '%s\n' "${seen[@]}" | sort -n | sed -n 1,1p)
    hi=$(printf '%s\n' "${seen[@]}" | sort -n | tail -1)
    printf '  %-10s band %3s..%-3s  seen %s..%s: %s\n' "$sym" "$bmin" "$bmax" "${lo:-?}" "${hi:-?}" "$c"
    if [ "$bmin" = - ] && [ -n "${lo:-}" ]; then
        # the one method: floor of 0.75 x the lowest, ceiling of 1.25 x the highest
        printf '  %-10s the band the one method gives from this run: %s..%s (commit it in SYMS)\n' "$sym" \
            "$(( lo * 3 / 4 ))" "$(( (hi * 5 + 3) / 4 ))"
    fi
done
echo "instruction counts per wrapper under the x86_64 target sets (${TUNED_SETS# }), against their own bands:"
for row in "${SYMS[@]}"; do
    IFS=: read -r sym file _ <<<"$row"
    read -ra seen <<<"${TCOUNTS[$sym]:-}"
    [ "${#seen[@]}" -gt 0 ] || continue
    IFS=: read -r bmin bmax <<<"${TUNED_BAND[$sym]:--:-}"
    c=$(printf '%s\n' "${seen[@]}" | sort -n | uniq | tr '\n' ' ')
    lo=$(printf '%s\n' "${seen[@]}" | sort -n | sed -n 1,1p)
    hi=$(printf '%s\n' "${seen[@]}" | sort -n | tail -1)
    printf '  %-10s tuned band %4s..%-4s  seen %s..%s: %s\n' "$sym" "$bmin" "$bmax" "$lo" "$hi" "$c"
    if [ "$bmin" = - ]; then
        printf '  %-10s the tuned band the one method gives from this run: %s..%s (commit it in TUNED_BAND)\n' "$sym" \
            "$(( lo * 3 / 4 ))" "$(( (hi * 5 + 3) / 4 ))"
    fi
done
# The evaluator's frames, on every toolchain: STACK_MAX_EVAL applies on aarch64 as on x86_64.
echo "frames of the evaluator wrappers, per toolchain over every level and flag set run, in each"
echo "compiler's own -fstack-usage unit (gcc's include x86_64's 8-byte return address, clang's do not):"
for row in "${SYMS[@]}"; do
    IFS=: read -r sym file bound _ <<<"$row"
    is_eval_file "$file" || continue
    if [ -n "$(eval_dark_of "$file")" ]; then
        printf '  %-11s DARK\n' "$sym"
        continue
    fi
    for TC in gcc-aarch64 clang-aarch64 gcc-x86_64 clang-x86_64; do
        read -ra fr <<<"${FRAMES[$sym|$TC]:-}"
        if [ "${#fr[@]}" = 0 ]; then
            printf '  %-11s %-13s no build ran\n' "$sym" "$TC"
            continue
        fi
        lmax=$(printf '%s\n' "${fr[@]}" | cut -d: -f2 | sort -n | tail -1)
        umin=$(printf '%s\n' "${fr[@]}" | cut -d: -f3 | sort -n | sed -n 1,1p)
        umax=$(printf '%s\n' "${fr[@]}" | cut -d: -f3 | sort -n | tail -1)
        printf '  %-11s %-13s %s bytes of locals at most, -fstack-usage %s..%s against %s, over %s builds\n' \
            "$sym" "$TC" "$lmax" "$umin" "$umax" "$bound" "${#fr[@]}"
    done
done
# What the lookup wrappers' x86_64 frames actually hold: the reason the byte bound is above 16.
echo "x86_64 frames of the lookup wrappers, per toolchain over every level and flag set run; the"
echo "-fstack-usage bytes are in each compiler's own unit (gcc's include the 8-byte return address, clang's do not):"
for row in "${SYMS[@]}"; do
    IFS=: read -r sym file bound _ <<<"$row"
    [ "$sym" = hpcur ] && continue
    is_eval_file "$file" && continue
    for TC in gcc-x86_64 clang-x86_64; do
        read -ra fr <<<"${FRAMES[$sym|$TC]:-}"
        if [ "${#fr[@]}" = 0 ]; then
            printf '  %-11s %-13s no build ran\n' "$sym" "$TC"
            continue
        fi
        pmin=$(printf '%s\n' "${fr[@]}" | cut -d: -f1 | sort -n | sed -n 1,1p)
        pmax=$(printf '%s\n' "${fr[@]}" | cut -d: -f1 | sort -n | tail -1)
        lmax=$(printf '%s\n' "${fr[@]}" | cut -d: -f2 | sort -n | tail -1)
        umin=$(printf '%s\n' "${fr[@]}" | cut -d: -f3 | sort -n | sed -n 1,1p)
        umax=$(printf '%s\n' "${fr[@]}" | cut -d: -f3 | sort -n | tail -1)
        printf '  %-11s %-13s %s..%s pushes, %s bytes of locals at most, -fstack-usage %s..%s against %s, over %s builds\n' \
            "$sym" "$TC" "$pmin" "$pmax" "$lmax" "$umin" "$umax" "$bound" "${#fr[@]}"
    done
done
echo
# which controls a toolchain could not build, read from this run rather than written down: the set
# moves with the compiler (gcc 13 knows neither __atomic_fetch_max nor rcpc3; gcc 14 knows rcpc3)
na_lines=$(for k in "${!CTL_RESULT[@]}"; do
    case "$k" in *"|na") IFS='|' read -r n t _ <<<"$k"; echo "$n $t" ;; esac
done | sort)
if [ -n "$na_lines" ]; then
    echo "not applicable, and proven on another toolchain of the same architecture:"
    printf '%s\n' "$na_lines" | awk '{ printf "  %-22s on %s\n", $1, $2 }'
fi
if [ "${#SETS_NA[@]}" -gt 0 ]; then
    echo "flag sets not applicable to a compiler the distribution does not build with:"
    printf '  %s\n' "${SETS_NA[@]}"
fi

if [ "$fail" != 0 ]; then
    echo "HOT PATH GATE: FAILED"
    exit 1
fi
req_missing=()
for TC in "${REQUIRED[@]}"; do
    case " ${missing[*]:-} " in *" $TC "*) req_missing+=("$TC") ;; esac
done
if [ "${#missing[@]}" != 0 ] || { [ "$STRICT" = 1 ] && { [ -z "$APXS_FLAGS" ] || [ -z "$NGINX_FLAGS" ]; }; }; then
    echo "HOT PATH GATE: INCOMPLETE: clean and every control refused on ${ran[*]:-nothing}; NOT CHECKED on ${missing[*]:-no toolchain}"
    [ "${#unproven[@]}" != 0 ] && echo "    and these controls are proven nowhere in this run: ${unproven[*]}"
    [ -z "$APXS_FLAGS" ] && echo "    and the Apache module's flags were not checked (no apxs)"
    [ -z "$NGINX_FLAGS" ] && echo "    and the nginx module's flags were not checked (no nginx)"
    if [ "$STRICT" = 1 ] || [ "${#req_missing[@]}" = "${#REQUIRED[@]}" ]; then
        exit 1
    fi
    exit 0
fi
dark_note=""
[ -n "$EVAL_DARK" ] && dark_note="; the evaluator's $(eval_rows | wc -w) rows DARK ($EVAL_DARK)"
held_note=""
if [ "${#LOCALS_HELD[@]}" -gt 0 ]; then
    held_note="; no local and no relocation on any leg but these, each held exactly by its table: $(printf '%s\n' "${!LOCALS_HELD[@]}" | sort | tr '\n' ' ' | sed 's/ $//')"
fi
echo "HOT PATH GATE: CLEAR on ${ran[*]}: no call, no atomic, no fence, no string op, no store outside the caller's context; every negative control refused by its named check$held_note$dark_note"
