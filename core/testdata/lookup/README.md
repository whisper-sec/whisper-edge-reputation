# testdata/lookup

Inputs for `lookup-gate.sh`, the gate `make check-lookup` runs over `whisper-edge-lookup`.

Almost nothing here is committed data. The gate writes its fixtures fresh on every run, from tools in
this tree, so a fixture cannot drift from the writer that defines it:

- the eight planes, each with its `--expect` file, from `make-test-snapshot.py --plane`, once with no
  validity bound and once with one, so the same planes can be judged fresh, stale and in a tenant's
  grace;
- the domain sweep from `make-test-snapshot.py --sweep`: one directory where every in-domain value of
  every record field has its own range, and one directory per value the loader must refuse; the counts
  are restated by `lookup-states.py l2` and the gate holds the writer to them;
- the derived manifests, from `lookup-check.py derive`, each the feed writer's own manifest from `writer/`
  verbatim or with one edit (`derived/README.md`
  lists each one and the single edit that makes it);
- the manifest reader's seed corpus from `lookup-check.py seeds`, among them every cap at its bound and
  one past it;
- the differential's directories from `lookup-states.py build`: for each of the 22 programs (the policy
  corpus's `accept/` programs, the shipped default and `deny-all.conf`), one directory per state of the
  planes its rules read, and plan.tsv, the case list the gate runs; every plane is a copy of one of the eight above, a
  stale one from the bounded set, a refused one cut short. Each request is restated by the gate from the
  plan and the directory, and each record from the `.ranges` file the writer leaves beside its `--expect`
  file, so neither evaluator is given anything the tool printed.

What is committed:

- `deny-all.conf`, a policy whose one rule denies every address the hold-harmless set does not hold;
- `floor-and-ctx.policy`, in the record form, a floor and a context rule that both read reputation under
  `mode deny`: fresh, the floor decides (the corpus never runs a floor under `mode deny`, so this is
  where step 3 is reached); stale, both programs print a dependents line;
- `floor-log-ctx-decides.policy`, in the record form, under `mode log`: a floor deny that mode log
  downgrades, a context log rule, and a context allow that decides at rule 2, so the decision line's
  `rule` and `text` (the deciding rule) and its `would-deny-rule` and `would-deny-text` (the floor's
  downgraded deny) name different rules in different programs;
- `disarmed-old-form.txt`, the free-text output the tool printed before its line form, captured from that
  build over the disarmed snapshot and the interop gate's nine probes: the interop gate's disarmed check
  must refuse it, which shows the check cannot pass against a stale build;
- `writer/`, the feed writer's own manifests and the planes they name, written by the real publisher and
  composer through the builder's own fixture test, which also holds these bytes to what the
  writer produces now (`derived/README.md` describes each).

The builder's own planes and their expectations live in `../format2/`, the format-1 interop fixtures in
`..`.
