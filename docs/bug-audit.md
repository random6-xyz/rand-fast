# Bug audit

What was checked, what was reproduced, and what was left alone.

The rule for this audit: a candidate is only a bug once a test fails on the
current code. Candidates that could not be made to fail are recorded here, not
"fixed" by guessing. Every entry names the exact site so the next reader can
disagree with the verdict.

## Fixed

### 1. `diagnose` reported swap pressure that never happened

**Site:** `fast/src/scoring.rs` (`memory_rates`, `score_memory`),
`fast/src/diagnose.rs` (`Evidence`, `collect_evidence`, `print_report`).

`memory_rates` rebuilt the memory verdict's input with a hard-coded
`swap_start_kb: 0`. The swap signal is growth over the window
(`Rates::swap_delta_kb`), so zeroing the baseline turned *any* host that was
already using more than 1 MiB of swap before the run into
`Memory pressure` at severity 0.7 for every diagnosis, with the evidence line
claiming "N KiB of new swap over the window". `fast memory` used the real
baseline (`fast/src/memory.rs`, `swap_start_kb: first.swap_kb`) and called the
same process `Idle`. `scoring.rs` documents that the two commands must agree.

**Reproduction:** `scoring::tests::resident_swap_alone_is_not_pressure_here_either`
(set `swap_kb == swap_start_kb == 8 MiB`, assert the verdict is `Idle` and no
`Memory pressure` cause is ranked). Fails before the change, passes after.

**Fix:** `Evidence` carries `swap_start_kb`, `fast diagnose` reads
`memory::read_swap_used_kb()` before collection starts, `memory_rates` uses it,
the text report prints both numbers, and the evidence line states the growth
(`"{n} KiB of new swap ({start} KiB at the start)"`) so a reader can check the
claim. `data.measured.swap_start_kb` is additive, which keeps the v2 JSON rule
(fields may be added, never repurposed).

### 2. Unparsable PSI was published as "available, 0%"

**Site:** `fast/src/memory.rs` (`read_psi`, `parse_avg10`).

`read_psi` set `available: true` as soon as the file could be *read*, then
`parse_avg10` returned `0.0` for a missing or malformed `avg10=` field. The
result was a PSI reading of "available, some 0%, full 0%": the scoring then
treats memory pressure as measured-and-absent, which rules out a cause nobody
measured. This is the same class of defect as the swap bug: a zero that was
never observed.

**Reproduction:** `memory::tests::psi_that_does_not_parse_is_unavailable_not_zero`
(write `some avg10=n/a` / `full avg10=n/a` to a temp file, assert
`!psi.available`). Fails before the change, passes after. The older
`extracts_avg10_from_a_line` asserted the buggy `0.0` for a body with no
`avg10` field; it now expects `None`.

**Fix:** `parse_avg10` returns `Option<f32>`; `read_psi` reports PSI as
available only when both the `some` and `full` lines parsed. Everything that
consumed `available` (`scoring::score_memory`, `daemon::tick`) already treated
`false` as "cannot tell", so they needed no change.

## Not reproduced

### 3. Daemon restore and rotation accounting

Checked `Restored`/`restore_ring` and `daemon_storage::rotate_with`.

- `restore_ring` rebases `previous_at` to the newest restored interval and
  keeps only entries inside the window; `Ring::push` then enforces the count
  cap, so a restored timeline cannot exceed the window it claims to cover.
  Pinned by `daemon::tests` around `restore_ring` (window survives a restart,
  restored entries carry no `fired` state, so a restart cannot re-announce an
  incident already written).
- `rotate_with` removes by count before bytes, never removes `current`, keeps
  unreadable/unrecognized data rather than deleting what it cannot classify,
  and stops the byte pass at any entry it failed to measure, reporting the cap
  as unknown. Pinned by
  `daemon_storage::tests::count_cap_never_removes_the_current_bundle`,
  `byte_and_count_caps_apply_together`, and
  `rotation_failure_and_unreadable_unrelated_data_leave_cap_unknown`.

No failing test was produced. The count cap skipping `current` is deliberate:
the bundle being written is the one the reader came for.

### 4. TCP ownership attribution

Checked `tcp_ownership::parse_net_table` / `parse_endpoint` /
`read_inventory`, and `tcp::TcpCollector::{seed, retire_missing}`.

- Column offsets are pinned by `tcp_ownership::tests::decodes_ipv4_addresses_in_the_order_the_kernel_prints_them`
  and `decodes_ipv6_addresses_word_by_word` (which also asserts the
  `retrnsmt` column decodes to 3 for the fixture row, so the retransmission
  field is not off by one).
- A socket with no descriptor (`TIME_WAIT`, `CLOSE`, inode 0) never enters the
  held set, and a listener address bound twice is reported as ambiguous instead
  of attributed to one process.
- `retire_missing` only counts an exclusion when a record was actually removed
  and the key is still in the namespace table, so a plain close is not
  reported as "the target handed this socket away".

No failing test was produced. `seed`/`retire_missing` need live eBPF maps, so
they are not unit-testable; the invariant they implement is stated in the
comments and exercised end to end by `tools/qemu-smoke.sh`'s tcp-ownership
scenario.

**Known risk, not changed:** `TcpCollector::verified` (`fast/src/tcp.rs`) gains
one key per socket seen by any reconcile and is never pruned. That is
deliberate for a bounded diagnosis, which keeps verified connections in the
report after they close, but a long-running `fast daemon` on a target that
opens connections continuously will grow it without limit. Bounding it means
deciding how long a closed connection stays in the report, which is a product
decision rather than a defect fix, so it is recorded here instead of being
changed silently.

## Verification

```bash
cargo test --offline --workspace
cargo clippy --offline --workspace --all-targets -- -D warnings
```
