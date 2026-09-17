# A fixture must be able to tell its own sibling rows apart

The recurring weakness in this repo's tests is not the assertions — they drive real code paths well.
It is the **fixtures' discriminating power**: an assertion that is true of the fixture for a reason
other than the one under test.

Three instances, all found by mutation testing on Phase 1.5b Task 3:

1. The AC16 lstat-vs-stat test ran against an **empty journal directory**, so a mutation sourcing
   `date` from `snapshot.taken_at` was unobservable — 70/70 passed.
2. Nothing asserted the **serialised JSON**, only Rust structs, so a `skip_serializing_if`, a field
   rename, or a type change would all have shipped green.
3. `fixture()` creates all four symlinks within **one second**, so a row's own link mtime is
   indistinguishable from any sibling's. A mutation sourcing every row's date from the `system`
   link's mtime **survives** — a regression showing one shared install date on every generation
   would ship green. (Open accepted cost; fix is to stamp each link to a distinct second.)

**Rules that follow:**
- State a discriminating test's **comparison unit and minimum gap**, not just an ordering. A
  sub-second fixture gap cannot discriminate a whole-unix-second wire value: compared
  second-to-second the *correct* implementation fails; compared against full precision the *wrong*
  one passes.
- Prefer **stamping** a timestamp explicitly (`std::fs::File::set_times` + `FileTimes`, std since
  1.75, no dependency, no `sleep`) over relying on wall-clock ordering.
- Make the assertion **two-sided**: equals the value under test **and** differs from the decoy.
- **Verify a new test can fail.** Mutate the implementation in a scratch copy and watch it go red
  before trusting it. When mutation-testing this repo, attack the fixture before the assertions.
