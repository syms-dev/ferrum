# Every new ferrumd route needs its own unauthenticated-401 test

ferrumd's entire authorization surface is `build_router` in `crates/ferrumd/src/main.rs` (~:217-234):
routes in the `protected` group get `.route_layer(require_session)`; anything registered outside it
is public. The existing gate test `the_real_mutating_routes_are_really_behind_the_csrf_gate`
(~:638-662) enumerates **mutating** routes only, so **a read route added outside `protected` is
invisible to the whole suite**.

This was proven, not theorised. On Phase 1.5b Task 3 a devil's-advocate pass mutation-tested the
suite: it moved `GET /api/generations` out of `protected` into the public group and **all 70 tests
passed**. A second mutation — making `require_session` wave `GET` through, the plausible "reads don't
need auth" regression — failed exactly one test out of 71, and only after the fix below existed.

**Rule:** every new route in the `protected` group ships with a test in `main.rs`'s `tests` module
driving the real router with no cookie and asserting exactly `UNAUTHORIZED`:
`build_router(state).oneshot(GET <path>)` — model it on `an_unauthenticated_password_change_is_refused`.
Assert the precise status; a handler that merely errors returns 500, which must not count as a pass.

Note `/api/catalog` (Task 2, already merged) still lacks this test — the gap is a recurring class,
not a one-off. The cause is that test lanes keep their attention inside the handler's own file and
never cross into `main.rs`, where `build_router` exists precisely so tests can exercise the real
middleware stack.
