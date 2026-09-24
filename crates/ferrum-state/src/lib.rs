//! Shared, zero-privilege read access to ferrum's rollback bookkeeping: the
//! snapshot journal and the generation list correlated against it.
//!
//! Extracted from the `ferrum-apply` BINARY crate so `ferrumd` can read the
//! same data, following the precedent `ferrum-secrets` set in Phase 1.5a --
//! two crates needing identical logic get one shared library rather than
//! two copies that drift.
//!
//! Both modules were written and tested inside `ferrum-apply` and moved here
//! intact. Their own comments anticipated exactly this: `GenerationInfo`'s
//! `date`/`current` fields were documented as "used when listing all
//! generations, e.g. a future ferrumd-facing API", and `parse_nix_env_list`
//! and `correlate` were "kept for a future `list-generations` consumer".
//! That consumer is `GET /api/generations`.
//!
//! Nothing here needs privilege. Reading the journal needs only group
//! access to the journal directory, which is what lets the unprivileged
//! daemon render a rollback UI without going anywhere near the privileged
//! applier.
pub mod generations;
pub mod journal;
