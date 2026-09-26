//! Test-only counters of the two expensive writer steps a byte-exact
//! finalization must never repeat: serializing a manifest and constructing a
//! zstd encoder.
//!
//! Per thread, like the other seams: a test resets them, drives one call on
//! its own thread, and reads what that call did.

use std::cell::Cell;

thread_local! {
    static MANIFEST_SERIALIZATIONS: Cell<u64> = const { Cell::new(0) };
    static ZSTD_ENCODERS: Cell<u64> = const { Cell::new(0) };
}

/// Counts one manifest serialization.
pub(crate) fn count_manifest_serialization() {
    MANIFEST_SERIALIZATIONS.with(|count| count.set(count.get() + 1));
}

/// Counts one zstd encoder construction.
pub(crate) fn count_zstd_encoder() {
    ZSTD_ENCODERS.with(|count| count.set(count.get() + 1));
}

/// Returns `(manifest serializations, zstd encoders)` counted on this thread
/// since the last [`reset`].
pub(crate) fn read() -> (u64, u64) {
    (
        MANIFEST_SERIALIZATIONS.with(Cell::get),
        ZSTD_ENCODERS.with(Cell::get),
    )
}

/// Sets both counters on this thread back to zero.
pub(crate) fn reset() {
    MANIFEST_SERIALIZATIONS.with(|count| count.set(0));
    ZSTD_ENCODERS.with(|count| count.set(0));
}
