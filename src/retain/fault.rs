//! The test-only fault seam for `retain`.
//!
//! Compiled only under `cfg(test)`: the `step!` macro in the parent module
//! calls [`hit`] before every filesystem operation it wraps, and a release
//! build expands that macro to the operation alone, so no hook exists there.
//!
//! The seam is per thread. A test installs one with [`install`], which returns
//! a guard that removes it again, and every operation the test drives on its
//! own thread consults it. Operations on other threads see no seam at all.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;

/// A filesystem step the seam can observe and fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    OpenComponent,
    DrawName,
    MakeDirectory,
    OpenStagingDirectory,
    CreateSnapshot,
    WriteSnapshot,
    FlushSnapshot,
    ReopenSnapshot,
    StatSnapshot,
    UnlinkSnapshot,
    ListStaging,
    RemoveStagingEntry,
    RemoveStagingDirectory,
    InspectDestination,
    CreateTemporary,
    ReadRetained,
    WriteTemporary,
    SyncFile,
    VerifyRead,
    Link,
    Rename,
    RemoveTemporary,
    SyncStagingDirectory,
    SyncParent,
    /// Preparation opening an input's source file.
    OpenInput,
    /// Preparation reading an input's source file.
    ReadInput,
    /// Reopen opening `/` or a component of the preparation directory.
    OpenPreparationComponent,
    /// Reopen naming a component it could not open.
    InspectPreparationComponent,
    /// Reopen checking the preparation directory's or its parent's mode.
    InspectPreparationDirectory,
    ListPreparation,
    /// Reopen's `statat` of a preparation file.
    StatPreparationFile,
    OpenPreparationFile,
    /// Reopen's `fstat` of an opened preparation file.
    InspectPreparationFile,
    ReadPreparationFile,
}

/// How a publication temporary is damaged just before it is verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Corruption {
    /// Flips every bit of the first byte, keeping the length.
    FlipFirstByte,
    /// Drops the last byte.
    TruncateOne,
}

/// A callback run just before one occurrence of a step.
struct Hook {
    step: Step,
    occurrence: usize,
    callback: Box<dyn FnOnce()>,
}

struct Fault {
    step: Step,
    kind: io::ErrorKind,
    /// The 1-based occurrence to fail, or every occurrence when `None`.
    occurrence: Option<usize>,
}

/// The faults, overrides and callbacks a test arranges before driving `retain`.
#[derive(Default)]
pub(crate) struct Seam {
    faults: Vec<Fault>,
    forced_names: VecDeque<[u8; 16]>,
    write_fail_at: Option<(u64, io::ErrorKind)>,
    corruption: Option<Corruption>,
    before_publish: Option<Box<dyn FnOnce()>>,
    hooks: Vec<Hook>,
    record: Vec<Step>,
    counts: HashMap<Step, usize>,
}

impl Seam {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Fails every occurrence of `step` with `kind`.
    pub(crate) fn fail(mut self, step: Step, kind: io::ErrorKind) -> Self {
        self.faults.push(Fault {
            step,
            kind,
            occurrence: None,
        });
        self
    }

    /// Fails only the `n`th (1-based) occurrence of `step` with `kind`.
    pub(crate) fn fail_nth(mut self, step: Step, n: usize, kind: io::ErrorKind) -> Self {
        self.faults.push(Fault {
            step,
            kind,
            occurrence: Some(n),
        });
        self
    }

    /// Makes the next random-name draw return `bytes`.
    pub(crate) fn force_name(mut self, bytes: [u8; 16]) -> Self {
        self.forced_names.push_back(bytes);
        self
    }

    /// Fails a snapshot write once it reaches byte `k`; bytes before `k` land.
    pub(crate) fn fail_write_at(mut self, k: u64, kind: io::ErrorKind) -> Self {
        self.write_fail_at = Some((k, kind));
        self
    }

    pub(crate) fn corrupt(mut self, corruption: Corruption) -> Self {
        self.corruption = Some(corruption);
        self
    }

    /// Runs `callback` just before the `n`th (1-based) occurrence of `step`,
    /// before any fault arranged for it.
    pub(crate) fn before(
        mut self,
        step: Step,
        n: usize,
        callback: impl FnOnce() + 'static,
    ) -> Self {
        self.hooks.push(Hook {
            step,
            occurrence: n,
            callback: Box::new(callback),
        });
        self
    }

    /// Runs `callback` once, just before `linkat` or `renameat` publishes.
    pub(crate) fn before_publish(mut self, callback: impl FnOnce() + 'static) -> Self {
        self.before_publish = Some(Box::new(callback));
        self
    }
}

thread_local! {
    static SEAM: RefCell<Option<Seam>> = const { RefCell::new(None) };
}

/// Removes the installed seam when dropped.
#[must_use = "the seam is removed when the guard drops"]
pub(crate) struct SeamGuard(());

/// Returns the steps the installed seam observed so far, in order.
pub(crate) fn record() -> Vec<Step> {
    SEAM.with(|seam| {
        seam.borrow()
            .as_ref()
            .map(|seam| seam.record.clone())
            .unwrap_or_default()
    })
}

impl Drop for SeamGuard {
    fn drop(&mut self) {
        // `try_with`: a guard dropped during thread teardown must not panic.
        let _ = SEAM.try_with(|seam| seam.borrow_mut().take());
    }
}

/// Installs `seam` on this thread until the returned guard drops.
pub(crate) fn install(seam: Seam) -> SeamGuard {
    SEAM.with(|slot| *slot.borrow_mut() = Some(seam));
    SeamGuard(())
}

/// Records `step`, runs the callback arranged for this occurrence, and
/// returns the error arranged for it, if any.
///
/// The callback runs with the seam released, so it may drive filesystem
/// operations of its own.
pub(crate) fn hit(step: Step) -> io::Result<()> {
    let (callback, result) = SEAM.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(seam) = slot.as_mut() else {
            return (None, Ok(()));
        };
        seam.record.push(step);
        let count = seam.counts.entry(step).or_insert(0);
        *count += 1;
        let count = *count;
        let callback = seam
            .hooks
            .iter()
            .position(|hook| hook.step == step && hook.occurrence == count)
            .map(|at| seam.hooks.remove(at).callback);
        let result = match seam
            .faults
            .iter()
            .find(|f| f.step == step && f.occurrence.is_none_or(|n| n == count))
        {
            Some(fault) => Err(io::Error::new(fault.kind, format!("injected {step:?}"))),
            None => Ok(()),
        };
        (callback, result)
    });
    if let Some(callback) = callback {
        callback();
    }
    result
}

/// Returns the forced name for this draw, if the test arranged one.
pub(crate) fn forced_name() -> Option<[u8; 16]> {
    SEAM.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .and_then(|seam| seam.forced_names.pop_front())
    })
}

/// Caps a snapshot write of `len` bytes at `offset` so it stops at the
/// arranged failure byte, and fails once the write starts there.
pub(crate) fn cap_write(offset: u64, len: usize) -> io::Result<usize> {
    SEAM.with(|slot| {
        let slot = slot.borrow();
        let Some((k, kind)) = slot.as_ref().and_then(|seam| seam.write_fail_at) else {
            return Ok(len);
        };
        if offset >= k {
            return Err(io::Error::new(kind, "injected write failure"));
        }
        Ok(usize::try_from(k - offset).map_or(len, |before| before.min(len)))
    })
}

pub(crate) fn corruption() -> Option<Corruption> {
    SEAM.with(|slot| slot.borrow().as_ref().and_then(|seam| seam.corruption))
}

/// Runs the arranged pre-publication callback, once.
pub(crate) fn before_publish() {
    let callback = SEAM.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .and_then(|seam| seam.before_publish.take())
    });
    if let Some(callback) = callback {
        callback();
    }
}
