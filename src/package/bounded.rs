//! Writers that refuse the byte which would cross a limit before it is
//! written or allocated, rather than checking a finished buffer or file.
//!
//! Both take an ordered list of [`Ceiling`]s. Each write passes on at most
//! the smallest allowance left, and once none is left refuses with a
//! [`LimitFault`] naming the first exhausted ceiling in list order — so a
//! caller lists the narrowest scope first and it is the one reported when one
//! byte crosses several. Faults travel as typed [`io::Error`] payloads and are
//! recovered by downcast, never by kind or message.

use std::fmt;
use std::io::{self, Write};

use super::LimitResource;

/// One limit a bounded writer enforces: the resource reported when it is
/// reached, that resource's configured value, and how many bytes this writer
/// may take from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ceiling {
    pub(crate) resource: LimitResource,
    /// The configured value a fault reports.
    pub(crate) limit: u64,
    /// The bytes this writer may store or pass on under it.
    pub(crate) allowance: u64,
}

impl Ceiling {
    /// A ceiling whose allowance is the whole configured value.
    pub(crate) fn whole(resource: LimitResource, limit: u64) -> Ceiling {
        Ceiling {
            resource,
            limit,
            allowance: limit,
        }
    }
}

/// A ceiling was reached: the payload of the [`io::Error`] a bounded writer
/// refuses a byte with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LimitFault {
    pub(crate) resource: LimitResource,
    pub(crate) limit: u64,
}

impl fmt::Display for LimitFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the {} limit of {} was exceeded",
            self.resource, self.limit
        )
    }
}

impl std::error::Error for LimitFault {}

/// A [`BoundedVec`] could not reserve memory: the payload of an
/// [`io::ErrorKind::OutOfMemory`] error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocFault;

impl fmt::Display for AllocFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded buffer could not reserve memory")
    }
}

impl std::error::Error for AllocFault {}

impl LimitFault {
    /// Recovers the fault `error` carries as its payload, or returns `error`
    /// unchanged. Only the payload's type decides.
    pub(crate) fn recover(error: io::Error) -> Result<LimitFault, io::Error> {
        match error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<LimitFault>())
        {
            Some(fault) => Ok(*fault),
            None => Err(error),
        }
    }
}

/// Returns the bytes left under the tightest of `ceilings` once `used` are
/// taken, or the first exhausted ceiling's fault.
fn remaining(ceilings: &[Ceiling], used: u64) -> Result<u64, LimitFault> {
    let mut smallest = u64::MAX;
    for ceiling in ceilings {
        let left = ceiling.allowance.saturating_sub(used);
        if left == 0 {
            return Err(LimitFault {
                resource: ceiling.resource,
                limit: ceiling.limit,
            });
        }
        smallest = smallest.min(left);
    }
    Ok(smallest)
}

fn refuse(fault: LimitFault) -> io::Error {
    io::Error::other(fault)
}

/// A writer passing on at most the smallest allowance of its ceilings to
/// `inner`; refused bytes never reach it.
pub(crate) struct LimitWriter<W> {
    inner: W,
    ceilings: Vec<Ceiling>,
    passed: u64,
}

impl<W> LimitWriter<W> {
    pub(crate) fn new(inner: W, ceilings: Vec<Ceiling>) -> LimitWriter<W> {
        LimitWriter {
            inner,
            ceilings,
            passed: 0,
        }
    }

    /// Returns the inner writer.
    pub(crate) fn into_inner(self) -> W {
        #[cfg(test)]
        seam::record_passed(self.passed);
        self.inner
    }
}

impl<W: Write> Write for LimitWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let left = remaining(&self.ceilings, self.passed).map_err(refuse)?;
        let take = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        let chunk = buf.get(..take).unwrap_or(buf);
        let written = self.inner.write(chunk)?;
        let written = written.min(chunk.len());
        self.passed = self
            .passed
            .checked_add(u64::try_from(written).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("bounded writer length overflowed"))?;
        #[cfg(test)]
        seam::record_passed(self.passed);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Smallest capacity a [`BoundedVec`] grows to, when its ceilings allow it.
const MIN_GROWTH: u64 = 64;

/// An in-memory writer that stores at most the smallest allowance of its
/// ceilings, and never requests capacity beyond it.
///
/// It grows with `try_reserve_exact` only, doubling its length up to the
/// smallest allowance, so the capacity it asks for never exceeds that
/// allowance; only allocator rounding can make the actual capacity larger. A
/// failed reservation is an [`io::ErrorKind::OutOfMemory`] error carrying
/// [`AllocFault`].
#[derive(Debug)]
pub(crate) struct BoundedVec {
    bytes: Vec<u8>,
    ceilings: Vec<Ceiling>,
}

impl BoundedVec {
    pub(crate) fn new(ceilings: Vec<Ceiling>) -> BoundedVec {
        BoundedVec {
            bytes: Vec::new(),
            ceilings,
        }
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.bytes
    }

    /// Reserves room for `needed` more bytes, `cap` bytes being the most the
    /// buffer may ever hold.
    fn grow(&mut self, needed: usize, cap: u64) -> io::Result<()> {
        let len = self.bytes.len();
        let required = len
            .checked_add(needed)
            .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, AllocFault))?;
        if required <= self.bytes.capacity() {
            return Ok(());
        }
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let doubled = len
            .saturating_mul(2)
            .max(usize::try_from(MIN_GROWTH).unwrap_or(0));
        let target = doubled.min(cap).max(required);
        let additional = target - len;
        #[cfg(test)]
        seam::record_reservation(len, additional)?;
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, AllocFault))
    }
}

impl Write for BoundedVec {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let used = u64::try_from(self.bytes.len()).map_err(io::Error::other)?;
        let left = remaining(&self.ceilings, used).map_err(refuse)?;
        let take = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        let chunk = buf.get(..take).unwrap_or(buf);
        // `left` is at least one here, so `used + left` cannot overflow a
        // ceiling's allowance.
        self.grow(chunk.len(), used + left)?;
        self.bytes.extend_from_slice(chunk);
        #[cfg(test)]
        seam::record_stored(self.bytes.len());
        Ok(chunk.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The test-only seam of the bounded writers: what each one requested and
/// passed on, and an injected reservation failure.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::RefCell;
    use std::io;

    use super::AllocFault;

    #[derive(Default)]
    struct Seam {
        reservations: Vec<(usize, usize)>,
        fail_reservation: Option<usize>,
        passed: Vec<u64>,
        stored: Option<usize>,
    }

    thread_local! {
        static SEAM: RefCell<Option<Seam>> = const { RefCell::new(None) };
    }

    /// Removes the installed seam when dropped.
    #[must_use = "the seam is removed when the guard drops"]
    pub(crate) struct SeamGuard(());

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            let _ = SEAM.try_with(|seam| seam.borrow_mut().take());
        }
    }

    /// Installs a recording seam on this thread, failing the `fail`th
    /// (1-based) reservation when given.
    pub(crate) fn install(fail: Option<usize>) -> SeamGuard {
        SEAM.with(|slot| {
            *slot.borrow_mut() = Some(Seam {
                fail_reservation: fail,
                ..Seam::default()
            });
        });
        SeamGuard(())
    }

    /// Every `(length, additional)` reservation request so far.
    pub(crate) fn reservations() -> Vec<(usize, usize)> {
        SEAM.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|seam| seam.reservations.clone())
                .unwrap_or_default()
        })
    }

    /// The most bytes a `BoundedVec` held, or `None` when none stored any.
    pub(crate) fn stored() -> Option<usize> {
        SEAM.with(|slot| slot.borrow().as_ref().and_then(|seam| seam.stored))
    }

    /// The running total each `LimitWriter` write passed on, in order.
    pub(crate) fn passed() -> Vec<u64> {
        SEAM.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|seam| seam.passed.clone())
                .unwrap_or_default()
        })
    }

    pub(super) fn record_reservation(len: usize, additional: usize) -> io::Result<()> {
        SEAM.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(seam) = slot.as_mut() else {
                return Ok(());
            };
            seam.reservations.push((len, additional));
            if seam.fail_reservation == Some(seam.reservations.len()) {
                return Err(io::Error::new(io::ErrorKind::OutOfMemory, AllocFault));
            }
            Ok(())
        })
    }

    pub(super) fn record_stored(len: usize) {
        SEAM.with(|slot| {
            if let Some(seam) = slot.borrow_mut().as_mut() {
                seam.stored = Some(seam.stored.map_or(len, |most| most.max(len)));
            }
        });
    }

    pub(super) fn record_passed(total: u64) {
        SEAM.with(|slot| {
            if let Some(seam) = slot.borrow_mut().as_mut() {
                seam.passed.push(total);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::*;
    use crate::retain::RetentionScope;

    fn ceilings(pairs: &[(LimitResource, u64)]) -> Vec<Ceiling> {
        pairs
            .iter()
            .map(|&(resource, allowance)| Ceiling {
                resource,
                limit: allowance,
                allowance,
            })
            .collect()
    }

    fn as_u64(n: usize) -> u64 {
        u64::try_from(n).unwrap()
    }

    #[track_caller]
    fn limit_fault(error: &io::Error) -> LimitFault {
        *error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<LimitFault>())
            .expect("a limit payload")
    }

    #[test]
    fn a_bounded_vec_holds_exactly_its_smallest_ceiling() {
        let _seam = seam::install(None);
        let mut buf = BoundedVec::new(ceilings(&[
            (LimitResource::RawManifest, 100),
            (LimitResource::Package, 40),
        ]));
        for chunk in [&b"0123456789"[..]; 4] {
            buf.write_all(chunk).expect("within the ceiling");
        }
        let error = buf.write(b"x").expect_err("the next byte is refused");
        assert_eq!(
            limit_fault(&error),
            LimitFault {
                resource: LimitResource::Package,
                limit: 40
            }
        );
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 40);
        for (len, additional) in seam::reservations() {
            assert!(len + additional <= 40, "{len} + {additional}");
        }
    }

    #[test]
    fn a_straddling_write_stores_up_to_the_ceiling_then_faults() {
        let mut buf = BoundedVec::new(ceilings(&[(LimitResource::RawManifest, 7)]));
        let error = buf.write_all(b"0123456789").expect_err("refused");
        assert_eq!(limit_fault(&error).resource, LimitResource::RawManifest);
        assert_eq!(buf.into_inner(), b"0123456");
    }

    #[test]
    fn reservations_grow_geometrically_and_never_past_the_ceiling() {
        let _seam = seam::install(None);
        let cap = 10_000u64;
        let mut buf = BoundedVec::new(ceilings(&[(LimitResource::RawManifest, cap)]));
        let mut stored = 0u64;
        loop {
            match buf.write(b"abc") {
                Ok(n) => stored += as_u64(n),
                Err(error) => {
                    assert_eq!(limit_fault(&error).resource, LimitResource::RawManifest);
                    break;
                }
            }
        }
        assert_eq!(stored, cap);
        let reservations = seam::reservations();
        assert!(!reservations.is_empty());
        for &(len, additional) in &reservations {
            let (len, additional) = (as_u64(len), as_u64(additional));
            assert!(additional <= cap - len, "a request past the allowance");
            assert_eq!(len + additional, (2 * len).max(MIN_GROWTH).min(cap));
        }
        assert_eq!(
            reservations.last().map(|&(len, add)| as_u64(len + add)),
            Some(cap)
        );
        assert!(reservations.len() < 16, "{reservations:?}");
    }

    #[test]
    fn the_first_exhausted_ceiling_in_list_order_is_reported() {
        let mut buf = BoundedVec::new(ceilings(&[
            (LimitResource::RawManifest, 10),
            (LimitResource::Package, 10),
        ]));
        buf.write_all(b"0123456789").expect("ten bytes");
        let error = buf.write(b"x").expect_err("the eleventh");
        assert_eq!(limit_fault(&error).resource, LimitResource::RawManifest);

        let mut buf = BoundedVec::new(ceilings(&[
            (LimitResource::RawManifest, 10),
            (LimitResource::Package, 9),
        ]));
        let error = buf.write_all(b"0123456789x").expect_err("refused");
        assert_eq!(limit_fault(&error).resource, LimitResource::Package);
        assert_eq!(buf.into_inner().len(), 9);
    }

    #[test]
    fn a_failed_reservation_is_out_of_memory_with_its_payload() {
        let _seam = seam::install(Some(1));
        let mut buf = BoundedVec::new(ceilings(&[(LimitResource::RawManifest, 100)]));
        let error = buf.write(b"x").expect_err("the reservation fails");
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(
            error
                .get_ref()
                .is_some_and(<dyn std::error::Error + Send + Sync>::is::<AllocFault>)
        );
        assert!(buf.into_inner().is_empty());
    }

    #[test]
    fn a_zero_ceiling_allocates_nothing() {
        let _seam = seam::install(None);
        let mut buf = BoundedVec::new(ceilings(&[(LimitResource::Package, 0)]));
        let error = buf.write(b"x").expect_err("refused");
        assert_eq!(limit_fault(&error).resource, LimitResource::Package);
        assert!(seam::reservations().is_empty());
    }

    #[test]
    fn a_limit_writer_passes_on_at_most_its_smallest_allowance() {
        let mut inner = Vec::new();
        let mut writer = LimitWriter::new(
            &mut inner,
            ceilings(&[
                (LimitResource::CompressedArchive, 10),
                (LimitResource::Package, 10),
            ]),
        );
        writer.write_all(b"0123456789").expect("ten bytes");
        let error = writer.write(b"x").expect_err("the eleventh");
        assert_eq!(
            limit_fault(&error),
            LimitFault {
                resource: LimitResource::CompressedArchive,
                limit: 10
            }
        );
        drop(writer);
        assert_eq!(inner, b"0123456789");

        let mut inner = Vec::new();
        let mut writer = LimitWriter::new(
            &mut inner,
            ceilings(&[
                (LimitResource::CompressedArchive, 10),
                (LimitResource::Package, 4),
            ]),
        );
        let error = writer.write_all(b"0123456789").expect_err("refused");
        assert_eq!(limit_fault(&error).resource, LimitResource::Package);
        drop(writer);
        assert_eq!(inner, b"0123");
    }

    #[test]
    fn package_wins_over_a_retained_disk_budget_reached_on_the_same_byte() {
        let dir = tempfile::tempdir().expect("a staging parent");
        let parent = std::fs::canonicalize(dir.path()).expect("canonical");
        let scope = RetentionScope::new(
            &parent,
            4,
            std::num::NonZeroUsize::new(64).expect("nonzero"),
        )
        .expect("a scope");
        let snapshot = scope.snapshot_writer().expect("a snapshot");
        let mut writer = LimitWriter::new(
            snapshot,
            ceilings(&[
                (LimitResource::CompressedArchive, 10),
                (LimitResource::Package, 4),
            ]),
        );
        writer.write_all(b"0123").expect("four bytes");
        let error = writer.write(b"4").expect_err("refused");
        assert_eq!(limit_fault(&error).resource, LimitResource::Package);
        let retained = writer.into_inner().finish().expect("finished");
        assert_eq!(retained.len(), 4);
    }

    #[test]
    fn an_inner_failure_passes_through_unchanged() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::StorageFull))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer =
            LimitWriter::new(Full, ceilings(&[(LimitResource::CompressedArchive, 10)]));
        let error = writer.write(b"x").expect_err("refused");
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(LimitFault::recover(error).is_err());
    }
}
