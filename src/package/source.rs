//! The adapter every read of retained storage during verification goes
//! through, and the typed payload that tells its failures apart from verdicts.
//!
//! The framing, extraction and image code reads through plain
//! [`Read`] + [`Seek`] and reports an [`io::Error`] however it arises: a
//! `read_exact` that met the end of a short package is as much an
//! [`io::Error`] as a disk that failed. Only the second is a failure of
//! retained storage, so [`RetainedSource`] wraps every error the underlying
//! [`RetainedReader`] itself returns in a [`RetainedIoFault`], keeping its
//! kind, and the callers recover it by type before anything else classifies
//! the error. An end of file the framing code detects on its own is an `Ok(0)`
//! from here, carries no payload, and keeps its verdict.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use super::RetainedReader;

/// A failure of retained storage itself, carried as an [`io::Error`] payload
/// through code that reads a [`RetainedSource`].
#[derive(Debug)]
pub(crate) struct RetainedIoFault(io::Error);

impl fmt::Display for RetainedIoFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reading retained storage failed: {}", self.0)
    }
}

impl std::error::Error for RetainedIoFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl RetainedIoFault {
    /// Wraps `original` as the payload of an error of the same kind.
    fn wrap(original: io::Error) -> io::Error {
        io::Error::new(original.kind(), RetainedIoFault(original))
    }

    /// Recovers the original error `error` carries as a [`RetainedIoFault`]
    /// payload, or returns `error` unchanged when it carries none.
    ///
    /// Only the payload's type decides; no kind or message is inspected.
    pub(crate) fn recover(error: io::Error) -> Result<io::Error, io::Error> {
        let carries = error
            .get_ref()
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<RetainedIoFault>);
        if !carries {
            return Err(error);
        }
        let kind = error.kind();
        match error
            .into_inner()
            .map(<dyn std::error::Error + Send + Sync>::downcast::<RetainedIoFault>)
        {
            Some(Ok(fault)) => Ok(fault.0),
            // Unreachable: the payload was just seen to be this type. Kept as
            // the retained failure it was seen to be rather than trusted to an
            // `expect`.
            Some(Err(inner)) => Ok(io::Error::new(kind, inner)),
            None => Ok(io::Error::from(kind)),
        }
    }

    /// Returns the original error when `error` carries a [`RetainedIoFault`],
    /// and `error` itself otherwise.
    pub(crate) fn unwrap_or_same(error: io::Error) -> io::Error {
        Self::recover(error).unwrap_or_else(|error| error)
    }
}

/// Which retained snapshot a [`RetainedSource`] reads, for the test seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SourceRole {
    /// The package snapshot, during bounded authentication.
    Package,
    /// The package snapshot, positioned at the archive block and copied.
    ArchiveCopy,
    /// The archive-block snapshot, during the outer walk.
    Archive,
    /// An image member's snapshot, during image validation.
    Image,
}

/// A [`Read`] + [`Seek`] adapter over a [`RetainedReader`] whose own errors
/// leave it as [`RetainedIoFault`] payloads.
pub(crate) struct RetainedSource<'a> {
    reader: RetainedReader<'a>,
    // Read only by the test seam, which a release build does not compile.
    #[cfg_attr(not(test), allow(dead_code))]
    role: SourceRole,
}

impl<'a> RetainedSource<'a> {
    pub(crate) fn new(reader: RetainedReader<'a>, role: SourceRole) -> RetainedSource<'a> {
        RetainedSource { reader, role }
    }
}

impl Read for RetainedSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(test)]
        seam::hit(self.role, seam::Op::Read).map_err(RetainedIoFault::wrap)?;
        #[cfg(test)]
        seam::request(self.role, buf.len());
        let result = self.reader.read(buf);
        #[cfg(test)]
        seam::observe(self.role, seam::Op::Read, &result);
        result.map_err(RetainedIoFault::wrap)
    }
}

impl Seek for RetainedSource<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        #[cfg(test)]
        seam::hit(self.role, seam::Op::Seek).map_err(RetainedIoFault::wrap)?;
        let result = self.reader.seek(pos);
        #[cfg(test)]
        seam::observe(self.role, seam::Op::Seek, &result);
        result.map_err(RetainedIoFault::wrap)
    }
}

/// The test-only fault seam for [`RetainedSource`].
///
/// Per thread, like the retention seam: a test installs one and every source
/// it drives on its own thread consults it. An injected failure stands in for
/// the underlying [`RetainedReader`] failing, so it is wrapped exactly as a
/// real one would be.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::path::Path;

    use super::SourceRole;

    /// A retained-reader operation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) enum Op {
        Read,
        Seek,
    }

    /// What one operation of the underlying reader returned.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Observed {
        pub(crate) role: SourceRole,
        pub(crate) op: Op,
        /// The bytes a read returned or the position a seek reached, or the
        /// error kind.
        pub(crate) outcome: Result<u64, io::ErrorKind>,
    }

    type ImageHook = Box<dyn FnMut(&Path)>;

    /// The faults and observations one test arranges.
    #[derive(Default)]
    pub(crate) struct Seam {
        faults: Vec<(SourceRole, Op, usize, io::ErrorKind)>,
        counts: HashMap<(SourceRole, Op), usize>,
        observed: Vec<Observed>,
        largest_requests: HashMap<SourceRole, usize>,
        before_images: Option<ImageHook>,
    }

    impl Seam {
        pub(crate) fn new() -> Seam {
            Seam::default()
        }

        /// Fails the `n`th (1-based) `op` of a `role` source with `kind`.
        pub(crate) fn fail_nth(
            mut self,
            role: SourceRole,
            op: Op,
            n: usize,
            kind: io::ErrorKind,
        ) -> Seam {
            self.faults.push((role, op, n, kind));
            self
        }

        /// Runs `hook` with the private staging directory just before image
        /// validation starts.
        pub(crate) fn before_images(mut self, hook: impl FnMut(&Path) + 'static) -> Seam {
            self.before_images = Some(Box::new(hook));
            self
        }
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

    /// Installs `seam` on this thread until the returned guard drops.
    pub(crate) fn install(seam: Seam) -> SeamGuard {
        SEAM.with(|slot| *slot.borrow_mut() = Some(seam));
        SeamGuard(())
    }

    /// Returns every operation the underlying readers answered so far.
    pub(crate) fn observed() -> Vec<Observed> {
        SEAM.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|seam| seam.observed.clone())
                .unwrap_or_default()
        })
    }

    /// Returns the largest buffer a read of a `role` source asked for.
    pub(crate) fn largest_request(role: SourceRole) -> usize {
        SEAM.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|seam| seam.largest_requests.get(&role).copied())
                .unwrap_or_default()
        })
    }

    /// Records the size of a read's buffer.
    pub(super) fn request(role: SourceRole, len: usize) {
        SEAM.with(|slot| {
            if let Some(seam) = slot.borrow_mut().as_mut() {
                let largest = seam.largest_requests.entry(role).or_insert(0);
                *largest = (*largest).max(len);
            }
        });
    }

    /// Counts this `op` and returns the failure arranged for it, if any.
    pub(super) fn hit(role: SourceRole, op: Op) -> io::Result<()> {
        SEAM.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(seam) = slot.as_mut() else {
                return Ok(());
            };
            let count = seam.counts.entry((role, op)).or_insert(0);
            *count += 1;
            let count = *count;
            match seam
                .faults
                .iter()
                .find(|(r, o, n, _)| *r == role && *o == op && *n == count)
            {
                Some((_, _, _, kind)) => Err(io::Error::new(*kind, format!("injected {op:?}"))),
                None => Ok(()),
            }
        })
    }

    /// Records what the underlying reader returned.
    pub(super) fn observe<T: Copy + TryInto<u64>>(
        role: SourceRole,
        op: Op,
        result: &io::Result<T>,
    ) {
        SEAM.with(|slot| {
            if let Some(seam) = slot.borrow_mut().as_mut() {
                let outcome = match result {
                    Ok(value) => Ok((*value).try_into().unwrap_or(u64::MAX)),
                    Err(error) => Err(error.kind()),
                };
                seam.observed.push(Observed { role, op, outcome });
            }
        });
    }

    /// Runs the arranged pre-image hook.
    pub(crate) fn before_images(private: &Path) {
        let hook = SEAM.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .and_then(|seam| seam.before_images.take())
        });
        if let Some(mut hook) = hook {
            hook(private);
        }
    }
}
