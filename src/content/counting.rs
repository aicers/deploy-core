//! Budgets, allocation lengths, and the one reader every primitive reads a
//! caller's source through.

use std::io::{self, ErrorKind, Read};

use super::{ContentFault, Latch, ResourceLimit, chunk_len, widen};
use crate::package::LimitResource;

/// A running count of one resource against its configured value.
///
/// `used` never exceeds `limit`: a charge that would take it past is refused
/// and leaves it unchanged.
#[derive(Clone, Debug)]
pub(crate) struct Budget {
    resource: LimitResource,
    limit: u64,
    used: u64,
}

impl Budget {
    /// Returns an empty budget for `limit`.
    pub(crate) fn new(limit: ResourceLimit) -> Budget {
        Budget {
            resource: limit.resource,
            limit: limit.max,
            used: 0,
        }
    }

    /// Returns how much has been charged.
    pub(crate) fn used(&self) -> u64 {
        self.used
    }

    /// Returns how much may still be charged.
    pub(crate) fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Returns the fault reporting this budget exceeded.
    pub(crate) fn exceeded(&self) -> ContentFault {
        ContentFault::LimitExceeded {
            resource: self.resource,
            limit: self.limit,
        }
    }

    /// Checks that `n` more units fit, without charging them.
    ///
    /// # Errors
    ///
    /// Returns [`ContentFault::LimitExceeded`] for this budget when they do
    /// not.
    pub(crate) fn check(&self, n: u64) -> Result<(), ContentFault> {
        if n <= self.remaining() {
            Ok(())
        } else {
            Err(self.exceeded())
        }
    }

    /// Charges `n` units.
    ///
    /// # Errors
    ///
    /// Returns [`ContentFault::LimitExceeded`] for this budget, charging
    /// nothing, when `n` more units would exceed it.
    pub(crate) fn charge(&mut self, n: u64) -> Result<(), ContentFault> {
        self.check(n)?;
        self.used = self.used.checked_add(n).ok_or_else(|| self.exceeded())?;
        Ok(())
    }
}

/// Charges `n` units to every budget in `budgets`, or to none of them.
///
/// The budgets are checked in slice order, which callers arrange narrowest
/// scope first, so the fault names the narrowest budget `n` would exceed.
///
/// # Errors
///
/// Returns [`ContentFault::LimitExceeded`] for the first budget in slice order
/// that `n` would exceed, having charged nothing.
pub(crate) fn charge_all(budgets: &mut [&mut Budget], n: u64) -> Result<(), ContentFault> {
    if let Some(budget) = budgets.iter().find(|budget| budget.check(n).is_err()) {
        return Err(budget.exceeded());
    }
    for budget in budgets.iter_mut() {
        budget.charge(n)?;
    }
    Ok(())
}

/// Converts an advertised length, or a buffer size this crate is about to
/// request, into an allocation length.
///
/// Every allocation this crate sizes from a `u64` goes through here first, so
/// none is ever sized from a length that was not held to a limit.
///
/// # Errors
///
/// Returns [`ContentFault::LimitExceeded`] for `limit` when `value` is above
/// `limit.max`, or does not fit in `usize` — which is possible only on a target
/// narrower than 64 bits.
pub(crate) fn alloc_len(value: u64, limit: ResourceLimit) -> Result<usize, ContentFault> {
    if value > limit.max {
        return Err(limit.exceeded());
    }
    usize::try_from(value).map_err(|_| limit.exceeded())
}

/// A reader that charges every byte it delivers to an ordered chain of
/// budgets: its own per-item budget first, then borrowed shared ones, arranged
/// narrowest scope first.
///
/// It is the only way any primitive reads a caller's source. Every error from
/// the source leaves it as a [`ContentFault`] payload — a source failure as
/// [`ContentFault::Io`], a fault from a primitive stacked beneath it as itself —
/// and an [`ErrorKind::Interrupted`] is retried rather than surfaced.
///
/// No request to the source exceeds the copy buffer, and none reaches more
/// than one byte past the tightest allowance: once an allowance is spent, the
/// next read probes a single byte, and a byte arriving is the limit fault. What
/// the source advertises about its own length is never consulted.
pub(crate) struct CountingReader<'b, R> {
    source: R,
    own: Budget,
    shared: Vec<&'b mut Budget>,
    copy_buffer: usize,
    position: u64,
    latch: Latch,
}

impl<'b, R: Read> CountingReader<'b, R> {
    /// Returns a reader over `source` charging `own`, then each of `shared` in
    /// order, and requesting at most `copy_buffer` bytes at a time.
    pub(crate) fn new(
        source: R,
        own: ResourceLimit,
        shared: Vec<&'b mut Budget>,
        copy_buffer: usize,
    ) -> CountingReader<'b, R> {
        CountingReader {
            source,
            own: Budget::new(own),
            shared,
            // A zero copy buffer is refused by `ContentLimits`; clamping keeps
            // a zero-length request from ever reading as end of file.
            copy_buffer: copy_buffer.max(1),
            position: 0,
            latch: Latch::default(),
        }
    }

    fn chain(&self) -> impl Iterator<Item = &Budget> {
        std::iter::once(&self.own).chain(self.shared.iter().map(|budget| &**budget))
    }

    /// Returns how many bytes have been delivered.
    pub(crate) fn position(&self) -> u64 {
        self.position
    }

    /// Returns this reader's own per-item budget.
    pub(crate) fn own(&self) -> &Budget {
        &self.own
    }

    /// Returns the smallest remaining allowance across the chain.
    pub(crate) fn remaining(&self) -> u64 {
        self.chain().map(Budget::remaining).fold(u64::MAX, u64::min)
    }

    /// Checks that `n` more bytes would be within every allowance, without
    /// reading anything.
    ///
    /// # Errors
    ///
    /// Returns [`ContentFault::LimitExceeded`] for the first budget in chain
    /// order whose remaining allowance is below `n` — the same budget an
    /// actual read of `n` bytes would fault on.
    pub(crate) fn check_available(&self, n: u64) -> Result<(), ContentFault> {
        match self.chain().find(|budget| budget.check(n).is_err()) {
            Some(budget) => Err(budget.exceeded()),
            None => Ok(()),
        }
    }

    fn read_source(&mut self, buf: &mut [u8]) -> Result<usize, ContentFault> {
        loop {
            match self.source.read(buf) {
                Ok(n) => return Ok(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => return Err(ContentFault::from_io(err)),
            }
        }
    }

    fn read_counted(&mut self, buf: &mut [u8]) -> Result<usize, ContentFault> {
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.remaining();
        if remaining == 0 {
            let mut probe = [0u8; 1];
            if self.read_source(&mut probe)? == 0 {
                return Ok(0);
            }
            return Err(self
                .check_available(1)
                .err()
                .unwrap_or_else(|| self.own.exceeded()));
        }
        let len = chunk_len(buf.len().min(self.copy_buffer), remaining);
        let request = &mut buf[..len];
        let n = self.read_source(request)?;
        if n > len {
            return Err(ContentFault::Io(io::Error::new(
                ErrorKind::InvalidData,
                "the source reported more bytes than were requested",
            )));
        }
        let n_u64 = widen(n);
        self.check_available(n_u64)?;
        self.own.charge(n_u64)?;
        for budget in &mut self.shared {
            budget.charge(n_u64)?;
        }
        self.position = self.position.saturating_add(n_u64);
        Ok(n)
    }
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.latch.check().map_err(ContentFault::into_io)?;
        self.read_counted(buf)
            .map_err(|fault| self.latch.record(fault).into_io())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read};

    use crate::content::fixture::RecordingSource;
    use crate::content::{
        Budget, ContentFault, CountingReader, MalformedReason, ResourceLimit, alloc_len, charge_all,
    };
    use crate::package::LimitResource;

    fn limit(resource: LimitResource, max: u64) -> ResourceLimit {
        ResourceLimit { resource, max }
    }

    fn fault(result: std::io::Result<usize>) -> ContentFault {
        ContentFault::from_io(result.unwrap_err())
    }

    fn exceeded(resource: LimitResource, limit: u64) -> ContentFault {
        ContentFault::LimitExceeded { resource, limit }
    }

    #[test]
    fn a_large_first_read_delivers_the_allowance_then_faults_on_one_more_byte() {
        let (source, log) = RecordingSource::new(vec![7; 100]);
        let mut reader = CountingReader::new(
            source,
            limit(LimitResource::ConfigJson, 10),
            vec![],
            1 << 20,
        );
        let mut buf = [0u8; 4096];
        assert_eq!(reader.read(&mut buf).unwrap(), 10);
        assert_eq!(reader.own().used(), 10);
        assert_eq!(
            fault(reader.read(&mut buf)),
            exceeded(LimitResource::ConfigJson, 10)
        );
        let log = log.borrow();
        assert_eq!(log.delivered, 11);
        assert_eq!(log.requests, vec![10, 1]);
    }

    #[test]
    fn a_fault_is_terminal_and_the_source_is_not_read_again() {
        let (source, log) = RecordingSource::new(vec![7; 100]);
        let mut reader =
            CountingReader::new(source, limit(LimitResource::ConfigJson, 3), vec![], 1 << 20);
        let mut buf = [0u8; 16];
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        let first = fault(reader.read(&mut buf));
        assert_eq!(first, exceeded(LimitResource::ConfigJson, 3));
        assert_eq!(fault(reader.read(&mut buf)), first);
        assert_eq!(log.borrow().delivered, 4);
        assert_eq!(log.borrow().requests.len(), 2);
    }

    #[test]
    fn a_source_error_is_a_terminal_io_fault() {
        let (mut source, log) = RecordingSource::new(vec![7; 100]);
        source.fail_at(5, ErrorKind::ConnectionReset);
        let mut reader = CountingReader::new(
            source,
            limit(LimitResource::ConfigJson, 50),
            vec![],
            1 << 20,
        );
        let mut buf = [0u8; 5];
        assert_eq!(reader.read(&mut buf).unwrap(), 5);
        let first = fault(reader.read(&mut buf));
        assert!(
            matches!(&first, ContentFault::Io(err) if err.kind() == ErrorKind::ConnectionReset)
        );
        let requests = log.borrow().requests.len();
        let again = fault(reader.read(&mut buf));
        assert!(
            matches!(&again, ContentFault::Io(err) if err.kind() == ErrorKind::ConnectionReset)
        );
        assert_eq!(log.borrow().requests.len(), requests);
        assert_eq!(log.borrow().delivered, 5);
    }

    #[test]
    fn a_fault_from_a_stacked_primitive_passes_through_unchanged() {
        let inner_source = RecordingSource::new(vec![1; 10]).0;
        let inner = CountingReader::new(
            inner_source,
            limit(LimitResource::StoredLayerBlob, 4),
            vec![],
            64,
        );
        let mut outer =
            CountingReader::new(inner, limit(LimitResource::DecodedLayer, 100), vec![], 64);
        let mut buf = [0u8; 16];
        assert_eq!(outer.read(&mut buf).unwrap(), 4);
        assert_eq!(
            fault(outer.read(&mut buf)),
            exceeded(LimitResource::StoredLayerBlob, 4)
        );
        // Terminal in the outer reader too, and malformed faults travel alike.
        assert_eq!(
            fault(outer.read(&mut buf)),
            exceeded(LimitResource::StoredLayerBlob, 4)
        );
        let malformed = ContentFault::Malformed(MalformedReason::Truncated);
        let mut failing = CountingReader::new(
            FaultingSource(Some(malformed)),
            limit(LimitResource::DecodedLayer, 100),
            vec![],
            64,
        );
        assert_eq!(
            fault(failing.read(&mut buf)),
            ContentFault::Malformed(MalformedReason::Truncated)
        );
        assert_eq!(
            fault(failing.read(&mut buf)),
            ContentFault::Malformed(MalformedReason::Truncated)
        );
    }

    struct FaultingSource(Option<ContentFault>);

    impl Read for FaultingSource {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            match self.0.take() {
                Some(fault) => Err(fault.into_io()),
                None => Ok(1),
            }
        }
    }

    #[test]
    fn an_interrupted_source_is_retried() {
        let (mut source, log) = RecordingSource::new(vec![7; 20]);
        source.interrupt_at(0);
        source.interrupt_at(8);
        let mut reader =
            CountingReader::new(source, limit(LimitResource::ConfigJson, 20), vec![], 8);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, vec![7; 20]);
        assert_eq!(log.borrow().interrupts, 2);
    }

    #[test]
    fn the_advertised_length_is_never_consulted() {
        for (len, ok) in [(10, true), (11, false)] {
            let (mut source, log) = RecordingSource::new(vec![7; len]);
            source.advertise(1);
            let mut reader =
                CountingReader::new(source, limit(LimitResource::ConfigJson, 10), vec![], 64);
            let mut out = Vec::new();
            let result = reader.read_to_end(&mut out);
            if ok {
                assert_eq!(result.unwrap(), 10);
            } else {
                assert_eq!(fault(result), exceeded(LimitResource::ConfigJson, 10));
            }
            assert_eq!(out.len(), 10);
            assert_eq!(log.borrow().delivered, len);
        }
    }

    #[test]
    fn no_request_exceeds_the_copy_buffer() {
        let (source, log) = RecordingSource::new(vec![7; 100]);
        let mut reader =
            CountingReader::new(source, limit(LimitResource::ConfigJson, 1000), vec![], 7);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 100);
        assert!(log.borrow().requests.iter().all(|request| *request <= 7));
    }

    #[test]
    fn an_empty_buffer_does_not_touch_the_source() {
        let (source, log) = RecordingSource::new(vec![7; 100]);
        let mut reader =
            CountingReader::new(source, limit(LimitResource::ConfigJson, 0), vec![], 7);
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        assert!(log.borrow().requests.is_empty());
    }

    #[test]
    fn the_chain_reports_the_first_exhausted_budget_in_order() {
        let read_n = |image: u64, n: usize| {
            let mut per_image = Budget::new(limit(LimitResource::DecodedLayersPerImage, image));
            let mut per_op = Budget::new(limit(LimitResource::DecodedLayersPerOperation, 100));
            let (source, _) = RecordingSource::new(vec![1; 50]);
            let mut reader = CountingReader::new(
                source,
                limit(LimitResource::DecodedLayer, 10),
                vec![&mut per_image, &mut per_op],
                64,
            );
            let mut buf = vec![0u8; n];
            let mut delivered = 0;
            let result = loop {
                match reader.read(&mut buf[delivered..]) {
                    Ok(0) => break Ok(()),
                    Ok(read) => {
                        delivered += read;
                        if delivered == n {
                            break Ok(());
                        }
                    }
                    Err(err) => break Err(ContentFault::from_io(err)),
                }
            };
            (delivered, result)
        };
        let (delivered, result) = read_n(5, 7);
        assert_eq!(delivered, 5);
        assert_eq!(
            result.unwrap_err(),
            exceeded(LimitResource::DecodedLayersPerImage, 5)
        );
        let (delivered, result) = read_n(20, 12);
        assert_eq!(delivered, 10);
        assert_eq!(
            result.unwrap_err(),
            exceeded(LimitResource::DecodedLayer, 10)
        );

        let mut per_image = Budget::new(limit(LimitResource::DecodedLayersPerImage, 0));
        let mut per_op = Budget::new(limit(LimitResource::DecodedLayersPerOperation, 0));
        let (source, _) = RecordingSource::new(vec![1; 50]);
        let mut reader = CountingReader::new(
            source,
            limit(LimitResource::DecodedLayer, 0),
            vec![&mut per_image, &mut per_op],
            64,
        );
        assert_eq!(
            fault(reader.read(&mut [0u8; 4])),
            exceeded(LimitResource::DecodedLayer, 0)
        );
    }

    #[test]
    fn a_source_ending_exactly_at_the_limit_is_end_of_file() {
        let (source, log) = RecordingSource::new(vec![1; 10]);
        let mut reader =
            CountingReader::new(source, limit(LimitResource::ConfigJson, 10), vec![], 64);
        let mut out = Vec::new();
        assert_eq!(reader.read_to_end(&mut out).unwrap(), 10);
        assert_eq!(log.borrow().delivered, 10);
    }

    #[test]
    fn check_available_names_what_a_read_would() {
        let mut per_image = Budget::new(limit(LimitResource::DecodedLayersPerImage, 8));
        let (source, _) = RecordingSource::new(vec![1; 50]);
        let mut reader = CountingReader::new(
            source,
            limit(LimitResource::DecodedLayer, 10),
            vec![&mut per_image],
            64,
        );
        assert!(reader.check_available(8).is_ok());
        let predicted = reader.check_available(9).unwrap_err();
        assert_eq!(predicted, exceeded(LimitResource::DecodedLayersPerImage, 8));
        let mut buf = [0u8; 9];
        assert_eq!(reader.read(&mut buf).unwrap(), 8);
        assert_eq!(fault(reader.read(&mut buf)), predicted);
        assert_eq!(reader.position(), 8);
    }

    #[test]
    fn a_failed_charge_all_charges_nothing() {
        let mut item = Budget::new(limit(LimitResource::LayerExtension, 10));
        let mut image = Budget::new(limit(LimitResource::LayerExtensionTotal, 5));
        charge_all(&mut [&mut item, &mut image], 3).unwrap();
        assert_eq!(
            charge_all(&mut [&mut item, &mut image], 3).unwrap_err(),
            exceeded(LimitResource::LayerExtensionTotal, 5)
        );
        assert_eq!((item.used(), image.used()), (3, 3));
        assert_eq!(
            charge_all(&mut [&mut item, &mut image], u64::MAX).unwrap_err(),
            exceeded(LimitResource::LayerExtension, 10)
        );
        assert_eq!((item.used(), image.used()), (3, 3));
        let mut unbounded = Budget::new(limit(LimitResource::LayerExtension, u64::MAX));
        unbounded.charge(1).unwrap();
        assert_eq!(
            unbounded.charge(u64::MAX).unwrap_err(),
            exceeded(LimitResource::LayerExtension, u64::MAX)
        );
        assert_eq!(unbounded.used(), 1);
    }

    #[test]
    fn simultaneous_limits_report_the_narrowest_scope() {
        let mut item = Budget::new(limit(LimitResource::DecodedLayer, 4));
        let mut image = Budget::new(limit(LimitResource::DecodedLayersPerImage, 4));
        let mut operation = Budget::new(limit(LimitResource::DecodedLayersPerOperation, 4));
        assert_eq!(
            charge_all(&mut [&mut item, &mut image, &mut operation], 5).unwrap_err(),
            exceeded(LimitResource::DecodedLayer, 4)
        );
        let mut item = Budget::new(limit(LimitResource::DecodedLayer, 10));
        assert_eq!(
            charge_all(&mut [&mut item, &mut image, &mut operation], 5).unwrap_err(),
            exceeded(LimitResource::DecodedLayersPerImage, 4)
        );
        let mut image = Budget::new(limit(LimitResource::DecodedLayersPerImage, 10));
        assert_eq!(
            charge_all(&mut [&mut item, &mut image, &mut operation], 5).unwrap_err(),
            exceeded(LimitResource::DecodedLayersPerOperation, 4)
        );
    }

    #[test]
    fn alloc_len_holds_a_value_to_its_limit() {
        let config = limit(LimitResource::ConfigJson, 4096);
        assert_eq!(alloc_len(4096, config).unwrap(), 4096);
        assert_eq!(
            alloc_len(4097, config).unwrap_err(),
            exceeded(LimitResource::ConfigJson, 4096)
        );
        assert_eq!(
            alloc_len(u64::MAX, config).unwrap_err(),
            exceeded(LimitResource::ConfigJson, 4096)
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn alloc_len_refuses_a_value_beyond_usize() {
        let wide = limit(LimitResource::StoredLayerBlob, u64::MAX);
        assert_eq!(
            alloc_len(u64::from(u32::MAX) + 1, wide).unwrap_err(),
            exceeded(LimitResource::StoredLayerBlob, u64::MAX)
        );
    }
}
