//! A strict, bounded JSON reader: a byte limit on the document, a limit on its
//! nesting, and refusal of duplicate object keys, all before `serde_json`
//! deserializes it.
//!
//! `serde_json` keeps the last of two equal keys without a word, even inside a
//! `deny_unknown_fields` struct, and recurses once per nesting level. A single
//! iterative scan over the document first applies the RFC 8259 grammar,
//! refuses a key repeated within one object and bounds the depth, so the
//! deserializer only ever sees a document all three already hold for.

use std::collections::HashSet;
use std::io::{self, Read};

use serde::de::DeserializeOwned;

use super::{
    Budget, ContentFault, CountingReader, MalformedReason, ResourceLimit, chunk_len, widen,
};

/// Reads a whole JSON document from `source`, charging it to a fresh
/// `document` budget and then to `total`.
///
/// `source` is read only through a [`CountingReader`], so source errors,
/// retries, request sizes and the first-excess-byte rule are exactly that
/// reader's. Each step reserves at most `k` more bytes — the copy buffer or the
/// remaining allowance, whichever is smaller, or one byte for the probe once
/// the allowance is spent — before reading once into them, and keeps only what
/// the read returned. Budgets are charged only for bytes kept.
///
/// # Errors
///
/// - [`ContentFault::LimitExceeded`] for `document` when the document is
///   longer than it, or for `total`'s resource at the first byte beyond that;
///   the document wins when both are reached at the same byte.
/// - [`ContentFault::Io`] when the source fails, or with
///   [`io::ErrorKind::OutOfMemory`] when a reservation cannot be made.
pub(crate) fn read_bounded<R: Read>(
    source: R,
    document: ResourceLimit,
    total: &mut Budget,
    copy_buffer: usize,
) -> Result<Vec<u8>, ContentFault> {
    let copy_buffer = copy_buffer.max(1);
    let mut reader = CountingReader::new(source, document, vec![total], copy_buffer);
    let mut bytes = Vec::new();
    loop {
        let remaining = reader.remaining();
        let k = if remaining == 0 {
            1
        } else {
            chunk_len(copy_buffer, remaining)
        };
        let accepted = bytes.len();
        bytes
            .try_reserve_exact(k)
            .map_err(|_| ContentFault::Io(io::Error::from(io::ErrorKind::OutOfMemory)))?;
        // The reservation above succeeded, so the new length is representable.
        bytes.resize(accepted + k, 0);
        #[cfg(test)]
        seam::record_reservation(accepted, k, bytes.len());
        let n = reader
            .read(&mut bytes[accepted..])
            .map_err(ContentFault::from_io)?;
        bytes.truncate(accepted + n);
        #[cfg(test)]
        seam::record_read(bytes.len());
        if n == 0 {
            return Ok(bytes);
        }
    }
}

/// Parses `bytes` as a `T`, after checking the document limit and scanning the
/// whole document for syntax, depth and duplicate keys.
///
/// A scalar root is at depth 0 and each array or object adds one level as it
/// opens, so the root container is at depth 1 and a `depth.max` of 64 admits
/// 64 nested containers.
///
/// # Errors
///
/// - [`ContentFault::LimitExceeded`] for `document` when `bytes` is longer
///   than it, before any scanning.
/// - The first scan fault in byte order: [`MalformedReason::JsonSyntax`],
///   [`ContentFault::LimitExceeded`] for `depth`, or
///   [`MalformedReason::JsonDuplicateKey`].
/// - [`MalformedReason::JsonShape`] when `serde_json` cannot deserialize a `T`.
pub(crate) fn parse<T: DeserializeOwned>(
    bytes: &[u8],
    document: ResourceLimit,
    depth: ResourceLimit,
) -> Result<T, ContentFault> {
    if widen(bytes.len()) > document.max {
        return Err(document.exceeded());
    }
    scan(bytes, depth)?;
    serde_json::from_slice(bytes).map_err(|_| ContentFault::Malformed(MalformedReason::JsonShape))
}

/// The most state one scan held at once, reported so a test can show it stays
/// proportional to the document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Footprint {
    /// The most containers open at once.
    pub(crate) containers: usize,
    /// The most decoded key bytes held at once across every open object.
    pub(crate) key_bytes: usize,
}

/// Scans `bytes` once, left to right and without recursion, reporting the
/// first syntax, depth or duplicate-key fault in byte order.
pub(crate) fn scan(bytes: &[u8], depth: ResourceLimit) -> Result<Footprint, ContentFault> {
    let mut scanner = Scanner {
        bytes,
        pos: 0,
        depth,
        stack: Vec::new(),
        key_bytes: 0,
        footprint: Footprint::default(),
    };
    scanner.run()?;
    Ok(scanner.footprint)
}

enum Frame {
    Array,
    /// An open object and the decoded keys seen in it so far.
    Object(HashSet<String>),
}

struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: ResourceLimit,
    stack: Vec<Frame>,
    key_bytes: usize,
    footprint: Footprint,
}

fn syntax() -> ContentFault {
    ContentFault::Malformed(MalformedReason::JsonSyntax)
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn run(&mut self) -> Result<(), ContentFault> {
        'value: loop {
            self.skip_whitespace();
            match self.peek() {
                Some(b'{') => {
                    self.open(Frame::Object(HashSet::new()))?;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        self.close();
                    } else {
                        self.key()?;
                        continue 'value;
                    }
                }
                Some(b'[') => {
                    self.open(Frame::Array)?;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        self.close();
                    } else {
                        continue 'value;
                    }
                }
                Some(b'"') => {
                    self.string(false)?;
                }
                Some(b't') => self.literal(b"true")?,
                Some(b'f') => self.literal(b"false")?,
                Some(b'n') => self.literal(b"null")?,
                Some(b'-' | b'0'..=b'9') => self.number()?,
                _ => return Err(syntax()),
            }
            // A value is complete; close every container it completes.
            loop {
                self.skip_whitespace();
                match self.stack.last() {
                    None if self.pos == self.bytes.len() => return Ok(()),
                    None => return Err(syntax()),
                    Some(Frame::Array) => match self.next_byte() {
                        Some(b',') => continue 'value,
                        Some(b']') => self.close(),
                        _ => return Err(syntax()),
                    },
                    Some(Frame::Object(_)) => match self.next_byte() {
                        Some(b',') => {
                            self.skip_whitespace();
                            self.key()?;
                            continue 'value;
                        }
                        Some(b'}') => self.close(),
                        _ => return Err(syntax()),
                    },
                }
            }
        }
    }

    fn open(&mut self, frame: Frame) -> Result<(), ContentFault> {
        if widen(self.stack.len()).saturating_add(1) > self.depth.max {
            return Err(self.depth.exceeded());
        }
        self.pos += 1;
        self.stack.push(frame);
        self.footprint.containers = self.footprint.containers.max(self.stack.len());
        Ok(())
    }

    fn close(&mut self) {
        if let Some(Frame::Object(keys)) = self.stack.pop() {
            let held: usize = keys.iter().map(String::len).sum();
            self.key_bytes = self.key_bytes.saturating_sub(held);
        }
    }

    /// Reads one object key and the colon after it, refusing a key the
    /// innermost object already has.
    fn key(&mut self) -> Result<(), ContentFault> {
        if self.peek() != Some(b'"') {
            return Err(syntax());
        }
        let key = self.string(true)?.ok_or_else(syntax)?;
        let len = key.len();
        let Some(Frame::Object(keys)) = self.stack.last_mut() else {
            return Err(syntax());
        };
        if !keys.insert(key) {
            return Err(ContentFault::Malformed(MalformedReason::JsonDuplicateKey));
        }
        self.key_bytes = self.key_bytes.saturating_add(len);
        self.footprint.key_bytes = self.footprint.key_bytes.max(self.key_bytes);
        self.skip_whitespace();
        if self.next_byte() != Some(b':') {
            return Err(syntax());
        }
        Ok(())
    }

    /// Reads a string starting at its opening quote, validating its escapes
    /// and its UTF-8, and returns it decoded when `decode` is set.
    fn string(&mut self, decode: bool) -> Result<Option<String>, ContentFault> {
        self.pos += 1;
        let start = self.pos;
        let mut decoded = decode.then(Vec::new);
        loop {
            match self.next_byte().ok_or_else(syntax)? {
                b'"' => break,
                b'\\' => {
                    let ch = self.escape()?;
                    if let Some(decoded) = decoded.as_mut() {
                        let mut utf8 = [0u8; 4];
                        decoded.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
                    }
                }
                0x00..=0x1f => return Err(syntax()),
                byte => {
                    if let Some(decoded) = decoded.as_mut() {
                        decoded.push(byte);
                    }
                }
            }
        }
        // Escapes are ASCII, so the raw string is UTF-8 exactly when every
        // byte outside them is.
        let raw = self.bytes.get(start..self.pos - 1).ok_or_else(syntax)?;
        std::str::from_utf8(raw).map_err(|_| syntax())?;
        decoded
            .map(|decoded| String::from_utf8(decoded).map_err(|_| syntax()))
            .transpose()
    }

    /// Reads the escape after a backslash and returns the character it names.
    /// A `\u` surrogate must pair with the one after it; a lone one names no
    /// character and is refused.
    fn escape(&mut self) -> Result<char, ContentFault> {
        Ok(match self.next_byte().ok_or_else(syntax)? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex4()?;
                let scalar = match unit {
                    0xd800..=0xdbff => {
                        if self.next_byte() != Some(b'\\') || self.next_byte() != Some(b'u') {
                            return Err(syntax());
                        }
                        let low = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(syntax());
                        }
                        0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
                    }
                    0xdc00..=0xdfff => return Err(syntax()),
                    _ => unit,
                };
                char::from_u32(scalar).ok_or_else(syntax)?
            }
            _ => return Err(syntax()),
        })
    }

    fn hex4(&mut self) -> Result<u32, ContentFault> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = char::from(self.next_byte().ok_or_else(syntax)?)
                .to_digit(16)
                .ok_or_else(syntax)?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), ContentFault> {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        if !rest.starts_with(word) {
            return Err(syntax());
        }
        self.pos += word.len();
        Ok(())
    }

    /// Reads `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
    fn number(&mut self) -> Result<(), ContentFault> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.next_byte() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(syntax()),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.required_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.required_digits()?;
        }
        Ok(())
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.pos += 1;
        }
    }

    fn required_digits(&mut self) -> Result<(), ContentFault> {
        if !self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            return Err(syntax());
        }
        self.digits();
        Ok(())
    }
}

/// A test-only record of every reservation [`read_bounded`] makes and of the
/// vector's length after each step.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::RefCell;

    /// One step of [`super::read_bounded`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Step {
        /// Bytes accepted before the step.
        pub(crate) accepted: usize,
        /// Bytes the step reserved and initialized: its `k`.
        pub(crate) requested: usize,
        /// The vector's length once initialized for the read.
        pub(crate) initialized: usize,
        /// The vector's length after the read, once truncated.
        pub(crate) after_read: Option<usize>,
    }

    thread_local! {
        static STEPS: RefCell<Option<Vec<Step>>> = const { RefCell::new(None) };
    }

    /// Starts recording on this thread.
    pub(crate) fn start() {
        STEPS.with(|steps| *steps.borrow_mut() = Some(Vec::new()));
    }

    /// Stops recording on this thread and returns what was recorded.
    pub(crate) fn take() -> Vec<Step> {
        STEPS.with(|steps| steps.borrow_mut().take().unwrap_or_default())
    }

    pub(super) fn record_reservation(accepted: usize, requested: usize, initialized: usize) {
        STEPS.with(|steps| {
            if let Some(steps) = steps.borrow_mut().as_mut() {
                steps.push(Step {
                    accepted,
                    requested,
                    initialized,
                    after_read: None,
                });
            }
        });
    }

    pub(super) fn record_read(len: usize) {
        STEPS.with(|steps| {
            if let Some(step) = steps
                .borrow_mut()
                .as_mut()
                .and_then(|steps| steps.last_mut())
            {
                step.after_read = Some(len);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::ErrorKind;

    use serde::Deserialize;

    use super::{parse, read_bounded, scan, seam};
    use crate::content::fixture::RecordingSource;
    use crate::content::{Budget, ContentFault, MalformedReason, ResourceLimit};
    use crate::package::{ContentLimits, LimitResource};

    fn limit(resource: LimitResource, max: u64) -> ResourceLimit {
        ResourceLimit { resource, max }
    }

    fn exceeded(resource: LimitResource, limit: u64) -> ContentFault {
        ContentFault::LimitExceeded { resource, limit }
    }

    fn malformed(reason: MalformedReason) -> ContentFault {
        ContentFault::Malformed(reason)
    }

    const DOCUMENT: ResourceLimit = ResourceLimit {
        resource: LimitResource::IndexJson,
        max: 1 << 20,
    };
    const DEPTH: ResourceLimit = ResourceLimit {
        resource: LimitResource::JsonDepth,
        max: 64,
    };

    fn value(text: &str) -> Result<serde_json::Value, ContentFault> {
        parse(text.as_bytes(), DOCUMENT, DEPTH)
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Closed {
        a: u32,
        #[serde(default)]
        rest: Option<serde_json::Value>,
    }

    #[test]
    fn duplicate_keys_are_refused_wherever_they_are() {
        for text in [
            r#"{"a":1,"a":2}"#,
            r#"{"x":{"b":1,"b":1}}"#,
            r#"[1,{"c":true,"c":false}]"#,
            r#"{"a":1,"\u0061":2}"#,
            r#"{"😀":1,"😀":2}"#,
            r#"{"😀":1,"\uD83D\uDE00":2}"#,
        ] {
            assert_eq!(
                value(text).unwrap_err(),
                malformed(MalformedReason::JsonDuplicateKey),
                "{text}"
            );
        }
        // Equal keys in different objects are not duplicates.
        assert!(value(r#"{"a":{"a":1},"b":{"a":2}}"#).is_ok());
    }

    #[test]
    fn the_root_container_is_at_depth_one() {
        let one = limit(LimitResource::JsonDepth, 1);
        for text in ["1", "\"s\"", "[]", r#"{"a":1}"#] {
            assert!(parse::<serde_json::Value>(text.as_bytes(), DOCUMENT, one).is_ok());
        }
        assert_eq!(
            parse::<serde_json::Value>(b"[[]]", DOCUMENT, one).unwrap_err(),
            exceeded(LimitResource::JsonDepth, 1)
        );
        let default = ContentLimits::default().resource_limit(LimitResource::JsonDepth);
        let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse::<serde_json::Value>(nested(64).as_bytes(), DOCUMENT, default).is_ok());
        assert_eq!(
            parse::<serde_json::Value>(nested(65).as_bytes(), DOCUMENT, default).unwrap_err(),
            exceeded(LimitResource::JsonDepth, 64)
        );
    }

    #[test]
    fn syntax_errors_are_refused() {
        for text in [
            &b""[..],
            b"   ",
            b"\"\xff\"",
            b"{\"\xc3\x28\":1}",
            br#""\x""#,
            br#""\ud800""#,
            br#""\udc00x""#,
            b"{} x",
            b"[1,]",
            b"{\"a\":1,}",
            b"01",
            b"1.",
            b"-",
            b"tru",
            b"\"a\nb\"",
            b"{\"a\" 1}",
            b"[1 2]",
            b"\xef\xbb\xbf{}",
        ] {
            assert_eq!(
                parse::<serde_json::Value>(text, DOCUMENT, DEPTH).unwrap_err(),
                malformed(MalformedReason::JsonSyntax),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        for text in [
            "0",
            "-0.5e+10",
            "1E3",
            r#""\/\b\f\n\r\t\"\\é""#,
            " [ true , false , null ] ",
        ] {
            assert!(value(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn shapes_are_checked_after_the_scan() {
        assert_eq!(
            parse::<Closed>(br#"{"a":1}"#, DOCUMENT, DEPTH).unwrap(),
            Closed { a: 1, rest: None }
        );
        assert_eq!(
            parse::<Closed>(br#"{"a":1,"b":2}"#, DOCUMENT, DEPTH).unwrap_err(),
            malformed(MalformedReason::JsonShape)
        );
        assert_eq!(
            parse::<Closed>(br#"{"a":1,"rest":{"k":1,"k":2}}"#, DOCUMENT, DEPTH).unwrap_err(),
            malformed(MalformedReason::JsonDuplicateKey)
        );
        assert_eq!(
            parse::<BTreeMap<String, u8>>(br#"{"k":1,"k":2}"#, DOCUMENT, DEPTH).unwrap_err(),
            malformed(MalformedReason::JsonDuplicateKey)
        );
    }

    #[test]
    fn the_document_limit_is_checked_before_scanning() {
        let text = br#"{"key":"value"}"#;
        let len = u64::try_from(text.len()).unwrap();
        let config = limit(LimitResource::ConfigJson, len);
        assert!(parse::<serde_json::Value>(text, config, DEPTH).is_ok());
        let config = limit(LimitResource::ConfigJson, len - 1);
        assert_eq!(
            parse::<serde_json::Value>(text, config, DEPTH).unwrap_err(),
            exceeded(LimitResource::ConfigJson, len - 1)
        );
        // Oversize and malformed: the limit, since no scan runs.
        assert_eq!(
            parse::<serde_json::Value>(b"{{{{", limit(LimitResource::ConfigJson, 3), DEPTH)
                .unwrap_err(),
            exceeded(LimitResource::ConfigJson, 3)
        );
    }

    #[test]
    fn the_first_fault_in_byte_order_wins() {
        assert_eq!(
            value(r#"{"a":1,"a":2,}"#).unwrap_err(),
            malformed(MalformedReason::JsonDuplicateKey)
        );
        let one = limit(LimitResource::JsonDepth, 1);
        assert_eq!(
            parse::<serde_json::Value>(br#"[[{"a":1,"a":1}]]"#, DOCUMENT, one).unwrap_err(),
            exceeded(LimitResource::JsonDepth, 1)
        );
        assert_eq!(
            value(r#"{"a":1,"b":2 "a":3}"#).unwrap_err(),
            malformed(MalformedReason::JsonSyntax)
        );
    }

    #[test]
    fn the_scanner_holds_state_proportional_to_the_document() {
        let text = format!("{}1{}", r#"{"k":"#.repeat(40), "}".repeat(40));
        let footprint = scan(text.as_bytes(), DEPTH).unwrap();
        assert_eq!(footprint.containers, 40);
        assert_eq!(footprint.key_bytes, 40);
        let wide = format!(
            "{{{}}}",
            (0..1000)
                .map(|n| format!("\"key{n}\":{n}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let footprint = scan(wide.as_bytes(), DEPTH).unwrap();
        assert_eq!(footprint.containers, 1);
        assert!(footprint.key_bytes < wide.len());
    }

    fn read(
        data: &[u8],
        document: ResourceLimit,
        total: &mut Budget,
        copy_buffer: usize,
    ) -> (Result<Vec<u8>, ContentFault>, usize, Vec<usize>) {
        let (mut source, log) = RecordingSource::new(data.to_vec());
        let result = read_bounded(&mut source, document, total, copy_buffer);
        let log = log.borrow();
        (result, log.delivered, log.requests.clone())
    }

    #[test]
    fn documents_are_reported_under_their_own_resource() {
        let data = br#"{"schemaVersion":2}"#;
        let len = u64::try_from(data.len()).unwrap();
        for resource in [LimitResource::IndexJson, LimitResource::ConfigJson] {
            let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 1 << 20));
            let (result, delivered, _) = read(data, limit(resource, len - 1), &mut total, 64);
            assert_eq!(result.unwrap_err(), exceeded(resource, len - 1));
            assert_eq!(delivered, data.len());
            assert_eq!(total.used(), len - 1);
        }
    }

    #[test]
    fn an_exhausted_total_is_reported_at_the_first_byte_beyond_it() {
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 10));
        total.charge(9).unwrap();
        let (result, delivered, _) = read(b"{}", DOCUMENT, &mut total, 64);
        assert_eq!(
            result.unwrap_err(),
            exceeded(LimitResource::ImageJsonTotal, 10)
        );
        assert_eq!(delivered, 2);
        assert_eq!(total.used(), 10);
    }

    #[test]
    fn the_document_wins_when_both_limits_are_reached_at_the_same_byte() {
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 4));
        let (result, _, _) = read(b"[1,2]", limit(LimitResource::IndexJson, 4), &mut total, 64);
        assert_eq!(result.unwrap_err(), exceeded(LimitResource::IndexJson, 4));
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 3));
        let (result, _, _) = read(b"[1,2]", limit(LimitResource::IndexJson, 4), &mut total, 64);
        assert_eq!(
            result.unwrap_err(),
            exceeded(LimitResource::ImageJsonTotal, 3)
        );
    }

    #[test]
    fn a_successful_read_charges_exactly_what_it_returns() {
        let data = br#"{"layers":["a","b","c"]}"#;
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 1000));
        total.charge(100).unwrap();
        let (result, _, requests) = read(data, DOCUMENT, &mut total, 7);
        assert_eq!(result.unwrap(), data);
        assert_eq!(total.used(), 100 + u64::try_from(data.len()).unwrap());
        assert!(requests.iter().all(|request| *request <= 7));
    }

    #[test]
    fn source_errors_and_interruptions() {
        let (mut source, _) = RecordingSource::new(b"[1,2,3]".to_vec());
        source.interrupt_at(0);
        source.interrupt_at(3);
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 100));
        assert_eq!(
            read_bounded(&mut source, DOCUMENT, &mut total, 2).unwrap(),
            b"[1,2,3]"
        );
        let (mut source, _) = RecordingSource::new(b"[1,2,3]".to_vec());
        source.fail_at(4, ErrorKind::TimedOut);
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 100));
        let fault = read_bounded(&mut source, DOCUMENT, &mut total, 64).unwrap_err();
        assert!(matches!(&fault, ContentFault::Io(err) if err.kind() == ErrorKind::TimedOut));
        assert_eq!(total.used(), 4);
    }

    #[test]
    fn reservations_never_exceed_k() {
        let data = br#"{"config":{"digest":"sha256:0123456789"}}"#;
        let document = limit(LimitResource::ConfigJson, 30);
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 1000));
        seam::start();
        let (result, _, _) = read(data, document, &mut total, 8);
        let steps = seam::take();
        assert_eq!(result.unwrap_err(), exceeded(LimitResource::ConfigJson, 30));
        assert!(!steps.is_empty());
        for step in &steps {
            let remaining = 30 - step.accepted;
            let k = if remaining == 0 { 1 } else { remaining.min(8) };
            assert_eq!(step.requested, k, "{step:?}");
            assert_eq!(step.initialized, step.accepted + k, "{step:?}");
            if let Some(after) = step.after_read {
                assert!(after <= step.accepted + k, "{step:?}");
            }
        }
        // The last step is the probe, which read nothing into the vector.
        assert_eq!(steps.last().unwrap().requested, 1);
        assert_eq!(steps.last().unwrap().after_read, None);
    }

    #[test]
    fn a_small_copy_buffer_reads_and_parses_identically() {
        let data = br#"{"schemaVersion":2,"manifests":[{"digest":"sha256:ab","size":7}]}"#;
        let mut outcomes = Vec::new();
        for copy_buffer in [ContentLimits::default().copy_buffer_len(), 7] {
            let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, 1 << 20));
            let (result, _, requests) = read(data, DOCUMENT, &mut total, copy_buffer);
            assert!(requests.iter().all(|request| *request <= copy_buffer));
            let bytes = result.unwrap();
            outcomes.push((
                parse::<serde_json::Value>(&bytes, DOCUMENT, DEPTH).unwrap(),
                bytes,
                total.used(),
            ));
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }

    #[test]
    fn an_unbounded_document_needs_no_overflow_handling() {
        let mut total = Budget::new(limit(LimitResource::ImageJsonTotal, u64::MAX));
        let (result, _, _) = read(
            b"{}",
            limit(LimitResource::IndexJson, u64::MAX),
            &mut total,
            64,
        );
        assert_eq!(result.unwrap(), b"{}");
    }
}
