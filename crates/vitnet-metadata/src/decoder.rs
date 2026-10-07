use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read};
use std::ops::Range;
use vitnet_core::Diagnostic;

pub const HEADER: &[u8] = b"Handle, Kind, Name, Children";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawRecord {
    pub handle: u32,
    pub kind: Vec<u8>,
    pub name: Vec<u8>,
    pub children: Vec<u32>,
    pub byte_range: Range<usize>,
    pub logical_record: u64,
    pub physical_line_start: u64,
    pub physical_line_end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataError {
    pub diagnostic: Box<Diagnostic>,
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}

impl std::error::Error for MetadataError {}

pub struct StreamingDecoder<R: Read> {
    reader: BufReader<R>,
    strict: bool,
    initialized: bool,
    done: bool,
    byte_offset: usize,
    physical_line: u64,
    logical_record: u64,
    max_record_bytes: usize,
}

impl<R: Read> StreamingDecoder<R> {
    #[must_use]
    pub fn new(reader: R, buffer_capacity: usize, strict: bool) -> Self {
        Self {
            reader: BufReader::with_capacity(buffer_capacity.max(1), reader),
            strict,
            initialized: false,
            done: false,
            byte_offset: 0,
            physical_line: 1,
            logical_record: 0,
            max_record_bytes: 64 * 1024 * 1024,
        }
    }

    #[must_use]
    pub fn with_record_limit(mut self, max_record_bytes: usize) -> Self {
        self.max_record_bytes = max_record_bytes.max(1);
        self
    }

    fn read_byte(&mut self) -> Result<Option<u8>, MetadataError> {
        let buffer = match self.reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) => {
                return Err(MetadataError {
                    diagnostic: Box::new(
                        Diagnostic::malformed(
                            "metadata.io",
                            format!("failed to read metadata input: {error}"),
                        )
                        .at(
                            self.byte_offset as u64,
                            self.logical_record,
                            self.physical_line,
                        ),
                    ),
                });
            }
        };
        let byte = buffer.first().copied();
        if byte.is_some() {
            self.reader.consume(1);
            self.byte_offset += 1;
        }
        Ok(byte)
    }

    fn error(&self, code: &str, message: impl Into<String>) -> MetadataError {
        MetadataError {
            diagnostic: Box::new(Diagnostic::malformed(code, message).at(
                self.byte_offset as u64,
                self.logical_record,
                self.physical_line,
            )),
        }
    }

    fn initialize(&mut self) -> Result<(), MetadataError> {
        let mut header = Vec::with_capacity(HEADER.len());
        loop {
            match self.read_byte()? {
                Some(b'\n') => {
                    self.physical_line += 1;
                    break;
                }
                Some(b'\r') => {
                    if self.read_byte()? != Some(b'\n') {
                        return Err(self.error(
                            "metadata.csv.header",
                            "carriage return in header is not followed by line feed",
                        ));
                    }
                    self.physical_line += 1;
                    break;
                }
                Some(byte) => header.push(byte),
                None => {
                    return Err(self.error(
                        "metadata.csv.header",
                        "input ended before the metadata header",
                    ));
                }
            }
        }
        if header != HEADER {
            let mut diagnostic =
                self.error("metadata.csv.header", "metadata header does not match");
            diagnostic.diagnostic.expected = Some(String::from_utf8_lossy(HEADER).into_owned());
            diagnostic.diagnostic.actual = Some(String::from_utf8_lossy(&header).into_owned());
            return Err(diagnostic);
        }
        self.initialized = true;
        Ok(())
    }

    fn next_record(&mut self) -> Result<Option<RawRecord>, MetadataError> {
        if !self.initialized {
            self.initialize()?;
        }
        if self.done {
            return Ok(None);
        }

        let start = self.byte_offset;
        let start_line = self.physical_line;
        let mut bytes = Vec::new();

        loop {
            let Some(byte) = self.read_byte()? else {
                self.done = true;
                if bytes.is_empty() {
                    return Ok(None);
                }
                if !record_structure_complete(&bytes) {
                    return Err(self.error(
                        "metadata.csv.quote",
                        "input ended before a complete quoted children field",
                    ));
                }
                break;
            };
            if bytes.len() >= self.max_record_bytes {
                let mut error = self.error(
                    "resource.record_limit",
                    "logical CSV record exceeded the configured decoder limit",
                );
                error.diagnostic.expected =
                    Some(format!("at most {} bytes", self.max_record_bytes));
                error.diagnostic.actual = Some(format!("more than {} bytes", bytes.len()));
                error.diagnostic.guidance =
                    Some("increase --memory-limit for unusually large metadata names".into());
                return Err(error);
            }

            if byte == b'\n' {
                self.physical_line += 1;
                let without_cr = bytes.last().is_some_and(|value| *value == b'\r');
                let candidate = if without_cr {
                    &bytes[..bytes.len() - 1]
                } else {
                    &bytes
                };
                if record_structure_complete(candidate) {
                    if without_cr {
                        bytes.pop();
                    }
                    break;
                }
                bytes.push(byte);
            } else {
                bytes.push(byte);
            }
        }

        self.logical_record += 1;
        parse_record(
            &bytes,
            start..self.byte_offset,
            self.logical_record,
            start_line,
            self.physical_line,
            self.strict,
        )
        .map(Some)
    }
}

impl<R: Read> Iterator for StreamingDecoder<R> {
    type Item = Result<RawRecord, MetadataError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

fn parse_record(
    bytes: &[u8],
    byte_range: Range<usize>,
    logical_record: u64,
    physical_line_start: u64,
    physical_line_end: u64,
    strict: bool,
) -> Result<RawRecord, MetadataError> {
    let fields = split_fields(bytes).map_err(|message| MetadataError {
        diagnostic: Box::new(Diagnostic::malformed("metadata.csv.record", message).at(
            byte_range.start as u64,
            logical_record,
            physical_line_start,
        )),
    })?;
    let handle = parse_handle(trim_ascii(fields[0])).map_err(|actual| MetadataError {
        diagnostic: Box::new({
            let mut diagnostic = Diagnostic::malformed(
                "metadata.csv.handle",
                "invalid metadata handle",
            )
            .at(byte_range.start as u64, logical_record, physical_line_start);
            diagnostic.expected = Some("u32 producer hexadecimal handle".into());
            diagnostic.actual = Some(actual);
            diagnostic
        }),
    })?;
    let kind = trim_ascii(fields[1]).to_vec();
    let name = unescape_field(trim_ascii(fields[2]), strict).map_err(|message| MetadataError {
        diagnostic: Box::new(Diagnostic::malformed("metadata.csv.name", message).at(
            byte_range.start as u64,
            logical_record,
            physical_line_start,
        )),
    })?;
    let children_field =
        unescape_field(trim_ascii(fields[3]), strict).map_err(|message| MetadataError {
            diagnostic: Box::new(Diagnostic::malformed("metadata.csv.children", message).at(
                byte_range.start as u64,
                logical_record,
                physical_line_start,
            )),
        })?;
    let children =
        children_field
            .split(u8::is_ascii_whitespace)
            .filter(|value| !value.is_empty())
            .map(|value| {
                parse_handle(value).map_err(|actual| MetadataError {
                    diagnostic: Box::new({
                        let mut diagnostic =
                            Diagnostic::malformed("metadata.csv.children", "invalid child handle")
                                .at(byte_range.start as u64, logical_record, physical_line_start);
                        diagnostic.actual = Some(actual);
                        diagnostic
                    }),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

    Ok(RawRecord {
        handle,
        kind,
        name,
        children,
        byte_range,
        logical_record,
        physical_line_start,
        physical_line_end,
    })
}

fn split_fields(bytes: &[u8]) -> Result<[&[u8]; 4], String> {
    let first = bytes
        .iter()
        .position(|byte| *byte == b',')
        .ok_or_else(|| "missing handle delimiter".to_owned())?;
    let second_relative = bytes[first + 1..]
        .iter()
        .position(|byte| *byte == b',')
        .ok_or_else(|| "missing kind delimiter".to_owned())?;
    let second = first + 1 + second_relative;

    for delimiter in (second + 1..bytes.len())
        .rev()
        .filter(|index| bytes[*index] == b',')
    {
        let children = trim_ascii(&bytes[delimiter + 1..]);
        if valid_children_field(children) {
            return Ok([
                &bytes[..first],
                &bytes[first + 1..second],
                &bytes[second + 1..delimiter],
                &bytes[delimiter + 1..],
            ]);
        }
    }
    Err("missing final quoted children field".into())
}

fn record_structure_complete(bytes: &[u8]) -> bool {
    split_fields(bytes).is_ok()
}

fn valid_children_field(field: &[u8]) -> bool {
    let Some(inner) = field
        .strip_prefix(b"\"")
        .and_then(|value| value.strip_suffix(b"\""))
    else {
        return false;
    };
    inner
        .split(u8::is_ascii_whitespace)
        .filter(|value| !value.is_empty())
        .all(|value| parse_handle(value).is_ok())
}

fn unescape_field(field: &[u8], strict: bool) -> Result<Vec<u8>, String> {
    if !field.starts_with(b"\"") {
        return Ok(field.to_vec());
    }
    if !field.ends_with(b"\"") || field.len() < 2 {
        return Err("quoted name has no closing quote".into());
    }
    let inner = &field[1..field.len() - 1];
    let mut output = Vec::with_capacity(inner.len());
    let mut index = 0;
    while index < inner.len() {
        match inner[index] {
            b'\\' if index + 1 < inner.len() && matches!(inner[index + 1], b'\\' | b'"') => {
                output.push(inner[index + 1]);
                index += 2;
            }
            b'\\' if strict && index + 1 == inner.len() => {
                return Err("name ends with an incomplete backslash escape".into());
            }
            b'"' if index + 1 < inner.len() && inner[index + 1] == b'"' => {
                output.push(b'"');
                index += 2;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    Ok(output)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_handle(value: &[u8]) -> Result<u32, String> {
    let display = String::from_utf8_lossy(value).into_owned();
    if let Some(hex) = value
        .strip_prefix(b"0x")
        .or_else(|| value.strip_prefix(b"0X"))
    {
        let hex = std::str::from_utf8(hex).map_err(|_| display.clone())?;
        u32::from_str_radix(hex, 16).map_err(|_| display)
    } else {
        let decimal = std::str::from_utf8(value).map_err(|_| display.clone())?;
        u32::from_str_radix(decimal, 16).map_err(|_| display)
    }
}

#[must_use]
pub fn encode_header() -> &'static [u8] {
    HEADER
}

#[must_use]
pub fn encode_record(handle: u32, kind: &str, name: &[u8], children: &[u32]) -> Vec<u8> {
    let mut output = format!("{handle:08x}, {kind}, \"").into_bytes();
    for &byte in name {
        match byte {
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'"' => output.extend_from_slice(b"\\\""),
            _ => output.push(byte),
        }
    }
    output.extend_from_slice(b"\", \"");
    let mut child_text = String::new();
    for (index, child) in children.iter().enumerate() {
        if index > 0 {
            child_text.push(' ');
        }
        write!(&mut child_text, "{child:x}").expect("writing to String cannot fail");
    }
    output.extend_from_slice(child_text.as_bytes());
    output.push(b'"');
    output
}

/// Fuzz-ready boundary: consumes arbitrary bytes without panicking.
///
/// # Errors
///
/// Returns a typed diagnostic when the byte prefix is not a valid metadata
/// stream.
pub fn decode_metadata_prefix(bytes: &[u8], strict: bool) -> Result<usize, MetadataError> {
    StreamingDecoder::new(bytes, 64, strict)
        .try_fold(0_usize, |count, record| record.map(|_| count + 1))
}
