//! Artifact-local producer token resolution, never a build-exact source join.
//!
//! Stream field order and emitted reference kinds follow dotnet/runtime
//! `2eb7113245f7c536ab876dca5e3533fb96c81bbf` (`MstatObjectDumper` and
//! `TypeSystemMetadataEmitter`, MIT). Resolution is from metadata, not name prefixes.

use super::{
    Cursor, DecodeDetails, EntityKind, FormatVersion, IlDecoder, MIN_TRACKED_MEMORY, MstatError,
    PeImage, REQUIRED_STREAMS, TOKEN_RID_MASK, Tables, checked_slice, compressed_unsigned,
    decode_category, malformed, metadata_streams, read_index, read_u16, read_u32, resource_error,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::path::Path;

const MAX_DEPTH: usize = 32;
const MAX_COMPONENT_BYTES: usize = 16 * 1024;
const MAX_RECORD_MEMORY: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Method,
    Type,
    Field,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolResolutionBasis {
    ArtifactLocalEcma335,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SymbolResolution {
    Resolved {
        /// Full metadata assembly identity. Primitive/variable types have no assembly scope.
        assembly: Option<String>,
        declaring_type: String,
        member_name: Option<String>,
        /// Canonical readable signature, including calling convention and generic instantiation.
        signature: String,
    },
    Unresolved {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatSymbol {
    pub stream: String,
    pub raw_identity_blake3: String,
    pub identity: String,
    pub identity_lossy: bool,
    pub token: u32,
    pub kind: SymbolKind,
    pub resolution_basis: SymbolResolutionBasis,
    pub resolution: SymbolResolution,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatSymbolsSummary {
    pub schema: String,
    pub records: u64,
    pub resolved: u64,
    pub unresolved: u64,
    pub peak_tracked_memory_bytes: u64,
}

/// Visits one record per producer entry in `Methods`, `Types` and `RvaFields`.
///
/// Join to coalesced identities by `(stream, raw_identity_blake3)`, not token or
/// decoded spelling. Repeated keys can legitimately have multiple distinct tokens.
/// Tokens belong to this MSTAT artifact, not the original assembly. Unsupported
/// resolution forms are explicit unresolved records; corruption aborts extraction.
/// Memory retained by a visitor is its responsibility.
/// Raw producer names are retained with explicit lossy UTF-8 state; the existing
/// summary/coalesced visitors retain their stricter UTF-8 validation.
/// Parsing reserves 64 KiB plus at least 4 KiB for a record. Metadata strings
/// and signature blobs are limited to 16 KiB, recursion to 32 levels, and
/// record scratch memory to 1 MiB or the remaining caller budget, whichever is less.
///
/// # Errors
///
/// Returns checked PE/metadata/IL, token/signature, I/O, visitor or resource errors.
pub fn visit_symbols_path(
    path: &Path,
    memory_limit: u64,
    visitor: impl FnMut(MstatSymbol) -> Result<(), MstatError>,
) -> Result<MstatSymbolsSummary, MstatError> {
    let data = mmap_guard::map_file(path).map_err(|error| {
        let mut error = malformed("mstat.io", error.to_string(), None);
        error.diagnostic.input_path = Some(path.to_owned());
        error
    })?;
    visit_symbols(&data, memory_limit, visitor).map_err(|mut error| {
        error.diagnostic.input_path = Some(path.to_owned());
        error
    })
}

#[allow(clippy::too_many_lines)]
fn visit_symbols(
    bytes: &[u8],
    memory_limit: u64,
    mut visitor: impl FnMut(MstatSymbol) -> Result<(), MstatError>,
) -> Result<MstatSymbolsSummary, MstatError> {
    let record_limit = memory_limit
        .checked_sub(MIN_TRACKED_MEMORY)
        .filter(|limit| *limit >= 4096)
        .ok_or_else(|| resource_error("symbol visitor requires baseline plus 4096 bytes"))?
        .min(MAX_RECORD_MEMORY);
    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    if read_u16(bytes, pe_offset + 6)? > 128 {
        return Err(resource_error(
            "symbol PE section count exceeds bounded parser state",
        ));
    }
    let image = PeImage::parse(bytes)?;
    let metadata = image.rva_slice(image.metadata_rva, image.metadata_size)?;
    check_stream_budget(metadata)?;
    let (table_stream, strings, user_strings) = metadata_streams(metadata)?;
    let tables = Tables::parse(
        checked_slice(metadata, table_stream.offset, table_stream.size)?,
        checked_slice(metadata, strings.offset, strings.size)?,
    )?;
    let blobs = blob_stream(metadata)?;
    let names_section = image
        .sections
        .iter()
        .find(|section| section.name == b".names")
        .ok_or_else(|| malformed("mstat.section.names", "missing .names section", None))?;
    let names = image.section_logical_slice(names_section)?;
    let user_strings = checked_slice(metadata, user_strings.offset, user_strings.size)?;
    if tables.rows[32] != 1 {
        return Err(malformed(
            "mstat.assembly",
            "expected one Assembly row",
            None,
        ));
    }
    let assembly_row = checked_slice(tables.bytes, tables.table_offset(32)?, tables.row_size(32)?)?;
    if (FormatVersion {
        major: read_u16(assembly_row, 4)?,
        minor: read_u16(assembly_row, 6)?,
    }) != (FormatVersion { major: 2, minor: 2 })
    {
        return Err(malformed(
            "mstat.version",
            "symbol extraction requires MSTAT 2.2",
            None,
        ));
    }
    // Reuse the authoritative seven-stream decoder without allocating a MethodDef inventory.
    let mut seen = [false; 7];
    let mut details = DecodeDetails::default();
    for rid in 1..=tables.rows[6] {
        let mut resolver = Resolver::new(&tables, blobs, record_limit);
        let row = resolver.row(0x0600_0000 | rid, EntityKind::Method)?;
        let name = resolver.string(read_index(row, 8, tables.string_width)?)?;
        if let Some(index) = REQUIRED_STREAMS
            .iter()
            .position(|candidate| *candidate == name)
        {
            if seen[index] {
                return Err(malformed(
                    "mstat.method.duplicate",
                    "duplicate synthetic stream method",
                    None,
                ));
            }
            seen[index] = true;
            let body = image.method_body(read_u32(row, 0)?)?;
            if let Some((kind, count)) = symbol_stream(&name) {
                let mut decoder = IlDecoder::new(body.code, body.file_offset);
                while !decoder.is_empty() {
                    tables.validate_token(decoder.token()?, entity_kind(kind))?;
                    for _ in 0..count {
                        decoder.size()?;
                    }
                    raw_name(names, &mut decoder)?;
                }
            } else {
                decode_category(&name, body, &tables, names, user_strings, &mut details)?;
            }
        }
    }
    if seen.contains(&false) {
        return Err(malformed(
            "mstat.method.missing",
            "missing synthetic stream method",
            None,
        ));
    }
    let mut report = MstatSymbolsSummary {
        schema: "vitnet.mstat-symbols.v1".into(),
        records: 0,
        resolved: 0,
        unresolved: 0,
        peak_tracked_memory_bytes: MIN_TRACKED_MEMORY,
    };
    // Do not allocate a MethodDef inventory: this visitor remains streaming.
    for rid in 1..=tables.rows[6] {
        let mut resolver = Resolver::new(&tables, blobs, record_limit);
        let row = resolver.row(0x0600_0000 | rid, EntityKind::Method)?;
        let name = resolver.string(read_index(row, 8, tables.string_width)?)?;
        let Some((kind, count)) = symbol_stream(&name) else {
            continue;
        };
        let body = image.method_body(read_u32(row, 0)?)?;
        let mut decoder = IlDecoder::new(body.code, body.file_offset);
        while !decoder.is_empty() {
            let token = decoder.token()?;
            for _ in 0..count {
                decoder.size()?;
            }
            let raw = raw_name(names, &mut decoder)?;
            let mut resolver = Resolver::new(&tables, blobs, record_limit);
            resolver.charge(raw.len().saturating_mul(3).saturating_add(512))?;
            let outcome = resolver.resolve(token, kind, 0);
            let resolution = match outcome {
                Ok(value) => {
                    report.resolved += 1;
                    SymbolResolution::Resolved {
                        assembly: value.assembly,
                        declaring_type: value.name,
                        member_name: value.member,
                        signature: value.signature,
                    }
                }
                Err(ResolveError::Unsupported(reason)) => {
                    report.unresolved += 1;
                    SymbolResolution::Unresolved { reason }
                }
                Err(ResolveError::Malformed(error)) => return Err(error),
            };
            report.records += 1;
            report.peak_tracked_memory_bytes = report
                .peak_tracked_memory_bytes
                .max(MIN_TRACKED_MEMORY + resolver.used * 2);
            visitor(MstatSymbol {
                stream: name.clone(),
                raw_identity_blake3: blake3::hash(raw).to_hex().to_string(),
                identity: String::from_utf8_lossy(raw).into_owned(),
                identity_lossy: std::str::from_utf8(raw).is_err(),
                token,
                kind,
                resolution_basis: SymbolResolutionBasis::ArtifactLocalEcma335,
                resolution,
            })?;
        }
    }
    Ok(report)
}

fn symbol_stream(name: &str) -> Option<(SymbolKind, usize)> {
    match name {
        "Methods" => Some((SymbolKind::Method, 3)),
        "Types" => Some((SymbolKind::Type, 1)),
        "RvaFields" => Some((SymbolKind::Field, 1)),
        _ => None,
    }
}

const fn entity_kind(kind: SymbolKind) -> EntityKind {
    match kind {
        SymbolKind::Method => EntityKind::Method,
        SymbolKind::Type => EntityKind::Type,
        SymbolKind::Field => EntityKind::Field,
    }
}

fn raw_name<'a>(names: &'a [u8], decoder: &mut IlDecoder<'_>) -> Result<&'a [u8], MstatError> {
    let offset =
        usize::try_from(decoder.mangled_name_offset(names.len() as u64)?).map_err(|_| {
            malformed(
                "mstat.names.offset",
                "symbol name offset exceeds usize",
                None,
            )
        })?;
    let (length, prefix) = compressed_unsigned(names, offset, "mstat.names")?;
    let offset = offset
        .checked_add(prefix)
        .ok_or_else(|| malformed("mstat.names.offset", "symbol name offset overflow", None))?;
    checked_slice(names, offset, length)
}

fn blob_stream(metadata: &[u8]) -> Result<&[u8], MstatError> {
    // metadata_streams already checked the header, names, duplicates and overlap.
    let mut cursor = Cursor::new(metadata);
    cursor.skip(12)?;
    let length = cursor.u32()? as usize;
    cursor.skip(length)?;
    cursor.align4()?;
    cursor.skip(2)?;
    let count = cursor.u16()?;
    for _ in 0..count {
        let offset = cursor.u32()? as usize;
        let size = cursor.u32()? as usize;
        let length = cursor
            .remaining()
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed("mstat.metadata.stream", "missing stream terminator", None))?;
        let is_blob = &cursor.remaining()[..length] == b"#Blob";
        cursor.skip(length + 1)?;
        cursor.align4()?;
        if is_blob {
            return checked_slice(metadata, offset, size);
        }
    }

    // Legacy summary-only fixtures legitimately omit the blob heap. A symbol
    // referencing it will fail with a typed signature diagnostic, not resolve.
    Ok(&[])
}

fn check_stream_budget(metadata: &[u8]) -> Result<(), MstatError> {
    let mut cursor = Cursor::new(metadata);
    cursor.skip(12)?;
    let length = cursor.u32()? as usize;
    cursor.skip(length)?;
    cursor.align4()?;
    cursor.skip(2)?;
    let count = cursor.u16()?;
    if count > 64 {
        return Err(resource_error("symbol metadata stream count exceeds limit"));
    }
    for _ in 0..count {
        cursor.skip(8)?;
        let length = cursor
            .remaining()
            .iter()
            .take(257)
            .position(|byte| *byte == 0)
            .ok_or_else(|| resource_error("symbol metadata stream name exceeds limit"))?;
        cursor.skip(length + 1)?;
        cursor.align4()?;
    }
    Ok(())
}

enum ResolveError {
    Malformed(MstatError),
    Unsupported(String),
}

impl From<MstatError> for ResolveError {
    fn from(error: MstatError) -> Self {
        Self::Malformed(error)
    }
}

type Resolved<T> = Result<T, ResolveError>;

struct Managed {
    assembly: Option<String>,
    name: String,
    member: Option<String>,
    signature: String,
    generic_arity: Option<u32>,
}

struct Resolver<'a, 'b> {
    tables: &'b Tables<'a>,
    blobs: &'a [u8],
    limit: u64,
    used: u64,
    steps: usize,
    method_arity: Option<u32>,
}

impl<'a, 'b> Resolver<'a, 'b> {
    const fn new(tables: &'b Tables<'a>, blobs: &'a [u8], limit: u64) -> Self {
        // Half is reserved for transient formatting buffers before they are charged.
        Self {
            tables,
            blobs,
            limit: limit / 2,
            used: 0,
            steps: 0,
            method_arity: None,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), MstatError> {
        self.used = self
            .used
            .checked_add(bytes as u64)
            .ok_or_else(|| resource_error("symbol allocation overflow"))?;
        if self.used > self.limit {
            return Err(resource_error(
                "symbol record exceeds bounded visitor memory",
            ));
        }
        Ok(())
    }

    fn depth(&mut self, depth: usize) -> Resolved<()> {
        self.steps += 1;
        if depth > MAX_DEPTH || self.steps > MAX_COMPONENT_BYTES {
            return Err(resource_error("symbol recursion/work limit exceeded").into());
        }
        Ok(())
    }

    fn text(&mut self, value: String) -> Resolved<String> {
        self.charge(value.len().saturating_mul(2))?;
        Ok(value)
    }

    fn row(&self, token: u32, kind: EntityKind) -> Result<&'a [u8], MstatError> {
        self.tables.validate_token(token, kind)?;
        let table = (token >> 24) as usize;
        let size = self.tables.row_size(table)?;
        let offset = self
            .tables
            .table_offset(table)?
            .checked_add(
                ((token & TOKEN_RID_MASK) as usize - 1)
                    .checked_mul(size)
                    .ok_or_else(|| malformed("mstat.table.offset", "symbol row overflow", None))?,
            )
            .ok_or_else(|| malformed("mstat.table.offset", "symbol row overflow", None))?;
        checked_slice(self.tables.bytes, offset, size)
    }

    fn string(&mut self, offset: u32) -> Result<String, MstatError> {
        let tail =
            self.tables.strings.get(offset as usize..).ok_or_else(|| {
                malformed("mstat.strings", "symbol string offset out of range", None)
            })?;
        let end = tail
            .iter()
            .take(MAX_COMPONENT_BYTES + 1)
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                if tail.len() > MAX_COMPONENT_BYTES {
                    resource_error("symbol metadata string exceeds size limit")
                } else {
                    malformed("mstat.strings", "unterminated symbol string", None)
                }
            })?;
        self.charge(end.saturating_mul(2))?;
        let value = std::str::from_utf8(&tail[..end])
            .map_err(|_| malformed("mstat.strings", "symbol metadata string is not UTF-8", None))?;
        Ok(value.to_owned())
    }

    fn blob(&mut self, index: u32) -> Resolved<Sig<'a>> {
        if index == 0 {
            return Err(sig_error("missing symbol signature").into());
        }
        let bytes = self
            .blobs
            .get(index as usize..)
            .ok_or_else(|| sig_error("signature blob index out of range"))?;
        let mut cursor = Sig::new(bytes);
        let length = cursor.uint()? as usize;
        if length > MAX_COMPONENT_BYTES {
            return Err(resource_error("symbol signature exceeds size limit").into());
        }
        let bytes = checked_slice(bytes, cursor.position, length)
            .map_err(|_| sig_error("truncated signature blob"))?;
        Ok(Sig::new(bytes))
    }

    fn resolve(&mut self, token: u32, kind: SymbolKind, depth: usize) -> Resolved<Managed> {
        self.depth(depth)?;
        if kind == SymbolKind::Type {
            return self.type_token(token, depth + 1);
        }
        let entity = if kind == SymbolKind::Method {
            EntityKind::Method
        } else {
            EntityKind::Field
        };
        let row = self.row(token, entity)?;
        match token >> 24 {
            43 => self.method_spec(row, depth + 1),
            10 => self.member_ref(row, kind, depth + 1),
            4 | 6 => self.definition(token, row, kind, depth + 1),
            _ => unreachable!("validated member token"),
        }
    }

    fn type_token(&mut self, token: u32, depth: usize) -> Resolved<Managed> {
        self.depth(depth)?;
        let row = self.row(token, EntityKind::Type)?;
        if token >> 24 == 27 {
            let mut sig = self.blob(read_index(row, 0, self.tables.blob_width)?)?;
            let value = self.type_sig(&mut sig, depth + 1, false)?;
            sig.end()?;
            return Ok(value);
        }
        let (start, scope_width) = if token >> 24 == 1 {
            (0, self.tables.coded_index(&[0, 26, 35, 1], 2))
        } else {
            (4, 0)
        };
        let name = self.string(read_index(
            row,
            start + scope_width,
            self.tables.string_width,
        )?)?;
        if name.is_empty() {
            return Err(sig_error("empty managed type name").into());
        }
        let namespace = self.string(read_index(
            row,
            start + scope_width + self.tables.string_width,
            self.tables.string_width,
        )?)?;
        let (assembly, name) = if token >> 24 == 1 {
            let scope = read_index(row, 0, scope_width)?;
            match scope & 3 {
                2 => (
                    Some(self.assembly(0x2300_0000 | (scope >> 2))?),
                    qualified(&namespace, &name),
                ),
                3 => {
                    let parent = self.type_token(0x0100_0000 | (scope >> 2), depth + 1)?;
                    (parent.assembly, format!("{}+{name}", parent.name))
                }
                0 | 1 => {
                    let table = if scope.trailing_zeros() >= 2 { 0 } else { 26 };
                    if scope != 0 && (scope >> 2 == 0 || scope >> 2 > self.tables.rows[table]) {
                        return Err(malformed(
                            "mstat.token.rid",
                            "TypeRef module scope out of range",
                            None,
                        )
                        .into());
                    }
                    return Err(ResolveError::Unsupported(
                        "TypeRef module/nil resolution scope".into(),
                    ));
                }
                _ => unreachable!(),
            }
        } else {
            let mut parent = None;
            for rid in 1..=self.tables.rows[41] {
                let size = self.tables.row_size(41)?;
                let row = checked_slice(
                    self.tables.bytes,
                    self.tables.table_offset(41)? + (rid as usize - 1) * size,
                    size,
                )?;
                let nested = read_index(row, 0, self.tables.simple_index(2))?;
                let enclosing = read_index(
                    row,
                    self.tables.simple_index(2),
                    self.tables.simple_index(2),
                )?;
                self.tables
                    .validate_token(0x0200_0000 | nested, EntityKind::Type)?;
                self.tables
                    .validate_token(0x0200_0000 | enclosing, EntityKind::Type)?;
                if nested == token & TOKEN_RID_MASK {
                    if parent.is_some() {
                        return Err(sig_error("duplicate NestedClass ownership").into());
                    }
                    parent = Some(enclosing);
                }
            }
            if let Some(parent) = parent {
                let parent = self.type_token(0x0200_0000 | parent, depth + 1)?;
                (parent.assembly, format!("{}+{name}", parent.name))
            } else {
                (Some(self.local_assembly()?), qualified(&namespace, &name))
            }
        };
        let name = self.text(name)?;
        let signature = self.text(match &assembly {
            Some(assembly) => format!("[{assembly}]{name}"),
            None => name.clone(),
        })?;
        Ok(Managed {
            assembly,
            name,
            member: None,
            signature,
            generic_arity: None,
        })
    }

    fn assembly(&mut self, token: u32) -> Resolved<String> {
        let row = self.row(token, EntityKind::AssemblyRef)?;
        self.assembly_parts(row, 12, 0, self.tables.blob_width, false)
    }

    fn local_assembly(&mut self) -> Resolved<String> {
        let row = checked_slice(
            self.tables.bytes,
            self.tables.table_offset(32)?,
            self.tables.row_size(32)?,
        )?;
        self.assembly_parts(row, 16, 4, self.tables.blob_width, true)
    }

    fn assembly_parts(
        &mut self,
        row: &[u8],
        name_offset: usize,
        version_offset: usize,
        blob_width: usize,
        local: bool,
    ) -> Resolved<String> {
        let name = self.string(read_index(
            row,
            name_offset + blob_width,
            self.tables.string_width,
        )?)?;
        if name.is_empty() {
            return Err(sig_error("empty assembly name").into());
        }
        let culture = self.string(read_index(
            row,
            name_offset + blob_width + self.tables.string_width,
            self.tables.string_width,
        )?)?;
        let key_index = read_index(row, name_offset, blob_width)?;
        let key = if key_index == 0 {
            "null".into()
        } else {
            let blob = self.blob(key_index)?;
            self.hex(blob.bytes)?
        };
        let flags = read_u32(row, if local { 12 } else { 8 })?;
        self.text(format!(
            "{name}, Version={}.{}.{}.{}, Culture={}, {}={key}, Flags=0x{flags:08x}",
            read_u16(row, version_offset)?,
            read_u16(row, version_offset + 2)?,
            read_u16(row, version_offset + 4)?,
            read_u16(row, version_offset + 6)?,
            if culture.is_empty() {
                "neutral"
            } else {
                &culture
            },
            if flags & 1 == 0 {
                "PublicKeyToken"
            } else {
                "PublicKey"
            }
        ))
    }

    fn hex(&mut self, bytes: &[u8]) -> Resolved<String> {
        self.charge(bytes.len().saturating_mul(4))?;
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(result, "{byte:02x}").expect("String formatting");
        }
        Ok(result)
    }

    fn member_ref(&mut self, row: &[u8], kind: SymbolKind, depth: usize) -> Resolved<Managed> {
        let width = self.tables.coded_index(&[2, 1, 26, 6, 27], 3);
        let parent = read_index(row, 0, width)?;
        let name = self.string(read_index(row, width, self.tables.string_width)?)?;
        let mut sig = self.blob(read_index(
            row,
            width + self.tables.string_width,
            self.tables.blob_width,
        )?)?;
        let (signature, generic_arity) = self.member_signature(&mut sig, kind, depth + 1)?;
        sig.end()?;
        let table = match parent & 7 {
            0 => 2,
            1 => 1,
            4 => 27,
            2 | 3 => {
                let table = if parent & 7 == 2 { 26 } else { 6 };
                let rid = parent >> 3;
                if rid == 0 || rid > self.tables.rows[table] {
                    return Err(malformed(
                        "mstat.token.rid",
                        "MemberRef parent out of range",
                        None,
                    )
                    .into());
                }
                return Err(ResolveError::Unsupported(
                    "MemberRef ModuleRef/MethodDef parent".into(),
                ));
            }
            _ => {
                return Err(
                    malformed("mstat.token.kind", "invalid MemberRef parent tag", None).into(),
                );
            }
        };
        let mut owner = self.type_token((table << 24) | (parent >> 3), depth + 1)?;
        if name.is_empty() {
            return Err(sig_error("empty managed member name").into());
        }
        owner.member = Some(name);
        owner.signature = signature;
        owner.generic_arity = generic_arity;
        Ok(owner)
    }

    fn definition(
        &mut self,
        token: u32,
        row: &[u8],
        kind: SymbolKind,
        depth: usize,
    ) -> Resolved<Managed> {
        let method = kind == SymbolKind::Method;
        let name_offset = if method { 8 } else { 2 };
        let name = self.string(read_index(row, name_offset, self.tables.string_width)?)?;
        if name.is_empty() {
            return Err(sig_error("empty managed member name").into());
        }
        let mut sig = self.blob(read_index(
            row,
            name_offset + self.tables.string_width,
            self.tables.blob_width,
        )?)?;
        let (signature, generic_arity) = self.member_signature(&mut sig, kind, depth + 1)?;
        sig.end()?;
        let table = if method { 6 } else { 4 };
        let pointer = if method { 5 } else { 3 };
        if self.tables.rows[pointer] != 0 {
            return Err(ResolveError::Unsupported(
                "definition ownership through pointer table".into(),
            ));
        }
        let mut owner = None;
        let mut previous = 1;
        for rid in 1..=self.tables.rows[2] {
            let type_row = self.row(0x0200_0000 | rid, EntityKind::Type)?;
            let list_offset = 4
                + self.tables.string_width * 2
                + self.tables.coded_index(&[2, 1, 27], 2)
                + if method {
                    self.tables.simple_index(4)
                } else {
                    0
                };
            let start = read_index(type_row, list_offset, self.tables.simple_index(table))?;
            if start < previous || start == 0 || start > self.tables.rows[table] + 1 {
                return Err(sig_error("invalid TypeDef member list").into());
            }
            if start <= token & TOKEN_RID_MASK {
                owner = Some(rid);
            }
            previous = start;
        }
        let Some(owner) = owner else {
            return Err(sig_error("definition has no declaring type").into());
        };
        let mut owner = self.type_token(0x0200_0000 | owner, depth + 1)?;
        owner.member = Some(name);
        owner.signature = signature;
        owner.generic_arity = generic_arity;
        Ok(owner)
    }

    fn method_spec(&mut self, row: &[u8], depth: usize) -> Resolved<Managed> {
        let width = self.tables.coded_index(&[6, 10], 1);
        let parent = read_index(row, 0, width)?;
        let token = ((if parent & 1 == 0 { 6 } else { 10 }) << 24) | (parent >> 1);
        let mut owner = self.resolve(token, SymbolKind::Method, depth + 1)?;
        let mut sig = self.blob(read_index(row, width, self.tables.blob_width)?)?;
        if sig.byte()? != 0x0a {
            return Err(sig_error("invalid MethodSpec signature header").into());
        }
        let count = sig.uint()?;
        if count == 0 || owner.generic_arity != Some(count) {
            return Err(
                sig_error("MethodSpec argument count differs from generic method arity").into(),
            );
        }
        let args = self.arguments(&mut sig, count, depth + 1)?;
        sig.end()?;
        owner.signature = self.text(format!("{} inst<{args}>", owner.signature))?;
        Ok(owner)
    }

    fn arguments(&mut self, sig: &mut Sig<'a>, count: u32, depth: usize) -> Resolved<String> {
        if count as usize > sig.remaining() {
            return Err(sig_error("signature count exceeds remaining bytes").into());
        }
        let mut result = String::new();
        for index in 0..count {
            let value = self.type_sig(sig, depth + 1, false)?;
            self.charge(value.signature.len().saturating_mul(2).saturating_add(2))?;
            if index != 0 {
                result.push(',');
            }
            result.push_str(&value.signature);
        }
        Ok(result)
    }

    fn member_signature(
        &mut self,
        sig: &mut Sig<'a>,
        kind: SymbolKind,
        depth: usize,
    ) -> Resolved<(String, Option<u32>)> {
        if kind == SymbolKind::Field {
            if sig.byte()? != 6 {
                return Err(sig_error("field token references a non-field signature").into());
            }
            let value = self.type_sig(sig, depth + 1, false)?;
            return Ok((self.text(format!("field {}", value.signature))?, None));
        }
        let (signature, arity) = self.method_signature(sig, depth + 1)?;
        Ok((signature, Some(arity)))
    }

    fn method_signature(&mut self, sig: &mut Sig<'a>, depth: usize) -> Resolved<(String, u32)> {
        self.depth(depth)?;
        let cc = sig.byte()?;
        if cc & 0x80 != 0 || !matches!(cc & 15, 0..=5 | 9 | 11) || cc & 0x40 != 0 && cc & 0x20 == 0
        {
            return Err(sig_error("invalid method calling convention").into());
        }
        let arity = if cc & 0x10 == 0 { 0 } else { sig.uint()? };
        if cc & 0x10 != 0 && arity == 0 {
            return Err(sig_error("generic method signature has zero arity").into());
        }
        let previous_arity = self.method_arity.replace(arity);
        let count = sig.uint()?;
        let ret = self.type_sig(sig, depth + 1, true)?;
        if count as usize > sig.remaining() {
            return Err(sig_error("method parameter count exceeds bytes").into());
        }
        let mut parameters = String::new();
        let mut sentinel = false;
        for index in 0..count {
            if index != 0 {
                parameters.push(',');
            }
            if sig.peek()? == 0x41 {
                if sentinel || cc & 15 != 5 {
                    return Err(sig_error("invalid vararg sentinel").into());
                }
                sig.byte()?;
                sentinel = true;
                parameters.push_str("...,");
            }
            let value = self.type_sig(sig, depth + 1, false)?;
            self.charge(value.signature.len().saturating_mul(2).saturating_add(6))?;
            parameters.push_str(&value.signature);
        }
        self.method_arity = previous_arity;
        let signature = self.text(format!(
            "cc=0x{cc:02x};generic={arity};{}({parameters})",
            ret.signature
        ))?;
        Ok((signature, arity))
    }

    #[allow(clippy::too_many_lines)]
    fn type_sig(&mut self, sig: &mut Sig<'a>, depth: usize, allow_void: bool) -> Resolved<Managed> {
        self.depth(depth)?;
        let code = sig.byte()?;
        let primitive = match code {
            1 if allow_void => Some("void"),
            2 => Some("bool"),
            3 => Some("char"),
            4 => Some("int8"),
            5 => Some("uint8"),
            6 => Some("int16"),
            7 => Some("uint16"),
            8 => Some("int32"),
            9 => Some("uint32"),
            10 => Some("int64"),
            11 => Some("uint64"),
            12 => Some("float32"),
            13 => Some("float64"),
            14 => Some("string"),
            22 => Some("typedref"),
            24 => Some("native int"),
            25 => Some("native uint"),
            28 => Some("object"),
            _ => None,
        };
        if let Some(name) = primitive {
            return self.simple_type(name.into());
        }
        match code {
            0x11 | 0x12 => {
                let token = sig.type_token()?;
                let mut value = self.type_token(token, depth + 1)?;
                value.signature = self.text(format!(
                    "{} {}",
                    if code == 0x11 { "valuetype" } else { "class" },
                    value.signature
                ))?;
                Ok(value)
            }
            0x13 | 0x1e => {
                let index = sig.uint()?;
                if code == 0x1e && self.method_arity.is_some_and(|arity| index >= arity) {
                    return Err(sig_error("method signature variable exceeds generic arity").into());
                }
                self.simple_type(format!("{}{index}", if code == 0x13 { "!" } else { "!!" }))
            }
            0x0f | 0x10 | 0x1d => {
                let mut value = self.type_sig(sig, depth + 1, code == 0x0f)?;
                let suffix = match code {
                    0x0f => "*",
                    0x10 => "&",
                    _ => "[]",
                };
                value.name = self.text(format!("{}{suffix}", value.name))?;
                value.signature = self.text(format!("{}{suffix}", value.signature))?;
                Ok(value)
            }
            0x15 => {
                let marker = sig.byte()?;
                if !matches!(marker, 0x11 | 0x12) {
                    return Err(sig_error("invalid generic instance kind").into());
                }
                let token = sig.type_token()?;
                let mut value = self.type_token(token, depth + 1)?;
                let count = sig.uint()?;
                if count == 0 {
                    return Err(sig_error("empty generic type instantiation").into());
                }
                let args = self.arguments(sig, count, depth + 1)?;
                value.name = self.text(format!("{}<{args}>", value.name))?;
                value.signature = self.text(format!(
                    "{} {}<{args}>",
                    if marker == 0x11 { "valuetype" } else { "class" },
                    value.signature
                ))?;
                Ok(value)
            }
            0x14 => {
                let mut value = self.type_sig(sig, depth + 1, false)?;
                let rank = sig.uint()?;
                if rank == 0 || rank as usize > MAX_COMPONENT_BYTES {
                    return Err(sig_error("invalid array rank").into());
                }
                let sizes = sig.uint()?;
                if sizes > rank {
                    return Err(sig_error("array size count exceeds rank").into());
                }
                let mut shape = format!("rank={rank};sizes=");
                for _ in 0..sizes {
                    self.charge(24)?;
                    write!(shape, "{},", sig.uint()?).expect("String formatting");
                }
                shape.push_str(";bounds=");
                let bounds = sig.uint()?;
                if bounds > rank {
                    return Err(sig_error("array bound count exceeds rank").into());
                }
                for _ in 0..bounds {
                    self.charge(24)?;
                    write!(shape, "{},", sig.sint()?).expect("String formatting");
                }
                value.name = self.text(format!("{}[{shape}]", value.name))?;
                value.signature = self.text(format!("{}[{shape}]", value.signature))?;
                Ok(value)
            }
            0x1f | 0x20 => {
                let token = sig.type_token()?;
                let modifier = self.type_token(token, depth + 1)?;
                let mut value = self.type_sig(sig, depth + 1, allow_void)?;
                value.signature = self.text(format!(
                    "{}({}) {}",
                    if code == 0x1f { "modreq" } else { "modopt" },
                    modifier.signature,
                    value.signature
                ))?;
                Ok(value)
            }
            0x1b => {
                let (signature, _) = self.method_signature(sig, depth + 1)?;
                self.simple_type(format!("fnptr {signature}"))
            }
            _ => Err(sig_error(format!(
                "invalid/unsupported ECMA signature element 0x{code:02x}"
            ))
            .into()),
        }
    }

    fn simple_type(&mut self, name: String) -> Resolved<Managed> {
        self.charge(name.len().saturating_mul(4))?;
        Ok(Managed {
            assembly: None,
            signature: name.clone(),
            name,
            member: None,
            generic_arity: None,
        })
    }
}

fn qualified(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.into()
    } else {
        format!("{namespace}.{name}")
    }
}

fn sig_error(message: impl Into<String>) -> MstatError {
    malformed("mstat.symbol.signature", message, None)
}

struct Sig<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Sig<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    fn peek(&self) -> Result<u8, MstatError> {
        self.bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| sig_error("truncated signature"))
    }
    fn byte(&mut self) -> Result<u8, MstatError> {
        let value = self.peek()?;
        self.position += 1;
        Ok(value)
    }
    fn uint(&mut self) -> Result<u32, MstatError> {
        let (value, bits) = self.compressed()?;
        if bits == 14 && value < 128 || bits == 29 && value < 16384 {
            return Err(sig_error("non-canonical compressed unsigned integer"));
        }
        Ok(value)
    }
    fn compressed(&mut self) -> Result<(u32, u32), MstatError> {
        let first = self.byte()?;
        match first {
            0..=0x7f => Ok((u32::from(first), 7)),
            0x80..=0xbf => Ok(((u32::from(first & 0x3f) << 8) | u32::from(self.byte()?), 14)),
            0xc0..=0xdf => Ok((
                (u32::from(first & 0x1f) << 24)
                    | (u32::from(self.byte()?) << 16)
                    | (u32::from(self.byte()?) << 8)
                    | u32::from(self.byte()?),
                29,
            )),
            _ => Err(sig_error("invalid compressed signature integer")),
        }
    }
    fn sint(&mut self) -> Result<i32, MstatError> {
        let (value, bits) = self.compressed()?;
        let magnitude = i32::try_from(value >> 1).expect("29-bit integer");
        Ok(if value & 1 == 0 {
            magnitude
        } else {
            magnitude - (1 << (bits - 1))
        })
    }
    fn type_token(&mut self) -> Result<u32, MstatError> {
        let coded = self.uint()?;
        if coded >> 2 == 0 || coded >> 2 > TOKEN_RID_MASK {
            return Err(malformed(
                "mstat.token.rid",
                "TypeDefOrRef signature row out of range",
                None,
            ));
        }
        let table = match coded & 3 {
            0 => 2,
            1 => 1,
            2 => 27,
            _ => {
                return Err(malformed(
                    "mstat.token.kind",
                    "invalid TypeDefOrRef signature tag",
                    None,
                ));
            }
        };
        Ok((table << 24) | (coded >> 2))
    }
    fn end(&self) -> Result<(), MstatError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(sig_error("trailing signature bytes"))
        }
    }
}
