//! Checked, zero-copy summaries for `NativeAOT` MSTAT v2 files.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use vitnet_core::{Diagnostic, ResourceBudget};

const MIN_TRACKED_MEMORY: u64 = 64 * 1024;
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const METADATA_SIGNATURE: u32 = 0x424a_5342;
const CLI_DIRECTORY_INDEX: usize = 14;
const METHOD_DEF_TABLE: usize = 6;
const ASSEMBLY_TABLE: usize = 32;
const REQUIRED_STREAMS: [&str; 7] = [
    "Methods",
    "Types",
    "Blobs",
    "RvaFields",
    "FrozenObjects",
    "ManifestResources",
    "DeduplicatedMethods",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FormatVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CategorySummary {
    pub name: String,
    pub records: u64,
    pub items: u64,
    pub aggregate_size_bytes: u64,
    pub encoded_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MethodBreakdown {
    pub body_bytes: u64,
    pub gc_info_bytes: u64,
    pub exception_info_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrozenBreakdown {
    pub owned_records: u64,
    pub owned_bytes: u64,
    pub unowned_records: u64,
    pub unowned_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeduplicationSummary {
    pub groups: u64,
    pub folded_methods: u64,
    pub estimated_savings_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatSummary {
    pub schema: String,
    pub format_version: FormatVersion,
    pub assembly: String,
    pub input_bytes: u64,
    pub accounted_size_bytes: u64,
    pub mangled_names_bytes: u64,
    pub categories: Vec<CategorySummary>,
    pub methods: MethodBreakdown,
    pub frozen_objects: FrozenBreakdown,
    pub deduplicated_methods: DeduplicationSummary,
    pub peak_tracked_memory_bytes: u64,
}

#[derive(Debug, Error)]
#[error("{diagnostic}")]
pub struct MstatError {
    pub diagnostic: Box<Diagnostic>,
}

#[derive(Clone, Copy)]
struct Section<'a> {
    name: &'a [u8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
}

struct PeImage<'a> {
    bytes: &'a [u8],
    sections: Vec<Section<'a>>,
    metadata_rva: u32,
    metadata_size: u32,
}

#[derive(Clone, Copy)]
struct Stream {
    offset: usize,
    size: usize,
}

struct Tables<'a> {
    bytes: &'a [u8],
    strings: &'a [u8],
    rows: [u32; 64],
    data_offset: usize,
    string_width: usize,
    guid_width: usize,
    blob_width: usize,
}

#[derive(Clone, Copy)]
struct MethodRow {
    rva: u32,
    name: u32,
}

#[derive(Clone, Copy)]
struct MethodBody<'a> {
    code: &'a [u8],
    file_offset: u64,
}

#[derive(Default)]
struct DecodeDetails {
    methods: MethodBreakdown,
    frozen: FrozenBreakdown,
    deduplication: DeduplicationSummary,
}

/// Maps and summarizes an MSTAT file without copying its contents.
///
/// # Errors
///
/// Returns a typed I/O, malformed-input, unsupported-version, or resource
/// diagnostic.
pub fn summarize_path(path: &Path, memory_limit: u64) -> Result<MstatSummary, MstatError> {
    let data = mmap_guard::map_file(path).map_err(|error| {
        let mut diagnostic = Diagnostic::malformed("mstat.io", error.to_string());
        diagnostic.input_path = Some(path.to_owned());
        MstatError {
            diagnostic: Box::new(diagnostic),
        }
    })?;
    summarize(&data, memory_limit).map_err(|mut error| {
        error.diagnostic.input_path = Some(path.to_owned());
        error
    })
}

/// Summarizes an in-memory MSTAT image. This entry point supports independently
/// constructed fixtures and fuzzing without filesystem state.
///
/// # Errors
///
/// Returns a typed diagnostic when any checked boundary or record is invalid.
pub fn summarize(bytes: &[u8], memory_limit: u64) -> Result<MstatSummary, MstatError> {
    ResourceBudget::new(memory_limit, 0, 1, None)
        .check(MIN_TRACKED_MEMORY, 0)
        .map_err(|error| resource_error(error.to_string()))?;

    let image = PeImage::parse(bytes)?;
    let metadata = image.rva_slice(image.metadata_rva, image.metadata_size)?;
    let (tables_stream, strings_stream) = metadata_streams(metadata)?;
    let tables_bytes = checked_slice(metadata, tables_stream.offset, tables_stream.size)?;
    let strings = checked_slice(metadata, strings_stream.offset, strings_stream.size)?;
    let tables = Tables::parse(tables_bytes, strings)?;
    let (format_version, assembly) = tables.assembly()?;
    if format_version != (FormatVersion { major: 2, minor: 2 }) {
        let mut diagnostic = Diagnostic::malformed(
            "mstat.version",
            format!(
                "unsupported MSTAT format {}.{}",
                format_version.major, format_version.minor
            ),
        );
        diagnostic.expected = Some("MSTAT 2.2".into());
        return Err(MstatError {
            diagnostic: Box::new(diagnostic),
        });
    }

    let names = image
        .sections
        .iter()
        .find(|section| section.name == b".names")
        .ok_or_else(|| malformed("mstat.section.names", "missing .names section", None))?;
    let mangled_names_bytes = u64::from(names.virtual_size);
    let mut categories = Vec::with_capacity(REQUIRED_STREAMS.len());
    let mut details = DecodeDetails::default();
    let mut seen = [false; REQUIRED_STREAMS.len()];
    for row in tables.methods()? {
        let name = tables.string(row.name)?;
        let Some(index) = REQUIRED_STREAMS
            .iter()
            .position(|candidate| *candidate == name)
        else {
            continue;
        };
        if seen[index] {
            return Err(malformed(
                "mstat.method.duplicate",
                format!("duplicate synthetic method `{name}`"),
                None,
            ));
        }
        seen[index] = true;
        let body = image.method_body(row.rva)?;
        categories.push(decode_category(
            name,
            body,
            mangled_names_bytes,
            &mut details,
        )?);
    }
    for (index, name) in REQUIRED_STREAMS.iter().enumerate() {
        if !seen[index] {
            return Err(malformed(
                "mstat.method.missing",
                format!("missing synthetic method `{name}`"),
                None,
            ));
        }
    }
    categories.sort_by_key(|category| {
        REQUIRED_STREAMS
            .iter()
            .position(|name| *name == category.name)
            .unwrap_or(usize::MAX)
    });

    let accounted_size_bytes = categories
        .iter()
        .filter(|category| matches!(category.name.as_str(), "Methods" | "Types" | "Blobs"))
        .try_fold(0_u64, |total, category| {
            total.checked_add(category.aggregate_size_bytes)
        })
        .ok_or_else(|| malformed("mstat.size.overflow", "accounted size overflow", None))?;
    Ok(MstatSummary {
        schema: "vitnet.mstat-summary.v1".into(),
        format_version,
        assembly,
        input_bytes: bytes.len() as u64,
        accounted_size_bytes,
        mangled_names_bytes,
        categories,
        methods: details.methods,
        frozen_objects: details.frozen,
        deduplicated_methods: details.deduplication,
        peak_tracked_memory_bytes: MIN_TRACKED_MEMORY,
    })
}

impl<'a> PeImage<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, MstatError> {
        let pe_offset = usize::try_from(read_u32(bytes, 0x3c)?)
            .map_err(|_| malformed("mstat.pe.offset", "PE offset exceeds usize", Some(0x3c)))?;
        if checked_slice(bytes, pe_offset, 4)? != PE_SIGNATURE {
            return Err(malformed(
                "mstat.pe.signature",
                "invalid PE signature",
                Some(pe_offset as u64),
            ));
        }
        let coff = pe_offset
            .checked_add(4)
            .ok_or_else(|| malformed("mstat.pe.offset", "COFF offset overflow", None))?;
        let section_count = usize::from(read_u16(bytes, coff + 2)?);
        let optional_size = usize::from(read_u16(bytes, coff + 16)?);
        let optional = coff
            .checked_add(20)
            .ok_or_else(|| malformed("mstat.pe.offset", "optional-header offset overflow", None))?;
        checked_slice(bytes, optional, optional_size)?;
        let magic = read_u16(bytes, optional)?;
        let directory_offset = match magic {
            0x10b => 96,
            0x20b => 112,
            _ => {
                return Err(malformed(
                    "mstat.pe.magic",
                    format!("unsupported PE optional-header magic 0x{magic:04x}"),
                    Some(optional as u64),
                ));
            }
        };
        let cli_directory = optional
            .checked_add(directory_offset + CLI_DIRECTORY_INDEX * 8)
            .ok_or_else(|| malformed("mstat.pe.offset", "CLI-directory offset overflow", None))?;
        let cli_rva = read_u32(bytes, cli_directory)?;
        let cli_size = read_u32(bytes, cli_directory + 4)?;
        if cli_rva == 0 || cli_size < 16 {
            return Err(malformed(
                "mstat.pe.cli",
                "missing or truncated CLI header",
                Some(cli_directory as u64),
            ));
        }
        let section_headers = optional
            .checked_add(optional_size)
            .ok_or_else(|| malformed("mstat.pe.offset", "section-header offset overflow", None))?;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let offset = section_headers
                .checked_add(index.checked_mul(40).ok_or_else(|| {
                    malformed("mstat.pe.section", "section table offset overflow", None)
                })?)
                .ok_or_else(|| {
                    malformed("mstat.pe.section", "section table offset overflow", None)
                })?;
            let row = checked_slice(bytes, offset, 40)?;
            let name_end = row[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
            let raw_size = read_u32(row, 16)?;
            let raw_offset = read_u32(row, 20)?;
            checked_slice(
                bytes,
                usize::try_from(raw_offset).map_err(|_| {
                    malformed("mstat.pe.section", "section offset exceeds usize", None)
                })?,
                usize::try_from(raw_size).map_err(|_| {
                    malformed("mstat.pe.section", "section size exceeds usize", None)
                })?,
            )?;
            sections.push(Section {
                name: &row[..name_end],
                virtual_size: read_u32(row, 8)?,
                virtual_address: read_u32(row, 12)?,
                raw_size,
                raw_offset,
            });
        }
        let mut image = Self {
            bytes,
            sections,
            metadata_rva: 0,
            metadata_size: 0,
        };
        let cli = image.rva_slice(cli_rva, cli_size)?;
        image.metadata_rva = read_u32(cli, 8)?;
        image.metadata_size = read_u32(cli, 12)?;
        if image.metadata_rva == 0 || image.metadata_size == 0 {
            return Err(malformed(
                "mstat.metadata",
                "CLI header has no metadata directory",
                None,
            ));
        }
        Ok(image)
    }

    fn rva_file_offset(&self, rva: u32, size: u32) -> Result<usize, MstatError> {
        for section in &self.sections {
            let Some(relative) = rva.checked_sub(section.virtual_address) else {
                continue;
            };
            let Some(end) = relative.checked_add(size) else {
                continue;
            };
            if end <= section.raw_size {
                let offset = section
                    .raw_offset
                    .checked_add(relative)
                    .ok_or_else(|| malformed("mstat.pe.rva", "RVA file-offset overflow", None))?;
                return usize::try_from(offset)
                    .map_err(|_| malformed("mstat.pe.rva", "RVA file offset exceeds usize", None));
            }
        }
        Err(malformed(
            "mstat.pe.rva",
            format!("RVA range 0x{rva:08x}+{size} is not backed by a section"),
            None,
        ))
    }

    fn rva_slice(&self, rva: u32, size: u32) -> Result<&'a [u8], MstatError> {
        let offset = self.rva_file_offset(rva, size)?;
        checked_slice(
            self.bytes,
            offset,
            usize::try_from(size)
                .map_err(|_| malformed("mstat.pe.rva", "RVA size exceeds usize", None))?,
        )
    }

    fn method_body(&self, rva: u32) -> Result<MethodBody<'a>, MstatError> {
        let offset = self.rva_file_offset(rva, 1)?;
        let first = *self
            .bytes
            .get(offset)
            .ok_or_else(|| malformed("mstat.method.header", "missing method header", None))?;
        let (header_size, code_size) = match first & 3 {
            2 => (1_usize, usize::from(first >> 2)),
            3 => {
                self.rva_file_offset(rva, 12)?;
                let header = read_u16(self.bytes, offset)?;
                let header_size = usize::from(header >> 12) * 4;
                if header_size < 12 {
                    return Err(malformed(
                        "mstat.method.header",
                        "fat method header is shorter than 12 bytes",
                        Some(offset as u64),
                    ));
                }
                let code_size =
                    usize::try_from(read_u32(self.bytes, offset + 4)?).map_err(|_| {
                        malformed("mstat.method.header", "method size exceeds usize", None)
                    })?;
                (header_size, code_size)
            }
            _ => {
                return Err(malformed(
                    "mstat.method.header",
                    format!("invalid method header byte 0x{first:02x}"),
                    Some(offset as u64),
                ));
            }
        };
        let total_size = header_size
            .checked_add(code_size)
            .ok_or_else(|| malformed("mstat.method.header", "method-body size overflow", None))?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| malformed("mstat.method.header", "method body exceeds u32", None))?;
        self.rva_file_offset(rva, total_size_u32)?;
        let code_offset = offset
            .checked_add(header_size)
            .ok_or_else(|| malformed("mstat.method.header", "method-body offset overflow", None))?;
        let code = checked_slice(self.bytes, code_offset, code_size)?;
        Ok(MethodBody {
            code,
            file_offset: code_offset as u64,
        })
    }
}

impl<'a> Tables<'a> {
    fn parse(bytes: &'a [u8], strings: &'a [u8]) -> Result<Self, MstatError> {
        let mut cursor = Cursor::new(bytes);
        cursor.skip(4)?;
        cursor.skip(2)?;
        let heap_sizes = cursor.u8()?;
        cursor.skip(1)?;
        let valid = cursor.u64()?;
        cursor.skip(8)?;
        let mut rows = [0_u32; 64];
        for (table, count) in rows.iter_mut().enumerate() {
            if valid & (1_u64 << table) != 0 {
                *count = cursor.u32()?;
            }
        }
        Ok(Self {
            bytes,
            strings,
            rows,
            data_offset: cursor.position,
            string_width: if heap_sizes & 1 == 0 { 2 } else { 4 },
            guid_width: if heap_sizes & 2 == 0 { 2 } else { 4 },
            blob_width: if heap_sizes & 4 == 0 { 2 } else { 4 },
        })
    }

    fn methods(&self) -> Result<Vec<MethodRow>, MstatError> {
        let offset = self.table_offset(METHOD_DEF_TABLE)?;
        let row_size = self.row_size(METHOD_DEF_TABLE)?;
        let count = usize::try_from(self.rows[METHOD_DEF_TABLE])
            .map_err(|_| malformed("mstat.table.rows", "method count exceeds usize", None))?;
        let mut rows = Vec::with_capacity(count.min(16));
        for index in 0..count {
            let row_offset = offset
                .checked_add(index.checked_mul(row_size).ok_or_else(|| {
                    malformed("mstat.table.offset", "method row offset overflow", None)
                })?)
                .ok_or_else(|| {
                    malformed("mstat.table.offset", "method row offset overflow", None)
                })?;
            let row = checked_slice(self.bytes, row_offset, row_size)?;
            rows.push(MethodRow {
                rva: read_u32(row, 0)?,
                name: read_index(row, 8, self.string_width)?,
            });
        }
        Ok(rows)
    }

    fn assembly(&self) -> Result<(FormatVersion, String), MstatError> {
        if self.rows[ASSEMBLY_TABLE] != 1 {
            return Err(malformed(
                "mstat.assembly",
                format!(
                    "expected one Assembly row, found {}",
                    self.rows[ASSEMBLY_TABLE]
                ),
                None,
            ));
        }
        let offset = self.table_offset(ASSEMBLY_TABLE)?;
        let row = checked_slice(self.bytes, offset, self.row_size(ASSEMBLY_TABLE)?)?;
        let version = FormatVersion {
            major: read_u16(row, 4)?,
            minor: read_u16(row, 6)?,
        };
        let name_offset = 16 + self.blob_width;
        let name = self.string(read_index(row, name_offset, self.string_width)?)?;
        let culture = self.string(read_index(
            row,
            name_offset + self.string_width,
            self.string_width,
        )?)?;
        let display = if culture.is_empty() {
            name.to_owned()
        } else {
            format!("{name}, Culture={culture}")
        };
        Ok((version, display))
    }

    fn string(&self, offset: u32) -> Result<&'a str, MstatError> {
        let offset = usize::try_from(offset)
            .map_err(|_| malformed("mstat.strings", "string offset exceeds usize", None))?;
        let tail = self
            .strings
            .get(offset..)
            .ok_or_else(|| malformed("mstat.strings", "string offset is out of range", None))?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed("mstat.strings", "unterminated metadata string", None))?;
        std::str::from_utf8(&tail[..end])
            .map_err(|_| malformed("mstat.strings", "metadata string is not UTF-8", None))
    }

    fn table_offset(&self, target: usize) -> Result<usize, MstatError> {
        let mut offset = self.data_offset;
        for table in 0..target {
            let bytes = self
                .row_size(table)?
                .checked_mul(usize::try_from(self.rows[table]).map_err(|_| {
                    malformed("mstat.table.rows", "table row count exceeds usize", None)
                })?)
                .ok_or_else(|| {
                    malformed("mstat.table.offset", "metadata table size overflow", None)
                })?;
            offset = offset.checked_add(bytes).ok_or_else(|| {
                malformed("mstat.table.offset", "metadata table offset overflow", None)
            })?;
        }
        checked_slice(self.bytes, offset, 0)?;
        Ok(offset)
    }

    #[allow(clippy::too_many_lines)]
    fn row_size(&self, table: usize) -> Result<usize, MstatError> {
        let table_index = |table: usize| self.simple_index(table);
        let coded = |tables: &[usize], tag_bits: u32| self.coded_index(tables, tag_bits);
        let string = self.string_width;
        let guid = self.guid_width;
        let blob = self.blob_width;
        let size = match table {
            0 => 2 + string + guid * 3,
            1 => coded(&[0, 26, 35, 1], 2) + string * 2,
            2 => 4 + string * 2 + coded(&[2, 1, 27], 2) + table_index(4) + table_index(6),
            3 => table_index(4),
            4 | 23 => 2 + string + blob,
            5 => table_index(6),
            6 => 8 + string + blob + table_index(8),
            7 => table_index(8),
            8 => 4 + string,
            9 => table_index(2) + coded(&[2, 1, 27], 2),
            10 => coded(&[2, 1, 26, 6, 27], 3) + string + blob,
            11 => 2 + coded(&[4, 8, 23], 2) + blob,
            12 => {
                coded(
                    &[
                        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44,
                    ],
                    5,
                ) + coded(&[6, 10], 3)
                    + blob
            }
            13 => coded(&[4, 8], 1) + blob,
            14 => 2 + coded(&[2, 6, 32], 2) + blob,
            15 => 6 + table_index(2),
            16 | 29 => 4 + table_index(4),
            17 | 27 => blob,
            18 => table_index(2) + table_index(20),
            19 => table_index(20),
            20 => 2 + string + coded(&[2, 1, 27], 2),
            21 => table_index(2) + table_index(23),
            22 => table_index(23),
            24 => 2 + table_index(6) + coded(&[20, 23], 1),
            25 => table_index(2) + coded(&[6, 10], 1) * 2,
            26 => string,
            28 => 2 + coded(&[4, 6], 1) + string + table_index(26),
            30 => 8,
            31 => 4,
            32 => 16 + blob + string * 2,
            _ if self.rows[table] == 0 => 0,
            _ => {
                return Err(malformed(
                    "mstat.table.unsupported",
                    format!("unsupported populated metadata table {table}"),
                    None,
                ));
            }
        };
        Ok(size)
    }

    fn simple_index(&self, table: usize) -> usize {
        if self.rows[table] < 1 << 16 { 2 } else { 4 }
    }

    fn coded_index(&self, tables: &[usize], tag_bits: u32) -> usize {
        let maximum = tables
            .iter()
            .map(|table| self.rows[*table])
            .max()
            .unwrap_or(0);
        if maximum < (1_u32 << (16 - tag_bits)) {
            2
        } else {
            4
        }
    }
}

fn metadata_streams(metadata: &[u8]) -> Result<(Stream, Stream), MstatError> {
    let mut cursor = Cursor::new(metadata);
    if cursor.u32()? != METADATA_SIGNATURE {
        return Err(malformed(
            "mstat.metadata.signature",
            "invalid CLI metadata signature",
            Some(0),
        ));
    }
    cursor.skip(2 + 2 + 4)?;
    let version_length = usize::try_from(cursor.u32()?).map_err(|_| {
        malformed(
            "mstat.metadata.version",
            "version length exceeds usize",
            None,
        )
    })?;
    cursor.skip(version_length)?;
    cursor.align4()?;
    cursor.skip(2)?;
    let stream_count = usize::from(cursor.u16()?);
    let mut tables = None;
    let mut strings = None;
    for _ in 0..stream_count {
        let offset = usize::try_from(cursor.u32()?)
            .map_err(|_| malformed("mstat.metadata.stream", "stream offset exceeds usize", None))?;
        let size = usize::try_from(cursor.u32()?)
            .map_err(|_| malformed("mstat.metadata.stream", "stream size exceeds usize", None))?;
        let name_start = cursor.position;
        let name_end = cursor
            .remaining()
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                malformed(
                    "mstat.metadata.stream",
                    "unterminated metadata stream name",
                    Some(name_start as u64),
                )
            })?;
        let name = std::str::from_utf8(&cursor.remaining()[..name_end]).map_err(|_| {
            malformed(
                "mstat.metadata.stream",
                "metadata stream name is not UTF-8",
                Some(name_start as u64),
            )
        })?;
        cursor.skip(name_end + 1)?;
        cursor.align4()?;
        checked_slice(metadata, offset, size)?;
        let stream = Stream { offset, size };
        match name {
            "#~" | "#-" => tables = Some(stream),
            "#Strings" => strings = Some(stream),
            _ => {}
        }
    }
    Ok((
        tables.ok_or_else(|| {
            malformed(
                "mstat.metadata.tables",
                "missing #~ or #- metadata stream",
                None,
            )
        })?,
        strings.ok_or_else(|| {
            malformed(
                "mstat.metadata.strings",
                "missing #Strings metadata stream",
                None,
            )
        })?,
    ))
}

fn decode_category(
    name: &str,
    body: MethodBody<'_>,
    mangled_names_bytes: u64,
    details: &mut DecodeDetails,
) -> Result<CategorySummary, MstatError> {
    let mut decoder = IlDecoder::new(body.code, body.file_offset);
    let mut records = 0_u64;
    let mut items = 0_u64;
    let mut aggregate = 0_u64;
    while !decoder.is_empty() {
        match name {
            "Methods" => {
                decoder.token()?;
                let body_size = decoder.size()?;
                let gc_size = decoder.size()?;
                let eh_size = decoder.size()?;
                decoder.mangled_name_offset(mangled_names_bytes)?;
                details.methods.body_bytes = checked_add(details.methods.body_bytes, body_size)?;
                details.methods.gc_info_bytes =
                    checked_add(details.methods.gc_info_bytes, gc_size)?;
                details.methods.exception_info_bytes =
                    checked_add(details.methods.exception_info_bytes, eh_size)?;
                aggregate = checked_add(aggregate, body_size)?;
                aggregate = checked_add(aggregate, gc_size)?;
                aggregate = checked_add(aggregate, eh_size)?;
            }
            "Types" | "RvaFields" => {
                decoder.token()?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
                decoder.mangled_name_offset(mangled_names_bytes)?;
            }
            "Blobs" => {
                decoder.string_token()?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
            }
            "FrozenObjects" => {
                decoder.token()?;
                let size = decoder.size()?;
                aggregate = checked_add(aggregate, size)?;
                decoder.mangled_name_offset(mangled_names_bytes)?;
                if decoder.peek()? == 0xd0 {
                    decoder.token()?;
                    details.frozen.owned_records = checked_add(details.frozen.owned_records, 1)?;
                    details.frozen.owned_bytes = checked_add(details.frozen.owned_bytes, size)?;
                } else {
                    if decoder.i4()? != 0 {
                        return Err(decoder.error(
                            "mstat.il.frozen_owner",
                            "frozen-object owner must be ldtoken or zero",
                        ));
                    }
                    details.frozen.unowned_records =
                        checked_add(details.frozen.unowned_records, 1)?;
                    details.frozen.unowned_bytes = checked_add(details.frozen.unowned_bytes, size)?;
                }
            }
            "ManifestResources" => {
                decoder.i4()?;
                decoder.string_token()?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
            }
            "DeduplicatedMethods" => {
                decoder.token()?;
                let count = decoder.size()?;
                if count > decoder.remaining_len() as u64 / 6 {
                    return Err(decoder.error(
                        "mstat.il.deduplicated",
                        "deduplicated-method count exceeds remaining method body",
                    ));
                }
                for _ in 0..count {
                    decoder.token()?;
                    decoder.mangled_name_offset(mangled_names_bytes)?;
                }
                items = checked_add(items, count)?;
            }
            _ => unreachable!("caller only passes required stream names"),
        }
        records = checked_add(records, 1)?;
    }
    if name == "DeduplicatedMethods" {
        details.deduplication.groups = records;
        details.deduplication.folded_methods = items;
    }
    Ok(CategorySummary {
        name: name.into(),
        records,
        items,
        aggregate_size_bytes: aggregate,
        encoded_bytes: body.code.len() as u64,
    })
}

struct IlDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
    file_offset: u64,
}

impl<'a> IlDecoder<'a> {
    const fn new(bytes: &'a [u8], file_offset: u64) -> Self {
        Self {
            bytes,
            position: 0,
            file_offset,
        }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn peek(&self) -> Result<u8, MstatError> {
        self.remaining()
            .first()
            .copied()
            .ok_or_else(|| self.error("mstat.il.truncated", "truncated IL record"))
    }

    fn byte(&mut self) -> Result<u8, MstatError> {
        let byte = self.peek()?;
        self.position += 1;
        Ok(byte)
    }

    fn token(&mut self) -> Result<u32, MstatError> {
        self.opcode(0xd0, "ldtoken")?;
        self.u32()
    }

    fn string_token(&mut self) -> Result<u32, MstatError> {
        self.opcode(0x72, "ldstr")?;
        self.u32()
    }

    fn opcode(&mut self, expected: u8, name: &str) -> Result<(), MstatError> {
        let actual = self.byte()?;
        if actual == expected {
            Ok(())
        } else {
            Err(self.error(
                "mstat.il.opcode",
                format!("expected {name} (0x{expected:02x}), found 0x{actual:02x}"),
            ))
        }
    }

    fn i4(&mut self) -> Result<i32, MstatError> {
        let opcode = self.byte()?;
        match opcode {
            0x15 => Ok(-1),
            0x16..=0x1e => Ok(i32::from(opcode - 0x16)),
            0x1f => Ok(i32::from(i8::from_le_bytes([self.byte()?]))),
            0x20 => Ok(i32::from_le_bytes(self.array4()?)),
            _ => Err(self.error(
                "mstat.il.opcode",
                format!("expected ldc.i4, found 0x{opcode:02x}"),
            )),
        }
    }

    fn size(&mut self) -> Result<u64, MstatError> {
        let value = self.i4()?;
        u64::try_from(value).map_err(|_| {
            self.error(
                "mstat.il.size",
                format!("size/count value {value} is negative"),
            )
        })
    }

    fn mangled_name_offset(&mut self, section_size: u64) -> Result<u64, MstatError> {
        let offset = self.size()?;
        if offset < section_size {
            Ok(offset)
        } else {
            Err(self.error(
                "mstat.names.offset",
                format!("mangled-name offset {offset} exceeds .names section size {section_size}"),
            ))
        }
    }

    fn u32(&mut self) -> Result<u32, MstatError> {
        Ok(u32::from_le_bytes(self.array4()?))
    }

    fn array4(&mut self) -> Result<[u8; 4], MstatError> {
        let bytes = checked_slice(self.bytes, self.position, 4).map_err(|_| {
            self.error(
                "mstat.il.truncated",
                "truncated four-byte IL instruction operand",
            )
        })?;
        self.position += 4;
        Ok(bytes.try_into().expect("slice length is checked"))
    }

    fn error(&self, code: &str, message: impl Into<String>) -> MstatError {
        malformed(code, message, Some(self.file_offset + self.position as u64))
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn skip(&mut self, count: usize) -> Result<(), MstatError> {
        checked_slice(self.bytes, self.position, count)?;
        self.position += count;
        Ok(())
    }

    fn align4(&mut self) -> Result<(), MstatError> {
        let aligned = self
            .position
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or_else(|| malformed("mstat.offset", "alignment overflow", None))?;
        self.skip(aligned - self.position)
    }

    fn u8(&mut self) -> Result<u8, MstatError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| truncated(self.position, 1, self.bytes.len()))?;
        self.position += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, MstatError> {
        let value = read_u16(self.bytes, self.position)?;
        self.position += 2;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, MstatError> {
        let value = read_u32(self.bytes, self.position)?;
        self.position += 4;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, MstatError> {
        let value = read_u64(self.bytes, self.position)?;
        self.position += 8;
        Ok(value)
    }
}

fn read_index(bytes: &[u8], offset: usize, width: usize) -> Result<u32, MstatError> {
    match width {
        2 => Ok(u32::from(read_u16(bytes, offset)?)),
        4 => read_u32(bytes, offset),
        _ => unreachable!("metadata index widths are two or four"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, MstatError> {
    Ok(u16::from_le_bytes(
        checked_slice(bytes, offset, 2)?
            .try_into()
            .expect("slice length is checked"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, MstatError> {
    Ok(u32::from_le_bytes(
        checked_slice(bytes, offset, 4)?
            .try_into()
            .expect("slice length is checked"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, MstatError> {
    Ok(u64::from_le_bytes(
        checked_slice(bytes, offset, 8)?
            .try_into()
            .expect("slice length is checked"),
    ))
}

fn checked_slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], MstatError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| malformed("mstat.offset", "offset plus length overflow", None))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| truncated(offset, length, bytes.len()))
}

fn checked_add(left: u64, right: u64) -> Result<u64, MstatError> {
    left.checked_add(right)
        .ok_or_else(|| malformed("mstat.size.overflow", "MSTAT aggregate overflow", None))
}

fn truncated(offset: usize, length: usize, input_length: usize) -> MstatError {
    let mut diagnostic = Diagnostic::malformed(
        "mstat.truncated",
        format!("range at byte {offset} with length {length} exceeds input length {input_length}"),
    );
    diagnostic.byte_offset = Some(offset as u64);
    diagnostic.expected = Some(format!("{length} bytes"));
    diagnostic.actual = Some(input_length.saturating_sub(offset).to_string());
    MstatError {
        diagnostic: Box::new(diagnostic),
    }
}

fn malformed(
    code: impl Into<String>,
    message: impl Into<String>,
    offset: Option<u64>,
) -> MstatError {
    let mut diagnostic = Diagnostic::malformed(code, message);
    diagnostic.byte_offset = offset;
    MstatError {
        diagnostic: Box::new(diagnostic),
    }
}

fn resource_error(message: impl Into<String>) -> MstatError {
    MstatError {
        diagnostic: Box::new(Diagnostic::malformed("resource.memory_limit", message)),
    }
}
