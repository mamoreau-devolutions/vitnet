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
const USER_STRING_TOKEN: u32 = 0x7000_0000;
const TOKEN_RID_MASK: u32 = 0x00ff_ffff;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatDiffEntry {
    pub identity: String,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub delta_bytes: i128,
    pub before_records: u64,
    pub after_records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatDiffSection {
    pub name: String,
    pub accounted: bool,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub delta_bytes: i128,
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
    pub entries: Vec<MstatDiffEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatReconciliation {
    pub before_accounted_bytes: u64,
    pub after_accounted_bytes: u64,
    pub section_delta_sum: i128,
    pub total_delta_bytes: i128,
    pub balanced: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatDiff {
    pub schema: String,
    pub before_assembly: String,
    pub after_assembly: String,
    pub before_input_bytes: u64,
    pub after_input_bytes: u64,
    pub total_delta_bytes: i128,
    pub sections: Vec<MstatDiffSection>,
    pub before_deduplicated_methods: DeduplicationSummary,
    pub after_deduplicated_methods: DeduplicationSummary,
    pub reconciliation: MstatReconciliation,
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

#[derive(Clone, Copy)]
enum EntityKind {
    Method,
    Type,
    Field,
    AssemblyRef,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentitySource {
    Names,
    UserStrings,
    Owned,
}

#[derive(Clone, Copy, Debug)]
struct IdentityRef {
    source: IdentitySource,
    offset: u32,
    length: u32,
}

#[derive(Clone, Copy, Debug)]
struct InventoryRecord {
    fingerprint: [u8; 16],
    identity: IdentityRef,
    bytes: u64,
    records: u64,
}

struct InventorySection {
    name: &'static str,
    accounted: bool,
    records: Vec<InventoryRecord>,
}

struct Inventory<'a> {
    summary: MstatSummary,
    names: &'a [u8],
    user_strings: &'a [u8],
    owned_identities: Vec<Vec<u8>>,
    sections: Vec<InventorySection>,
    tracked_memory_bytes: u64,
}

#[derive(Clone, Copy)]
enum CandidateSide {
    Before,
    After,
}

#[derive(Clone, Copy)]
struct DiffCandidate {
    side: CandidateSide,
    record: InventoryRecord,
    before_bytes: u64,
    after_bytes: u64,
    before_records: u64,
    after_records: u64,
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

/// Memory-maps and structurally compares two MSTAT 2.2 files.
///
/// # Errors
///
/// Returns a typed I/O, malformed-input, or resource-limit diagnostic.
pub fn diff_paths(
    before: &Path,
    after: &Path,
    memory_limit: u64,
    top: usize,
) -> Result<MstatDiff, MstatError> {
    let before_data = mmap_guard::map_file(before).map_err(|error| {
        let mut diagnostic = Diagnostic::malformed("mstat.io", error.to_string());
        diagnostic.input_path = Some(before.to_owned());
        MstatError {
            diagnostic: Box::new(diagnostic),
        }
    })?;
    if before == after {
        return diff(&before_data, &before_data, memory_limit, top).map_err(|mut error| {
            error.diagnostic.input_path = Some(before.to_owned());
            error
        });
    }
    let after_data = mmap_guard::map_file(after).map_err(|error| {
        let mut diagnostic = Diagnostic::malformed("mstat.io", error.to_string());
        diagnostic.input_path = Some(after.to_owned());
        MstatError {
            diagnostic: Box::new(diagnostic),
        }
    })?;
    diff(&before_data, &after_data, memory_limit, top)
}

/// Structurally compares two in-memory MSTAT 2.2 images.
///
/// # Errors
///
/// Returns a typed malformed-input or resource-limit diagnostic.
pub fn diff(
    before: &[u8],
    after: &[u8],
    memory_limit: u64,
    top: usize,
) -> Result<MstatDiff, MstatError> {
    ResourceBudget::new(memory_limit, 0, 1, None)
        .check(MIN_TRACKED_MEMORY, 0)
        .map_err(|error| resource_error(error.to_string()))?;
    let per_input_limit = memory_limit.saturating_sub(MIN_TRACKED_MEMORY) / 2;
    let mut before_inventory = Inventory::parse(before, per_input_limit)?;
    let mut after_inventory = Inventory::parse(after, per_input_limit)?;
    before_inventory.sort_and_coalesce()?;
    after_inventory.sort_and_coalesce()?;
    diff_inventories(&before_inventory, &after_inventory, memory_limit, top)
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
    let (tables_stream, strings_stream, user_strings_stream) = metadata_streams(metadata)?;
    let tables_bytes = checked_slice(metadata, tables_stream.offset, tables_stream.size)?;
    let strings = checked_slice(metadata, strings_stream.offset, strings_stream.size)?;
    let user_strings = checked_slice(
        metadata,
        user_strings_stream.offset,
        user_strings_stream.size,
    )?;
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

    let names_section = image
        .sections
        .iter()
        .find(|section| section.name == b".names")
        .ok_or_else(|| malformed("mstat.section.names", "missing .names section", None))?;
    let names = image.section_logical_slice(names_section)?;
    let mangled_names_bytes = names.len() as u64;
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
            &tables,
            names,
            user_strings,
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

impl<'a> Inventory<'a> {
    fn parse(bytes: &'a [u8], memory_limit: u64) -> Result<Self, MstatError> {
        let summary = summarize(bytes, memory_limit.max(MIN_TRACKED_MEMORY))?;
        let expected_records = summary
            .categories
            .iter()
            .try_fold(0_u64, |total, category| {
                total.checked_add(if category.name == "DeduplicatedMethods" {
                    category.items
                } else {
                    category.records
                })
            })
            .ok_or_else(|| malformed("mstat.diff.records", "record count overflow", None))?;
        let required = expected_records
            .checked_mul(size_of::<InventoryRecord>() as u64)
            .ok_or_else(|| malformed("mstat.diff.memory", "inventory size overflow", None))?;
        if required > memory_limit {
            return Err(resource_error(format!(
                "MSTAT diff inventory requires at least {required} bytes per input; limit provides {memory_limit}"
            )));
        }

        let image = PeImage::parse(bytes)?;
        let metadata = image.rva_slice(image.metadata_rva, image.metadata_size)?;
        let (tables_stream, strings_stream, user_strings_stream) = metadata_streams(metadata)?;
        let tables = Tables::parse(
            checked_slice(metadata, tables_stream.offset, tables_stream.size)?,
            checked_slice(metadata, strings_stream.offset, strings_stream.size)?,
        )?;
        let user_strings = checked_slice(
            metadata,
            user_strings_stream.offset,
            user_strings_stream.size,
        )?;
        let names_section = image
            .sections
            .iter()
            .find(|section| section.name == b".names")
            .ok_or_else(|| malformed("mstat.section.names", "missing .names section", None))?;
        let names = image.section_logical_slice(names_section)?;

        let mut inventory = Self {
            summary,
            names,
            user_strings,
            owned_identities: Vec::new(),
            sections: REQUIRED_STREAMS
                .iter()
                .enumerate()
                .map(|(index, name)| InventorySection {
                    name,
                    accounted: index < 3,
                    records: Vec::new(),
                })
                .collect(),
            tracked_memory_bytes: required,
        };
        for (section, category) in inventory
            .sections
            .iter_mut()
            .zip(&inventory.summary.categories)
        {
            let count = if category.name == "DeduplicatedMethods" {
                category.items
            } else {
                category.records
            };
            section
                .records
                .try_reserve_exact(usize::try_from(count).map_err(|_| {
                    resource_error("MSTAT diff record count exceeds addressable memory")
                })?)
                .map_err(|error| {
                    resource_error(format!("unable to reserve MSTAT diff inventory: {error}"))
                })?;
        }

        for row in tables.methods()? {
            let name = tables.string(row.name)?;
            let Some(index) = REQUIRED_STREAMS
                .iter()
                .position(|candidate| *candidate == name)
            else {
                continue;
            };
            let body = image.method_body(row.rva)?;
            decode_inventory_category(
                name,
                body,
                &tables,
                names,
                user_strings,
                &mut inventory.sections[index].records,
                &mut inventory.owned_identities,
            )?;
        }
        Ok(inventory)
    }

    fn sort_and_coalesce(&mut self) -> Result<(), MstatError> {
        let names = self.names;
        let user_strings = self.user_strings;
        let owned = &self.owned_identities;
        for section in &mut self.sections {
            section.records.sort_unstable_by(|left, right| {
                compare_records(names, user_strings, owned, left, right)
            });
            let mut write = 0;
            for read in 0..section.records.len() {
                if write > 0
                    && compare_records(
                        names,
                        user_strings,
                        owned,
                        &section.records[write - 1],
                        &section.records[read],
                    )
                    .is_eq()
                {
                    section.records[write - 1].bytes = section.records[write - 1]
                        .bytes
                        .checked_add(section.records[read].bytes)
                        .ok_or_else(|| {
                            malformed("mstat.diff.size", "identity size overflow", None)
                        })?;
                    section.records[write - 1].records = section.records[write - 1]
                        .records
                        .checked_add(section.records[read].records)
                        .ok_or_else(|| {
                            malformed("mstat.diff.records", "identity count overflow", None)
                        })?;
                } else {
                    section.records[write] = section.records[read];
                    write += 1;
                }
            }
            section.records.truncate(write);
        }
        Ok(())
    }

    fn identity_bytes(&self, identity: IdentityRef) -> &[u8] {
        identity_bytes(
            self.names,
            self.user_strings,
            &self.owned_identities,
            identity,
        )
    }

    fn identity_display(&self, identity: IdentityRef) -> String {
        let bytes = self.identity_bytes(identity);
        let value = match identity.source {
            IdentitySource::UserStrings => {
                let utf16 = bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
                char::decode_utf16(utf16)
                    .map(|scalar| scalar.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect::<String>()
            }
            IdentitySource::Names | IdentitySource::Owned => {
                String::from_utf8_lossy(bytes).into_owned()
            }
        };
        truncate_identity(value, 256)
    }
}

fn decode_inventory_category(
    name: &str,
    body: MethodBody<'_>,
    tables: &Tables<'_>,
    names: &[u8],
    user_strings: &[u8],
    records: &mut Vec<InventoryRecord>,
    owned: &mut Vec<Vec<u8>>,
) -> Result<(), MstatError> {
    let mut decoder = IlDecoder::new(body.code, body.file_offset);
    while !decoder.is_empty() {
        match name {
            "Methods" => {
                tables.validate_token(decoder.token()?, EntityKind::Method)?;
                let body_size = decoder.size()?;
                let gc_size = decoder.size()?;
                let eh_size = decoder.size()?;
                let size = body_size
                    .checked_add(gc_size)
                    .and_then(|value| value.checked_add(eh_size))
                    .ok_or_else(|| malformed("mstat.diff.size", "method size overflow", None))?;
                let identity = name_identity(names, &mut decoder)?;
                records.push(inventory_record(identity, size, names, user_strings, owned));
            }
            "Types" => {
                tables.validate_token(decoder.token()?, EntityKind::Type)?;
                let size = decoder.size()?;
                let identity = name_identity(names, &mut decoder)?;
                records.push(inventory_record(identity, size, names, user_strings, owned));
            }
            "Blobs" => {
                let identity = user_string_identity(user_strings, decoder.string_token()?)?;
                let size = decoder.size()?;
                records.push(inventory_record(identity, size, names, user_strings, owned));
            }
            "RvaFields" => {
                tables.validate_token(decoder.token()?, EntityKind::Field)?;
                let size = decoder.size()?;
                let identity = name_identity(names, &mut decoder)?;
                records.push(inventory_record(identity, size, names, user_strings, owned));
            }
            "FrozenObjects" => {
                tables.validate_token(decoder.token()?, EntityKind::Type)?;
                let size = decoder.size()?;
                let identity = name_identity(names, &mut decoder)?;
                if decoder.peek()? == 0xd0 {
                    tables.validate_token(decoder.token()?, EntityKind::Type)?;
                } else if decoder.i4()? != 0 {
                    return Err(decoder.error(
                        "mstat.il.frozen_owner",
                        "frozen-object owner must be ldtoken or zero",
                    ));
                }
                records.push(inventory_record(identity, size, names, user_strings, owned));
            }
            "ManifestResources" => {
                let token = u32::try_from(decoder.i4()?).map_err(|_| {
                    decoder.error(
                        "mstat.token",
                        "manifest-resource assembly token is negative",
                    )
                })?;
                tables.validate_token(token, EntityKind::AssemblyRef)?;
                let resource = user_string_identity(user_strings, decoder.string_token()?)?;
                let size = decoder.size()?;
                let mut identity = tables.assembly_ref_identity(token)?.into_bytes();
                identity.push(0);
                identity.extend_from_slice(identity_bytes(names, user_strings, owned, resource));
                let owned_index = owned.len();
                owned.push(identity);
                let identity = IdentityRef {
                    source: IdentitySource::Owned,
                    offset: u32::try_from(owned_index)
                        .map_err(|_| resource_error("too many owned MSTAT diff identities"))?,
                    length: 0,
                };
                records.push(inventory_record(identity, size, names, user_strings, owned));
            }
            "DeduplicatedMethods" => {
                tables.validate_token(decoder.token()?, EntityKind::Method)?;
                let count = decoder.size()?;
                if count > decoder.remaining_len() as u64 / 6 {
                    return Err(decoder.error(
                        "mstat.il.deduplicated",
                        "deduplicated-method count exceeds remaining method body",
                    ));
                }
                for _ in 0..count {
                    tables.validate_token(decoder.token()?, EntityKind::Method)?;
                    let identity = name_identity(names, &mut decoder)?;
                    records.push(inventory_record(identity, 0, names, user_strings, owned));
                }
            }
            _ => unreachable!("caller only passes required stream names"),
        }
    }
    Ok(())
}

fn name_identity(names: &[u8], decoder: &mut IlDecoder<'_>) -> Result<IdentityRef, MstatError> {
    let offset = decoder.mangled_name_offset(names.len() as u64)?;
    let (value_offset, length) = ser_string_range(names, offset)?;
    Ok(IdentityRef {
        source: IdentitySource::Names,
        offset: u32::try_from(value_offset)
            .map_err(|_| resource_error("MSTAT name offset exceeds u32"))?,
        length: u32::try_from(length)
            .map_err(|_| resource_error("MSTAT name length exceeds u32"))?,
    })
}

fn user_string_identity(bytes: &[u8], token: u32) -> Result<IdentityRef, MstatError> {
    let (value_offset, length) = user_string_range(bytes, token)?;
    Ok(IdentityRef {
        source: IdentitySource::UserStrings,
        offset: u32::try_from(value_offset)
            .map_err(|_| resource_error("MSTAT user-string offset exceeds u32"))?,
        length: u32::try_from(length)
            .map_err(|_| resource_error("MSTAT user-string length exceeds u32"))?,
    })
}

fn inventory_record(
    identity: IdentityRef,
    bytes: u64,
    names: &[u8],
    user_strings: &[u8],
    owned: &[Vec<u8>],
) -> InventoryRecord {
    let hash = blake3::hash(identity_bytes(names, user_strings, owned, identity));
    let mut fingerprint = [0_u8; 16];
    fingerprint.copy_from_slice(&hash.as_bytes()[..16]);
    InventoryRecord {
        fingerprint,
        identity,
        bytes,
        records: 1,
    }
}

fn identity_bytes<'a>(
    names: &'a [u8],
    user_strings: &'a [u8],
    owned: &'a [Vec<u8>],
    identity: IdentityRef,
) -> &'a [u8] {
    match identity.source {
        IdentitySource::Names => {
            let start = identity.offset as usize;
            &names[start..start + identity.length as usize]
        }
        IdentitySource::UserStrings => {
            let start = identity.offset as usize;
            &user_strings[start..start + identity.length as usize]
        }
        IdentitySource::Owned => &owned[identity.offset as usize],
    }
}

fn compare_records(
    names: &[u8],
    user_strings: &[u8],
    owned: &[Vec<u8>],
    left: &InventoryRecord,
    right: &InventoryRecord,
) -> std::cmp::Ordering {
    left.fingerprint.cmp(&right.fingerprint).then_with(|| {
        identity_bytes(names, user_strings, owned, left.identity).cmp(identity_bytes(
            names,
            user_strings,
            owned,
            right.identity,
        ))
    })
}

fn compare_cross(
    before: &Inventory<'_>,
    left: &InventoryRecord,
    after: &Inventory<'_>,
    right: &InventoryRecord,
) -> std::cmp::Ordering {
    left.fingerprint.cmp(&right.fingerprint).then_with(|| {
        before
            .identity_bytes(left.identity)
            .cmp(after.identity_bytes(right.identity))
    })
}

fn diff_inventories(
    before: &Inventory<'_>,
    after: &Inventory<'_>,
    memory_limit: u64,
    top: usize,
) -> Result<MstatDiff, MstatError> {
    let tracked = inventory_tracked_bytes(before)
        .checked_add(inventory_tracked_bytes(after))
        .ok_or_else(|| malformed("mstat.diff.memory", "tracked-memory overflow", None))?;
    if tracked > memory_limit {
        return Err(resource_error(format!(
            "MSTAT diff state requires {tracked} bytes, exceeding the {memory_limit}-byte limit"
        )));
    }

    let mut sections = Vec::with_capacity(REQUIRED_STREAMS.len());
    for index in 0..REQUIRED_STREAMS.len() {
        sections.push(diff_section(
            before,
            &before.sections[index],
            after,
            &after.sections[index],
            top,
        )?);
    }
    let section_delta_sum = sections
        .iter()
        .filter(|section| section.accounted)
        .map(|section| section.delta_bytes)
        .sum::<i128>();
    let total_delta_bytes = i128::from(after.summary.accounted_size_bytes)
        - i128::from(before.summary.accounted_size_bytes);
    let reconciliation = MstatReconciliation {
        before_accounted_bytes: before.summary.accounted_size_bytes,
        after_accounted_bytes: after.summary.accounted_size_bytes,
        section_delta_sum,
        total_delta_bytes,
        balanced: section_delta_sum == total_delta_bytes,
    };
    if !reconciliation.balanced {
        return Err(malformed(
            "mstat.diff.reconciliation",
            "accounted section deltas do not reconcile to the overall delta",
            None,
        ));
    }
    Ok(MstatDiff {
        schema: "vitnet.mstat-diff.v1".into(),
        before_assembly: before.summary.assembly.clone(),
        after_assembly: after.summary.assembly.clone(),
        before_input_bytes: before.summary.input_bytes,
        after_input_bytes: after.summary.input_bytes,
        total_delta_bytes,
        sections,
        before_deduplicated_methods: before.summary.deduplicated_methods.clone(),
        after_deduplicated_methods: after.summary.deduplicated_methods.clone(),
        reconciliation,
        peak_tracked_memory_bytes: tracked,
    })
}

#[allow(clippy::too_many_lines)]
fn diff_section(
    before: &Inventory<'_>,
    before_section: &InventorySection,
    after: &Inventory<'_>,
    after_section: &InventorySection,
    top: usize,
) -> Result<MstatDiffSection, MstatError> {
    let before_bytes = sum_record_bytes(&before_section.records)?;
    let after_bytes = sum_record_bytes(&after_section.records)?;
    let mut left = 0;
    let mut right = 0;
    let mut added = 0_u64;
    let mut removed = 0_u64;
    let mut changed = 0_u64;
    let mut candidates = Vec::<DiffCandidate>::with_capacity(top.min(1024));
    while left < before_section.records.len() || right < after_section.records.len() {
        let ordering = match (
            before_section.records.get(left),
            after_section.records.get(right),
        ) {
            (Some(before_record), Some(after_record)) => {
                compare_cross(before, before_record, after, after_record)
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => break,
        };
        match ordering {
            std::cmp::Ordering::Less => {
                let record = before_section.records[left];
                removed = removed.saturating_add(1);
                consider_candidate(
                    &mut candidates,
                    DiffCandidate {
                        side: CandidateSide::Before,
                        record,
                        before_bytes: record.bytes,
                        after_bytes: 0,
                        before_records: record.records,
                        after_records: 0,
                    },
                    top,
                    before,
                    after,
                );
                left += 1;
            }
            std::cmp::Ordering::Greater => {
                let record = after_section.records[right];
                added = added.saturating_add(1);
                consider_candidate(
                    &mut candidates,
                    DiffCandidate {
                        side: CandidateSide::After,
                        record,
                        before_bytes: 0,
                        after_bytes: record.bytes,
                        before_records: 0,
                        after_records: record.records,
                    },
                    top,
                    before,
                    after,
                );
                right += 1;
            }
            std::cmp::Ordering::Equal => {
                let before_record = before_section.records[left];
                let after_record = after_section.records[right];
                if before_record.bytes != after_record.bytes
                    || before_record.records != after_record.records
                {
                    changed = changed.saturating_add(1);
                    consider_candidate(
                        &mut candidates,
                        DiffCandidate {
                            side: CandidateSide::After,
                            record: after_record,
                            before_bytes: before_record.bytes,
                            after_bytes: after_record.bytes,
                            before_records: before_record.records,
                            after_records: after_record.records,
                        },
                        top,
                        before,
                        after,
                    );
                }
                left += 1;
                right += 1;
            }
        }
    }
    candidates.sort_by(|left, right| compare_candidates(left, right, before, after));
    let entries = candidates
        .into_iter()
        .map(|candidate| {
            let inventory = match candidate.side {
                CandidateSide::Before => before,
                CandidateSide::After => after,
            };
            MstatDiffEntry {
                identity: inventory.identity_display(candidate.record.identity),
                before_bytes: candidate.before_bytes,
                after_bytes: candidate.after_bytes,
                delta_bytes: i128::from(candidate.after_bytes) - i128::from(candidate.before_bytes),
                before_records: candidate.before_records,
                after_records: candidate.after_records,
            }
        })
        .collect();
    Ok(MstatDiffSection {
        name: before_section.name.into(),
        accounted: before_section.accounted,
        before_bytes,
        after_bytes,
        delta_bytes: i128::from(after_bytes) - i128::from(before_bytes),
        added,
        removed,
        changed,
        entries,
    })
}

fn consider_candidate(
    candidates: &mut Vec<DiffCandidate>,
    candidate: DiffCandidate,
    top: usize,
    before: &Inventory<'_>,
    after: &Inventory<'_>,
) {
    if top == 0 {
        return;
    }
    candidates.push(candidate);
    candidates.sort_by(|left, right| compare_candidates(left, right, before, after));
    candidates.truncate(top);
}

fn compare_candidates(
    left: &DiffCandidate,
    right: &DiffCandidate,
    before: &Inventory<'_>,
    after: &Inventory<'_>,
) -> std::cmp::Ordering {
    let left_delta = i128::from(left.after_bytes) - i128::from(left.before_bytes);
    let right_delta = i128::from(right.after_bytes) - i128::from(right.before_bytes);
    right_delta
        .unsigned_abs()
        .cmp(&left_delta.unsigned_abs())
        .then_with(|| right_delta.cmp(&left_delta))
        .then_with(|| {
            candidate_identity(left, before, after).cmp(candidate_identity(right, before, after))
        })
}

fn candidate_identity<'a>(
    candidate: &DiffCandidate,
    before: &'a Inventory<'_>,
    after: &'a Inventory<'_>,
) -> &'a [u8] {
    match candidate.side {
        CandidateSide::Before => before.identity_bytes(candidate.record.identity),
        CandidateSide::After => after.identity_bytes(candidate.record.identity),
    }
}

fn sum_record_bytes(records: &[InventoryRecord]) -> Result<u64, MstatError> {
    records.iter().try_fold(0_u64, |total, record| {
        total
            .checked_add(record.bytes)
            .ok_or_else(|| malformed("mstat.diff.size", "section size overflow", None))
    })
}

fn inventory_tracked_bytes(inventory: &Inventory<'_>) -> u64 {
    let records = inventory
        .sections
        .iter()
        .map(|section| {
            (section.records.capacity() as u64).saturating_mul(size_of::<InventoryRecord>() as u64)
        })
        .sum::<u64>();
    let owned = inventory
        .owned_identities
        .iter()
        .map(|value| value.capacity() as u64)
        .sum::<u64>();
    records
        .saturating_add(owned)
        .saturating_add(inventory.tracked_memory_bytes.min(MIN_TRACKED_MEMORY))
}

fn truncate_identity(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push('…');
    value
}

impl<'a> PeImage<'a> {
    #[allow(clippy::too_many_lines)]
    fn parse(bytes: &'a [u8]) -> Result<Self, MstatError> {
        if checked_slice(bytes, 0, 2)? != b"MZ" {
            return Err(malformed(
                "mstat.pe.dos_signature",
                "invalid DOS MZ signature",
                Some(0),
            ));
        }
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
        let directory_offset: usize = match magic {
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
        let directory_relative = directory_offset
            .checked_add(CLI_DIRECTORY_INDEX * 8)
            .ok_or_else(|| {
                malformed(
                    "mstat.pe.offset",
                    "CLI-directory relative offset overflow",
                    None,
                )
            })?;
        if directory_relative + 8 > optional_size {
            return Err(malformed(
                "mstat.pe.cli",
                "optional header does not contain a CLI data directory",
                Some(optional as u64),
            ));
        }
        let directory_count_offset = match magic {
            0x10b => 92,
            0x20b => 108,
            _ => unreachable!("PE magic was validated"),
        };
        if read_u32(bytes, optional + directory_count_offset)? <= 14 {
            return Err(malformed(
                "mstat.pe.cli",
                "PE declares no CLI data directory",
                Some((optional + directory_count_offset) as u64),
            ));
        }
        let cli_directory = optional
            .checked_add(directory_relative)
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
        let section_table_bytes = section_count
            .checked_mul(40)
            .ok_or_else(|| malformed("mstat.pe.section", "section table size overflow", None))?;
        checked_slice(bytes, section_headers, section_table_bytes)?;
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
        for (index, section) in sections.iter().enumerate() {
            let section_start = u64::from(section.raw_offset);
            let section_end = section_start + u64::from(section.raw_size);
            for other in &sections[..index] {
                let other_start = u64::from(other.raw_offset);
                let other_end = other_start + u64::from(other.raw_size);
                if section.raw_size != 0
                    && other.raw_size != 0
                    && section_start < other_end
                    && other_start < section_end
                {
                    return Err(malformed(
                        "mstat.pe.section_overlap",
                        "PE sections have overlapping raw ranges",
                        Some(section_start),
                    ));
                }
            }
        }
        if sections
            .iter()
            .filter(|section| section.name == b".names")
            .count()
            > 1
        {
            return Err(malformed(
                "mstat.section.names",
                "duplicate .names sections",
                None,
            ));
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

    fn section_logical_slice(&self, section: &Section<'_>) -> Result<&'a [u8], MstatError> {
        if section.virtual_size > section.raw_size {
            return Err(malformed(
                "mstat.pe.section",
                format!(
                    "section {} virtual size exceeds its raw data",
                    String::from_utf8_lossy(section.name)
                ),
                Some(u64::from(section.raw_offset)),
            ));
        }
        checked_slice(
            self.bytes,
            usize::try_from(section.raw_offset)
                .map_err(|_| malformed("mstat.pe.section", "section offset exceeds usize", None))?,
            usize::try_from(section.virtual_size)
                .map_err(|_| malformed("mstat.pe.section", "section size exceeds usize", None))?,
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
            31 | 33 => 4,
            32 => 16 + blob + string * 2,
            34 => 12,
            35 => 12 + blob * 2 + string * 2,
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

    fn validate_token(&self, token: u32, kind: EntityKind) -> Result<(), MstatError> {
        let table = usize::try_from(token >> 24)
            .map_err(|_| malformed("mstat.token", "token table exceeds usize", None))?;
        let rid = token & TOKEN_RID_MASK;
        let allowed = match kind {
            EntityKind::Method => matches!(table, 6 | 10 | 43),
            EntityKind::Type => matches!(table, 1 | 2 | 27),
            EntityKind::Field => matches!(table, 4 | 10),
            EntityKind::AssemblyRef => table == 35,
        };
        if !allowed {
            return Err(malformed(
                "mstat.token.kind",
                format!("metadata token 0x{token:08x} has an unexpected table"),
                None,
            ));
        }
        if rid == 0 || rid > self.rows[table] {
            return Err(malformed(
                "mstat.token.rid",
                format!(
                    "metadata token 0x{token:08x} references row {rid}, but table {table} has {} rows",
                    self.rows[table]
                ),
                None,
            ));
        }
        Ok(())
    }

    fn assembly_ref_identity(&self, token: u32) -> Result<String, MstatError> {
        self.validate_token(token, EntityKind::AssemblyRef)?;
        let row_index = usize::try_from((token & TOKEN_RID_MASK) - 1)
            .map_err(|_| malformed("mstat.token.rid", "assembly row exceeds usize", None))?;
        let row_size = self.row_size(35)?;
        let offset = self
            .table_offset(35)?
            .checked_add(row_index.checked_mul(row_size).ok_or_else(|| {
                malformed("mstat.table.offset", "assembly row offset overflow", None)
            })?)
            .ok_or_else(|| malformed("mstat.table.offset", "assembly row offset overflow", None))?;
        let row = checked_slice(self.bytes, offset, row_size)?;
        let name_offset = 12 + self.blob_width;
        let name = self.string(read_index(row, name_offset, self.string_width)?)?;
        let culture = self.string(read_index(
            row,
            name_offset + self.string_width,
            self.string_width,
        )?)?;
        Ok(if culture.is_empty() {
            name.to_owned()
        } else {
            format!("{name}, Culture={culture}")
        })
    }
}

#[allow(clippy::too_many_lines)]
fn metadata_streams(metadata: &[u8]) -> Result<(Stream, Stream, Stream), MstatError> {
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
    let mut user_strings = None;
    let mut ranges = Vec::<(usize, usize, String)>::with_capacity(stream_count);
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
        let end = offset
            .checked_add(size)
            .ok_or_else(|| malformed("mstat.metadata.stream", "stream range overflow", None))?;
        if let Some((_, _, existing)) = ranges
            .iter()
            .find(|(start, existing_end, _)| size != 0 && offset < *existing_end && *start < end)
        {
            return Err(malformed(
                "mstat.metadata.stream_overlap",
                format!("metadata streams `{existing}` and `{name}` overlap"),
                Some(offset as u64),
            ));
        }
        if ranges.iter().any(|(_, _, existing)| existing == name) {
            return Err(malformed(
                "mstat.metadata.stream_duplicate",
                format!("duplicate metadata stream `{name}`"),
                Some(name_start as u64),
            ));
        }
        ranges.push((offset, end, name.to_owned()));
        let stream = Stream { offset, size };
        match name {
            "#~" | "#-" => {
                if tables.replace(stream).is_some() {
                    return Err(malformed(
                        "mstat.metadata.tables",
                        "multiple metadata table streams",
                        Some(name_start as u64),
                    ));
                }
            }
            "#Strings" => strings = Some(stream),
            "#US" => user_strings = Some(stream),
            _ => {}
        }
    }
    let tables = tables.ok_or_else(|| {
        malformed(
            "mstat.metadata.tables",
            "missing #~ or #- metadata stream",
            None,
        )
    })?;
    let strings = strings.ok_or_else(|| {
        malformed(
            "mstat.metadata.strings",
            "missing #Strings metadata stream",
            None,
        )
    })?;
    let user_strings = user_strings.ok_or_else(|| {
        malformed(
            "mstat.metadata.user_strings",
            "missing #US metadata stream",
            None,
        )
    })?;
    Ok((tables, strings, user_strings))
}

fn decode_category(
    name: &str,
    body: MethodBody<'_>,
    tables: &Tables<'_>,
    names: &[u8],
    user_strings: &[u8],
    details: &mut DecodeDetails,
) -> Result<CategorySummary, MstatError> {
    let mut decoder = IlDecoder::new(body.code, body.file_offset);
    let mut records = 0_u64;
    let mut items = 0_u64;
    let mut aggregate = 0_u64;
    while !decoder.is_empty() {
        match name {
            "Methods" => {
                tables.validate_token(decoder.token()?, EntityKind::Method)?;
                let body_size = decoder.size()?;
                let gc_size = decoder.size()?;
                let eh_size = decoder.size()?;
                validate_ser_string(names, decoder.mangled_name_offset(names.len() as u64)?)?;
                details.methods.body_bytes = checked_add(details.methods.body_bytes, body_size)?;
                details.methods.gc_info_bytes =
                    checked_add(details.methods.gc_info_bytes, gc_size)?;
                details.methods.exception_info_bytes =
                    checked_add(details.methods.exception_info_bytes, eh_size)?;
                aggregate = checked_add(aggregate, body_size)?;
                aggregate = checked_add(aggregate, gc_size)?;
                aggregate = checked_add(aggregate, eh_size)?;
            }
            "Types" => {
                tables.validate_token(decoder.token()?, EntityKind::Type)?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
                validate_ser_string(names, decoder.mangled_name_offset(names.len() as u64)?)?;
            }
            "RvaFields" => {
                tables.validate_token(decoder.token()?, EntityKind::Field)?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
                validate_ser_string(names, decoder.mangled_name_offset(names.len() as u64)?)?;
            }
            "Blobs" => {
                validate_user_string(user_strings, decoder.string_token()?)?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
            }
            "FrozenObjects" => {
                tables.validate_token(decoder.token()?, EntityKind::Type)?;
                let size = decoder.size()?;
                aggregate = checked_add(aggregate, size)?;
                validate_ser_string(names, decoder.mangled_name_offset(names.len() as u64)?)?;
                if decoder.peek()? == 0xd0 {
                    tables.validate_token(decoder.token()?, EntityKind::Type)?;
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
                let token = u32::try_from(decoder.i4()?).map_err(|_| {
                    decoder.error(
                        "mstat.token",
                        "manifest-resource assembly token is negative",
                    )
                })?;
                tables.validate_token(token, EntityKind::AssemblyRef)?;
                validate_user_string(user_strings, decoder.string_token()?)?;
                aggregate = checked_add(aggregate, decoder.size()?)?;
            }
            "DeduplicatedMethods" => {
                tables.validate_token(decoder.token()?, EntityKind::Method)?;
                let count = decoder.size()?;
                if count > decoder.remaining_len() as u64 / 6 {
                    return Err(decoder.error(
                        "mstat.il.deduplicated",
                        "deduplicated-method count exceeds remaining method body",
                    ));
                }
                for _ in 0..count {
                    tables.validate_token(decoder.token()?, EntityKind::Method)?;
                    validate_ser_string(names, decoder.mangled_name_offset(names.len() as u64)?)?;
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

fn validate_ser_string(bytes: &[u8], offset: u64) -> Result<(), MstatError> {
    ser_string_range(bytes, offset).map(|_| ())
}

fn ser_string_range(bytes: &[u8], offset: u64) -> Result<(usize, usize), MstatError> {
    let offset = usize::try_from(offset)
        .map_err(|_| malformed("mstat.names.offset", "name offset exceeds usize", None))?;
    let (length, prefix) = compressed_unsigned(bytes, offset, "mstat.names")?;
    let value_offset = offset
        .checked_add(prefix)
        .ok_or_else(|| malformed("mstat.names.offset", "name offset overflow", None))?;
    let value = checked_slice(bytes, value_offset, length)?;
    std::str::from_utf8(value)
        .map_err(|_| malformed("mstat.names.utf8", "mangled name is not valid UTF-8", None))?;
    Ok((value_offset, length))
}

fn validate_user_string(bytes: &[u8], token: u32) -> Result<(), MstatError> {
    user_string_range(bytes, token).map(|_| ())
}

fn user_string_range(bytes: &[u8], token: u32) -> Result<(usize, usize), MstatError> {
    if token & !TOKEN_RID_MASK != USER_STRING_TOKEN {
        return Err(malformed(
            "mstat.user_string.token",
            format!("invalid #US token 0x{token:08x}"),
            None,
        ));
    }
    let offset = usize::try_from(token & TOKEN_RID_MASK)
        .map_err(|_| malformed("mstat.user_string.offset", "#US offset exceeds usize", None))?;
    let (length, prefix) = compressed_unsigned(bytes, offset, "mstat.user_string")?;
    if length == 0 || (length - 1) % 2 != 0 {
        return Err(malformed(
            "mstat.user_string.length",
            format!("#US entry has invalid encoded length {length}"),
            Some(offset as u64),
        ));
    }
    let value_offset = offset
        .checked_add(prefix)
        .ok_or_else(|| malformed("mstat.user_string.offset", "#US offset overflow", None))?;
    let value = checked_slice(bytes, value_offset, length)?;
    if !matches!(value[length - 1], 0 | 1) {
        return Err(malformed(
            "mstat.user_string.terminal",
            "#US entry has an invalid terminal byte",
            Some((value_offset + length - 1) as u64),
        ));
    }
    let utf16 = value[..length - 1]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
    if char::decode_utf16(utf16).any(|scalar| scalar.is_err()) {
        return Err(malformed(
            "mstat.user_string.utf16",
            "#US entry is not valid UTF-16",
            Some(value_offset as u64),
        ));
    }
    Ok((value_offset, length - 1))
}

fn compressed_unsigned(
    bytes: &[u8],
    offset: usize,
    code: &str,
) -> Result<(usize, usize), MstatError> {
    let first = *bytes
        .get(offset)
        .ok_or_else(|| truncated(offset, 1, bytes.len()))?;
    let (value, width) = if first & 0x80 == 0 {
        (usize::from(first), 1)
    } else if first & 0xc0 == 0x80 {
        let second = *bytes
            .get(offset + 1)
            .ok_or_else(|| truncated(offset, 2, bytes.len()))?;
        ((usize::from(first & 0x3f) << 8) | usize::from(second), 2)
    } else if first & 0xe0 == 0xc0 {
        let encoded = checked_slice(bytes, offset, 4)?;
        (
            (usize::from(first & 0x1f) << 24)
                | (usize::from(encoded[1]) << 16)
                | (usize::from(encoded[2]) << 8)
                | usize::from(encoded[3]),
            4,
        )
    } else {
        return Err(malformed(
            format!("{code}.compressed_length"),
            format!("invalid compressed unsigned prefix 0x{first:02x}"),
            Some(offset as u64),
        ));
    };
    Ok((value, width))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_collision_falls_back_to_exact_identity_bytes() {
        let names = b"alphaomega";
        let fingerprint = [7_u8; 16];
        let alpha = InventoryRecord {
            fingerprint,
            identity: IdentityRef {
                source: IdentitySource::Names,
                offset: 0,
                length: 5,
            },
            bytes: 1,
            records: 1,
        };
        let omega = InventoryRecord {
            fingerprint,
            identity: IdentityRef {
                source: IdentitySource::Names,
                offset: 5,
                length: 5,
            },
            bytes: 1,
            records: 1,
        };
        assert_eq!(
            compare_records(names, &[], &[], &alpha, &omega),
            std::cmp::Ordering::Less
        );
    }
}
