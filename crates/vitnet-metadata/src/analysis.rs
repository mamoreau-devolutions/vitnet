use crate::{
    CURRENT_OFFSET_BITS, MetadataError, OffsetNormalizer, OwnerCandidate, RawRecord,
    detect_offset_bits, lower_bound_sizes, select_owner,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use vitnet_core::Diagnostic;

pub const NATIVEAOT_METADATA_LIMIT: u64 = (1 << CURRENT_OFFSET_BITS) - 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataRecord {
    pub logical_offset: u64,
    pub kind: Vec<u8>,
    pub name: Vec<u8>,
    pub assembly: Option<Vec<u8>>,
    pub namespace: Option<Vec<u8>>,
    pub type_name: Option<Vec<u8>>,
    pub is_string: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisOptions {
    pub assembly_filter: Option<Vec<u8>>,
    pub type_filter: Option<Vec<u8>>,
    pub contains_filter: Option<Vec<u8>>,
    pub top: usize,
    pub preview_bytes: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            assembly_filter: None,
            type_filter: None,
            contains_filter: None,
            top: 50,
            preview_bytes: 256,
        }
    }
}

impl AnalysisOptions {
    fn filtered(&self) -> bool {
        self.assembly_filter.is_some()
            || self.type_filter.is_some()
            || self.contains_filter.is_some()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Concentration {
    pub total_bytes: u64,
    pub reported_bytes: u64,
    pub omitted_bytes: u64,
    pub total_groups: usize,
    pub reported_groups: usize,
    pub reported_share_basis_points: u64,
}

fn concentration(total: u64, groups: usize, entries: &[Aggregate]) -> Concentration {
    let reported = entries.iter().map(|entry| entry.bytes).sum::<u64>();
    Concentration {
        total_bytes: total,
        reported_bytes: reported,
        omitted_bytes: total - reported,
        total_groups: groups,
        reported_groups: entries.len(),
        reported_share_basis_points: if total == 0 {
            0
        } else {
            u64::try_from(u128::from(reported) * 10_000 / u128::from(total)).unwrap()
        },
    }
}

fn contains_context(
    filter: &[u8],
    values: impl IntoIterator<Item = Option<impl AsRef<[u8]>>>,
) -> bool {
    values.into_iter().flatten().any(|value| {
        filter.is_empty()
            || value
                .as_ref()
                .windows(filter.len())
                .any(|part| part == filter)
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Aggregate {
    pub name: String,
    pub bytes: u64,
    pub records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Preview {
    pub text: String,
    pub original_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StringEntry {
    pub preview: Preview,
    pub bytes: u64,
    pub logical_offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assembly: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
}

impl StringEntry {
    fn charge(&self) -> u64 {
        (self.preview.text.len()
            + self.assembly.as_ref().map_or(0, String::len)
            + self.namespace.as_ref().map_or(0, String::len)
            + self.type_name.as_ref().map_or(0, String::len)) as u64
            + 160
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LimitStatus {
    AtOrBelowHeadroomUnknown {
        limit: u64,
        observed_lower_bound: u64,
    },
    OverByAtLeast {
        limit: u64,
        observed_lower_bound: u64,
        bytes: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Analysis {
    pub offset_bits: u8,
    pub observed_lower_bound: u64,
    pub total_lower_bound: u64,
    pub selected_lower_bound: u64,
    pub total_is_lower_bound: bool,
    pub final_record_size_known: bool,
    pub observed_record_count: u64,
    pub record_count: u64,
    pub by_kind: Vec<Aggregate>,
    pub by_assembly: Vec<Aggregate>,
    pub by_namespace: Vec<Aggregate>,
    pub by_type: Vec<Aggregate>,
    pub largest_strings: Vec<StringEntry>,
    pub unowned: Vec<Aggregate>,
    pub limit_status: LimitStatus,
    pub peak_tracked_bytes: u64,
    #[serde(default)]
    pub concentration: BTreeMap<String, Concentration>,
}

#[must_use]
pub fn preview_bytes(bytes: &[u8], maximum_display_bytes: usize) -> Preview {
    let display = String::from_utf8_lossy(bytes);
    let mut text = String::new();
    for character in display.chars() {
        if text.len() + character.len_utf8() > maximum_display_bytes {
            break;
        }
        text.push(character);
    }
    Preview {
        truncated: text.len() < display.len(),
        text,
        original_bytes: bytes.len() as u64,
    }
}

#[must_use]
pub fn top_n(mut values: Vec<Aggregate>, limit: usize) -> Vec<Aggregate> {
    values.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });
    values.truncate(limit);
    values
}

/// Resolves producer offsets and ownership context for an in-memory test input.
///
/// Production callers should use [`analyze_stream`] so row storage remains
/// bounded by the decoder buffer.
///
/// # Errors
///
/// Returns a typed diagnostic when strict offset normalization fails.
pub fn metadata_records_from_raw(
    raw: &[RawRecord],
    strict_offsets: bool,
) -> Result<Vec<MetadataRecord>, MetadataError> {
    let offset_bits = raw.first().map_or(CURRENT_OFFSET_BITS, |record| {
        detect_offset_bits(record.handle, &record.kind)
    });
    let mut normalizer = OffsetNormalizer::with_bits(strict_offsets, offset_bits);
    let offsets = raw
        .iter()
        .map(|record| normalizer.push(record.handle).map(|value| value.logical))
        .collect::<Result<Vec<_>, _>>()?;

    let candidates = raw
        .iter()
        .enumerate()
        .flat_map(|(index, record)| {
            let depth = scope_depth(&record.kind);
            record
                .children
                .iter()
                .copied()
                .map(move |child_handle| OwnerCandidate {
                    owner_index: index,
                    source_index: index,
                    depth,
                    child_handle,
                })
        })
        .collect::<Vec<_>>();

    let direct_owners = raw
        .iter()
        .enumerate()
        .map(|(index, record)| select_owner(index, record.handle, &candidates))
        .collect::<Vec<_>>();

    Ok(raw
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let mut assembly = None;
            let mut namespace = None;
            let mut type_name = None;
            let mut current = Some(index);
            let mut visited = BTreeSet::new();
            while let Some(owner_index) = current {
                if !visited.insert(owner_index) {
                    break;
                }
                let owner = &raw[owner_index];
                match scope_depth(&owner.kind) {
                    1 if assembly.is_none() => assembly = Some(owner.name.clone()),
                    2 if namespace.is_none() => namespace = Some(owner.name.clone()),
                    3 if type_name.is_none() => type_name = Some(owner.name.clone()),
                    _ => {}
                }
                current = direct_owners[owner_index]
                    .as_ref()
                    .map(|selection| selection.owner_index);
            }
            MetadataRecord {
                logical_offset: offsets[index],
                kind: record.kind.clone(),
                name: record.name.clone(),
                assembly,
                namespace,
                type_name,
                is_string: is_string_kind(&record.kind),
            }
        })
        .collect())
}

#[derive(Clone, Copy, Debug, Default)]
struct Context {
    assembly: Option<u32>,
    namespace: Option<u32>,
    type_name: Option<u32>,
}

impl Context {
    fn depth(self) -> u8 {
        if self.type_name.is_some() {
            3
        } else if self.namespace.is_some() {
            2
        } else {
            u8::from(self.assembly.is_some())
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    source_index: u64,
    context: Context,
}

#[derive(Clone, Debug)]
struct PendingRecord {
    logical_offset: u64,
    kind: u32,
    context: Context,
    string_preview: Option<Preview>,
    selected: bool,
}

#[derive(Default)]
struct Interner {
    indexes: HashMap<Vec<u8>, u32>,
    values: Vec<Vec<u8>>,
    retained_bytes: u64,
}

impl Interner {
    fn intern(&mut self, value: &[u8]) -> u32 {
        if let Some(index) = self.indexes.get(value) {
            return *index;
        }
        let index = u32::try_from(self.values.len()).expect("interner index exceeded u32");
        let owned = value.to_vec();
        self.retained_bytes = self.retained_bytes.saturating_add(owned.len() as u64 + 48);
        self.values.push(owned.clone());
        self.indexes.insert(owned, index);
        index
    }

    fn get(&self, index: u32) -> &[u8] {
        &self.values[index as usize]
    }
}

#[derive(Clone, Copy, Default)]
struct Counter {
    bytes: u64,
    records: u64,
}

/// Single-pass metadata analyzer. It retains one entry per unique referenced
/// handle or identifier, never one entry per input row.
pub struct StreamingAnalyzer {
    options: AnalysisOptions,
    aggregate_limit: usize,
    normalizer: OffsetNormalizer,
    memory_limit: u64,
    identifiers: Interner,
    kinds: Interner,
    candidates: HashMap<u32, Candidate>,
    by_kind: HashMap<u32, Counter>,
    by_assembly: HashMap<u32, Counter>,
    by_namespace: HashMap<u32, Counter>,
    by_type: HashMap<u32, Counter>,
    unowned: HashMap<u32, Counter>,
    strings: Vec<StringEntry>,
    string_charge: u64,
    pending: Option<PendingRecord>,
    record_count: u64,
    selected_record_count: u64,
    selected_lower_bound: u64,
    observed_lower_bound: u64,
    peak_tracked_bytes: u64,
    offset_layout_detected: bool,
}

impl StreamingAnalyzer {
    #[must_use]
    pub fn new(options: AnalysisOptions, strict_offsets: bool, memory_limit: u64) -> Self {
        let aggregate_limit = options.top;
        Self::with_aggregate_limit(options, strict_offsets, memory_limit, aggregate_limit)
    }

    #[must_use]
    pub fn with_aggregate_limit(
        options: AnalysisOptions,
        strict_offsets: bool,
        memory_limit: u64,
        aggregate_limit: usize,
    ) -> Self {
        Self {
            options,
            aggregate_limit,
            normalizer: OffsetNormalizer::new(strict_offsets),
            memory_limit,
            identifiers: Interner::default(),
            kinds: Interner::default(),
            candidates: HashMap::new(),
            by_kind: HashMap::new(),
            by_assembly: HashMap::new(),
            by_namespace: HashMap::new(),
            by_type: HashMap::new(),
            unowned: HashMap::new(),
            strings: Vec::new(),
            string_charge: 0,
            pending: None,
            record_count: 0,
            selected_record_count: 0,
            selected_lower_bound: 0,
            observed_lower_bound: 0,
            peak_tracked_bytes: 0,
            offset_layout_detected: false,
        }
    }

    /// Consumes one decoded row.
    ///
    /// # Errors
    ///
    /// Returns a typed offset or resource-limit diagnostic.
    pub fn push(&mut self, record: RawRecord) -> Result<(), MetadataError> {
        if !self.offset_layout_detected {
            self.normalizer = OffsetNormalizer::with_bits(
                self.normalizer.is_strict(),
                detect_offset_bits(record.handle, &record.kind),
            );
            self.offset_layout_detected = true;
        }
        let byte_offset = record.byte_range.start as u64;
        let logical_record = record.logical_record;
        let physical_line = record.physical_line_start;
        let normalized = self.normalizer.push(record.handle).map_err(|mut error| {
            error.diagnostic.byte_offset = Some(byte_offset);
            error.diagnostic.logical_record = Some(logical_record);
            error.diagnostic.physical_line = Some(physical_line);
            error
        })?;
        if let Some(previous) = self.pending.take() {
            let bytes = normalized
                .logical
                .checked_sub(previous.logical_offset)
                .ok_or_else(|| {
                    resource_error("metadata.offset.invariant", "logical offsets decreased")
                })?;
            self.finish_record(previous, bytes);
        } else if !self.options.filtered() && normalized.logical > 0 {
            let prefix = self.kinds.intern(b"(metadata prefix)");
            add_bytes(&mut self.by_kind, prefix, normalized.logical, 0);
            add_bytes(&mut self.unowned, prefix, normalized.logical, 0);
            self.selected_lower_bound = normalized.logical;
        }

        let mut context = self
            .candidates
            .get(&record.handle)
            .map_or_else(Context::default, |candidate| candidate.context);
        match scope_depth(&record.kind) {
            1 => {
                context = Context {
                    assembly: Some(self.identifiers.intern(&record.name)),
                    namespace: None,
                    type_name: None,
                };
            }
            2 => {
                context.namespace = Some(self.identifiers.intern(&record.name));
                context.type_name = None;
            }
            3 => {
                // NativeMetadataWriter's TypeDefinition display name is already
                // namespace/nesting-qualified. Prefixing owner context would
                // duplicate names such as `System.System.String`.
                let qualified = qualify(
                    context.assembly.map(|index| self.identifiers.get(index)),
                    &record.name,
                    b"!",
                );
                context.type_name = Some(self.identifiers.intern(&qualified));
            }
            _ => {}
        }

        let candidate = Candidate {
            source_index: self.record_count,
            context,
        };
        for child in record.children {
            let replace = self.candidates.get(&child).is_none_or(|existing| {
                candidate.source_index > existing.source_index
                    || (candidate.source_index == existing.source_index
                        && candidate.context.depth() > existing.context.depth())
            });
            if replace {
                self.candidates.insert(child, candidate);
            }
        }

        let selected = self.selected(context);
        let string_preview = (selected && is_string_kind(&record.kind))
            .then(|| preview_bytes(&record.name, self.options.preview_bytes));
        let kind = self.kinds.intern(&record.kind);
        self.pending = Some(PendingRecord {
            logical_offset: normalized.logical,
            kind,
            context,
            string_preview,
            selected,
        });
        self.record_count += 1;
        self.selected_record_count += u64::from(selected);
        self.observed_lower_bound = normalized.logical;
        self.check_memory().map_err(|mut error| {
            error.diagnostic.byte_offset = Some(byte_offset);
            error.diagnostic.logical_record = Some(logical_record);
            error.diagnostic.physical_line = Some(physical_line);
            error
        })
    }

    fn selected(&self, context: Context) -> bool {
        self.options.assembly_filter.as_ref().is_none_or(|filter| {
            context
                .assembly
                .is_some_and(|index| self.identifiers.get(index) == filter)
        }) && self.options.type_filter.as_ref().is_none_or(|filter| {
            context
                .type_name
                .is_some_and(|index| self.identifiers.get(index) == filter)
        }) && self.options.contains_filter.as_ref().is_none_or(|filter| {
            contains_context(
                filter,
                [context.assembly, context.namespace, context.type_name]
                    .map(|index| index.map(|index| self.identifiers.get(index))),
            )
        })
    }

    fn finish_record(&mut self, record: PendingRecord, bytes: u64) {
        if !record.selected {
            return;
        }
        self.selected_lower_bound = self.selected_lower_bound.saturating_add(bytes);
        add_counter(&mut self.by_kind, record.kind, bytes);
        let string_owner = record.string_preview.as_ref().map(|_| {
            (
                record.context.assembly,
                record.context.namespace,
                record.context.type_name,
            )
        });
        if let Some(assembly) = record.context.assembly {
            add_counter(&mut self.by_assembly, assembly, bytes);
        }
        if let Some(namespace) = record.context.namespace {
            add_counter(&mut self.by_namespace, namespace, bytes);
        }
        if let Some(type_name) = record.context.type_name {
            add_counter(&mut self.by_type, type_name, bytes);
        } else {
            add_counter(&mut self.unowned, record.kind, bytes);
        }
        if let Some(preview) = record.string_preview {
            let entry = StringEntry {
                preview,
                bytes,
                logical_offset: record.logical_offset,
                assembly: string_owner
                    .as_ref()
                    .and_then(|owner| owner.0)
                    .map(|id| display(self.identifiers.get(id))),
                namespace: string_owner
                    .as_ref()
                    .and_then(|owner| owner.1)
                    .map(|id| display(self.identifiers.get(id))),
                type_name: string_owner
                    .and_then(|owner| owner.2)
                    .map(|id| display(self.identifiers.get(id))),
            };
            let position = self
                .strings
                .partition_point(|retained| compare_strings(retained, &entry).is_le());
            if position >= self.options.top {
                return;
            }
            if self.strings.len() == self.options.top
                && let Some(removed) = self.strings.pop()
            {
                self.string_charge -= removed.charge();
            }
            self.string_charge += entry.charge();
            self.strings.insert(position, entry);
        }
    }

    fn tracked_bytes(&self) -> u64 {
        let retained = self
            .identifiers
            .retained_bytes
            .saturating_add(self.kinds.retained_bytes)
            .saturating_add(self.candidates.len() as u64 * 64)
            .saturating_add(
                (self.by_kind.len()
                    + self.by_assembly.len()
                    + self.by_namespace.len()
                    + self.by_type.len()
                    + self.unowned.len()) as u64
                    * 32,
            )
            .saturating_add(self.string_charge);
        // Hash tables, allocators, and temporary decode fields have
        // implementation-dependent overhead. A 2x charge keeps the configured
        // limit conservative instead of presenting a false RSS guarantee.
        retained.saturating_mul(2).saturating_add(64 * 1024)
    }

    fn check_memory(&mut self) -> Result<(), MetadataError> {
        let tracked = self.tracked_bytes();
        self.peak_tracked_bytes = self.peak_tracked_bytes.max(tracked);
        if tracked > self.memory_limit {
            let mut diagnostic = Diagnostic::malformed(
                "resource.memory_limit",
                "metadata ownership state exceeded the configured memory limit",
            );
            diagnostic.expected = Some(format!("at most {} bytes", self.memory_limit));
            diagnostic.actual = Some(format!("{tracked} tracked bytes"));
            diagnostic.guidance =
                Some("increase --memory-limit or reduce the analyzed input/filter scope".into());
            return Err(MetadataError {
                diagnostic: Box::new(diagnostic),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn finish(mut self) -> Analysis {
        if let Some(last) = self.pending.take() {
            self.finish_record(last, 0);
        }
        let total = self.observed_lower_bound;
        let selected = if self.options.filtered() {
            self.selected_lower_bound
        } else {
            total
        };
        let sections = [
            ("by_kind", &self.by_kind, &self.kinds, usize::MAX),
            (
                "by_assembly",
                &self.by_assembly,
                &self.identifiers,
                self.aggregate_limit,
            ),
            (
                "by_namespace",
                &self.by_namespace,
                &self.identifiers,
                self.aggregate_limit,
            ),
            (
                "by_type",
                &self.by_type,
                &self.identifiers,
                self.aggregate_limit,
            ),
            ("unowned", &self.unowned, &self.kinds, self.aggregate_limit),
        ];
        let mut coverage = BTreeMap::new();
        let [by_kind, by_assembly, by_namespace, by_type, unowned] =
            sections.map(|(name, values, interner, limit)| {
                let entries = aggregates(values, interner, limit);
                coverage.insert(
                    name.into(),
                    concentration(
                        values.values().map(|value| value.bytes).sum(),
                        values.len(),
                        &entries,
                    ),
                );
                entries
            });
        Analysis {
            offset_bits: self.normalizer.offset_bits(),
            observed_lower_bound: total,
            total_lower_bound: selected,
            selected_lower_bound: selected,
            total_is_lower_bound: true,
            final_record_size_known: false,
            observed_record_count: self.record_count,
            record_count: self.selected_record_count,
            by_kind,
            by_assembly,
            by_namespace,
            by_type,
            largest_strings: self.strings,
            unowned,
            limit_status: limit_status(total, self.normalizer.limit()),
            peak_tracked_bytes: self.peak_tracked_bytes,
            concentration: coverage,
        }
    }
}

/// Analyzes a decoder stream without retaining decoded rows.
///
/// # Errors
///
/// Returns the first typed decode, offset, or resource diagnostic.
pub fn analyze_stream<I>(
    records: I,
    options: AnalysisOptions,
    strict_offsets: bool,
    memory_limit: u64,
) -> Result<Analysis, MetadataError>
where
    I: IntoIterator<Item = Result<RawRecord, MetadataError>>,
{
    let mut analyzer = StreamingAnalyzer::new(options, strict_offsets, memory_limit);
    for record in records {
        analyzer.push(record?)?;
    }
    Ok(analyzer.finish())
}

/// Analyzes a stream with independent aggregate and string top-N limits.
///
/// Comparison mode uses this to retain complete aggregate identities without
/// retaining every string candidate.
///
/// # Errors
///
/// Returns the first typed decode, offset, or resource diagnostic.
pub fn analyze_stream_with_aggregate_limit<I>(
    records: I,
    options: AnalysisOptions,
    strict_offsets: bool,
    memory_limit: u64,
    aggregate_limit: usize,
) -> Result<Analysis, MetadataError>
where
    I: IntoIterator<Item = Result<RawRecord, MetadataError>>,
{
    let mut analyzer = StreamingAnalyzer::with_aggregate_limit(
        options,
        strict_offsets,
        memory_limit,
        aggregate_limit,
    );
    for record in records {
        analyzer.push(record?)?;
    }
    Ok(analyzer.finish())
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn analyze(records: &[MetadataRecord], options: &AnalysisOptions) -> Analysis {
    let offsets = records
        .iter()
        .map(|record| record.logical_offset)
        .collect::<Vec<_>>();
    let sizes = lower_bound_sizes(&offsets);
    let selected = records
        .iter()
        .zip(&sizes.record_lower_bounds)
        .filter(|(record, _)| {
            options
                .assembly_filter
                .as_ref()
                .is_none_or(|assembly| record.assembly.as_ref() == Some(assembly))
                && options
                    .type_filter
                    .as_ref()
                    .is_none_or(|name| record.type_name.as_ref() == Some(name))
                && options.contains_filter.as_ref().is_none_or(|filter| {
                    contains_context(
                        filter,
                        [&record.assembly, &record.namespace, &record.type_name]
                            .map(Option::as_deref),
                    )
                })
        })
        .collect::<Vec<_>>();

    let mut kinds = BTreeMap::new();
    let mut assemblies = BTreeMap::new();
    let mut namespaces = BTreeMap::new();
    let mut types = BTreeMap::new();
    let mut unowned = BTreeMap::new();
    let mut strings = Vec::new();

    for &(record, bytes) in &selected {
        add(&mut kinds, display(&record.kind), *bytes);
        if let Some(assembly) = &record.assembly {
            add(&mut assemblies, display(assembly), *bytes);
        }
        if let Some(namespace) = &record.namespace {
            add(&mut namespaces, display(namespace), *bytes);
        }
        if let Some(type_name) = &record.type_name {
            add(&mut types, display(type_name), *bytes);
        } else {
            add(&mut unowned, display(&record.kind), *bytes);
        }
        if record.is_string {
            strings.push(StringEntry {
                preview: preview_bytes(&record.name, options.preview_bytes),
                bytes: *bytes,
                logical_offset: record.logical_offset,
                assembly: record.assembly.as_ref().map(|value| display(value)),
                namespace: record.namespace.as_ref().map(|value| display(value)),
                type_name: record.type_name.as_ref().map(|value| display(value)),
            });
        }
    }
    if !options.filtered()
        && let Some(prefix_bytes) = offsets.first().copied().filter(|value| *value > 0)
    {
        kinds.insert("(metadata prefix)".into(), (prefix_bytes, 0));
        unowned.insert("(metadata prefix)".into(), (prefix_bytes, 0));
    }

    strings.sort_by(compare_strings);
    strings.truncate(options.top);
    let total = sizes.total_lower_bound;
    let selected_total = if options.filtered() {
        selected.iter().map(|(_, bytes)| **bytes).sum()
    } else {
        total
    };
    let mut coverage = BTreeMap::new();
    let [by_kind, by_assembly, by_namespace, by_type, unowned] = [
        ("by_kind", kinds, usize::MAX),
        ("by_assembly", assemblies, options.top),
        ("by_namespace", namespaces, options.top),
        ("by_type", types, options.top),
        ("unowned", unowned, options.top),
    ]
    .map(|(name, values, limit)| {
        let total = values.values().map(|value| value.0).sum();
        let groups = values.len();
        let entries = top_n(to_aggregates(values), limit);
        coverage.insert(name.into(), concentration(total, groups, &entries));
        entries
    });
    Analysis {
        offset_bits: CURRENT_OFFSET_BITS,
        observed_lower_bound: total,
        total_lower_bound: selected_total,
        selected_lower_bound: selected_total,
        total_is_lower_bound: true,
        final_record_size_known: sizes.final_record_exact,
        observed_record_count: records.len() as u64,
        record_count: selected.len() as u64,
        by_kind,
        by_assembly,
        by_namespace,
        by_type,
        largest_strings: strings,
        unowned,
        limit_status: limit_status(total, NATIVEAOT_METADATA_LIMIT),
        peak_tracked_bytes: 0,
        concentration: coverage,
    }
}

fn scope_depth(kind: &[u8]) -> u32 {
    if kind.eq_ignore_ascii_case(b"TypeDefinition") || kind.eq_ignore_ascii_case(b"Type") {
        3
    } else if kind.eq_ignore_ascii_case(b"NamespaceDefinition")
        || kind.eq_ignore_ascii_case(b"Namespace")
    {
        2
    } else {
        u32::from(
            kind.eq_ignore_ascii_case(b"ScopeDefinition") || kind.eq_ignore_ascii_case(b"Assembly"),
        )
    }
}

fn is_string_kind(kind: &[u8]) -> bool {
    kind.eq_ignore_ascii_case(b"ConstantStringValue") || kind.eq_ignore_ascii_case(b"String")
}

fn qualify(parent: Option<&[u8]>, name: &[u8], separator: &[u8]) -> Vec<u8> {
    match parent.filter(|value| !value.is_empty()) {
        Some(parent) if !name.is_empty() => {
            let mut result = Vec::with_capacity(parent.len() + separator.len() + name.len());
            result.extend_from_slice(parent);
            result.extend_from_slice(separator);
            result.extend_from_slice(name);
            result
        }
        Some(parent) => parent.to_vec(),
        None => name.to_vec(),
    }
}

fn compare_strings(left: &StringEntry, right: &StringEntry) -> std::cmp::Ordering {
    right
        .bytes
        .cmp(&left.bytes)
        .then_with(|| {
            left.preview
                .text
                .as_bytes()
                .cmp(right.preview.text.as_bytes())
        })
        .then_with(|| left.logical_offset.cmp(&right.logical_offset))
}

fn add_counter(values: &mut HashMap<u32, Counter>, name: u32, bytes: u64) {
    add_bytes(values, name, bytes, 1);
}

fn add_bytes(values: &mut HashMap<u32, Counter>, name: u32, bytes: u64, records: u64) {
    let entry = values.entry(name).or_default();
    entry.bytes = entry.bytes.saturating_add(bytes);
    entry.records = entry.records.saturating_add(records);
}

fn aggregates(values: &HashMap<u32, Counter>, interner: &Interner, limit: usize) -> Vec<Aggregate> {
    top_n(
        values
            .iter()
            .map(|(name, value)| Aggregate {
                name: display(interner.get(*name)),
                bytes: value.bytes,
                records: value.records,
            })
            .collect(),
        limit,
    )
}

fn limit_status(total: u64, limit: u64) -> LimitStatus {
    if total > limit {
        LimitStatus::OverByAtLeast {
            limit,
            observed_lower_bound: total,
            bytes: total - limit,
        }
    } else {
        LimitStatus::AtOrBelowHeadroomUnknown {
            limit,
            observed_lower_bound: total,
        }
    }
}

fn resource_error(code: &str, message: &str) -> MetadataError {
    MetadataError {
        diagnostic: Box::new(Diagnostic::malformed(code, message)),
    }
}

fn display(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

fn add(values: &mut BTreeMap<String, (u64, u64)>, name: String, bytes: u64) {
    let entry = values.entry(name).or_default();
    entry.0 += bytes;
    entry.1 += 1;
}

fn to_aggregates(values: BTreeMap<String, (u64, u64)>) -> Vec<Aggregate> {
    values
        .into_iter()
        .map(|(name, (bytes, records))| Aggregate {
            name,
            bytes,
            records,
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComparisonEntry {
    pub name: String,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub delta_bytes: i128,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    pub entries: Vec<ComparisonEntry>,
    pub total_delta: i128,
}

#[must_use]
pub fn compare(before: &[Aggregate], after: &[Aggregate]) -> Comparison {
    let before = before
        .iter()
        .map(|value| (value.name.as_str(), value.bytes))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .iter()
        .map(|value| (value.name.as_str(), value.bytes))
        .collect::<BTreeMap<_, _>>();
    let names = before
        .keys()
        .chain(after.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut entries = names
        .into_iter()
        .map(|name| {
            let before_bytes = before.get(name).copied().unwrap_or(0);
            let after_bytes = after.get(name).copied().unwrap_or(0);
            ComparisonEntry {
                name: name.to_owned(),
                before_bytes,
                after_bytes,
                delta_bytes: i128::from(after_bytes) - i128::from(before_bytes),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .delta_bytes
            .abs()
            .cmp(&left.delta_bytes.abs())
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });
    let total_delta = entries.iter().map(|entry| entry.delta_bytes).sum();
    Comparison {
        entries,
        total_delta,
    }
}
