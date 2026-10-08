//! Literal producer-name insights, not demangling or exclusive ownership.

use super::{
    ASSEMBLY_TABLE, EntityKind, IlDecoder, METHOD_DEF_TABLE, MIN_TRACKED_MEMORY, MethodBody,
    MethodBreakdown, MethodRow, MstatError, MstatSummary, PeImage, REQUIRED_STREAMS, Tables,
    aligned_contains, bounded_identity, checked_add, checked_slice, malformed, metadata_streams,
    name_identity, read_index, resource_error, summarize, user_string_range,
    validate_resource_assembly_identities,
};
use memchr::memmem::Finder;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::Path;
use vitnet_core::Diagnostic;

const MAX_RULES: usize = 64;
const MAX_PATTERNS: usize = 64;
const MAX_RULE_NAME_BYTES: usize = 256;
const METADATA_BLOB_NAME_UTF16: &[u8] = b"M\0e\0t\0a\0d\0a\0t\0a\0";

#[cfg(test)]
mod tests {
    use super::{
        Budget, ExactIdentity, Finder, GroupKey, GroupRange, InsightCounts, Pattern, Record,
        aligned_contains, ranked_groups, select,
    };

    #[test]
    fn insight_selections_match_full_sort_at_every_limit() {
        let names: Vec<_> = (0..40)
            .map(|index| format!("{}-{index:03}", "n".repeat(300)))
            .collect();
        let records: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(index, name)| Record {
                identity: ExactIdentity::Name(name.as_bytes()),
                counts: InsightCounts {
                    bytes: (index % 5) as u64,
                    identities: 1,
                    records: 2,
                },
                components: [0; 3],
            })
            .collect();
        let mut expected = records.clone();
        expected.sort_unstable_by(|left, right| {
            right
                .counts
                .bytes
                .cmp(&left.counts.bytes)
                .then_with(|| left.identity.cmp(&right.identity))
        });
        for reverse in [false, true] {
            let mut input = records.clone();
            if reverse {
                input.reverse();
            }
            let groups: Vec<_> = input
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    let ExactIdentity::Name(name) = record.identity else {
                        unreachable!()
                    };
                    GroupRange {
                        key: GroupKey::Prefix(name),
                        start: index,
                        end: index + 1,
                        total: record.counts,
                        matched: record.counts,
                    }
                })
                .collect();
            for limit in 0..=records.len() + 1 {
                let selected = select(input.iter().copied(), limit);
                assert_eq!(selected.len(), limit.min(records.len()));
                for (actual, expected) in selected.iter().zip(&expected) {
                    assert_eq!(actual.identity, expected.identity);
                    assert_eq!(actual.counts, expected.counts);
                }
                let selected_groups = ranked_groups(&groups, limit);
                assert_eq!(selected_groups.len(), limit.min(groups.len()));
                for (actual, expected) in selected_groups.iter().zip(&expected) {
                    let ExactIdentity::Name(name) = expected.identity else {
                        unreachable!()
                    };
                    assert!(actual.key == GroupKey::Prefix(name));
                    assert_eq!(actual.matched, expected.counts);
                }
            }
        }
        assert!(select(std::iter::empty(), 5).is_empty());
        assert!(ranked_groups(&[], 5).is_empty());
    }

    #[test]
    fn compiled_literal_matching_preserves_binary_and_aligned_overlapping_hits() {
        for value in [
            &b"\xffabc\xfeabc"[..],
            &[1, 0, 0, 0],
            &[0, 65, 0, 1],
            &[65, 0, 1, 0],
            &[],
        ] {
            for needle in [&b"abc"[..], &[0, 0], &[65, 0], &[0xff], &[]] {
                let finder = Finder::new(needle);
                assert_eq!(
                    finder.find(value).is_some(),
                    crate::contains_bytes(value, needle, 1)
                );
                assert_eq!(
                    aligned_contains(&finder, value),
                    crate::contains_bytes(value, needle, 2)
                );
            }
        }
        assert!(aligned_contains(&Finder::new(&[0, 0]), &[1, 0, 0, 0]));
        let mut budget = Budget::new(1024 * 1024).unwrap();
        let pattern = Pattern::new("日😀", &mut budget).unwrap();
        let utf16: Vec<_> = "prefix日😀suffix"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(pattern.matches(ExactIdentity::UserString(&utf16)));
        assert!(pattern.matches(ExactIdentity::Name(b"\xff\xe6\x97\xa5\xf0\x9f\x98\x80\xfe")));
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortRule {
    pub name: String,
    pub contains: Vec<String>,
    pub stream: Option<String>,
}

/// `contains` intersects the four insight reports using full identities.
/// Exact metadata-blob reconciliation remains unfiltered.
/// `top` bounds each list and its examples independently; zero retains totals only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InsightsOptions {
    pub top: usize,
    pub contains: Option<String>,
    pub rules: Vec<CohortRule>,
}

impl Default for InsightsOptions {
    fn default() -> Self {
        Self {
            top: 20,
            contains: None,
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct InsightCounts {
    pub bytes: u64,
    pub identities: u64,
    pub records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentityInsightEntry {
    pub identity: String,
    pub identity_bytes: u64,
    pub truncated: bool,
    pub bytes: u64,
    pub records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MethodInsightEntry {
    pub identity: String,
    pub identity_bytes: u64,
    pub truncated: bool,
    pub bytes: u64,
    pub records: u64,
    pub body_bytes: u64,
    pub gc_info_bytes: u64,
    pub exception_info_bytes: u64,
    pub accounted_basis_points: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MethodsInsightReport {
    pub accounted_denominator_bytes: u64,
    pub total: InsightCounts,
    pub matched: InsightCounts,
    pub total_components: MethodBreakdown,
    pub matched_components: MethodBreakdown,
    pub top_components: MethodBreakdown,
    pub omitted_components: MethodBreakdown,
    pub top_bytes: u64,
    pub omitted_bytes: u64,
    pub entries: Vec<MethodInsightEntry>,
    #[serde(default)]
    pub size_bands: Vec<MethodSizeBand>,
}

/// Inclusive byte ranges over coalesced identities, independent of display top.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MethodSizeBand {
    pub minimum_bytes: u64,
    pub maximum_bytes: Option<u64>,
    pub total: InsightCounts,
    pub matched: InsightCounts,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobInsightReport {
    pub total: InsightCounts,
    pub matched: InsightCounts,
    pub top_bytes: u64,
    pub omitted_bytes: u64,
    pub entries: Vec<IdentityInsightEntry>,
    /// Exact unfiltered producer-name match, including zero-byte presence.
    pub dehydrated_data: InsightCounts,
}

/// Exact metadata values. Empty culture means the `AssemblyRef` culture is empty.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceAssemblyKey {
    pub name: String,
    pub culture: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceGroup<K> {
    pub key: K,
    pub total: InsightCounts,
    pub matched: InsightCounts,
    pub top_bytes: u64,
    pub omitted_bytes: u64,
    pub entries: Vec<IdentityInsightEntry>,
}

/// Each list reconciles independently. Lists are alternate views, not additive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceGroupList<K> {
    pub total: InsightCounts,
    pub matched: InsightCounts,
    pub total_groups: u64,
    pub matched_groups: u64,
    pub top_bytes: u64,
    pub omitted_bytes: u64,
    pub groups: Vec<ResourceGroup<K>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourcesInsightReport {
    pub accounted: bool,
    pub warning: String,
    pub by_assembly: ResourceGroupList<ResourceAssemblyKey>,
    pub by_culture: ResourceGroupList<String>,
    pub by_resource_name: ResourceGroupList<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericFamily {
    /// Full UTF-8 byte prefix before the first literal '<'; possibly empty.
    pub prefix: String,
    pub total: InsightCounts,
    pub matched: InsightCounts,
    pub top_bytes: u64,
    pub omitted_bytes: u64,
    pub examples: Vec<IdentityInsightEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericStreamReport {
    pub stream: String,
    pub total: InsightCounts,
    pub generic_shaped: InsightCounts,
    pub non_generic_shaped: InsightCounts,
    pub matched_generic_shaped: InsightCounts,
    pub total_families: u64,
    pub matched_families: u64,
    pub top_bytes: u64,
    pub omitted_bytes: u64,
    pub families: Vec<GenericFamily>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericsInsightReport {
    pub caveat: String,
    pub sections: Vec<GenericStreamReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortStreamCounts {
    pub stream: String,
    pub accounted: bool,
    pub matched: InsightCounts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortExample {
    pub stream: String,
    pub entry: IdentityInsightEntry,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortInsight {
    pub name: String,
    pub accounted: InsightCounts,
    pub non_accounted: InsightCounts,
    pub sections: Vec<CohortStreamCounts>,
    pub examples: Vec<CohortExample>,
}

/// Indices refer to `cohorts` in input-rule order. Counts are intersections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortIntersection {
    pub left: usize,
    pub right: usize,
    pub accounted: InsightCounts,
    pub non_accounted: InsightCounts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortsInsightReport {
    pub warning: String,
    pub accounted_denominator_bytes: u64,
    pub union_accounted: InsightCounts,
    pub union_non_accounted: InsightCounts,
    pub multiply_matched_accounted: InsightCounts,
    pub multiply_matched_non_accounted: InsightCounts,
    pub cohorts: Vec<CohortInsight>,
    pub intersections: Vec<CohortIntersection>,
    #[serde(default)]
    pub union_sections: Vec<CohortStreamCounts>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatInsights {
    pub schema: String,
    pub summary: MstatSummary,
    /// Checked, unfiltered sum of Blobs named exactly `Metadata` in full UTF-16.
    pub metadata_blob_bytes: u64,
    /// Original matching Blobs records; distinguishes absence from zero size.
    pub metadata_blob_records: u64,
    pub methods: MethodsInsightReport,
    pub resources: ResourcesInsightReport,
    pub generics: GenericsInsightReport,
    pub cohorts: CohortsInsightReport,
    #[serde(default)]
    pub blobs: BlobInsightReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InsightKind {
    Methods,
    Resources,
    Generics,
    Cohorts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InsightProjection {
    Methods(MethodsInsightReport),
    Resources(ResourcesInsightReport),
    Generics(GenericsInsightReport),
    Cohorts(CohortsInsightReport),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MstatProjection {
    pub summary: MstatSummary,
    pub data: InsightProjection,
}

impl InsightKind {
    fn streams(self) -> [bool; 7] {
        match self {
            Self::Methods => [true, false, false, false, false, false, false],
            Self::Resources => [false, false, false, false, false, true, false],
            Self::Generics => [true, true, false, false, false, false, false],
            Self::Cohorts => [true; 7],
        }
    }
}

/// Computes one typed projection, with a complete summary and input validation.
///
/// # Errors
///
/// Returns typed I/O, malformed-input, invalid-rule, or resource diagnostics.
pub fn project_insights_path(
    path: &Path,
    memory_limit: u64,
    options: &InsightsOptions,
    kind: InsightKind,
) -> Result<MstatProjection, MstatError> {
    let data = mmap_guard::map_file(path).map_err(|error| {
        let mut diagnostic = Diagnostic::malformed("mstat.io", error.to_string());
        diagnostic.input_path = Some(path.to_owned());
        MstatError {
            diagnostic: Box::new(diagnostic),
        }
    })?;
    project_insights(&data, memory_limit, options, kind).map_err(|mut error| {
        error.diagnostic.input_path = Some(path.to_owned());
        error
    })
}

/// Retains only the streams required for one report; every option is validated.
///
/// # Errors
///
/// Returns the same checked input and rule diagnostics as combined insights.
pub fn project_insights(
    bytes: &[u8],
    memory_limit: u64,
    options: &InsightsOptions,
    kind: InsightKind,
) -> Result<MstatProjection, MstatError> {
    let PreparedOptions {
        mut budget,
        filter,
        rules,
    } = prepare_options(memory_limit, options, Some(kind))?;
    let mut inventory = ParsedInventory::parse_selected(bytes, &mut budget, kind.streams())?;
    inventory.coalesce()?;
    let data = match kind {
        InsightKind::Methods => {
            InsightProjection::Methods(method_report(&inventory, filter.as_ref(), options.top)?)
        }
        InsightKind::Resources => InsightProjection::Resources(resource_report(
            &inventory,
            filter.as_ref(),
            options.top,
            &mut budget,
        )?),
        InsightKind::Generics => InsightProjection::Generics(generic_report(
            &inventory,
            filter.as_ref(),
            options.top,
            &mut budget,
        )?),
        InsightKind::Cohorts => InsightProjection::Cohorts(cohort_report(
            &inventory,
            filter.as_ref(),
            &rules,
            options.top,
            &mut budget,
        )?),
    };
    inventory.summary.peak_tracked_memory_bytes = budget.used;
    Ok(MstatProjection {
        summary: inventory.summary,
        data,
    })
}

/// Maps one file and shares a checked, exact inventory across all four reports.
///
/// # Errors
///
/// Returns typed I/O, malformed-input, invalid-rule, or resource diagnostics.
pub fn insights_path(
    path: &Path,
    memory_limit: u64,
    options: &InsightsOptions,
) -> Result<MstatInsights, MstatError> {
    let data = mmap_guard::map_file(path).map_err(|error| {
        let mut diagnostic = Diagnostic::malformed("mstat.io", error.to_string());
        diagnostic.input_path = Some(path.to_owned());
        MstatError {
            diagnostic: Box::new(diagnostic),
        }
    })?;
    insights(&data, memory_limit, options).map_err(|mut error| {
        error.diagnostic.input_path = Some(path.to_owned());
        error
    })
}

/// Generates bounded projections after exact accounting and coalescing.
///
/// # Errors
///
/// Invalid rules use `mstat.insights.rule`; capacity violations use
/// `resource.memory_limit`. No matches is a successful report with zero counts.
pub fn insights(
    bytes: &[u8],
    memory_limit: u64,
    options: &InsightsOptions,
) -> Result<MstatInsights, MstatError> {
    let PreparedOptions {
        mut budget,
        filter,
        rules,
    } = prepare_options(memory_limit, options, None)?;
    let mut inventory = ParsedInventory::parse(bytes, &mut budget)?;
    inventory.coalesce()?;
    let mut metadata_blob = InsightCounts::default();
    for record in &inventory.sections[2] {
        if matches!(record.identity, ExactIdentity::UserString(name) if name == METADATA_BLOB_NAME_UTF16)
        {
            add_counts(&mut metadata_blob, record.counts)?;
        }
    }
    let methods = method_report(&inventory, filter.as_ref(), options.top)?;
    let blobs = blob_report(&inventory, filter.as_ref(), options.top)?;
    let resources = resource_report(&inventory, filter.as_ref(), options.top, &mut budget)?;
    let generics = generic_report(&inventory, filter.as_ref(), options.top, &mut budget)?;
    let cohorts = cohort_report(
        &inventory,
        filter.as_ref(),
        &rules,
        options.top,
        &mut budget,
    )?;
    inventory.summary.peak_tracked_memory_bytes = budget.used;
    Ok(MstatInsights {
        schema: "vitnet.mstat-insights.v1".into(),
        summary: inventory.summary,
        metadata_blob_bytes: metadata_blob.bytes,
        metadata_blob_records: metadata_blob.records,
        methods,
        resources,
        generics,
        cohorts,
        blobs,
    })
}

struct PreparedOptions<'a> {
    budget: Budget,
    filter: Option<Pattern<'a>>,
    rules: Vec<Rule<'a>>,
}

fn prepare_options(
    memory_limit: u64,
    options: &InsightsOptions,
    kind: Option<InsightKind>,
) -> Result<PreparedOptions<'_>, MstatError> {
    let mut budget = Budget::new(memory_limit)?;
    let filter = options
        .contains
        .as_deref()
        .map(|text| Pattern::new(text, &mut budget))
        .transpose()?;
    let rules = validate_rules(&options.rules, &mut budget)?;
    let (fixed_lists, nested_lists, include_rules): (u64, u64, bool) = match kind {
        None => (9, 5, true),
        Some(InsightKind::Methods) => (1, 0, false),
        Some(InsightKind::Resources) => (3, 3, false),
        Some(InsightKind::Generics) => (2, 2, false),
        Some(InsightKind::Cohorts) => (1, 0, true),
    };
    let lists = fixed_lists
        .checked_add(if include_rules { rules.len() as u64 } else { 0 })
        .and_then(|value| value.checked_add(nested_lists.checked_mul(options.top as u64)?))
        .ok_or_else(|| resource_error("MSTAT insights top count overflow"))?;
    budget.charge(
        (options.top as u64)
            .checked_mul(lists)
            .and_then(|value| value.checked_mul(1024))
            .ok_or_else(|| resource_error("MSTAT insights report size overflow"))?,
    )?;
    Ok(PreparedOptions {
        budget,
        filter,
        rules,
    })
}

struct Budget {
    limit: u64,
    // Conservative peak: scratch allocations are not released from the charge.
    used: u64,
}

impl Budget {
    fn new(limit: u64) -> Result<Self, MstatError> {
        let mut budget = Self { limit, used: 0 };
        budget.charge(MIN_TRACKED_MEMORY)?;
        Ok(budget)
    }

    fn charge(&mut self, bytes: u64) -> Result<(), MstatError> {
        let used = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| resource_error("MSTAT insights memory charge overflow"))?;
        if used > self.limit {
            return Err(resource_error(format!(
                "MSTAT insights requires {used} tracked bytes; limit is {}",
                self.limit
            )));
        }
        self.used = used;
        Ok(())
    }

    fn vector<T>(&mut self, count: usize) -> Result<Vec<T>, MstatError> {
        self.charge(
            (count as u64)
                .checked_mul(size_of::<T>() as u64)
                .ok_or_else(|| resource_error("MSTAT insights vector size overflow"))?,
        )?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|error| {
            resource_error(format!("MSTAT insights allocation failed: {error}"))
        })?;
        // Account for any allocator-reported excess capacity.
        self.charge((values.capacity() - count) as u64 * size_of::<T>() as u64)?;
        Ok(values)
    }

    fn text(&mut self, value: &str) -> Result<String, MstatError> {
        self.charge(value.len() as u64)?;
        Ok(value.to_owned())
    }
}

struct Pattern<'a> {
    text: &'a str,
    utf8: Finder<'a>,
    utf16: Finder<'static>,
}

impl<'a> Pattern<'a> {
    fn new(text: &'a str, budget: &mut Budget) -> Result<Self, MstatError> {
        budget.charge(text.len() as u64)?;
        let count = text.encode_utf16().count();
        let mut utf16 =
            budget.vector(count.checked_mul(2).ok_or_else(|| {
                resource_error("MSTAT insights UTF-16 pattern length overflow")
            })?)?;
        for scalar in text.encode_utf16() {
            utf16.extend_from_slice(&scalar.to_le_bytes());
        }
        budget.charge(utf16.len() as u64)?;
        let utf16 = Finder::new(&utf16).into_owned();
        Ok(Self {
            text,
            utf8: Finder::new(text.as_bytes()),
            utf16,
        })
    }

    fn matches(&self, identity: ExactIdentity<'_>) -> bool {
        match identity {
            ExactIdentity::Name(name) => self.utf8.find(name).is_some(),
            ExactIdentity::UserString(name) => aligned_contains(&self.utf16, name),
            ExactIdentity::Resource(name, culture, resource) => {
                self.utf8.find(name.as_bytes()).is_some()
                    || self.utf8.find(culture.as_bytes()).is_some()
                    || aligned_contains(&self.utf16, resource)
                    // Preserve matching against the existing UTF-8 prefix too.
                    || resource_prefix_contains(name, culture, self.text)
            }
        }
    }
}

fn resource_prefix_contains(name: &str, culture: &str, needle: &str) -> bool {
    if culture.is_empty() || needle.is_empty() {
        return name.contains(needle);
    }
    // Streaming comparison avoids allocating an unbounded formatted prefix.
    let marker = b", Culture=";
    let end = name.len() + marker.len() + culture.len();
    let byte_at = |index: usize| {
        if index < name.len() {
            name.as_bytes()[index]
        } else if index < name.len() + marker.len() {
            marker[index - name.len()]
        } else {
            culture.as_bytes()[index - name.len() - marker.len()]
        }
    };
    for start in
        name.len().saturating_sub(needle.len().saturating_sub(1))..name.len() + marker.len()
    {
        if needle.len() <= end - start
            && needle
                .bytes()
                .enumerate()
                .all(|(offset, byte)| byte_at(start + offset) == byte)
        {
            return true;
        }
    }
    false
}

struct Rule<'a> {
    name: &'a str,
    stream: Option<usize>,
    patterns: Vec<Pattern<'a>>,
}

fn validate_rules<'a>(
    rules: &'a [CohortRule],
    budget: &mut Budget,
) -> Result<Vec<Rule<'a>>, MstatError> {
    if rules.len() > MAX_RULES {
        return Err(resource_error(
            "MSTAT insights supports at most 64 cohort rules",
        ));
    }
    let mut result = budget.vector::<Rule<'a>>(rules.len())?;
    for (index, rule) in rules.iter().enumerate() {
        if rule.name.trim().is_empty()
            || rule.contains.is_empty()
            || rule.contains.iter().any(String::is_empty)
            || rules[..index].iter().any(|other| other.name == rule.name)
        {
            return Err(malformed(
                "mstat.insights.rule",
                format!(
                    "invalid cohort rule at index {index}: names must be unique and nonempty; predicates must be nonempty literals"
                ),
                None,
            ));
        }
        let stream = rule
            .stream
            .as_deref()
            .map(|stream| {
                REQUIRED_STREAMS
                    .iter()
                    .position(|name| *name == stream)
                    .ok_or_else(|| {
                        malformed(
                            "mstat.insights.rule",
                            format!("invalid stream in cohort rule {index}"),
                            None,
                        )
                    })
            })
            .transpose()?;
        if rule.name.len() > MAX_RULE_NAME_BYTES || rule.contains.len() > MAX_PATTERNS {
            return Err(resource_error(
                "MSTAT cohort name or predicate count exceeds its cap",
            ));
        }
        budget.charge(rule.name.len() as u64)?;
        let mut patterns = budget.vector(rule.contains.len())?;
        for pattern in &rule.contains {
            if pattern.len() as u64 > (budget.limit / 64).min(1 << 20) {
                return Err(resource_error(
                    "MSTAT cohort predicate exceeds its byte cap",
                ));
            }
            patterns.push(Pattern::new(pattern, budget)?);
        }
        result.push(Rule {
            name: &rule.name,
            stream,
            patterns,
        });
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ExactIdentity<'a> {
    Name(&'a [u8]),
    UserString(&'a [u8]),
    Resource(&'a str, &'a str, &'a [u8]),
}

impl ExactIdentity<'_> {
    fn preview(self) -> (String, bool) {
        match self {
            Self::Name(bytes) => bounded_identity(
                std::str::from_utf8(bytes)
                    .expect("validated producer name")
                    .chars(),
            ),
            Self::UserString(bytes) => bounded_identity(utf16_chars(bytes)),
            Self::Resource(name, culture, resource) => {
                let culture_marker = if culture.is_empty() { "" } else { ", Culture=" };
                bounded_identity(
                    name.chars()
                        .chain(culture_marker.chars())
                        .chain(culture.chars())
                        .chain(std::iter::once('!'))
                        .chain(utf16_chars(resource)),
                )
            }
        }
    }

    fn byte_len(self) -> u64 {
        match self {
            Self::Name(bytes) | Self::UserString(bytes) => bytes.len() as u64,
            Self::Resource(name, culture, resource) => {
                (name.len()
                    + resource.len()
                    + 1
                    + if culture.is_empty() {
                        0
                    } else {
                        10 + culture.len()
                    }) as u64
            }
        }
    }
}

fn utf16_chars(bytes: &[u8]) -> impl Iterator<Item = char> + '_ {
    char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|part| u16::from_le_bytes([part[0], part[1]])),
    )
    .map(|value| value.expect("validated producer UTF-16"))
}

#[derive(Clone, Copy)]
struct Record<'a> {
    identity: ExactIdentity<'a>,
    counts: InsightCounts,
    components: [u64; 3],
}

struct ParsedInventory<'a> {
    summary: MstatSummary,
    sections: [Vec<Record<'a>>; 7],
}

impl<'a> ParsedInventory<'a> {
    fn parse(bytes: &'a [u8], budget: &mut Budget) -> Result<Self, MstatError> {
        Self::parse_selected(bytes, budget, [true; 7])
    }

    fn parse_selected(
        bytes: &'a [u8],
        budget: &mut Budget,
        selected: [bool; 7],
    ) -> Result<Self, MstatError> {
        let image = PeImage::parse(bytes)?;
        let metadata = image.rva_slice(image.metadata_rva, image.metadata_size)?;
        let (table_stream, string_stream, user_stream) = metadata_streams(metadata)?;
        let tables = Tables::parse(
            checked_slice(metadata, table_stream.offset, table_stream.size)?,
            checked_slice(metadata, string_stream.offset, string_stream.size)?,
        )?;
        budget
            .charge(u64::from(tables.rows[METHOD_DEF_TABLE]) * size_of::<MethodRow>() as u64 * 2)?;
        let assembly_row = checked_slice(
            tables.bytes,
            tables.table_offset(ASSEMBLY_TABLE)?,
            tables.row_size(ASSEMBLY_TABLE)?,
        )?;
        let assembly_name = tables.string(read_index(
            assembly_row,
            16 + tables.blob_width,
            tables.string_width,
        )?)?;
        let assembly_culture = tables.string(read_index(
            assembly_row,
            16 + tables.blob_width + tables.string_width,
            tables.string_width,
        )?)?;
        budget.charge((assembly_name.len() + assembly_culture.len() + 10) as u64 * 2)?;
        let summary = summarize(bytes, budget.limit)?;
        let user_strings = checked_slice(metadata, user_stream.offset, user_stream.size)?;
        let names_section = image
            .sections
            .iter()
            .find(|section| section.name == b".names")
            .ok_or_else(|| malformed("mstat.section.names", "missing .names section", None))?;
        let names = image.section_logical_slice(names_section)?;
        let mut sections = std::array::from_fn(|_| Vec::new());
        for (index, (section, category)) in sections.iter_mut().zip(&summary.categories).enumerate()
        {
            if !selected[index] {
                continue;
            }
            let count = if category.name == "DeduplicatedMethods" {
                category.items
            } else {
                category.records
            };
            *section = budget.vector(usize::try_from(count).map_err(|_| {
                resource_error("MSTAT insights record count exceeds addressable memory")
            })?)?;
        }
        for row in tables.methods()? {
            let name = tables.string(row.name)?;
            let Some(index) = REQUIRED_STREAMS.iter().position(|value| *value == name) else {
                continue;
            };
            let body = image.method_body(row.rva)?;
            if !selected[index] {
                if index == 5 {
                    validate_resource_assembly_identities(body, &tables)?;
                }
                continue;
            }
            decode_records(
                index,
                body,
                &tables,
                names,
                user_strings,
                &mut sections[index],
            )?;
        }
        Ok(Self { summary, sections })
    }

    fn coalesce(&mut self) -> Result<(), MstatError> {
        for section in &mut self.sections {
            section.sort_unstable_by_key(|record| record.identity);
            let mut write = 0;
            for read in 0..section.len() {
                if write > 0 && section[write - 1].identity == section[read].identity {
                    let record = section[read];
                    add_counts(&mut section[write - 1].counts, record.counts)?;
                    section[write - 1].counts.identities = 1;
                    for (target, value) in section[write - 1]
                        .components
                        .iter_mut()
                        .zip(record.components)
                    {
                        *target = checked_add(*target, value)?;
                    }
                } else {
                    section[write] = section[read];
                    write += 1;
                }
            }
            section.truncate(write);
        }
        Ok(())
    }
}

fn decode_records<'a>(
    stream: usize,
    body: MethodBody<'_>,
    tables: &Tables<'a>,
    names: &'a [u8],
    user_strings: &'a [u8],
    records: &mut Vec<Record<'a>>,
) -> Result<(), MstatError> {
    let mut decoder = IlDecoder::new(body.code, body.file_offset);
    while !decoder.is_empty() {
        let mut components = [0; 3];
        let (identity, bytes) = match stream {
            0 => {
                tables.validate_token(decoder.token()?, EntityKind::Method)?;
                for value in &mut components {
                    *value = decoder.size()?;
                }
                let bytes = checked_add(checked_add(components[0], components[1])?, components[2])?;
                (decoded_name(names, &mut decoder)?, bytes)
            }
            1 | 3 | 4 => {
                let kind = if stream == 3 {
                    EntityKind::Field
                } else {
                    EntityKind::Type
                };
                tables.validate_token(decoder.token()?, kind)?;
                let bytes = decoder.size()?;
                let identity = decoded_name(names, &mut decoder)?;
                if stream == 4 {
                    if decoder.peek()? == 0xd0 {
                        tables.validate_token(decoder.token()?, EntityKind::Type)?;
                    } else if decoder.i4()? != 0 {
                        return Err(decoder.error(
                            "mstat.il.frozen_owner",
                            "frozen-object owner must be ldtoken or zero",
                        ));
                    }
                }
                (identity, bytes)
            }
            2 => {
                let identity = decoded_user_string(user_strings, decoder.string_token()?)?;
                (ExactIdentity::UserString(identity), decoder.size()?)
            }
            5 => {
                let token = u32::try_from(decoder.i4()?).map_err(|_| {
                    decoder.error(
                        "mstat.token",
                        "manifest-resource assembly token is negative",
                    )
                })?;
                let (name, culture) = tables.assembly_ref_parts(token)?;
                let resource = decoded_user_string(user_strings, decoder.string_token()?)?;
                (
                    ExactIdentity::Resource(name, culture, resource),
                    decoder.size()?,
                )
            }
            6 => {
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
                    records.push(Record {
                        identity: decoded_name(names, &mut decoder)?,
                        counts: InsightCounts {
                            bytes: 0,
                            identities: 1,
                            records: 1,
                        },
                        components,
                    });
                }
                continue;
            }
            _ => unreachable!("seven checked streams"),
        };
        records.push(Record {
            identity,
            counts: InsightCounts {
                bytes,
                identities: 1,
                records: 1,
            },
            components,
        });
    }
    Ok(())
}

fn decoded_name<'a>(
    names: &'a [u8],
    decoder: &mut IlDecoder<'_>,
) -> Result<ExactIdentity<'a>, MstatError> {
    let identity = name_identity(names, decoder)?;
    Ok(ExactIdentity::Name(
        &names[identity.offset as usize..identity.offset as usize + identity.length as usize],
    ))
}

fn decoded_user_string(bytes: &[u8], token: u32) -> Result<&[u8], MstatError> {
    let (start, length) = user_string_range(bytes, token)?;
    checked_slice(bytes, start, length)
}

fn add_counts(target: &mut InsightCounts, value: InsightCounts) -> Result<(), MstatError> {
    target.bytes = checked_add(target.bytes, value.bytes)?;
    target.identities = checked_add(target.identities, value.identities)?;
    target.records = checked_add(target.records, value.records)?;
    Ok(())
}

fn matches(record: &Record<'_>, filter: Option<&Pattern<'_>>) -> bool {
    filter.is_none_or(|pattern| pattern.matches(record.identity))
}

fn ranked(left: &Record<'_>, right: &Record<'_>) -> Ordering {
    right
        .counts
        .bytes
        .cmp(&left.counts.bytes)
        .then_with(|| left.identity.cmp(&right.identity))
}

fn select<'a>(records: impl Iterator<Item = Record<'a>>, top: usize) -> Vec<Record<'a>> {
    let mut selected = Vec::with_capacity(top);
    for record in records {
        if top != 0
            && (selected.len() < top
                || selected
                    .last()
                    .is_some_and(|last| ranked(&record, last).is_lt()))
        {
            selected.push(record);
            selected.sort_unstable_by(ranked);
            selected.truncate(top);
        }
    }
    selected
}

fn entry(record: Record<'_>) -> IdentityInsightEntry {
    let (identity, truncated) = record.identity.preview();
    IdentityInsightEntry {
        identity,
        truncated,
        identity_bytes: record.identity.byte_len(),
        bytes: record.counts.bytes,
        records: record.counts.records,
    }
}

fn breakdown(components: [u64; 3]) -> MethodBreakdown {
    MethodBreakdown {
        body_bytes: components[0],
        gc_info_bytes: components[1],
        exception_info_bytes: components[2],
    }
}

fn method_report(
    inventory: &ParsedInventory<'_>,
    filter: Option<&Pattern<'_>>,
    top: usize,
) -> Result<MethodsInsightReport, MstatError> {
    let mut total = InsightCounts::default();
    let mut matched = InsightCounts::default();
    let mut total_components = [0; 3];
    let mut matched_components = [0; 3];
    let mut size_bands: Vec<_> = [
        (0, Some(0)),
        (1, Some(255)),
        (256, Some(4095)),
        (4096, Some(65535)),
        (65536, None),
    ]
    .into_iter()
    .map(|(minimum_bytes, maximum_bytes)| MethodSizeBand {
        minimum_bytes,
        maximum_bytes,
        total: InsightCounts::default(),
        matched: InsightCounts::default(),
    })
    .collect();
    for record in &inventory.sections[0] {
        let band = match record.counts.bytes {
            0 => 0,
            1..=255 => 1,
            256..=4095 => 2,
            4096..=65535 => 3,
            _ => 4,
        };
        add_counts(&mut size_bands[band].total, record.counts)?;
        add_counts(&mut total, record.counts)?;
        for (target, value) in total_components.iter_mut().zip(record.components) {
            *target = checked_add(*target, value)?;
        }
        if matches(record, filter) {
            add_counts(&mut size_bands[band].matched, record.counts)?;
            add_counts(&mut matched, record.counts)?;
            for (target, value) in matched_components.iter_mut().zip(record.components) {
                *target = checked_add(*target, value)?;
            }
        }
    }
    let mut top_components = [0; 3];
    let mut top_bytes = 0;
    let mut entries = Vec::with_capacity(top);
    for record in select(
        inventory.sections[0]
            .iter()
            .copied()
            .filter(|record| matches(record, filter)),
        top,
    ) {
        for (target, value) in top_components.iter_mut().zip(record.components) {
            *target = checked_add(*target, value)?;
        }
        top_bytes = checked_add(top_bytes, record.counts.bytes)?;
        let preview = entry(record);
        entries.push(MethodInsightEntry {
            identity: preview.identity,
            identity_bytes: preview.identity_bytes,
            truncated: preview.truncated,
            bytes: preview.bytes,
            records: preview.records,
            body_bytes: record.components[0],
            gc_info_bytes: record.components[1],
            exception_info_bytes: record.components[2],
            accounted_basis_points: basis_points(
                record.counts.bytes,
                inventory.summary.accounted_size_bytes,
            ),
        });
    }
    Ok(MethodsInsightReport {
        accounted_denominator_bytes: inventory.summary.accounted_size_bytes,
        total,
        matched,
        total_components: breakdown(total_components),
        matched_components: breakdown(matched_components),
        top_components: breakdown(top_components),
        omitted_components: breakdown(std::array::from_fn(|index| {
            matched_components[index] - top_components[index]
        })),
        top_bytes,
        omitted_bytes: matched.bytes - top_bytes,
        entries,
        size_bands,
    })
}

fn blob_report(
    inventory: &ParsedInventory<'_>,
    filter: Option<&Pattern<'_>>,
    top: usize,
) -> Result<BlobInsightReport, MstatError> {
    const DEHYDRATED: &[u8] = b"D\0e\0h\0y\0d\0r\0a\0t\0e\0d\0D\0a\0t\0a\0";
    let mut report = BlobInsightReport::default();
    for record in &inventory.sections[2] {
        add_counts(&mut report.total, record.counts)?;
        if matches!(record.identity, ExactIdentity::UserString(name) if name == DEHYDRATED) {
            add_counts(&mut report.dehydrated_data, record.counts)?;
        }
        if matches(record, filter) {
            add_counts(&mut report.matched, record.counts)?;
        }
    }
    for record in select(
        inventory.sections[2]
            .iter()
            .copied()
            .filter(|record| matches(record, filter)),
        top,
    ) {
        report.top_bytes = checked_add(report.top_bytes, record.counts.bytes)?;
        report.entries.push(entry(record));
    }
    report.omitted_bytes = report.matched.bytes - report.top_bytes;
    Ok(report)
}

fn basis_points(bytes: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        u64::try_from(u128::from(bytes) * 10_000 / u128::from(denominator))
            .expect("accounted fraction fits u64")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum GroupKey<'a> {
    Assembly(&'a str, &'a str),
    Culture(&'a str),
    ResourceName(&'a [u8]),
    Prefix(&'a [u8]),
}

#[derive(Clone, Copy)]
struct GroupRange<'a> {
    key: GroupKey<'a>,
    start: usize,
    end: usize,
    total: InsightCounts,
    matched: InsightCounts,
}

struct Groups<'a> {
    records: Vec<(GroupKey<'a>, Record<'a>)>,
    ranges: Vec<GroupRange<'a>>,
}

fn groups<'a>(
    records: &[Record<'a>],
    key: impl Fn(ExactIdentity<'a>) -> Option<GroupKey<'a>>,
    filter: Option<&Pattern<'_>>,
    budget: &mut Budget,
) -> Result<Groups<'a>, MstatError> {
    let mut ordered = budget.vector(records.len())?;
    for record in records {
        if let Some(key) = key(record.identity) {
            ordered.push((key, *record));
        }
    }
    ordered.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.identity.cmp(&right.1.identity))
    });
    let mut ranges: Vec<GroupRange<'a>> = budget.vector(ordered.len())?;
    for (index, (key, record)) in ordered.iter().enumerate() {
        if ranges.last().is_none_or(|last| last.key != *key) {
            ranges.push(GroupRange {
                key: *key,
                start: index,
                end: index,
                total: InsightCounts::default(),
                matched: InsightCounts::default(),
            });
        }
        let group = ranges.last_mut().expect("inserted group");
        group.end = index + 1;
        add_counts(&mut group.total, record.counts)?;
        if matches(record, filter) {
            add_counts(&mut group.matched, record.counts)?;
        }
    }
    Ok(Groups {
        records: ordered,
        ranges,
    })
}

fn ranked_groups<'a>(groups: &[GroupRange<'a>], top: usize) -> Vec<GroupRange<'a>> {
    let mut selected = Vec::with_capacity(top);
    let compare = |left: &GroupRange<'a>, right: &GroupRange<'a>| {
        right
            .matched
            .bytes
            .cmp(&left.matched.bytes)
            .then_with(|| left.key.cmp(&right.key))
    };
    for group in groups.iter().filter(|group| group.matched.identities > 0) {
        if top != 0
            && (selected.len() < top
                || selected
                    .last()
                    .is_some_and(|last| compare(group, last).is_lt()))
        {
            selected.push(*group);
            selected.sort_unstable_by(compare);
            selected.truncate(top);
        }
    }
    selected
}

fn group_examples(
    groups: &Groups<'_>,
    group: GroupRange<'_>,
    filter: Option<&Pattern<'_>>,
    top: usize,
) -> (Vec<IdentityInsightEntry>, u64) {
    let selected = select(
        groups.records[group.start..group.end]
            .iter()
            .map(|(_, record)| *record)
            .filter(|record| matches(record, filter)),
        top,
    );
    let top_bytes = selected.iter().map(|record| record.counts.bytes).sum();
    (selected.into_iter().map(entry).collect(), top_bytes)
}

fn resource_list<K>(
    groups: &Groups<'_>,
    filter: Option<&Pattern<'_>>,
    top: usize,
    budget: &mut Budget,
    key: impl Fn(GroupKey<'_>, &mut Budget) -> Result<K, MstatError>,
) -> Result<ResourceGroupList<K>, MstatError> {
    let mut total = InsightCounts::default();
    let mut matched = InsightCounts::default();
    let mut matched_groups = 0;
    for group in &groups.ranges {
        add_counts(&mut total, group.total)?;
        add_counts(&mut matched, group.matched)?;
        if group.matched.identities > 0 {
            matched_groups += 1;
        }
    }
    let mut top_bytes = 0;
    let mut result = Vec::with_capacity(top);
    for group in ranked_groups(&groups.ranges, top) {
        let key = key(group.key, budget)?;
        let (entries, entry_bytes) = group_examples(groups, group, filter, top);
        top_bytes = checked_add(top_bytes, group.matched.bytes)?;
        result.push(ResourceGroup {
            key,
            total: group.total,
            matched: group.matched,
            top_bytes: entry_bytes,
            omitted_bytes: group.matched.bytes - entry_bytes,
            entries,
        });
    }
    Ok(ResourceGroupList {
        total,
        matched,
        total_groups: groups.ranges.len() as u64,
        matched_groups,
        top_bytes,
        omitted_bytes: matched.bytes - top_bytes,
        groups: result,
    })
}

fn resource_report(
    inventory: &ParsedInventory<'_>,
    filter: Option<&Pattern<'_>>,
    top: usize,
    budget: &mut Budget,
) -> Result<ResourcesInsightReport, MstatError> {
    let records = &inventory.sections[5];
    let assemblies = groups(
        records,
        |identity| match identity {
            ExactIdentity::Resource(name, culture, _) => Some(GroupKey::Assembly(name, culture)),
            _ => unreachable!("resource stream"),
        },
        filter,
        budget,
    )?;
    let by_assembly = resource_list(&assemblies, filter, top, budget, |key, budget| match key {
        GroupKey::Assembly(name, culture) => Ok(ResourceAssemblyKey {
            name: budget.text(name)?,
            culture: budget.text(culture)?,
        }),
        _ => unreachable!("assembly key"),
    })?;
    let cultures = groups(
        records,
        |identity| match identity {
            ExactIdentity::Resource(_, culture, _) => Some(GroupKey::Culture(culture)),
            _ => unreachable!("resource stream"),
        },
        filter,
        budget,
    )?;
    let by_culture = resource_list(&cultures, filter, top, budget, |key, budget| match key {
        GroupKey::Culture(culture) => budget.text(culture),
        _ => unreachable!("culture key"),
    })?;
    let resources = groups(
        records,
        |identity| match identity {
            ExactIdentity::Resource(_, _, name) => Some(GroupKey::ResourceName(name)),
            _ => unreachable!("resource stream"),
        },
        filter,
        budget,
    )?;
    let by_resource_name =
        resource_list(&resources, filter, top, budget, |key, budget| match key {
            GroupKey::ResourceName(name) => {
                // UTF-8 uses at most three bytes per UTF-16 code unit.
                let maximum = name
                    .len()
                    .checked_mul(3)
                    .ok_or_else(|| resource_error("MSTAT resource name length overflow"))?
                    / 2;
                budget.charge(maximum as u64)?;
                let mut value = String::with_capacity(maximum);
                value.extend(utf16_chars(name));
                Ok(value)
            }
            _ => unreachable!("resource-name key"),
        })?;
    Ok(ResourcesInsightReport {
        accounted: false,
        warning: "ManifestResources overlaps Blobs and is non-accounted. The three group lists are independently reconciled alternate views; do not add them or add them to Blobs.".into(),
        by_assembly, by_culture, by_resource_name,
    })
}

fn generic_report(
    inventory: &ParsedInventory<'_>,
    filter: Option<&Pattern<'_>>,
    top: usize,
    budget: &mut Budget,
) -> Result<GenericsInsightReport, MstatError> {
    let mut sections = Vec::with_capacity(2);
    for (index, stream) in REQUIRED_STREAMS.iter().enumerate().take(2) {
        let records = &inventory.sections[index];
        let ranges = generic_group_ranges(records, filter, budget)?;
        let mut total = InsightCounts::default();
        for record in records {
            add_counts(&mut total, record.counts)?;
        }
        let mut generic_shaped = InsightCounts::default();
        let mut matched_generic_shaped = InsightCounts::default();
        let mut matched_families = 0;
        for group in &ranges {
            add_counts(&mut generic_shaped, group.total)?;
            add_counts(&mut matched_generic_shaped, group.matched)?;
            if group.matched.identities > 0 {
                matched_families += 1;
            }
        }
        let mut top_bytes = 0;
        let mut families = Vec::with_capacity(top);
        for group in ranked_groups(&ranges, top) {
            let GroupKey::Prefix(prefix) = group.key else {
                unreachable!("prefix key")
            };
            let prefix =
                budget.text(std::str::from_utf8(prefix).expect("validated UTF-8 prefix"))?;
            let selected = select(
                records[group.start..group.end]
                    .iter()
                    .copied()
                    .filter(|record| matches(record, filter)),
                top,
            );
            let example_bytes = selected.iter().map(|record| record.counts.bytes).sum();
            let examples = selected.into_iter().map(entry).collect();
            top_bytes = checked_add(top_bytes, group.matched.bytes)?;
            families.push(GenericFamily {
                prefix,
                total: group.total,
                matched: group.matched,
                top_bytes: example_bytes,
                omitted_bytes: group.matched.bytes - example_bytes,
                examples,
            });
        }
        sections.push(GenericStreamReport {
            stream: (*stream).into(),
            total,
            generic_shaped,
            non_generic_shaped: InsightCounts {
                bytes: total.bytes - generic_shaped.bytes,
                identities: total.identities - generic_shaped.identities,
                records: total.records - generic_shaped.records,
            },
            matched_generic_shaped,
            total_families: ranges.len() as u64,
            matched_families,
            top_bytes,
            omitted_bytes: matched_generic_shaped.bytes - top_bytes,
            families,
        });
    }
    Ok(GenericsInsightReport {
        caveat: "Literal producer-display classification only: a UTF-8 name containing '<' is generic-shaped, grouped by its exact byte prefix before the first '<'. Leading '<' yields an empty prefix and includes anonymous/generated names. This is not proof of managed generic instantiations and implies no runtime savings.".into(),
        sections,
    })
}

fn generic_prefix(identity: ExactIdentity<'_>) -> Option<&[u8]> {
    let ExactIdentity::Name(name) = identity else {
        unreachable!("Methods and Types use names");
    };
    memchr::memchr(b'<', name).map(|offset| &name[..offset])
}

fn generic_group_ranges<'a>(
    records: &[Record<'a>],
    filter: Option<&Pattern<'_>>,
    budget: &mut Budget,
) -> Result<Vec<GroupRange<'a>>, MstatError> {
    // Coalescing orders complete names lexicographically. Every family consists
    // of names starting with prefix + '<', so its members form one contiguous
    // interval, even though the family prefixes themselves need not be ordered.
    let mut previous = None;
    let mut count = 0;
    for record in records {
        if let Some(prefix) = generic_prefix(record.identity) {
            if previous != Some(prefix) {
                count += 1;
                previous = Some(prefix);
            }
        }
    }
    let mut ranges: Vec<GroupRange<'a>> = budget.vector(count)?;
    for (index, record) in records.iter().enumerate() {
        let Some(prefix) = generic_prefix(record.identity) else {
            continue;
        };
        let key = GroupKey::Prefix(prefix);
        if ranges.last().is_none_or(|last| last.key != key) {
            ranges.push(GroupRange {
                key,
                start: index,
                end: index + 1,
                total: InsightCounts::default(),
                matched: InsightCounts::default(),
            });
        }
        let group = ranges.last_mut().expect("inserted family");
        group.end = index + 1;
        add_counts(&mut group.total, record.counts)?;
        if matches(record, filter) {
            add_counts(&mut group.matched, record.counts)?;
        }
    }
    Ok(ranges)
}

fn cohort_report(
    inventory: &ParsedInventory<'_>,
    filter: Option<&Pattern<'_>>,
    rules: &[Rule<'_>],
    top: usize,
    budget: &mut Budget,
) -> Result<CohortsInsightReport, MstatError> {
    let mut counts: Vec<[InsightCounts; 7]> = budget.vector(rules.len())?;
    counts.resize(rules.len(), [InsightCounts::default(); 7]);
    let pair_count = rules.len() * rules.len().saturating_sub(1) / 2;
    let mut intersections: Vec<CohortIntersection> = budget.vector(pair_count)?;
    for left in 0..rules.len() {
        for right in left + 1..rules.len() {
            intersections.push(CohortIntersection {
                left,
                right,
                accounted: InsightCounts::default(),
                non_accounted: InsightCounts::default(),
            });
        }
    }
    let mut union = [InsightCounts::default(); 2];
    let mut union_sections = [InsightCounts::default(); 7];
    let mut multiple = union;
    let mut matched_rules: Vec<bool> = budget.vector(rules.len())?;
    matched_rules.resize(rules.len(), false);
    let mut examples = budget.vector(rules.len())?;
    examples.resize_with(rules.len(), || Vec::with_capacity(top));
    for (stream, records) in inventory.sections.iter().enumerate() {
        for record in records.iter().filter(|record| matches(record, filter)) {
            for (index, rule) in rules.iter().enumerate() {
                matched_rules[index] = rule.stream.is_none_or(|value| value == stream)
                    && rule
                        .patterns
                        .iter()
                        .any(|pattern| pattern.matches(record.identity));
                if matched_rules[index] {
                    add_counts(&mut counts[index][stream], record.counts)?;
                    select_cohort_example(&mut examples[index], (stream, *record), top);
                }
            }
            let matched_count = matched_rules.iter().filter(|value| **value).count();
            let side = usize::from(stream >= 3);
            if matched_count > 0 {
                add_counts(&mut union[side], record.counts)?;
                add_counts(&mut union_sections[stream], record.counts)?;
            }
            if matched_count > 1 {
                add_counts(&mut multiple[side], record.counts)?;
            }
            for intersection in &mut intersections {
                if matched_rules[intersection.left] && matched_rules[intersection.right] {
                    let target = if stream < 3 {
                        &mut intersection.accounted
                    } else {
                        &mut intersection.non_accounted
                    };
                    add_counts(target, record.counts)?;
                }
            }
        }
    }
    intersections.retain(|pair| pair.accounted.identities + pair.non_accounted.identities > 0);
    let mut cohorts = budget.vector(rules.len())?;
    for ((index, rule), examples) in rules.iter().enumerate().zip(examples) {
        let mut accounted = InsightCounts::default();
        let mut non_accounted = InsightCounts::default();
        let mut sections = budget.vector(7)?;
        for (stream, matched) in counts[index].iter().copied().enumerate() {
            add_counts(
                if stream < 3 {
                    &mut accounted
                } else {
                    &mut non_accounted
                },
                matched,
            )?;
            sections.push(CohortStreamCounts {
                stream: REQUIRED_STREAMS[stream].into(),
                accounted: stream < 3,
                matched,
            });
        }
        cohorts.push(CohortInsight {
            name: budget.text(rule.name)?,
            accounted,
            non_accounted,
            sections,
            examples: cohort_examples(examples),
        });
    }

    Ok(CohortsInsightReport {
        warning: "Case-sensitive literal OR predicates over opaque producer identities are heuristics, not exclusive ownership. Cohorts and pair intersections overlap: never sum cohorts. Non-accounted streams also overlap Blobs; deduplicated entries carry zero bytes, not estimated savings. Identity/record counts are stream-scoped; DeduplicatedMethods records count folded entries.".into(),
        accounted_denominator_bytes: inventory.summary.accounted_size_bytes,
        union_accounted: union[0], union_non_accounted: union[1],
        multiply_matched_accounted: multiple[0], multiply_matched_non_accounted: multiple[1],
        cohorts, intersections,
        union_sections: union_sections.into_iter().enumerate().map(|(stream, matched)| CohortStreamCounts {
            stream: REQUIRED_STREAMS[stream].into(), accounted: stream < 3, matched,
        }).collect(),
    })
}

fn ranked_cohort_examples(left: &(usize, Record<'_>), right: &(usize, Record<'_>)) -> Ordering {
    right
        .1
        .counts
        .bytes
        .cmp(&left.1.counts.bytes)
        .then_with(|| left.0.cmp(&right.0))
        .then_with(|| left.1.identity.cmp(&right.1.identity))
}

fn select_cohort_example<'a>(
    selected: &mut Vec<(usize, Record<'a>)>,
    candidate: (usize, Record<'a>),
    top: usize,
) {
    if top != 0
        && (selected.len() < top
            || selected
                .last()
                .is_some_and(|last| ranked_cohort_examples(&candidate, last).is_lt()))
    {
        selected.push(candidate);
        selected.sort_unstable_by(ranked_cohort_examples);
        selected.truncate(top);
    }
}

fn cohort_examples(selected: Vec<(usize, Record<'_>)>) -> Vec<CohortExample> {
    selected
        .into_iter()
        .map(|(stream, record)| CohortExample {
            stream: REQUIRED_STREAMS[stream].into(),
            entry: entry(record),
        })
        .collect()
}
