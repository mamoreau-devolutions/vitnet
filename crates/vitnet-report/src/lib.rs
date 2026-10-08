//! Stable report serialization.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use vitnet_core::Diagnostic;
use vitnet_metadata::{Analysis, Comparison, compare};

pub const METADATA_SCHEMA_V1: &str = "vitnet.metadata.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub path: Option<PathBuf>,
    pub bytes_read: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub producer_offset_bits: u8,
    pub metadata_lower_bound_bytes: u64,
    pub selected_lower_bound_bytes: u64,
    pub observed_record_count: u64,
    pub record_count: u64,
    pub total_is_lower_bound: bool,
    pub final_record_size_known: bool,
    pub peak_tracked_memory_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sections {
    #[serde(default)]
    pub concentration: std::collections::BTreeMap<String, vitnet_metadata::Concentration>,
    pub by_kind: Vec<vitnet_metadata::Aggregate>,
    pub by_assembly: Vec<vitnet_metadata::Aggregate>,
    pub by_namespace: Vec<vitnet_metadata::Aggregate>,
    pub by_type: Vec<vitnet_metadata::Aggregate>,
    pub largest_strings: Vec<vitnet_metadata::StringEntry>,
    pub unowned: Vec<vitnet_metadata::Aggregate>,
    pub limit_status: vitnet_metadata::LimitStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetadataEnvelope {
    pub schema: String,
    pub tool_version: String,
    pub input: InputDescriptor,
    pub summary: Summary,
    pub sections: Sections,
    pub diagnostics: Vec<Diagnostic>,
}

impl MetadataEnvelope {
    #[must_use]
    pub fn new(
        tool_version: impl Into<String>,
        input: InputDescriptor,
        analysis: Analysis,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: METADATA_SCHEMA_V1.into(),
            tool_version: tool_version.into(),
            input,
            summary: Summary {
                producer_offset_bits: analysis.offset_bits,
                metadata_lower_bound_bytes: analysis.observed_lower_bound,
                selected_lower_bound_bytes: analysis.selected_lower_bound,
                observed_record_count: analysis.observed_record_count,
                record_count: analysis.record_count,
                total_is_lower_bound: analysis.total_is_lower_bound,
                final_record_size_known: analysis.final_record_size_known,
                peak_tracked_memory_bytes: analysis.peak_tracked_bytes,
            },
            sections: Sections {
                concentration: analysis.concentration,
                by_kind: analysis.by_kind,
                by_assembly: analysis.by_assembly,
                by_namespace: analysis.by_namespace,
                by_type: analysis.by_type,
                largest_strings: analysis.largest_strings,
                unowned: analysis.unowned,
                limit_status: analysis.limit_status,
            },
            diagnostics,
        }
    }

    /// Serializes the stable envelope as pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if an envelope value cannot be encoded.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

pub const METADATA_COMPARISON_SCHEMA_V1: &str = "vitnet.metadata-comparison.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComparisonSummary {
    pub before_lower_bound_bytes: u64,
    pub after_lower_bound_bytes: u64,
    pub delta_bytes: i128,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComparisonSections {
    pub by_kind: Comparison,
    pub by_assembly: Comparison,
    pub by_namespace: Comparison,
    pub by_type: Comparison,
    pub unowned: Comparison,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetadataComparisonEnvelope {
    pub schema: String,
    pub tool_version: String,
    pub before: InputDescriptor,
    pub after: InputDescriptor,
    pub summary: ComparisonSummary,
    pub sections: ComparisonSections,
    pub diagnostics: Vec<Diagnostic>,
}

impl MetadataComparisonEnvelope {
    #[must_use]
    pub fn new(
        tool_version: impl Into<String>,
        before: &MetadataEnvelope,
        after: &MetadataEnvelope,
    ) -> Self {
        let before_bytes = before.summary.selected_lower_bound_bytes;
        let after_bytes = after.summary.selected_lower_bound_bytes;
        Self {
            schema: METADATA_COMPARISON_SCHEMA_V1.into(),
            tool_version: tool_version.into(),
            before: before.input.clone(),
            after: after.input.clone(),
            summary: ComparisonSummary {
                before_lower_bound_bytes: before_bytes,
                after_lower_bound_bytes: after_bytes,
                delta_bytes: i128::from(after_bytes) - i128::from(before_bytes),
            },
            sections: ComparisonSections {
                by_kind: compare(&before.sections.by_kind, &after.sections.by_kind),
                by_assembly: compare(&before.sections.by_assembly, &after.sections.by_assembly),
                by_namespace: compare(&before.sections.by_namespace, &after.sections.by_namespace),
                by_type: compare(&before.sections.by_type, &after.sections.by_type),
                unowned: compare(&before.sections.unowned, &after.sections.unowned),
            },
            diagnostics: Vec::new(),
        }
    }

    pub fn truncate(&mut self, limit: usize) {
        self.sections.by_kind.entries.truncate(limit);
        self.sections.by_assembly.entries.truncate(limit);
        self.sections.by_namespace.entries.truncate(limit);
        self.sections.by_type.entries.truncate(limit);
        self.sections.unowned.entries.truncate(limit);
    }
}
