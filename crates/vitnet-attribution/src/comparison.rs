use crate::model::{Binary, BinarySection, EvidenceDiagnostic};
use crate::{
    AttributionError, AttributionIndex, Fingerprint, error, hash_file, io, open_index, report,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use vitnet_mstat::MstatDiff;

/// Reads physical and virtual PE section lengths without loading the image.
///
/// # Errors
///
/// Returns malformed/truncated-image, I/O and section-bound diagnostics.
pub fn read_pe_binary(path: &Path) -> Result<Binary, AttributionError> {
    let mut file = File::open(path).map_err(|cause| io(path, cause))?;
    let length = file.metadata().map_err(|cause| io(path, cause))?.len();
    let mut dos = [0; 64];
    file.read_exact(&mut dos).map_err(|cause| io(path, cause))?;
    if &dos[..2] != b"MZ" {
        return Err(error(
            "attribution.binary.format",
            "native section inspection currently supports PE only",
        ));
    }
    let offset = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]);
    if offset < 64 {
        return Err(error(
            "attribution.binary.format",
            "PE header overlaps DOS header",
        ));
    }
    file.seek(SeekFrom::Start(u64::from(offset)))
        .map_err(|cause| io(path, cause))?;
    let mut header = [0; 24];
    file.read_exact(&mut header)
        .map_err(|cause| io(path, cause))?;
    if &header[..4] != b"PE\0\0" {
        return Err(error("attribution.binary.format", "invalid PE signature"));
    }
    let count = u16::from_le_bytes([header[6], header[7]]);
    if count > 4096 {
        return Err(error(
            "resource.memory_limit",
            "PE section count exceeds inspection bound",
        ));
    }
    let optional_size = u16::from_le_bytes([header[20], header[21]]);
    if u64::from(offset) + 24 + u64::from(optional_size) + u64::from(count) * 40 > length {
        return Err(error(
            "attribution.binary.section",
            "PE header/section table exceeds file",
        ));
    }
    if optional_size < 96 {
        return Err(error(
            "attribution.binary.format",
            "PE optional header is absent or truncated",
        ));
    }
    let mut magic = [0; 2];
    file.read_exact(&mut magic)
        .map_err(|cause| io(path, cause))?;
    let minimum = match u16::from_le_bytes(magic) {
        0x10b => 96,
        0x20b => 112,
        _ => {
            return Err(error(
                "attribution.binary.format",
                "unsupported PE optional header magic",
            ));
        }
    };
    if optional_size < minimum {
        return Err(error(
            "attribution.binary.format",
            "PE optional header is truncated",
        ));
    }
    file.seek(SeekFrom::Current(i64::from(optional_size) - 2))
        .map_err(|cause| io(path, cause))?;
    let mut sections = Vec::new();
    for _ in 0..count {
        let mut raw = [0; 40];
        file.read_exact(&mut raw).map_err(|cause| io(path, cause))?;
        let physical = u64::from(u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]));
        let pointer = u64::from(u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]));
        if pointer.checked_add(physical).is_none_or(|end| end > length) {
            return Err(error(
                "attribution.binary.section",
                "PE raw section exceeds file",
            ));
        }
        let end = raw[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        sections.push(BinarySection {
            name: String::from_utf8_lossy(&raw[..end]).into_owned(),
            file_bytes: physical,
            virtual_bytes: u64::from(u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]])),
        });
    }
    let machine = u16::from_le_bytes([header[4], header[5]]);
    let architecture = match machine {
        0x8664 => "x64".into(),
        0xaa64 => "arm64".into(),
        0x14c => "x86".into(),
        value => format!("machine_{value:04x}"),
    };
    Ok(Binary {
        path: path.to_owned(),
        format: "PE".into(),
        architecture,
        file_bytes: length,
        sections,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceChange {
    pub key: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhysicalDelta {
    pub before_path: Option<PathBuf>,
    pub after_path: Option<PathBuf>,
    pub before_bytes: Option<u64>,
    pub after_bytes: Option<u64>,
    pub delta_bytes: Option<i128>,
    pub sections: Vec<SectionDelta>,
    pub compatible_architecture: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SectionDelta {
    pub name: String,
    pub before_file_bytes: u64,
    pub after_file_bytes: u64,
    pub file_delta_bytes: i128,
    pub before_virtual_bytes: u64,
    pub after_virtual_bytes: u64,
    pub virtual_delta_bytes: i128,
}

/// Computes signed physical deltas while retaining unknown missing binaries.
///
/// # Errors
///
/// Rejects overflowing section aggregates.
pub fn physical_delta(
    before: Option<&Binary>,
    after: Option<&Binary>,
) -> Result<PhysicalDelta, AttributionError> {
    let mut sections: BTreeMap<String, (u64, u64, u64, u64)> = BTreeMap::new();
    for (binary, is_after) in [(before, false), (after, true)] {
        if let Some(binary) = binary {
            for section in &binary.sections {
                let group = sections.entry(section.name.clone()).or_default();
                let (physical, virtual_size) = if is_after {
                    (&mut group.2, &mut group.3)
                } else {
                    (&mut group.0, &mut group.1)
                };
                *physical = physical
                    .checked_add(section.file_bytes)
                    .ok_or_else(|| error("attribution.size", "physical section size overflow"))?;
                *virtual_size = virtual_size
                    .checked_add(section.virtual_bytes)
                    .ok_or_else(|| error("attribution.size", "virtual section size overflow"))?;
            }
        }
    }
    let complete = before.is_some() && after.is_some();
    Ok(PhysicalDelta {
        before_path: before.map(|binary| binary.path.clone()),
        after_path: after.map(|binary| binary.path.clone()),
        before_bytes: before.map(|binary| binary.file_bytes),
        after_bytes: after.map(|binary| binary.file_bytes),
        delta_bytes: before
            .zip(after)
            .map(|(left, right)| i128::from(right.file_bytes) - i128::from(left.file_bytes)),
        sections: if complete {
            sections
                .into_iter()
                .map(
                    |(name, (before_file, before_virtual, after_file, after_virtual))| {
                        SectionDelta {
                            name,
                            before_file_bytes: before_file,
                            after_file_bytes: after_file,
                            file_delta_bytes: i128::from(after_file) - i128::from(before_file),
                            before_virtual_bytes: before_virtual,
                            after_virtual_bytes: after_virtual,
                            virtual_delta_bytes: i128::from(after_virtual)
                                - i128::from(before_virtual),
                        }
                    },
                )
                .collect()
        } else {
            Vec::new()
        },
        compatible_architecture: before.zip(after).map(|(left, right)| {
            left.architecture == right.architecture && left.format == right.format
        }),
    })
}

#[must_use]
pub fn evidence_changes(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<EvidenceChange> {
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .map(|key| EvidenceChange {
            key: key.clone(),
            before: before.get(key).cloned(),
            after: after.get(key).cloned(),
        })
        .collect()
}

/// Checks current files/generations against captured fingerprints.
///
/// # Errors
///
/// Returns file or graph-cache I/O/structure diagnostics.
pub fn verify_artifacts(
    index: &AttributionIndex,
) -> Result<Vec<EvidenceDiagnostic>, AttributionError> {
    let mut diagnostics = Vec::new();
    for artifact in &index.artifacts {
        if artifact.graph_generation.is_some() {
            if artifact.path.is_dir() {
                let current =
                    vitnet_dgml::cache_info(&artifact.path).map_err(|cause| AttributionError {
                        diagnostic: cause.diagnostic,
                    })?;
                if Some(&current.generation) != artifact.graph_generation.as_ref() {
                    diagnostics.push(EvidenceDiagnostic {
                        code: "evidence.graph.stale".into(),
                        message: "graph generation changed after import".into(),
                        path: Some(artifact.path.clone()),
                    });
                }
            } else {
                diagnostics.push(EvidenceDiagnostic {
                    code: "evidence.missing".into(),
                    message: "graph is unavailable".into(),
                    path: Some(artifact.path.clone()),
                });
            }
        } else if let Some(expected) = &artifact.blake3 {
            if !artifact.path.is_file() {
                diagnostics.push(EvidenceDiagnostic {
                    code: "evidence.missing".into(),
                    message: "fingerprinted artifact is unavailable".into(),
                    path: Some(artifact.path.clone()),
                });
            } else if hash_file(&artifact.path)?.1 != *expected {
                diagnostics.push(EvidenceDiagnostic {
                    code: "evidence.artifact.stale".into(),
                    message: "artifact changed after import".into(),
                    path: Some(artifact.path.clone()),
                });
            }
        }
    }
    Ok(diagnostics)
}

#[derive(Clone, Debug, Serialize)]
pub struct AttributionDelta {
    pub assembly: String,
    pub mapping_status: String,
    pub before_visible_bytes: u64,
    pub after_visible_bytes: u64,
    pub visible_delta_bytes: i128,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComparisonReport {
    pub schema: String,
    pub provenance_changes: Vec<EvidenceChange>,
    pub package_changes: Vec<EvidenceChange>,
    pub graph_generation_changes: Vec<EvidenceChange>,
    pub mstat: Option<MstatDiff>,
    pub metadata: Option<MetadataDelta>,
    pub physical: PhysicalDelta,
    pub source_changes: Vec<EvidenceChange>,
    pub retention: Option<RetentionComparison>,
    pub attribution_visible_changes: Vec<AttributionDelta>,
    pub diagnostics: Vec<EvidenceDiagnostic>,
    pub caveats: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetadataDelta {
    pub before_lower_bound_bytes: u64,
    pub after_lower_bound_bytes: u64,
    pub lower_bound_delta_bytes: i128,
    pub by_kind: vitnet_metadata::Comparison,
    pub by_assembly: vitnet_metadata::Comparison,
    pub by_type: vitnet_metadata::Comparison,
    pub complete_dimensions: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetentionComparison {
    pub before: crate::RetentionReport,
    pub after: crate::RetentionReport,
    pub before_incoming_edges: u64,
    pub after_incoming_edges: u64,
    pub incoming_edge_delta: i128,
    pub caveat: String,
}

/// Adds explicitly selected, generation-bound retention witnesses to a comparison.
///
/// # Errors
///
/// Rejects absent/stale graph evidence and bounded-query failures.
pub fn compare_retention(
    before: &Path,
    after: &Path,
    before_node: u64,
    after_node: u64,
    graph_kind: &str,
    memory_limit: u64,
    options: &vitnet_dgml::WhyOptions,
) -> Result<RetentionComparison, AttributionError> {
    let before_report = crate::explain(
        before,
        before_node,
        graph_kind,
        memory_limit / 2,
        options,
        20,
    )?;
    let after_report =
        crate::explain(after, after_node, graph_kind, memory_limit / 2, options, 20)?;
    let before_incoming_edges = before_report.alternative_incoming.total_edges;
    let after_incoming_edges = after_report.alternative_incoming.total_edges;
    Ok(RetentionComparison {
        before: before_report, after: after_report, before_incoming_edges, after_incoming_edges,
        incoming_edge_delta: i128::from(after_incoming_edges) - i128::from(before_incoming_edges),
        caveat: "Explicit node selections are user-supplied cross-build correspondences. Full path and incoming reasons remain visible; edge-count changes are not removal/savings proof.".into(),
    })
}

fn artifact<'a>(index: &'a AttributionIndex, kind: &str) -> Option<&'a Fingerprint> {
    index
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == kind && artifact.available)
}

/// Compares full MSTAT evidence and physical binaries, retaining unknown missing data.
///
/// # Errors
///
/// Rejects stale source artifacts, corrupt indexes, invalid binary evidence and limits.
#[allow(clippy::too_many_lines)]
pub fn compare(
    before: &Path,
    after: &Path,
    memory_limit: u64,
    top: usize,
) -> Result<ComparisonReport, AttributionError> {
    let left = open_index(before, memory_limit / 2)?;
    let right = open_index(after, memory_limit / 2)?;
    let mut diagnostics = verify_artifacts(&left)?;
    diagnostics.extend(verify_artifacts(&right)?);
    let critical_paths: BTreeSet<_> = left
        .artifacts
        .iter()
        .chain(&right.artifacts)
        .filter(|artifact| matches!(artifact.kind.as_str(), "mstat" | "binary"))
        .map(|artifact| &artifact.path)
        .collect();
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code.rsplit('.').next() == Some("stale")
            && diagnostic
                .path
                .as_ref()
                .is_some_and(|path| critical_paths.contains(path))
    }) {
        return Err(error(
            "attribution.compare.stale",
            "comparison inputs changed since import; create new evidence indexes",
        ));
    }
    let mstat = match (artifact(&left, "mstat"), artifact(&right, "mstat")) {
        (Some(a), Some(b)) if a.path.is_file() && b.path.is_file() => Some(
            vitnet_mstat::diff_paths(&a.path, &b.path, memory_limit / 2, top).map_err(|cause| {
                AttributionError {
                    diagnostic: cause.diagnostic,
                }
            })?,
        ),
        _ => {
            diagnostics.push(EvidenceDiagnostic {
                code: "evidence.compare.mstat.missing".into(),
                message: "full MSTAT identity delta is unavailable".into(),
                path: None,
            });
            None
        }
    };
    let native = |index: &AttributionIndex| -> Result<Option<Binary>, AttributionError> {
        let paths: Vec<_> = index
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == "binary" && artifact.available && artifact.path.is_file()
            })
            .collect();
        match paths.len() {
            0 => Ok(None),
            1 => read_pe_binary(&paths[0].path).map(Some),
            _ => Err(error(
                "attribution.compare.binary",
                "comparison requires one primary native binary per bundle",
            )),
        }
    };
    let before_binary = native(&left)?;
    let after_binary = native(&right)?;
    let physical = physical_delta(before_binary.as_ref(), after_binary.as_ref())?;
    let source_map = |index: &AttributionIndex| {
        index
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == "source")
            .filter_map(|artifact| {
                artifact
                    .blake3
                    .as_ref()
                    .map(|hash| (artifact.path.to_string_lossy().into_owned(), hash.clone()))
            })
            .collect()
    };
    let metadata = left
        .metadata
        .as_ref()
        .zip(right.metadata.as_ref())
        .map(|(before, after)| MetadataDelta {
            before_lower_bound_bytes: before.total_lower_bound,
            after_lower_bound_bytes: after.total_lower_bound,
            lower_bound_delta_bytes: i128::from(after.total_lower_bound)
                - i128::from(before.total_lower_bound),
            by_kind: vitnet_metadata::compare(&before.by_kind, &after.by_kind),
            by_assembly: vitnet_metadata::compare(&before.by_assembly, &after.by_assembly),
            by_type: vitnet_metadata::compare(&before.by_type, &after.by_type),
            complete_dimensions: [before, after].iter().all(|analysis| {
                ["by_kind", "by_assembly", "by_type"].iter().all(|name| {
                    analysis
                        .concentration
                        .get(*name)
                        .is_some_and(|counts| counts.total_groups == counts.reported_groups)
                })
            }),
        });
    let package_map = |index: &AttributionIndex| {
        index
            .evidence
            .packages
            .iter()
            .map(|package| {
                (
                    format!("{}:{}", package.target, package.id),
                    package.version.clone(),
                )
            })
            .collect()
    };
    let graph_map = |index: &AttributionIndex| {
        index
            .artifacts
            .iter()
            .filter_map(|artifact| {
                artifact
                    .graph_generation
                    .as_ref()
                    .map(|generation| (artifact.kind.clone(), generation.clone()))
            })
            .collect()
    };
    let before_report = report(before, memory_limit / 2, top, None)?;
    let after_report = report(after, memory_limit / 2, top, None)?;
    let mut groups = BTreeMap::<(String, String), (u64, u64)>::new();
    for group in before_report.assembly_groups {
        groups
            .entry((group.name, group.mapping_status))
            .or_default()
            .0 = group.bytes;
    }
    for group in after_report.assembly_groups {
        groups
            .entry((group.name, group.mapping_status))
            .or_default()
            .1 = group.bytes;
    }
    let attribution_visible_changes = groups
        .into_iter()
        .map(|((assembly, status), (a, b))| AttributionDelta {
            assembly,
            mapping_status: status,
            before_visible_bytes: a,
            after_visible_bytes: b,
            visible_delta_bytes: i128::from(b) - i128::from(a),
        })
        .collect();
    Ok(ComparisonReport {
        schema: "vitnet.attribution-compare.v1".into(),
        provenance_changes: evidence_changes(&left.evidence.provenance, &right.evidence.provenance),
        package_changes: evidence_changes(&package_map(&left), &package_map(&right)),
        graph_generation_changes: evidence_changes(&graph_map(&left), &graph_map(&right)),
        mstat, metadata, physical,
        source_changes: evidence_changes(&source_map(&left), &source_map(&right)),
        retention: None, attribution_visible_changes, diagnostics,
        caveats: vec![
            "Physical file deltas are separate from logical MSTAT accounting and do not prove one edit caused the entire difference.".into(),
            "Missing native/MSTAT evidence is unknown, never a zero saving. Incompatible architectures/toolchains must not be treated as a controlled experiment.".into(),
            "Attribution deltas cover displayed top groups only; absent display rows are not proof of zero complete bytes. Full MSTAT diff remains independently reconciled.".into(),
            "A graph generation change is provenance, not a computed graph edge/removal diff; new witnesses are needed to confirm changed retention.".into(),
            "Metadata totals are lower bounds. When complete_dimensions=false, projected group deltas are display comparisons, not complete additions/removals.".into(),
        ],
    })
}
