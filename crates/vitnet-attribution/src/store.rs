use crate::model::{EVIDENCE_SCHEMA, Evidence, EvidenceDiagnostic};
use crate::{AttributionError, error, io};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use vitnet_mstat::{CoalescedIdentity, MstatSummary};

pub const INDEX_SCHEMA: &str = "vitnet.attribution-index.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fingerprint {
    pub kind: String,
    pub path: PathBuf,
    pub available: bool,
    pub file_bytes: Option<u64>,
    pub blake3: Option<String>,
    pub matches_expected: Option<bool>,
    pub graph_generation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttributionIndex {
    pub schema: String,
    pub evidence: Evidence,
    pub artifacts: Vec<Fingerprint>,
    pub mstat: Option<MstatSummary>,
    #[serde(default)]
    pub metadata: Option<vitnet_metadata::Analysis>,
    pub identities: u64,
    pub identities_blake3: String,
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

/// Hashes a file with a fixed streaming buffer.
///
/// # Errors
///
/// Returns file I/O or length-overflow diagnostics.
pub fn hash_file(path: &Path) -> Result<(u64, String), AttributionError> {
    let mut input = File::open(path).map_err(|cause| io(path, cause))?;
    let mut buffer = vec![0; 64 * 1024];
    let mut hash = blake3::Hasher::new();
    let mut size = 0_u64;
    loop {
        let count = input.read(&mut buffer).map_err(|cause| io(path, cause))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| error("attribution.size", "file length overflow"))?;
    }
    Ok((size, hash.finalize().to_hex().to_string()))
}

/// Reads a JSON document within its reserved memory share.
///
/// # Errors
///
/// Returns I/O, JSON, or resource-limit diagnostics.
pub fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    memory_limit: u64,
) -> Result<T, AttributionError> {
    let file = File::open(path).map_err(|cause| io(path, cause))?;
    let length = file.metadata().map_err(|cause| io(path, cause))?.len();
    let limit = (memory_limit / 8).min(256 * 1024 * 1024);
    if length > limit {
        return Err(error(
            "resource.memory_limit",
            "evidence JSON exceeds its bounded memory share",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|cause| io(path, cause))?;
    if bytes.len() as u64 > limit {
        return Err(error(
            "resource.memory_limit",
            "evidence JSON grew beyond its memory share",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|cause| error("attribution.json", cause.to_string()))
}

fn diagnostic(code: &str, message: String, path: Option<PathBuf>) -> EvidenceDiagnostic {
    EvidenceDiagnostic {
        code: code.into(),
        message,
        path,
    }
}

/// Validates versioned evidence declarations.
///
/// # Errors
///
/// Rejects unsupported schemas and invalid or duplicate evidence keys.
pub fn validate_evidence(evidence: &Evidence) -> Result<(), AttributionError> {
    if evidence.schema != EVIDENCE_SCHEMA {
        return Err(error("attribution.schema", "unsupported evidence schema"));
    }
    if evidence.sources.iter().any(|source| {
        source.line == 0 || source.end_line < source.line || source.type_name.is_empty()
    }) {
        return Err(error(
            "attribution.source",
            "invalid source declaration or line range",
        ));
    }
    if evidence.mappings.iter().any(|mapping| {
        mapping.identity.is_empty() || mapping.assembly.is_empty() || mapping.basis.is_empty()
    }) {
        return Err(error(
            "attribution.mapping",
            "explicit mappings need identity, assembly and evidence basis",
        ));
    }
    let mut keys = std::collections::BTreeSet::new();
    for package in &evidence.packages {
        if package.id.is_empty()
            || package.version.is_empty()
            || !keys.insert((&package.target, &package.id, &package.version))
        {
            return Err(error(
                "attribution.package",
                "empty or duplicate resolved package identity",
            ));
        }
    }
    Ok(())
}

/// Imports evidence and full MSTAT identities atomically, without copying raw inputs.
///
/// # Errors
///
/// Returns typed schema, file, corruption, duplicate-output and resource diagnostics.
#[allow(clippy::too_many_lines)]
pub fn import(
    manifest: &Path,
    output: &Path,
    memory_limit: u64,
    strict: bool,
) -> Result<AttributionIndex, AttributionError> {
    if memory_limit < 16 * 1024 * 1024 {
        return Err(error(
            "resource.memory_limit",
            "attribution import needs at least 16 MiB",
        ));
    }
    if output.exists() {
        return Err(error(
            "attribution.output.exists",
            "use a new index directory; existing evidence is immutable",
        ));
    }
    let mut evidence: Evidence = read_json(manifest, memory_limit)?;
    validate_evidence(&evidence)?;
    let base = manifest.parent().unwrap_or_else(|| Path::new("."));
    let resolve = |path: &mut PathBuf| {
        if !path.as_os_str().is_empty() && path.is_relative() {
            *path = base.join(&*path);
        }
    };
    for artifact in &mut evidence.artifacts {
        resolve(&mut artifact.path);
    }
    for source in &mut evidence.sources {
        resolve(&mut source.path);
    }
    for assembly in &mut evidence.assemblies {
        resolve(&mut assembly.path);
    }
    for generator in &mut evidence.generators {
        resolve(&mut generator.assembly_path);
        for path in &mut generator.generated_files {
            resolve(path);
        }
    }
    for resource in &mut evidence.resources {
        if let Some(path) = &mut resource.source_path {
            resolve(path);
        }
    }
    for binary in &mut evidence.binaries {
        resolve(&mut binary.path);
    }
    for mapping in &mut evidence.mappings {
        for path in &mut mapping.source_paths {
            resolve(path);
        }
    }
    let mut known: std::collections::BTreeSet<_> = evidence
        .artifacts
        .iter()
        .map(|artifact| (artifact.kind.clone(), artifact.path.clone()))
        .collect();
    let additional = evidence
        .sources
        .iter()
        .map(|source| ("source", &source.path))
        .chain(
            evidence
                .assemblies
                .iter()
                .map(|assembly| ("assembly", &assembly.path)),
        )
        .chain(
            evidence
                .binaries
                .iter()
                .map(|binary| ("binary", &binary.path)),
        );
    for (kind, path) in additional {
        if known.insert((kind.to_owned(), path.clone())) {
            evidence.artifacts.push(crate::model::Artifact {
                kind: kind.into(),
                path: path.clone(),
                revision: None,
                blake3: None,
            });
        }
    }
    let mut diagnostics = evidence.diagnostics.clone();
    let build_revisions: std::collections::BTreeSet<_> = evidence
        .provenance
        .iter()
        .filter(|(key, value)| {
            !value.is_empty()
                && (key.starts_with("binlog.source_revision:")
                    || (key.starts_with("binlog.property:")
                        && matches!(
                            key.rsplit(':').next(),
                            Some("SourceRevisionId" | "RepositoryCommit" | "GitCommit")
                        )))
        })
        .map(|(_, value)| value)
        .collect();
    if !build_revisions.is_empty() {
        for (key, current) in evidence
            .provenance
            .iter()
            .filter(|(key, _)| key.starts_with("source.current_revision:"))
        {
            if !build_revisions.contains(current) {
                diagnostics.push(diagnostic(
                    "evidence.revision.mismatch",
                    format!(
                        "{key}={current} differs from recorded build revision(s): {}",
                        build_revisions
                            .iter()
                            .map(|revision| revision.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    None,
                ));
            }
        }
    }
    let mut artifacts = Vec::new();
    let mut mstat_path = None;
    let mut metadata_path = None;
    for artifact in &evidence.artifacts {
        let mut fingerprint = Fingerprint {
            kind: artifact.kind.clone(),
            path: artifact.path.clone(),
            available: false,
            file_bytes: None,
            blake3: None,
            matches_expected: None,
            graph_generation: None,
        };
        if artifact.path.is_file() {
            let (length, hash) = hash_file(&artifact.path)?;
            fingerprint.available = true;
            fingerprint.file_bytes = Some(length);
            fingerprint.matches_expected =
                artifact.blake3.as_ref().map(|expected| expected == &hash);
            fingerprint.blake3 = Some(hash);
            if artifact.kind == "mstat" && mstat_path.replace(artifact.path.clone()).is_some() {
                return Err(error(
                    "attribution.mstat",
                    "one evidence bundle must describe one MSTAT input",
                ));
            }
            if artifact.kind == "metadata" && metadata_path.replace(artifact.path.clone()).is_some()
            {
                return Err(error(
                    "attribution.metadata",
                    "one metadata input is allowed per bundle",
                ));
            }
        } else if artifact.path.is_dir()
            && matches!(artifact.kind.as_str(), "scan_index" | "codegen_index")
        {
            let info =
                vitnet_dgml::cache_info(&artifact.path).map_err(|cause| AttributionError {
                    diagnostic: cause.diagnostic,
                })?;
            fingerprint.available = true;
            fingerprint.graph_generation = Some(info.generation);
        } else {
            diagnostics.push(diagnostic(
                "evidence.missing",
                format!("{} evidence is unavailable", artifact.kind),
                Some(artifact.path.clone()),
            ));
        }
        if fingerprint.matches_expected == Some(false) {
            diagnostics.push(diagnostic(
                "evidence.fingerprint.mismatch",
                "artifact does not match its declared fingerprint".into(),
                Some(artifact.path.clone()),
            ));
        }
        if let (Some(expected), Some(actual)) = (
            evidence.provenance.get("source_revision"),
            &artifact.revision,
        ) {
            if expected != actual {
                diagnostics.push(diagnostic(
                    "evidence.revision.mismatch",
                    format!("expected revision {expected}, artifact declares {actual}"),
                    Some(artifact.path.clone()),
                ));
            }
        }
        artifacts.push(fingerprint);
    }
    if mstat_path.is_none() {
        diagnostics.push(diagnostic(
            "evidence.mstat.missing",
            "MSTAT accounting is unavailable; attribution byte coverage is unknown".into(),
            None,
        ));
    }
    if strict && !diagnostics.is_empty() {
        return Err(error(
            "attribution.evidence.incomplete",
            format!(
                "strict import rejected {} evidence diagnostics",
                diagnostics.len()
            ),
        ));
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|cause| io(parent, cause))?;
    let temporary = tempfile::Builder::new()
        .prefix(".vitnet-attribution-")
        .tempdir_in(parent)
        .map_err(|cause| io(parent, cause))?;
    let entries_path = temporary.path().join("identities.ndjson");
    let mut writer =
        BufWriter::new(File::create(&entries_path).map_err(|cause| io(&entries_path, cause))?);
    let mut count = 0_u64;
    let metadata = metadata_path
        .map(|path| {
            let input = File::open(&path).map_err(|cause| io(&path, cause))?;
            let projection_limit =
                usize::try_from((memory_limit / 4096).max(1)).unwrap_or(usize::MAX);
            let decoder = vitnet_metadata::StreamingDecoder::new(input, 64 * 1024, strict)
                .with_record_limit(
                    usize::try_from((memory_limit / 32).min(16 * 1024 * 1024))
                        .unwrap_or(16 * 1024 * 1024),
                );
            vitnet_metadata::analyze_stream_with_aggregate_limit(
                decoder,
                vitnet_metadata::AnalysisOptions {
                    top: projection_limit,
                    ..Default::default()
                },
                strict,
                memory_limit / 4,
                projection_limit,
            )
            .map_err(|cause| AttributionError {
                diagnostic: cause.diagnostic,
            })
        })
        .transpose()?;
    let mstat = if let Some(path) = mstat_path {
        Some(
            vitnet_mstat::visit_coalesced_path(&path, memory_limit / 2, |entry| {
                let row = serde_json::to_vec(&entry).map_err(|cause| vitnet_mstat::MstatError {
                    diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
                        "attribution.io",
                        cause.to_string(),
                    )),
                })?;
                if row.len() as u64 > (memory_limit / 64).min(32 * 1024 * 1024) - 1 {
                    return Err(vitnet_mstat::MstatError {
                        diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
                            "resource.memory_limit",
                            "serialized identity exceeds cache row budget",
                        )),
                    });
                }
                writer
                    .write_all(&row)
                    .map_err(|cause| vitnet_mstat::MstatError {
                        diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
                            "attribution.io",
                            cause.to_string(),
                        )),
                    })?;
                writer
                    .write_all(b"\n")
                    .map_err(|cause| vitnet_mstat::MstatError {
                        diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
                            "attribution.io",
                            cause.to_string(),
                        )),
                    })?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| vitnet_mstat::MstatError {
                        diagnostic: Box::new(vitnet_core::Diagnostic::malformed(
                            "attribution.count",
                            "identity count overflow",
                        )),
                    })?;
                Ok(())
            })
            .map_err(|cause| AttributionError {
                diagnostic: cause.diagnostic,
            })?,
        )
    } else {
        None
    };
    writer.flush().map_err(|cause| io(&entries_path, cause))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|cause| io(&entries_path, cause))?;
    drop(writer);
    let index = AttributionIndex {
        schema: INDEX_SCHEMA.into(),
        evidence,
        artifacts,
        mstat,
        metadata,
        identities: count,
        identities_blake3: hash_file(&entries_path)?.1,
        diagnostics,
    };
    let index_path = temporary.path().join("index.json");
    let mut index_writer =
        BufWriter::new(File::create(&index_path).map_err(|cause| io(&index_path, cause))?);
    serde_json::to_writer(&mut index_writer, &index)
        .map_err(|cause| error("attribution.json", cause.to_string()))?;
    index_writer
        .flush()
        .map_err(|cause| io(&index_path, cause))?;
    index_writer
        .get_ref()
        .sync_all()
        .map_err(|cause| io(&index_path, cause))?;
    if index_writer
        .get_ref()
        .metadata()
        .map_err(|cause| io(&index_path, cause))?
        .len()
        > (memory_limit / 8).min(256 * 1024 * 1024)
    {
        return Err(error(
            "resource.memory_limit",
            "persisted evidence exceeds the index manifest memory share",
        ));
    }
    drop(index_writer);
    fs::rename(temporary.path(), output).map_err(|cause| io(output, cause))?;
    Ok(index)
}

/// Opens a versioned index manifest without rescanning original inputs.
///
/// # Errors
///
/// Rejects I/O, invalid schemas, JSON and memory limits.
pub fn open_index(path: &Path, memory_limit: u64) -> Result<AttributionIndex, AttributionError> {
    let index: AttributionIndex = read_json(&path.join("index.json"), memory_limit)?;
    if index.schema != INDEX_SCHEMA {
        return Err(error(
            "attribution.schema",
            "unsupported attribution index schema",
        ));
    }
    validate_evidence(&index.evidence)?;
    Ok(index)
}

/// Streams cached identities and verifies their complete payload hash and count.
///
/// # Errors
///
/// Returns visitor, I/O, corrupt-cache and resource diagnostics.
pub fn visit_identities(
    directory: &Path,
    index: &AttributionIndex,
    memory_limit: u64,
    mut visitor: impl FnMut(&CoalescedIdentity) -> Result<(), AttributionError>,
) -> Result<(), AttributionError> {
    visit_identities_with_offsets(directory, index, memory_limit, |entry, _| visitor(entry))
}

/// Streams verified identities with their byte offsets in the immutable cache.
///
/// # Errors
///
/// Returns visitor, I/O, corrupt-cache and resource diagnostics.
pub fn visit_identities_with_offsets(
    directory: &Path,
    index: &AttributionIndex,
    memory_limit: u64,
    mut visitor: impl FnMut(&CoalescedIdentity, u64) -> Result<(), AttributionError>,
) -> Result<(), AttributionError> {
    let path = directory.join("identities.ndjson");
    let mut reader = BufReader::new(File::open(&path).map_err(|cause| io(&path, cause))?);
    let limit = (memory_limit / 64).min(32 * 1024 * 1024);
    let mut line = Vec::new();
    let mut hasher = blake3::Hasher::new();
    let mut count = 0_u64;
    let mut offset = 0_u64;
    loop {
        line.clear();
        loop {
            let bytes = reader.fill_buf().map_err(|cause| io(&path, cause))?;
            if bytes.is_empty() {
                break;
            }
            let length = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |position| position + 1);
            if (line.len() + length) as u64 > limit {
                return Err(error(
                    "resource.memory_limit",
                    "identity row exceeds its bounded memory share",
                ));
            }
            let done = bytes[length - 1] == b'\n';
            line.extend_from_slice(&bytes[..length]);
            reader.consume(length);
            if done {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        hasher.update(&line);
        let entry: CoalescedIdentity = serde_json::from_slice(&line)
            .map_err(|cause| error("attribution.cache.identity", cause.to_string()))?;
        count = count
            .checked_add(1)
            .ok_or_else(|| error("attribution.count", "identity count overflow"))?;
        visitor(&entry, offset)?;
        offset = offset
            .checked_add(line.len() as u64)
            .ok_or_else(|| error("attribution.size", "identity byte offset overflow"))?;
    }
    if count != index.identities || hasher.finalize().to_hex().as_str() != index.identities_blake3 {
        return Err(error(
            "attribution.cache.integrity",
            "identity payload hash or record count does not match index",
        ));
    }
    Ok(())
}
