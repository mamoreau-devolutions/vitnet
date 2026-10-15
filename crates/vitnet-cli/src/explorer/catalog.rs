use super::{attribution, diagnostic, io, preview};
use crate::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use vitnet_attribution::model::Evidence;
use vitnet_dgml::IndexControl;

const RECORD_LIMIT: u64 = 32 * 1024 * 1024;
const TEXT_PAGE: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dataset {
    pub records: u64,
    pub data_bytes: u64,
    pub blake3: String,
    pub offsets_blake3: String,
}

pub(super) struct Writer<'a> {
    directory: &'a Path,
    memory: u64,
    control: &'a IndexControl,
    pub datasets: BTreeMap<String, Dataset>,
}

fn paths(directory: &Path, name: &str) -> Result<(PathBuf, PathBuf), AppError> {
    if name.is_empty()
        || name.len() > 100
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(diagnostic("explorer.dataset", "invalid dataset identifier"));
    }
    Ok((
        directory.join(format!("catalog_{name}.ndjson")),
        directory.join(format!("catalog_{name}.offsets")),
    ))
}

fn cancelled(control: &IndexControl) -> Result<(), AppError> {
    if control.is_cancelled() {
        Err(diagnostic(
            "resource.cancelled",
            "dataset operation cancelled",
        ))
    } else {
        Ok(())
    }
}

impl<'a> Writer<'a> {
    pub fn new(directory: &'a Path, memory: u64, control: &'a IndexControl) -> Self {
        Self {
            directory,
            memory,
            control,
            datasets: BTreeMap::new(),
        }
    }

    pub fn write<T: Serialize>(
        &mut self,
        name: &str,
        records: impl IntoIterator<Item = T>,
    ) -> Result<(), AppError> {
        if self.datasets.contains_key(name) {
            return Err(diagnostic(
                "explorer.dataset",
                "duplicate dataset identifier",
            ));
        }
        let (data_path, offset_path) = paths(self.directory, name)?;
        let mut data = BufWriter::new(File::create(&data_path).map_err(io)?);
        let mut offsets = BufWriter::new(File::create(&offset_path).map_err(io)?);
        let mut count = 0_u64;
        let mut bytes = 0_u64;
        for record in records {
            cancelled(self.control)?;
            let mut encoded = LimitedRecord {
                bytes: Vec::new(),
                limit: (self.memory / 64).min(RECORD_LIMIT),
            };
            serde_json::to_writer(&mut encoded, &record)
                .map_err(|cause| diagnostic("resource.explorer.record", cause.to_string()))?;
            offsets.write_all(&bytes.to_le_bytes()).map_err(io)?;
            data.write_all(&encoded.bytes).map_err(io)?;
            data.write_all(b"\n").map_err(io)?;
            bytes = bytes
                .checked_add(encoded.bytes.len() as u64 + 1)
                .ok_or_else(|| diagnostic("explorer.dataset", "dataset length overflow"))?;
            count = count
                .checked_add(1)
                .ok_or_else(|| diagnostic("explorer.dataset", "dataset count overflow"))?;
        }
        offsets.write_all(&bytes.to_le_bytes()).map_err(io)?;
        data.flush().map_err(io)?;
        offsets.flush().map_err(io)?;
        data.get_ref().sync_all().map_err(io)?;
        offsets.get_ref().sync_all().map_err(io)?;
        self.datasets.insert(
            name.into(),
            Dataset {
                records: count,
                data_bytes: bytes,
                blake3: vitnet_attribution::hash_file(&data_path)
                    .map_err(attribution)?
                    .1,
                offsets_blake3: vitnet_attribution::hash_file(&offset_path)
                    .map_err(attribution)?
                    .1,
            },
        );
        Ok(())
    }

    pub fn evidence(&mut self, prefix: &str, evidence: &Evidence) -> Result<(), AppError> {
        self.write(
            &format!("{prefix}evidence_header"),
            [json!({
                "schema":evidence.schema, "label":evidence.label,
            })],
        )?;
        self.write(
            &format!("{prefix}provenance"),
            evidence
                .provenance
                .iter()
                .map(|(key, value)| json!({"key":key, "value":value})),
        )?;
        self.write(&format!("{prefix}evidence_artifacts"), &evidence.artifacts)?;
        self.write(&format!("{prefix}packages"), &evidence.packages)?;
        self.write(&format!("{prefix}assemblies"), &evidence.assemblies)?;
        self.write(&format!("{prefix}sources"), &evidence.sources)?;
        self.write(&format!("{prefix}xaml_documents"), &evidence.xaml_documents)?;
        self.write(&format!("{prefix}generator_evidence"), &evidence.generators)?;
        self.write(&format!("{prefix}generator_runs"), &evidence.generator_runs)?;
        self.write(
            &format!("{prefix}generator_links"),
            &evidence.generator_links,
        )?;
        self.write(&format!("{prefix}resource_evidence"), &evidence.resources)?;
        self.write(&format!("{prefix}binaries"), &evidence.binaries)?;
        self.write(&format!("{prefix}mappings"), &evidence.mappings)?;
        self.write(
            &format!("{prefix}evidence_diagnostics"),
            &evidence.diagnostics,
        )
    }
}

struct LimitedRecord {
    bytes: Vec<u8>,
    limit: u64,
}

impl Write for LimitedRecord {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() as u64 + bytes.len() as u64 + 1 > self.limit {
            return Err(std::io::Error::other(
                "complete record exceeds reserved memory share",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) struct Reader {
    name: String,
    data: File,
    offsets: File,
    descriptor: Dataset,
    data_path: PathBuf,
    offset_path: PathBuf,
    data_modified: SystemTime,
    offset_modified: SystemTime,
}

impl Reader {
    pub fn open(directory: &Path, name: &str, descriptor: &Dataset) -> Result<Self, AppError> {
        let (data_path, offset_path) = paths(directory, name)?;
        let data_meta = fs::metadata(&data_path).map_err(io)?;
        let offset_meta = fs::metadata(&offset_path).map_err(io)?;
        let expected_offsets = descriptor
            .records
            .checked_add(1)
            .and_then(|n| n.checked_mul(8))
            .ok_or_else(|| diagnostic("explorer.dataset", "dataset count overflow"))?;
        if data_meta.len() != descriptor.data_bytes || offset_meta.len() != expected_offsets {
            return Err(diagnostic(
                "explorer.dataset.integrity",
                "dataset lengths differ from manifest",
            ));
        }
        for (path, hash) in [
            (&data_path, &descriptor.blake3),
            (&offset_path, &descriptor.offsets_blake3),
        ] {
            if vitnet_attribution::hash_file(path).map_err(attribution)?.1 != *hash {
                return Err(diagnostic(
                    "explorer.dataset.integrity",
                    "dataset fingerprint changed",
                ));
            }
        }
        let mut offsets = File::open(&offset_path).map_err(io)?;
        let mut validation = BufReader::new(&mut offsets);
        let mut previous = None;
        for position in 0..=descriptor.records {
            let mut bytes = [0; 8];
            validation.read_exact(&mut bytes).map_err(io)?;
            let offset = u64::from_le_bytes(bytes);
            if (position == 0 && offset != 0)
                || previous.is_some_and(|old| offset <= old)
                || offset > descriptor.data_bytes
                || (position == descriptor.records && offset != descriptor.data_bytes)
            {
                return Err(diagnostic(
                    "explorer.dataset.integrity",
                    "invalid dataset offsets",
                ));
            }
            previous = Some(offset);
        }
        drop(validation);
        Ok(Self {
            name: name.into(),
            data: File::open(&data_path).map_err(io)?,
            offsets,
            descriptor: descriptor.clone(),
            data_modified: data_meta.modified().map_err(io)?,
            offset_modified: offset_meta.modified().map_err(io)?,
            data_path,
            offset_path,
        })
    }

    pub fn check(&self) -> Result<(), AppError> {
        let data = fs::metadata(&self.data_path).map_err(io)?;
        let offsets = fs::metadata(&self.offset_path).map_err(io)?;
        if data.len() != self.descriptor.data_bytes
            || offsets.len() != (self.descriptor.records + 1) * 8
            || data.modified().map_err(io)? != self.data_modified
            || offsets.modified().map_err(io)? != self.offset_modified
        {
            return Err(diagnostic(
                "explorer.dataset.stale",
                "dataset changed; prepare a new bundle",
            ));
        }
        Ok(())
    }

    pub fn record(&mut self, ordinal: u64, memory: u64) -> Result<Value, AppError> {
        if ordinal >= self.descriptor.records {
            return Err(diagnostic(
                "explorer.cursor",
                "record ordinal outside dataset",
            ));
        }
        self.offsets
            .seek(SeekFrom::Start(ordinal * 8))
            .map_err(io)?;
        let mut bytes = [0; 16];
        self.offsets.read_exact(&mut bytes).map_err(io)?;
        let start = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let end = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        if start >= end
            || end > self.descriptor.data_bytes
            || end - start > (memory / 64).min(RECORD_LIMIT)
        {
            return Err(diagnostic(
                "explorer.dataset.integrity",
                "invalid or oversized record range",
            ));
        }
        self.data.seek(SeekFrom::Start(start)).map_err(io)?;
        let mut encoded = Vec::new();
        (&mut self.data)
            .take(end - start)
            .read_to_end(&mut encoded)
            .map_err(io)?;
        if encoded.last() != Some(&b'\n') {
            return Err(diagnostic(
                "explorer.dataset.integrity",
                "record is not newline terminated",
            ));
        }
        serde_json::from_slice(&encoded)
            .map_err(|cause| diagnostic("explorer.dataset.json", cause.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn page(
        &mut self,
        contains: &str,
        filters: &BTreeMap<String, String>,
        after: Option<u64>,
        limit: usize,
        memory: u64,
        control: &IndexControl,
    ) -> Result<Value, AppError> {
        self.check()?;
        if limit == 0
            || limit > super::PAGE_LIMIT
            || contains.len() > 1024
            || filters.len() > 8
            || filters
                .iter()
                .any(|(key, value)| key.len() > 128 || value.len() > 4096)
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "dataset page exceeds query budgets",
            ));
        }
        validate_filter_fields(self, filters, memory, control)?;
        if after.is_some_and(|after| after >= self.descriptor.records) {
            return Err(diagnostic("explorer.cursor", "page cursor outside dataset"));
        }
        let started = Instant::now();
        let parsed_filters: Vec<_> = filters
            .iter()
            .map(|(key, expected)| (key, expected, serde_json::from_str::<Value>(expected).ok()))
            .collect();
        let mut entries = Vec::new();
        let mut scanned = 0_u64;
        let mut next = after;
        let mut stop = "complete";
        for ordinal in after.map_or(0, |n| n + 1)..self.descriptor.records {
            if control.is_cancelled() {
                stop = "cancelled";
                break;
            }
            if scanned >= super::MAX_SCANNED {
                stop = "max_scanned";
                break;
            }
            if started.elapsed() >= Duration::from_millis(super::QUERY_TIMEOUT_MS) {
                stop = "timeout";
                break;
            }
            let value = self.record(ordinal, memory)?;
            scanned += 1;
            next = Some(ordinal);
            if matches_text(&value, contains)
                && parsed_filters.iter().all(|(key, expected, parsed)| {
                    value.get(key).is_some_and(|v| {
                        v.as_str()
                            .map_or_else(|| parsed.as_ref() == Some(v), |v| v == *expected)
                    })
                })
            {
                entries.push(record_preview(&value, ordinal));
                if entries.len() == limit {
                    if ordinal + 1 < self.descriptor.records {
                        stop = "limit";
                    }
                    break;
                }
            }
        }
        if stop == "complete" {
            next = None;
        }
        Ok(
            json!({"entries":entries,"total":self.descriptor.records,"scanned":scanned,
            "next_after":next.map(|n| n.to_string()),"stop_reason":stop,"order":"dataset_ordinal"}),
        )
    }
}

fn validate_filter_fields(
    reader: &mut Reader,
    filters: &BTreeMap<String, String>,
    memory: u64,
    control: &IndexControl,
) -> Result<(), AppError> {
    if filters.is_empty() {
        return Ok(());
    }
    let schema = match reader.name.as_str() {
        "opportunities" => serde_json::to_value(vitnet_attribution::Opportunity::default()),
        "budgets" => serde_json::to_value(vitnet_attribution::Budget::default()),
        _ => return Ok(()),
    }
    .map_err(|cause| diagnostic("explorer.dataset.json", cause.to_string()))?;
    let mut unknown: BTreeSet<_> = filters
        .keys()
        .filter(|field| schema.get(*field).is_none())
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    let started = Instant::now();
    for ordinal in 0..reader.descriptor.records {
        cancelled(control)?;
        if ordinal >= super::MAX_SCANNED
            || started.elapsed() >= Duration::from_millis(super::QUERY_TIMEOUT_MS)
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "cannot establish captured filter fields within query bounds",
            ));
        }
        let record = reader.record(ordinal, memory)?;
        unknown.retain(|field| record.get(*field).is_none());
        if unknown.is_empty() {
            return Ok(());
        }
    }
    if let Some(field) = unknown.first() {
        return Err(diagnostic(
            "explorer.query",
            format!(
                "unsupported exact filter field {field:?} for {}",
                reader.name
            ),
        ));
    }
    Ok(())
}

fn matches_text(value: &Value, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(items) => items.iter().any(|item| matches_text(item, needle)),
        Value::Object(items) => items
            .iter()
            .any(|(key, item)| key.contains(needle) || matches_text(item, needle)),
        _ => value.to_string().contains(needle),
    }
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
    }
}

pub(super) fn record_preview(value: &Value, ordinal: u64) -> Value {
    let mut fields = serde_json::Map::new();
    let mut shortened = Vec::new();
    for key in [
        "name",
        "title",
        "kind",
        "evidence_tier",
        "owner",
        "namespace",
        "context",
        "argument",
        "root",
        "role",
        "ownership",
        "family_count",
        "context_count",
        "xaml_bytes",
        "serializer_bytes",
        "generic_bytes",
        "methods_bytes",
        "types_bytes",
        "blobs_bytes",
        "other_additive_bytes",
        "metadata_lower_bound_bytes",
        "generator",
        "output_path",
        "trigger_type",
        "rule",
        "additive_bytes",
        "overlapping_bytes",
        "family",
        "package",
        "id",
        "version",
        "target",
        "attribute",
        "source_ordinal",
        "input_association",
        "assembly",
        "type_name",
        "member",
        "stream",
        "bytes",
        "file_bytes",
        "identities",
        "canonical_shared_identities",
        "dimension",
        "status",
        "mapping_status",
        "storage",
        "container",
        "path",
        "code",
        "key",
        "value",
        "basis",
        "direct",
        "logical_offset",
    ] {
        if let Some(field) = value.get(key) {
            if !field.is_object() && !field.is_array() {
                fields.insert(
                    key.into(),
                    match field {
                        Value::String(text) => {
                            let (text, truncated) = preview(text, 512);
                            if truncated {
                                shortened.push(key);
                            }
                            json!(text)
                        }
                        _ => field.clone(),
                    },
                );
            }
        }
        if fields.len() >= 32 {
            break;
        }
    }
    let captured = &value["preview"];
    if let Some(text) = captured["text"].as_str() {
        fields.insert("text".into(), json!(preview(text, 512).0));
        if preview(text, 512).1 {
            shortened.push("text");
        }
    }
    let label = summary(value);
    json!({"ordinal":ordinal.to_string(),"summary":label,"fields":fields,
    "capture":{
        "fields_truncated":shortened,
        "upstream_truncated":captured["truncated"].as_bool().unwrap_or(false),
        "original_text_bytes":captured.get("original_bytes"),
        "captured_text_bytes":captured["text"].as_str().map(str::len),
        "scope":"Bounded display fields. Open the original captured record for complete values; upstream omissions cannot be reconstructed."
    }})
}

fn summary(value: &Value) -> String {
    match value {
        Value::Object(items) => {
            let label = [
                "owner",
                "context",
                "argument",
                "root",
                "package",
                "name",
                "title",
                "family",
                "type_name",
                "id",
                "identity",
                "code",
                "key",
                "label",
                "path",
                "assembly",
            ]
            .into_iter()
            .find_map(|key| items.get(key).and_then(Value::as_str));
            label
                .or_else(|| value["preview"]["text"].as_str())
                .map_or_else(|| format!("{} fields", items.len()), |v| preview(v, 512).0)
        }
        Value::Array(items) => format!("{} items", items.len()),
        Value::String(text) => preview(text, 512).0,
        _ => value.to_string(),
    }
}

impl Reader {
    pub fn scope(
        &mut self,
        dimension: &str,
        stream: &str,
        name: &str,
        memory: u64,
    ) -> Result<Option<Value>, AppError> {
        self.check()?;
        let mut begin = 0;
        let mut end = self.descriptor.records;
        while begin < end {
            let middle = begin + (end - begin) / 2;
            let value = self.record(middle, memory)?;
            let key = ["dimension", "stream", "name"].map(|key| value[key].as_str().unwrap_or(""));
            match key.cmp(&[dimension, stream, name]) {
                std::cmp::Ordering::Less => begin = middle + 1,
                std::cmp::Ordering::Greater => end = middle,
                std::cmp::Ordering::Equal => return Ok(Some(value)),
            }
        }
        Ok(None)
    }
}

pub(super) fn value_page(
    root: &Value,
    path: &[u64],
    start: u64,
    key: bool,
) -> Result<Value, AppError> {
    if path.len() > 64 {
        return Err(diagnostic(
            "resource.explorer.path",
            "value path exceeds 64 steps",
        ));
    }
    let mut value = root;
    let mut selected_key = None;
    for index in path {
        let index = usize::try_from(*index)
            .map_err(|_| diagnostic("explorer.cursor", "path index overflow"))?;
        match value {
            Value::Object(items) => {
                let (name, child) = items
                    .iter()
                    .nth(index)
                    .ok_or_else(|| diagnostic("explorer.cursor", "object field outside record"))?;
                selected_key = Some(name);
                value = child;
            }
            Value::Array(items) => {
                value = items
                    .get(index)
                    .ok_or_else(|| diagnostic("explorer.cursor", "array index outside record"))?;
                selected_key = None;
            }
            _ => {
                return Err(diagnostic(
                    "explorer.cursor",
                    "cannot descend into a scalar",
                ));
            }
        }
    }
    let key_value;
    if key {
        key_value = Value::String(
            selected_key
                .ok_or_else(|| {
                    diagnostic("explorer.cursor", "selected value has no object field name")
                })?
                .clone(),
        );
        value = &key_value;
    }
    match value {
        Value::String(text) => {
            let begin = usize::try_from(start)
                .map_err(|_| diagnostic("explorer.cursor", "text offset overflow"))?;
            if begin > text.len() || !text.is_char_boundary(begin) {
                return Err(diagnostic(
                    "explorer.cursor",
                    "text offset is outside a UTF-8 boundary",
                ));
            }
            let (chunk, _) = preview(&text[begin..], TEXT_PAGE);
            let end = begin + chunk.len();
            Ok(
                json!({"kind":"string","text":chunk,"total_bytes":text.len(),"start":start,
                "next_start":(end < text.len()).then_some(end)}),
            )
        }
        Value::Array(items) => children_page(
            items.len(),
            start,
            items.iter().enumerate().map(|(n, v)| (n, None, v)),
            "array",
        ),
        Value::Object(items) => children_page(
            items.len(),
            start,
            items.iter().enumerate().map(|(n, (k, v))| (n, Some(k), v)),
            "object",
        ),
        _ => {
            if start != 0 {
                return Err(diagnostic(
                    "explorer.cursor",
                    "scalar values have no continuation",
                ));
            }
            Ok(json!({"kind":kind(value),"display":value.to_string(),"next_start":null}))
        }
    }
}

fn children_page<'a>(
    total: usize,
    start: u64,
    values: impl Iterator<Item = (usize, Option<&'a String>, &'a Value)>,
    kind: &str,
) -> Result<Value, AppError> {
    let begin = usize::try_from(start)
        .map_err(|_| diagnostic("explorer.cursor", "child offset overflow"))?;
    if begin > total {
        return Err(diagnostic("explorer.cursor", "child cursor outside record"));
    }
    let entries: Vec<_> = values
        .skip(begin)
        .take(super::PAGE_LIMIT)
        .map(|(index, key, value)| {
            let (key, key_truncated) = key.map_or((index.to_string(), false), |k| preview(k, 512));
            json!({"index":index,"key":key,"key_truncated":key_truncated,
            "kind":self::kind(value),"summary":summary(value)})
        })
        .collect();
    let end = begin + entries.len();
    Ok(
        json!({"kind":kind,"entries":entries,"total":total,"start":start,
        "next_start":(end < total).then_some(end)}),
    )
}
