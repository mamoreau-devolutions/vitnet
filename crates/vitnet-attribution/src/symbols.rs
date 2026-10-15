use crate::{AttributionError, error, hash_file, io};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const RECORD_BYTES: u64 = 40;
pub const SYMBOL_SCHEMA: &str = "vitnet.symbol-sidecar.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolSidecar {
    pub schema: String,
    pub records: u64,
    pub payload_bytes: u64,
    pub payload_blake3: String,
    pub lookup_blake3: String,
}

fn key(stream: &str, raw: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(stream.as_bytes());
    hash.update(&[0]);
    hash.update(raw.as_bytes());
    *hash.finalize().as_bytes()
}

pub(crate) struct SymbolWriter {
    directory: PathBuf,
    output: BufWriter<File>,
    keys: Vec<([u8; 32], u32, u64)>,
    position: u64,
    memory: u64,
}

impl SymbolWriter {
    pub(crate) fn new(directory: &Path, memory: u64) -> Result<Self, AttributionError> {
        if memory < 64 * 1024 {
            return Err(error(
                "resource.symbols",
                "symbol writer needs at least 64 KiB",
            ));
        }
        let path = directory.join("symbols.ndjson");
        Ok(Self {
            directory: directory.into(),
            output: BufWriter::new(File::create(&path).map_err(|cause| io(&path, cause))?),
            keys: Vec::new(),
            position: 0,
            memory,
        })
    }

    pub(crate) fn push(
        &mut self,
        stream: &str,
        raw: &str,
        token: u32,
        record: &impl Serialize,
    ) -> Result<(), AttributionError> {
        if (self.keys.len() as u64 + 1)
            .saturating_mul(std::mem::size_of::<([u8; 32], u32, u64)>() as u64 * 2)
            > self.memory
        {
            return Err(error(
                "resource.symbols",
                "compact symbol lookup exceeds its reserved memory share",
            ));
        }
        let bytes =
            serde_json::to_vec(record).map_err(|cause| error("symbols.json", cause.to_string()))?;
        if bytes.len() as u64 > (self.memory / 8).min(8 << 20) {
            return Err(error(
                "resource.symbols",
                "symbol record exceeds its bounded row share",
            ));
        }
        self.keys.push((key(stream, raw), token, self.position));
        self.output
            .write_all(&bytes)
            .and_then(|()| self.output.write_all(b"\n"))
            .map_err(|cause| io(&self.directory.join("symbols.ndjson"), cause))?;
        self.position = self
            .position
            .checked_add(bytes.len() as u64 + 1)
            .ok_or_else(|| error("symbols.size", "symbol sidecar length overflow"))?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<SymbolSidecar, AttributionError> {
        let payload = self.directory.join("symbols.ndjson");
        self.output.flush().map_err(|cause| io(&payload, cause))?;
        self.output
            .get_ref()
            .sync_all()
            .map_err(|cause| io(&payload, cause))?;
        self.keys.sort_unstable();
        self.keys
            .dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        self.keys
            .sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.2.cmp(&right.2)));
        let lookup = self.directory.join("symbols.idx");
        let mut output = BufWriter::new(File::create(&lookup).map_err(|cause| io(&lookup, cause))?);
        for (hash, _, offset) in &self.keys {
            output
                .write_all(hash)
                .and_then(|()| output.write_all(&offset.to_le_bytes()))
                .map_err(|cause| io(&lookup, cause))?;
        }
        output.flush().map_err(|cause| io(&lookup, cause))?;
        output
            .get_ref()
            .sync_all()
            .map_err(|cause| io(&lookup, cause))?;
        Ok(SymbolSidecar {
            schema: SYMBOL_SCHEMA.into(),
            records: self.keys.len() as u64,
            payload_bytes: self.position,
            payload_blake3: hash_file(&payload)?.1,
            lookup_blake3: hash_file(&lookup)?.1,
        })
    }
}

/// Verified, disk-backed managed-symbol lookup. No verbose catalog is loaded into memory.
pub struct SymbolLookup {
    payload: BufReader<File>,
    lookup: Vec<([u8; 32], u64)>,
    directory: PathBuf,
    descriptor: SymbolSidecar,
    row_limit: u64,
    payload_modified: SystemTime,
    lookup_modified: SystemTime,
}

impl SymbolLookup {
    /// Opens and verifies both immutable sidecar payloads.
    ///
    /// # Errors
    ///
    /// Rejects missing, corrupt, unsorted or unsupported sidecars.
    pub fn open(
        directory: &Path,
        descriptor: &SymbolSidecar,
        memory: u64,
    ) -> Result<Self, AttributionError> {
        if memory < 64 * 1024 {
            return Err(error(
                "resource.symbols",
                "symbol reader needs at least 64 KiB",
            ));
        }
        if descriptor.schema != SYMBOL_SCHEMA {
            return Err(error("symbols.schema", "unsupported symbol sidecar"));
        }
        let payload_path = directory.join("symbols.ndjson");
        let lookup_path = directory.join("symbols.idx");
        let lookup_bytes = descriptor
            .records
            .checked_mul(RECORD_BYTES)
            .ok_or_else(|| error("symbols.size", "lookup length overflow"))?;
        if lookup_bytes > memory / 4 {
            return Err(error(
                "resource.symbols",
                "compact symbol lookup exceeds its reserved reader share",
            ));
        }
        let payload = hash_file(&payload_path)?;
        let lookup = hash_file(&lookup_path)?;
        if payload != (descriptor.payload_bytes, descriptor.payload_blake3.clone())
            || lookup != (lookup_bytes, descriptor.lookup_blake3.clone())
        {
            return Err(error(
                "symbols.integrity",
                "symbol sidecar hashes/counts do not match the imported index",
            ));
        }
        let mut result = Self {
            payload: BufReader::new(
                File::open(&payload_path).map_err(|cause| io(&payload_path, cause))?,
            ),
            lookup: Vec::with_capacity(
                usize::try_from(descriptor.records)
                    .map_err(|_| error("resource.symbols", "symbol count exceeds address space"))?,
            ),
            directory: directory.into(),
            descriptor: descriptor.clone(),
            row_limit: (memory / 64).min(8 << 20),
            payload_modified: std::fs::metadata(&payload_path)
                .map_err(|cause| io(&payload_path, cause))?
                .modified()
                .map_err(|cause| io(&payload_path, cause))?,
            lookup_modified: std::fs::metadata(&lookup_path)
                .map_err(|cause| io(&lookup_path, cause))?
                .modified()
                .map_err(|cause| io(&lookup_path, cause))?,
        };
        let mut previous = None;
        let mut input =
            BufReader::new(File::open(&lookup_path).map_err(|cause| io(&lookup_path, cause))?);
        for _ in 0..descriptor.records {
            let mut bytes = [0; 40];
            input
                .read_exact(&mut bytes)
                .map_err(|cause| io(&lookup_path, cause))?;
            let mut hash = [0; 32];
            hash.copy_from_slice(&bytes[..32]);
            let mut offset = [0; 8];
            offset.copy_from_slice(&bytes[32..]);
            let record = (hash, u64::from_le_bytes(offset));
            if previous.is_some_and(|p| p > record) || record.1 >= descriptor.payload_bytes {
                return Err(error(
                    "symbols.integrity",
                    "symbol lookup is unsorted or has an invalid offset",
                ));
            }
            previous = Some(record);
            result.lookup.push(record);
        }
        Ok(result)
    }

    /// Checks immutable payload lengths and modification times between operations.
    ///
    /// # Errors
    ///
    /// Rejects changed or missing sidecars.
    pub fn check(&self) -> Result<(), AttributionError> {
        for (name, length, modified) in [
            (
                "symbols.ndjson",
                self.descriptor.payload_bytes,
                self.payload_modified,
            ),
            (
                "symbols.idx",
                self.descriptor.records * RECORD_BYTES,
                self.lookup_modified,
            ),
        ] {
            let path = self.directory.join(name);
            let metadata = std::fs::metadata(&path).map_err(|cause| io(&path, cause))?;
            if metadata.len() != length
                || metadata.modified().map_err(|cause| io(&path, cause))? != modified
            {
                return Err(error(
                    "symbols.stale",
                    "symbol evidence changed; import a new immutable index",
                ));
            }
        }
        Ok(())
    }

    fn index(&self, position: u64) -> Result<([u8; 32], u64), AttributionError> {
        let position = usize::try_from(position)
            .map_err(|_| error("symbols.integrity", "invalid symbol position"))?;
        self.lookup
            .get(position)
            .copied()
            .ok_or_else(|| error("symbols.integrity", "symbol position exceeds lookup"))
    }

    /// Looks up every captured token candidate for one raw, stream-qualified identity.
    ///
    /// # Errors
    ///
    /// Rejects corrupt rows and excessive candidate counts or row sizes.
    pub fn get(&mut self, stream: &str, raw: &str) -> Result<Vec<Value>, AttributionError> {
        let expected = key(stream, raw);
        let (mut low, mut high) = (0, self.descriptor.records);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.index(middle)?.0 < expected {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let path = self.directory.join("symbols.ndjson");
        let mut result = Vec::new();
        let mut retained = 0_u64;
        while low < self.descriptor.records {
            let (hash, offset) = self.index(low)?;
            if hash != expected {
                break;
            }
            if result.len() >= 64 {
                return Err(error(
                    "resource.symbols",
                    "more than 64 token candidates share one captured identity",
                ));
            }
            self.payload
                .seek(SeekFrom::Start(offset))
                .map_err(|cause| io(&path, cause))?;
            let mut bytes = Vec::new();
            self.payload
                .by_ref()
                .take(self.row_limit + 1)
                .read_until(b'\n', &mut bytes)
                .map_err(|cause| io(&path, cause))?;
            if bytes.len() as u64 > self.row_limit || bytes.last() != Some(&b'\n') {
                return Err(error(
                    "symbols.integrity",
                    "symbol record is too large or incomplete",
                ));
            }
            retained = retained
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| error("resource.symbols", "candidate size overflow"))?;
            if retained > self.row_limit {
                return Err(error(
                    "resource.symbols",
                    "symbol candidates exceed their total reserved row share",
                ));
            }
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|cause| error("symbols.json", cause.to_string()))?;
            if value["stream"].as_str() != Some(stream)
                || value["raw_identity_blake3"].as_str() != Some(raw)
            {
                return Err(error(
                    "symbols.integrity",
                    "symbol lookup key and original row disagree",
                ));
            }
            result.push(value);
            low += 1;
        }
        Ok(result)
    }
}
