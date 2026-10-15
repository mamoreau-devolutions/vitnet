use super::{attribution, diagnostic, io};
use crate::AppError;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use vitnet_dgml::IndexControl;

const NAME: &str = "ranking.bin";
const FAN_IN: usize = 16;
const BUFFER: usize = 8192;
type Key = (Reverse<u64>, u64);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Descriptor {
    pub records: u64,
    pub blake3: String,
}

fn check(control: &IndexControl) -> Result<(), AppError> {
    if control.is_cancelled() {
        return Err(diagnostic(
            "resource.cancelled",
            "ranking operation cancelled",
        ));
    }
    Ok(())
}

fn write_key(output: &mut impl Write, key: Key) -> Result<(), AppError> {
    output.write_all(&key.0.0.to_le_bytes()).map_err(io)?;
    output.write_all(&key.1.to_le_bytes()).map_err(io)
}

fn read_key(input: &mut impl Read) -> Result<Option<Key>, AppError> {
    let mut bytes = [0; 16];
    let first = input.read(&mut bytes[..1]).map_err(io)?;
    if first == 0 {
        return Ok(None);
    }
    input.read_exact(&mut bytes[1..]).map_err(io)?;
    Ok(Some((
        Reverse(u64::from_le_bytes(bytes[..8].try_into().unwrap())),
        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
    )))
}

pub(super) struct Writer {
    runs: tempfile::TempDir,
    keys: Vec<Key>,
    capacity: usize,
    max_runs: usize,
    paths: Vec<PathBuf>,
    records: u64,
    control: IndexControl,
}

impl Writer {
    pub fn new(directory: &Path, memory: u64, control: &IndexControl) -> Result<Self, AppError> {
        let capacity = usize::try_from((memory / 64) / 16)
            .map_err(|_| diagnostic("resource.explorer.ranking", "ranking memory overflow"))?;
        if capacity < 1024 {
            return Err(diagnostic(
                "resource.explorer.ranking",
                "ranking needs 16 KiB of sort memory",
            ));
        }
        Ok(Self {
            runs: tempfile::Builder::new()
                .prefix(".ranking-")
                .tempdir_in(directory)
                .map_err(io)?,
            keys: Vec::with_capacity(capacity),
            capacity,
            max_runs: usize::try_from(memory / 128 / 4096).map_err(|_| {
                diagnostic("resource.explorer.ranking", "run metadata budget overflow")
            })?,
            paths: Vec::new(),
            records: 0,
            control: control.clone(),
        })
    }

    pub fn push(&mut self, bytes: u64, ordinal: u64) -> Result<(), AppError> {
        check(&self.control)?;
        if ordinal != self.records {
            return Err(diagnostic(
                "explorer.ranking",
                "ranking input ordinals are not contiguous",
            ));
        }
        self.keys.push((Reverse(bytes), ordinal));
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| diagnostic("explorer.ranking", "ranking count overflow"))?;
        if self.keys.len() == self.capacity {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), AppError> {
        if self.keys.is_empty() {
            return Ok(());
        }
        check(&self.control)?;
        if self.paths.len() >= self.max_runs {
            return Err(diagnostic(
                "resource.explorer.ranking",
                "sort-run metadata exceeds its memory reservation; increase --memory-limit",
            ));
        }
        self.keys.sort_unstable();
        let path = self
            .runs
            .path()
            .join(format!("run-{}.bin", self.paths.len()));
        let mut output = BufWriter::with_capacity(BUFFER, File::create(&path).map_err(io)?);
        for key in &self.keys {
            check(&self.control)?;
            write_key(&mut output, *key)?;
        }
        output.flush().map_err(io)?;
        self.keys.clear();
        self.paths.push(path);
        Ok(())
    }

    pub fn finish(mut self, directory: &Path) -> Result<Descriptor, AppError> {
        self.flush()?;
        self.keys = Vec::new();
        // Bound file handles and merge buffers independently of corpus cardinality.
        let mut pass = 0;
        while self.paths.len() > FAN_IN {
            let mut next = Vec::new();
            for (index, paths) in self.paths.chunks(FAN_IN).enumerate() {
                let path = self.runs.path().join(format!("merge-{pass}-{index}.bin"));
                merge(paths, &path, &self.control)?;
                next.push(path);
            }
            for path in &self.paths {
                fs::remove_file(path).map_err(io)?;
            }
            self.paths = next;
            pass += 1;
        }
        let path = directory.join(NAME);
        merge(&self.paths, &path, &self.control)?;
        Ok(Descriptor {
            records: self.records,
            blake3: vitnet_attribution::hash_file(&path).map_err(attribution)?.1,
        })
    }
}

fn merge(paths: &[PathBuf], path: &Path, control: &IndexControl) -> Result<(), AppError> {
    let mut inputs: Vec<_> = paths
        .iter()
        .map(|path| {
            File::open(path)
                .map(|file| BufReader::with_capacity(BUFFER, file))
                .map_err(io)
        })
        .collect::<Result<_, _>>()?;
    let mut heap = BinaryHeap::new();
    for (index, input) in inputs.iter_mut().enumerate() {
        if let Some(key) = read_key(input)? {
            heap.push(Reverse((key, index)));
        }
    }
    let mut output = BufWriter::with_capacity(BUFFER, File::create(path).map_err(io)?);
    while let Some(Reverse((key, index))) = heap.pop() {
        check(control)?;
        write_key(&mut output, key)?;
        if let Some(key) = read_key(&mut inputs[index])? {
            heap.push(Reverse((key, index)));
        }
    }
    output.flush().map_err(io)?;
    output.get_ref().sync_all().map_err(io)
}

pub(super) struct Reader {
    file: File,
    path: PathBuf,
    modified: SystemTime,
    pub records: u64,
}

impl Reader {
    pub fn open(
        directory: &Path,
        descriptor: &Descriptor,
        identities: u64,
    ) -> Result<Self, AppError> {
        let path = directory.join(NAME);
        let metadata = fs::metadata(&path).map_err(io)?;
        if descriptor.records != identities
            || descriptor.records.checked_mul(16) != Some(metadata.len())
            || vitnet_attribution::hash_file(&path).map_err(attribution)?.1 != descriptor.blake3
        {
            return Err(diagnostic(
                "explorer.ranking.integrity",
                "ranking fingerprint or count differs",
            ));
        }
        let mut input = BufReader::new(File::open(&path).map_err(io)?);
        let mut previous = None;
        while let Some(key) = read_key(&mut input)? {
            if key.1 >= identities || previous.is_some_and(|old| old >= key) {
                return Err(diagnostic(
                    "explorer.ranking.integrity",
                    "ranking is not strictly byte/ordinal ordered",
                ));
            }
            previous = Some(key);
        }
        Ok(Self {
            file: File::open(&path).map_err(io)?,
            path,
            modified: metadata.modified().map_err(io)?,
            records: identities,
        })
    }

    pub fn check(&self) -> Result<(), AppError> {
        let metadata = fs::metadata(&self.path).map_err(io)?;
        if metadata.len() != self.records * 16 || metadata.modified().map_err(io)? != self.modified
        {
            return Err(diagnostic(
                "explorer.ranking.stale",
                "ranking changed; prepare a new bundle",
            ));
        }
        Ok(())
    }

    pub fn entry(&mut self, position: u64) -> Result<(u64, u64), AppError> {
        if position >= self.records {
            return Err(diagnostic(
                "explorer.cursor",
                "ranking position outside dataset",
            ));
        }
        self.file.seek(SeekFrom::Start(position * 16)).map_err(io)?;
        let key = read_key(&mut self.file)?
            .ok_or_else(|| diagnostic("explorer.ranking.integrity", "missing ranking entry"))?;
        Ok((key.0.0, key.1))
    }
}
