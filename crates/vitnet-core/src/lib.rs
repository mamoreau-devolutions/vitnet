//! Shared Phase 0/1 contracts.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;
use thiserror::Error;

/// Stable process exit codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    ThresholdFailure = 1,
    InvalidOptions = 2,
    MalformedInput = 3,
    IoOrCache = 4,
    ResourceLimit = 5,
    InternalInvariant = 6,
}

impl ExitCode {
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Table,
    Json,
    Ndjson,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwitchMode {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ByteSize(pub u64);

impl fmt::Display for ByteSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}B", self.0)
    }
}

impl FromStr for ByteSize {
    type Err = OptionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let split = value
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(value.len());
        let (digits, suffix) = value.split_at(split);
        if digits.is_empty() {
            return Err(OptionError::InvalidByteSize(value.to_owned()));
        }
        let number = digits
            .parse::<u64>()
            .map_err(|_| OptionError::InvalidByteSize(value.to_owned()))?;
        let multiplier = match suffix.to_ascii_lowercase().as_str() {
            "" | "b" => 1_u64,
            "kib" => 1_u64 << 10,
            "mib" => 1_u64 << 20,
            "gib" => 1_u64 << 30,
            _ => return Err(OptionError::InvalidByteSize(value.to_owned())),
        };
        number
            .checked_mul(multiplier)
            .map(Self)
            .ok_or_else(|| OptionError::ByteSizeOverflow(value.to_owned()))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OptionError {
    #[error("invalid byte size `{0}`; expected bytes, KiB, MiB, or GiB")]
    InvalidByteSize(String),
    #[error("byte size `{0}` exceeds the supported u64 range")]
    ByteSizeOverflow(String),
}

/// Serializable context for malformed input and operational failures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_record: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn malformed(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            input_path: None,
            zip_entry: None,
            byte_offset: None,
            logical_record: None,
            physical_line: None,
            expected: None,
            actual: None,
            guidance: None,
        }
    }

    #[must_use]
    pub fn at(mut self, byte_offset: u64, logical_record: u64, physical_line: u64) -> Self {
        self.byte_offset = Some(byte_offset);
        self.logical_record = Some(logical_record);
        self.physical_line = Some(physical_line);
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(offset) = self.byte_offset {
            write!(formatter, " at byte {offset}")?;
        }
        if let Some(record) = self.logical_record {
            write!(formatter, ", record {record}")?;
        }
        if let Some(line) = self.physical_line {
            write!(formatter, ", line {line}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}

/// Shared limits and cancellation state for bounded algorithms.
#[derive(Clone, Debug)]
pub struct ResourceBudget {
    pub memory_limit: u64,
    pub temporary_disk_limit: u64,
    pub worker_limit: usize,
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
}

impl ResourceBudget {
    #[must_use]
    pub fn new(
        memory_limit: u64,
        temporary_disk_limit: u64,
        worker_limit: usize,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            memory_limit,
            temporary_disk_limit,
            worker_limit: worker_limit.max(1),
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Checks cancellation, deadline, memory, and temporary-disk usage.
    ///
    /// # Errors
    ///
    /// Returns a typed diagnostic when any configured safety limit is reached.
    pub fn check(&self, tracked_memory: u64, temporary_disk: u64) -> Result<(), ResourceError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ResourceError::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ResourceError::Deadline);
        }
        if tracked_memory > self.memory_limit {
            return Err(ResourceError::Memory {
                limit: self.memory_limit,
                actual: tracked_memory,
            });
        }
        if temporary_disk > self.temporary_disk_limit {
            return Err(ResourceError::TemporaryDisk {
                limit: self.temporary_disk_limit,
                actual: temporary_disk,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ResourceError {
    #[error("operation was cancelled")]
    Cancelled,
    #[error("operation deadline was reached")]
    Deadline,
    #[error("tracked memory {actual} bytes exceeds limit {limit} bytes")]
    Memory { limit: u64, actual: u64 },
    #[error("temporary data {actual} bytes exceeds limit {limit} bytes")]
    TemporaryDisk { limit: u64, actual: u64 },
}
