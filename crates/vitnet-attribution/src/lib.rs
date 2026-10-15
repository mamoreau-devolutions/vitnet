//! Versioned, local evidence import and generic source attribution.

mod comparison;
pub mod model;
mod opportunities;
mod reports;
mod retention;
mod shapes;
mod store;

pub use comparison::*;
pub use opportunities::*;
mod symbols;
pub use reports::*;
pub use retention::*;
pub use shapes::*;
pub use store::*;
pub use symbols::{SYMBOL_SCHEMA, SymbolLookup, SymbolSidecar};

use std::path::Path;
use thiserror::Error;
use vitnet_core::Diagnostic;

#[derive(Debug, Error)]
#[error("{diagnostic}")]
pub struct AttributionError {
    pub diagnostic: Box<Diagnostic>,
}

pub(crate) fn error(code: &str, message: impl Into<String>) -> AttributionError {
    AttributionError {
        diagnostic: Box::new(Diagnostic::malformed(code, message)),
    }
}

pub(crate) fn io(path: &Path, cause: impl std::fmt::Display) -> AttributionError {
    let mut diagnostic = Diagnostic::malformed("attribution.io", cause.to_string());
    diagnostic.input_path = Some(path.to_owned());
    AttributionError {
        diagnostic: Box::new(diagnostic),
    }
}
pub mod lenses;
