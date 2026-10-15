use super::diagnostic;
use crate::AppError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize)]
pub(super) struct Bucket {
    pub title: String,
    pub description: String,
    pub investigation: String,
    pub source: String,
    pub view: String,
}

pub(super) fn catalog() -> Result<BTreeMap<String, Bucket>, AppError> {
    serde_json::from_str(include_str!("assets/buckets.json"))
        .map_err(|error| diagnostic("explorer.glossary", error.to_string()))
}

pub(super) fn lookup(name: &str) -> Result<Option<Bucket>, AppError> {
    Ok(catalog()?.remove(name))
}
