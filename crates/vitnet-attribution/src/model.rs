use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const EVIDENCE_SCHEMA: &str = "vitnet.evidence.v1";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub provenance: BTreeMap<String, String>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub packages: Vec<Package>,
    #[serde(default)]
    pub assemblies: Vec<Assembly>,
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub generators: Vec<Generator>,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub binaries: Vec<Binary>,
    #[serde(default)]
    pub mappings: Vec<Mapping>,
    #[serde(default)]
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub kind: String,
    pub path: PathBuf,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub blake3: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub target: String,
    pub id: String,
    pub version: String,
    pub direct: bool,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assembly {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub types: Vec<ManagedType>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedType {
    pub name: String,
    pub kind: String,
    pub members: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub assembly: String,
    pub type_name: String,
    #[serde(default)]
    pub member: Option<String>,
    pub path: PathBuf,
    pub line: u64,
    pub end_line: u64,
    pub kind: String,
    #[serde(default)]
    pub attributes: Vec<String>,
    #[serde(default)]
    pub generated_by: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generator {
    pub name: String,
    pub version: String,
    pub assembly_path: PathBuf,
    #[serde(default)]
    pub generated_files: Vec<PathBuf>,
    #[serde(default)]
    pub input_symbols: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub assembly: String,
    pub container: String,
    pub name: String,
    pub bytes: u64,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub source_path: Option<PathBuf>,
    pub storage: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binary {
    pub path: PathBuf,
    pub format: String,
    pub architecture: String,
    pub file_bytes: u64,
    #[serde(default)]
    pub sections: Vec<BinarySection>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinarySection {
    pub name: String,
    pub file_bytes: u64,
    pub virtual_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub stream: String,
    pub identity: String,
    pub assembly: String,
    #[serde(default)]
    pub source_paths: Vec<PathBuf>,
    pub basis: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
}
