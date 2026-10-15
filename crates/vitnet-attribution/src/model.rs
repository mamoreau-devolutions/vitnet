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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xaml_documents: Vec<XamlDocument>,
    #[serde(default)]
    pub generators: Vec<Generator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generator_runs: Vec<GeneratorRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generator_links: Vec<GeneratorLink>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<SourceAnnotation>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAnnotation {
    pub target: String,
    pub attributes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XamlDocument {
    pub path: PathBuf,
    pub assembly: String,
    pub declared_class: Option<String>,
    pub root_element: String,
    pub sha256: String,
    pub includes: Vec<String>,
    pub keys: Vec<String>,
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
pub struct GeneratorRun {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub assembly_path: Option<PathBuf>,
    #[serde(default)]
    pub project_path: Option<PathBuf>,
    #[serde(default)]
    pub target_assembly: Option<String>,
    #[serde(default)]
    pub target_assembly_path: Option<PathBuf>,
    #[serde(default)]
    pub configuration: Option<String>,
    #[serde(default)]
    pub target_framework: Option<String>,
    pub status: String,
    pub basis: String,
    #[serde(default)]
    pub outputs: Vec<GeneratorOutput>,
    pub execution_status: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorOutput {
    pub path: PathBuf,
    #[serde(default)]
    pub sha256: Option<String>,
    pub build_match: String,
    #[serde(default)]
    pub pdb_checksums: Vec<GeneratorChecksum>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorChecksum {
    pub pdb_path: PathBuf,
    pub algorithm: String,
    pub checksum: String,
    pub status: String,
    pub assembly_match: String,
    #[serde(default)]
    pub target_assembly: Option<String>,
    #[serde(default)]
    pub target_assembly_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorLink {
    pub generator: String,
    pub output_path: PathBuf,
    #[serde(default)]
    pub trigger_source: Option<PathBuf>,
    #[serde(default)]
    pub trigger_type: Option<String>,
    #[serde(default)]
    pub trigger_member: Option<String>,
    #[serde(default)]
    pub trigger_symbol: Option<String>,
    pub rule: String,
    pub evidence_tier: String,
    pub basis: String,
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

impl Resource {
    /// Physical containers overlap their decoded child assets.
    #[must_use]
    pub fn is_container(&self) -> bool {
        matches!(
            self.storage.as_str(),
            "manifest_container" | "avalonia_container"
        )
    }
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
