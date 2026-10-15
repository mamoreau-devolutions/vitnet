use crate::model::{Evidence, EvidenceDiagnostic, Resource, Source};
use crate::{AttributionError, AttributionIndex, error, open_index, parse_shape, visit_identities};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use vitnet_mstat::CoalescedIdentity;

#[derive(Clone, Debug, Serialize)]
pub struct SourceMatch {
    pub status: String,
    pub basis: String,
    pub assemblies: Vec<String>,
    pub sources: Vec<Source>,
}

fn locate_entry(matcher: &Matcher<'_>, entry: &CoalescedIdentity) -> SourceMatch {
    if entry.identity_lossy {
        SourceMatch {
            status: "unmapped_lossy_identity".into(),
            basis: "Display decoding replaced invalid Unicode; raw-identity hash preserves distinctions".into(),
            assemblies: Vec::new(), sources: Vec::new(),
        }
    } else {
        matcher.locate(&entry.stream, &entry.identity)
    }
}

pub(crate) fn producer_fragment(value: &str) -> String {
    value.replace(['.', '+', '`'], "_")
}

pub struct Matcher<'a> {
    evidence: &'a Evidence,
    assemblies: HashMap<String, BTreeSet<String>>,
    sources: HashMap<String, Vec<usize>>,
    explicit: HashMap<(&'a str, &'a str), Vec<usize>>,
    managed: HashMap<(String, String), Vec<usize>>,
}

impl<'a> Matcher<'a> {
    #[must_use]
    pub fn new(evidence: &'a Evidence) -> Self {
        let mut assemblies: HashMap<String, BTreeSet<String>> = HashMap::new();
        for name in evidence
            .assemblies
            .iter()
            .map(|assembly| &assembly.name)
            .chain(evidence.sources.iter().map(|source| &source.assembly))
            .filter(|name| !name.is_empty())
        {
            assemblies
                .entry(producer_fragment(name))
                .or_default()
                .insert(name.clone());
        }
        let mut sources: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, source) in evidence.sources.iter().enumerate() {
            let key = format!(
                "{}_{}",
                producer_fragment(&source.assembly),
                producer_fragment(&source.type_name)
            );
            sources.entry(key).or_default().push(index);
        }
        let mut explicit: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
        for (index, mapping) in evidence.mappings.iter().enumerate() {
            explicit
                .entry((&mapping.stream, &mapping.identity))
                .or_default()
                .push(index);
        }
        let mut managed: HashMap<(String, String), Vec<usize>> = HashMap::new();
        for (index, source) in evidence.sources.iter().enumerate() {
            managed
                .entry((
                    source.assembly.clone(),
                    Self::normalized_type(&source.type_name),
                ))
                .or_default()
                .push(index);
        }
        Self {
            evidence,
            assemblies,
            sources,
            explicit,
            managed,
        }
    }

    /// Uses captured artifact-local token candidates before opaque spelling fallbacks.
    ///
    /// # Errors
    ///
    /// Rejects corrupt sidecar rows or exhausted lookup bounds.
    pub fn locate_entry(
        &self,
        entry: &CoalescedIdentity,
        symbols: Option<&mut crate::SymbolLookup>,
    ) -> Result<SourceMatch, AttributionError> {
        let Some(symbols) = symbols else {
            return Ok(locate_entry(self, entry));
        };
        let candidates = symbols.get(&entry.stream, &entry.raw_identity_blake3)?;
        self.locate_symbols(entry, &candidates)
    }

    /// Joins resolved managed owners while retaining signature/owner conflicts.
    ///
    /// # Errors
    ///
    /// Rejects candidates with wrong raw identity keys or unsupported resolution discriminators.
    pub fn locate_symbols(
        &self,
        entry: &CoalescedIdentity,
        candidates: &[serde_json::Value],
    ) -> Result<SourceMatch, AttributionError> {
        if candidates.is_empty()
            || self
                .explicit
                .contains_key(&(entry.stream.as_str(), entry.identity.as_str()))
        {
            return Ok(locate_entry(self, entry));
        }
        let mut resolutions = BTreeSet::new();
        let mut assemblies = BTreeSet::new();
        let mut source_indices = BTreeSet::new();
        let mut unresolved = false;
        for candidate in candidates {
            if candidate["stream"].as_str() != Some(&entry.stream)
                || candidate["raw_identity_blake3"].as_str() != Some(&entry.raw_identity_blake3)
            {
                return Err(error(
                    "symbols.integrity",
                    "symbol candidate belongs to another raw identity",
                ));
            }
            let resolution = &candidate["resolution"];
            match resolution["status"].as_str() {
                Some("unresolved") => {
                    unresolved = true;
                    continue;
                }
                Some("resolved") => {}
                _ => {
                    return Err(error(
                        "symbols.schema",
                        "unsupported symbol resolution status",
                    ));
                }
            }
            let Some(assembly) = resolution["assembly"].as_str() else {
                unresolved = true;
                continue;
            };
            let complete_assembly = assembly;
            let assembly = assembly.split(',').next().unwrap_or(assembly).trim();
            let declaring = resolution["declaring_type"]
                .as_str()
                .ok_or_else(|| error("symbols.schema", "resolved symbol lacks declaring type"))?;
            let member = resolution["member_name"].as_str();
            let signature = resolution["signature"]
                .as_str()
                .ok_or_else(|| error("symbols.schema", "resolved symbol lacks signature"))?;
            resolutions.insert((
                complete_assembly.to_owned(),
                declaring.to_owned(),
                member.map(str::to_owned),
                signature.to_owned(),
            ));
            assemblies.insert(assembly.to_owned());
            if let Some(indices) = self
                .managed
                .get(&(assembly.to_owned(), Self::normalized_type(declaring)))
            {
                for index in indices {
                    let source = &self.evidence.sources[*index];
                    let source_member = source
                        .member
                        .as_deref()
                        .map(|name| name.split('(').next().unwrap_or(name));
                    if source_member.is_none() || source_member == member {
                        source_indices.insert(*index);
                    }
                }
            }
        }
        if unresolved {
            let mut fallback = locate_entry(self, entry);
            if fallback.assemblies.is_empty() {
                fallback.status = "unmapped_symbol_candidates".into();
            } else if !assemblies.is_empty() {
                assemblies.extend(fallback.assemblies);
                fallback.assemblies = assemblies.into_iter().collect();
                if fallback.assemblies.len() > 1 {
                    fallback.status = "ambiguous".into();
                }
            }
            fallback.basis.push_str("; captured token resolution is incomplete/unsupported. Remaining spelling associations are candidates, not verified typed ownership; inspect complete token evidence.");
            return Ok(fallback);
        }
        Ok(SourceMatch {
                status: if resolutions.len() == 1 { "managed_symbol_join" } else { "managed_symbol_ambiguous" }.into(),
                basis: "MSTAT-artifact-local ECMA-335 owner/signature join keyed by complete stream/raw-name hash. Source declarations remain independently captured name candidates; source/build checksum equality is not established by this join.".into(),
                assemblies: assemblies.into_iter().collect(),
                sources: source_indices.into_iter().map(|index| self.evidence.sources[index].clone()).collect(),
            })
    }

    fn normalized_type(value: &str) -> String {
        let mut result = String::new();
        let mut depth = 0_u32;
        let mut arity = false;
        for character in value.trim_start_matches("global::").chars() {
            match character {
                '<' => depth += 1,
                '>' if depth > 0 => depth -= 1,
                _ if depth > 0 => {}
                '`' => arity = true,
                '0'..='9' if arity => {}
                _ => {
                    arity = false;
                    result.push(if character == '+' { '.' } else { character });
                }
            }
        }
        result
    }

    #[allow(clippy::too_many_lines)]
    pub fn locate(&self, stream: &str, identity: &str) -> SourceMatch {
        if let Some(indices) = self.explicit.get(&(stream, identity)) {
            let mappings: Vec<_> = indices
                .iter()
                .map(|index| &self.evidence.mappings[*index])
                .collect();
            let assemblies: BTreeSet<_> = mappings
                .iter()
                .map(|mapping| mapping.assembly.clone())
                .collect();
            let paths: BTreeSet<_> = mappings
                .iter()
                .flat_map(|mapping| &mapping.source_paths)
                .collect();
            return SourceMatch {
                status: if assemblies.len() == 1 {
                    "asserted"
                } else {
                    "ambiguous"
                }
                .into(),
                basis: mappings
                    .iter()
                    .map(|mapping| mapping.basis.as_str())
                    .collect::<Vec<_>>()
                    .join("; "),
                assemblies: assemblies.into_iter().collect(),
                sources: self
                    .evidence
                    .sources
                    .iter()
                    .filter(|source| paths.contains(&source.path))
                    .cloned()
                    .collect(),
            };
        }
        if stream == "ManifestResources" {
            if let Some((assembly, _)) = identity.split_once('!') {
                return SourceMatch {
                    status: "resource_assembly".into(),
                    basis: "MSTAT resource assembly identity".into(),
                    assemblies: vec![assembly.into()],
                    sources: Vec::new(),
                };
            }
        }
        let mut candidates = BTreeSet::new();
        for (offset, character) in identity.char_indices() {
            if character == '_' {
                if let Some(indices) = self.assemblies.get(&identity[..offset]) {
                    for name in indices {
                        candidates.insert(name.clone());
                    }
                }
            }
            if offset > 1024 {
                break;
            }
        }
        let owner = identity
            .split_once("__")
            .map_or(identity, |(owner, _)| owner);
        let owner = owner.split_once('<').map_or(owner, |(family, _)| family);
        let member = identity
            .split_once("__")
            .map(|(_, member)| member.split_once('<').map_or(member, |(name, _)| name));
        let mut source_key = owner;
        let indices = loop {
            if let Some(indices) = self.sources.get(source_key) {
                break Some(indices);
            }
            if let Some((parent, _)) = source_key.rsplit_once('_') {
                source_key = parent;
            } else {
                break None;
            }
        };
        let sources = indices.map_or_else(Vec::new, |indices| {
            let exact_members: Vec<_> = indices
                .iter()
                .filter_map(|index| {
                    let source = &self.evidence.sources[*index];
                    (source
                        .member
                        .as_deref()
                        .map(|name| name.split('(').next().unwrap_or(name))
                        == member
                        && member.is_some())
                    .then_some(source.clone())
                })
                .collect();
            if exact_members.is_empty() {
                indices
                    .iter()
                    .filter_map(|index| {
                        let source = &self.evidence.sources[*index];
                        source.member.is_none().then_some(source.clone())
                    })
                    .collect()
            } else {
                exact_members
            }
        });
        let source_owners: BTreeSet<_> = sources
            .iter()
            .map(|source| (&source.assembly, &source.type_name))
            .collect();
        SourceMatch {
            status: match (candidates.len(), source_owners.len()) {
                (_, owners) if owners > 1 => "ambiguous",
                (0, _) => "unmapped",
                (1, _) => "producer_prefix_candidate",
                _ => "ambiguous",
            }
            .into(),
            basis: if source_key == owner {
                "Opaque producer-name spelling hypothesis; not a verified managed-symbol join"
            } else {
                "Nearest enclosing producer-name spelling candidate; not a verified nested/member join"
            }.into(),
            assemblies: candidates.into_iter().collect(),
            sources,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ByteGroup {
    pub name: String,
    pub bytes: u64,
    pub identities: u64,
    pub mapping_status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageRoute {
    pub target: String,
    pub package: String,
    pub direct: bool,
    pub shortest_route: Option<Vec<String>>,
    pub retained_by_packages: Vec<String>,
    pub missing_dependencies: Vec<String>,
    pub cyclic_target: bool,
}

/// Computes deterministic shortest resolved routes with bounded path storage.
///
/// # Errors
///
/// Rejects route materialization exceeding the caller's memory share.
#[allow(clippy::too_many_lines)]
pub fn package_routes(
    evidence: &Evidence,
    memory_limit: u64,
) -> Result<Vec<PackageRoute>, AttributionError> {
    let targets: BTreeSet<_> = evidence
        .packages
        .iter()
        .map(|package| &package.target)
        .collect();
    let mut output = Vec::new();
    let mut stored_bytes = 0_u64;
    for target in targets {
        let packages: BTreeMap<_, _> = evidence
            .packages
            .iter()
            .filter(|package| &package.target == target)
            .map(|package| (format!("{}/{}", package.id, package.version), package))
            .collect();
        let mut incoming: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        let mut parents = BTreeMap::<String, Option<String>>::new();
        for (key, package) in &packages {
            if package.direct {
                queue.push_back(key.clone());
                parents.insert(key.clone(), None);
            }
            for dependency in &package.dependencies {
                incoming
                    .entry(dependency.clone())
                    .or_default()
                    .push(key.clone());
            }
        }
        while let Some(key) = queue.pop_front() {
            if let Some(package) = packages.get(&key) {
                for dependency in &package.dependencies {
                    if packages.contains_key(dependency) && !parents.contains_key(dependency) {
                        parents.insert(dependency.clone(), Some(key.clone()));
                        queue.push_back(dependency.clone());
                    }
                }
            }
        }
        let mut indegrees: BTreeMap<_, _> =
            packages.keys().map(|key| (key.clone(), 0_usize)).collect();
        for package in packages.values() {
            for dependency in &package.dependencies {
                if let Some(count) = indegrees.get_mut(dependency) {
                    *count += 1;
                }
            }
        }
        let mut ready: VecDeque<_> = indegrees
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(key, _)| key.clone())
            .collect();
        let mut removed = 0;
        while let Some(key) = ready.pop_front() {
            removed += 1;
            for dependency in &packages[&key].dependencies {
                if let Some(count) = indegrees.get_mut(dependency) {
                    *count -= 1;
                    if *count == 0 {
                        ready.push_back(dependency.clone());
                    }
                }
            }
        }
        for (key, package) in &packages {
            let route = if parents.contains_key(key) {
                let mut route = Vec::new();
                let mut cursor = key.as_str();
                loop {
                    stored_bytes = stored_bytes.saturating_add(cursor.len() as u64 + 32);
                    if stored_bytes > memory_limit / 8 {
                        return Err(error(
                            "resource.memory_limit",
                            "package route paths exceed memory share",
                        ));
                    }
                    route.push(cursor.to_owned());
                    if let Some(Some(parent)) = parents.get(cursor) {
                        cursor = parent;
                    } else {
                        break;
                    }
                }
                route.reverse();
                Some(route)
            } else {
                None
            };
            output.push(PackageRoute {
                target: target.clone(),
                package: key.clone(),
                direct: package.direct,
                shortest_route: route,
                retained_by_packages: incoming.remove(key).unwrap_or_default(),
                missing_dependencies: package
                    .dependencies
                    .iter()
                    .filter(|key| !packages.contains_key(*key))
                    .cloned()
                    .collect(),
                cyclic_target: removed != packages.len(),
            });
        }
    }
    Ok(output)
}

#[derive(Clone, Debug, Serialize)]
pub struct Contributor {
    pub stream: String,
    pub identity: String,
    pub bytes: u64,
    pub sources: SourceMatch,
}

#[derive(Clone, Debug, Serialize)]
pub struct GeneratorReport {
    pub name: String,
    pub version: String,
    pub generated_files: usize,
    pub declared_inputs: usize,
    pub generated_declarations: u64,
    pub candidate_accounted_bytes: u64,
    pub asserted_accounted_bytes: u64,
    pub caveat: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ShapeReport {
    pub family: String,
    pub stream: String,
    pub bytes: u64,
    pub distinct_shapes: u64,
    pub producer_identities: u64,
    pub canonical_shared_shapes: u64,
    pub argument_kinds: BTreeMap<String, u64>,
    pub source_examples: Vec<Source>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResourceDuplicate {
    pub sha256: String,
    pub bytes_each: u64,
    pub instances: Vec<Resource>,
    pub instance_count: usize,
    pub caveat: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttributionReport {
    pub schema: String,
    pub label: String,
    pub provenance: BTreeMap<String, String>,
    pub accounted_bytes: Option<u64>,
    pub metadata_lower_bound_bytes: Option<u64>,
    pub metadata_type_sources: Vec<MetadataTypeSource>,
    pub accounted_mapping_bytes: BTreeMap<String, u64>,
    pub assembly_groups: Vec<ByteGroup>,
    pub package_groups: Vec<ByteGroup>,
    pub package_routes: Vec<PackageRoute>,
    pub contributors: Vec<Contributor>,
    pub generators: Vec<GeneratorReport>,
    pub generic_families: Vec<ShapeReport>,
    pub malformed_generic_identities: u64,
    pub resources: Vec<Resource>,
    pub duplicate_assets: Vec<ResourceDuplicate>,
    pub displayed_resource_bytes: u64,
    pub full_resource_asset_bytes: u64,
    pub full_resource_container_bytes: u64,
    pub package_route_count: usize,
    pub generator_count: usize,
    pub duplicate_asset_group_count: usize,
    pub diagnostics: Vec<EvidenceDiagnostic>,
    pub caveats: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetadataTypeSource {
    pub qualified_type: String,
    pub lower_bound_bytes: u64,
    pub sources: Vec<Source>,
    pub status: String,
}

fn add(
    groups: &mut BTreeMap<(String, String), ByteGroup>,
    name: String,
    status: &str,
    bytes: u64,
) -> Result<(), AttributionError> {
    let group = groups
        .entry((name.clone(), status.into()))
        .or_insert_with(|| ByteGroup {
            name,
            mapping_status: status.into(),
            ..ByteGroup::default()
        });
    group.bytes = group
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| error("attribution.size", "group byte overflow"))?;
    group.identities += 1;
    Ok(())
}

fn ranked(mut groups: Vec<ByteGroup>, top: usize) -> Vec<ByteGroup> {
    groups.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.mapping_status.cmp(&right.mapping_status))
    });
    groups.truncate(top);
    groups
}

fn candidate_packages(evidence: &Evidence, assemblies: &[String]) -> BTreeSet<String> {
    evidence
        .assemblies
        .iter()
        .filter(|assembly| assemblies.contains(&assembly.name))
        .filter_map(|assembly| assembly.package.clone())
        .collect()
}

/// Groups asset content hashes, independently of equal-length clues.
///
/// # Errors
///
/// Rejects invalid hashes and inconsistent declared lengths.
pub fn asset_duplicates(
    resources: &[Resource],
) -> Result<Vec<ResourceDuplicate>, AttributionError> {
    let mut groups: BTreeMap<String, Vec<Resource>> = BTreeMap::new();
    for resource in resources {
        if resource.is_container() {
            continue;
        }
        if let Some(hash) = &resource.sha256 {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(error(
                    "attribution.resource.hash",
                    "asset SHA-256 must contain 64 hex digits",
                ));
            }
            groups
                .entry(hash.to_ascii_lowercase())
                .or_default()
                .push(resource.clone());
        }
    }
    let mut output = Vec::new();
    for (hash, mut instances) in groups {
        instances.sort_by(|left, right| {
            (&left.assembly, &left.container, &left.name).cmp(&(
                &right.assembly,
                &right.container,
                &right.name,
            ))
        });
        instances.dedup_by(|left, right| {
            left.assembly == right.assembly
                && left.container == right.container
                && left.name == right.name
        });
        if instances
            .iter()
            .any(|instance| instance.bytes != instances[0].bytes)
        {
            return Err(error(
                "attribution.resource.hash",
                "identical content hashes declare different asset lengths",
            ));
        }
        if instances.len() > 1 {
            output.push(ResourceDuplicate {
                sha256: hash, bytes_each: instances[0].bytes, instance_count: instances.len(), instances,
                caveat: "Collector content hashes establish equal asset content, not independently reclaimable native bytes.".into(),
            });
        }
    }
    Ok(output)
}

/// Computes complete attribution aggregates with bounded displayed examples.
///
/// # Errors
///
/// Returns cache, schema, integrity, arithmetic and resource-limit diagnostics.
#[allow(clippy::too_many_lines)]
pub fn report(
    directory: &Path,
    memory_limit: u64,
    top: usize,
    contains: Option<&str>,
) -> Result<AttributionReport, AttributionError> {
    if top == 0 || top as u64 > memory_limit / 16384 {
        return Err(error(
            "resource.memory_limit",
            "attribution top count exceeds report budget",
        ));
    }
    let index = open_index(directory, memory_limit)?;
    let evidence = &index.evidence;
    let matcher = Matcher::new(evidence);
    let mut symbols = index
        .symbols
        .as_ref()
        .map(|descriptor| crate::SymbolLookup::open(directory, descriptor, memory_limit))
        .transpose()?;
    let mut coverage = BTreeMap::<String, u64>::new();
    let mut assembly_groups = BTreeMap::new();
    let mut package_groups = BTreeMap::new();
    let mut contributors: Vec<Contributor> = Vec::new();
    let mut generator_bytes: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut shapes: BTreeMap<(String, String), (ShapeReport, BTreeSet<String>)> = BTreeMap::new();
    let mut shape_storage = 0_u64;
    let mut kinds = HashMap::new();
    for assembly in &evidence.assemblies {
        for item in &assembly.types {
            let key = format!(
                "{}_{}",
                producer_fragment(&assembly.name),
                producer_fragment(&item.name)
            );
            kinds
                .entry(key)
                .and_modify(|kind| *kind = "ambiguous")
                .or_insert(item.kind.as_str());
        }
    }
    let mut malformed_shapes = 0;
    visit_identities(directory, &index, memory_limit, |entry| {
        let located = matcher.locate_entry(entry, symbols.as_mut())?;
        if entry.accounted {
            let value = coverage.entry(located.status.clone()).or_default();
            *value = value
                .checked_add(entry.bytes)
                .ok_or_else(|| error("attribution.size", "coverage byte overflow"))?;
            let name = if located.assemblies.len() == 1 {
                located.assemblies[0].clone()
            } else {
                format!("_{}", located.status)
            };
            add(&mut assembly_groups, name, &located.status, entry.bytes)?;
            let packages = candidate_packages(evidence, &located.assemblies);
            let name = if located.assemblies.len() == 1 && packages.len() == 1 {
                packages
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "_unresolved_or_shared".into())
            } else {
                "_unresolved_or_shared".into()
            };
            add(&mut package_groups, name, &located.status, entry.bytes)?;
            let emitters: BTreeSet<_> = located
                .sources
                .iter()
                .filter_map(|source| source.generated_by.as_ref())
                .collect();
            for emitter in emitters {
                let value = generator_bytes
                    .entry((emitter.clone(), located.status.clone()))
                    .or_default();
                *value = value
                    .checked_add(entry.bytes)
                    .ok_or_else(|| error("attribution.size", "generator byte overflow"))?;
            }
        }
        if !entry.identity_lossy && matches!(entry.stream.as_str(), "Methods" | "Types") {
            match parse_shape(&entry.identity) {
                Ok(Some(shape)) => {
                    let key = (entry.stream.clone(), shape.family.clone());
                    let (group, unique) = shapes.entry(key).or_insert_with(|| {
                        (
                            ShapeReport {
                                family: shape.family.clone(),
                                stream: entry.stream.clone(),
                                ..ShapeReport::default()
                            },
                            BTreeSet::new(),
                        )
                    });
                    group.bytes = group
                        .bytes
                        .checked_add(entry.bytes)
                        .ok_or_else(|| error("attribution.size", "shape byte overflow"))?;
                    group.producer_identities += 1;
                    let shape_key = format!("{:?}:{:?}", shape.group_boundaries, shape.arguments);
                    if unique.insert(shape_key) {
                        shape_storage = shape_storage
                            .checked_add(
                                shape.arguments.iter().map(String::len).sum::<usize>() as u64 + 96,
                            )
                            .ok_or_else(|| {
                                error("resource.memory_limit", "generic state accounting overflow")
                            })?;
                        group.distinct_shapes += 1;
                        group.canonical_shared_shapes += u64::from(shape.canonical_shared);
                        for argument in &shape.arguments {
                            let kind =
                                if argument.contains("___Canon") || argument.contains("__Canon") {
                                    "canonical_shared"
                                } else {
                                    kinds.get(argument).copied().unwrap_or("unknown")
                                };
                            *group.argument_kinds.entry(kind.into()).or_default() += 1;
                        }
                    }
                    if group.source_examples.is_empty() {
                        group
                            .source_examples
                            .extend(located.sources.iter().take(3).cloned());
                    }
                }
                Ok(None) => {}
                Err(cause) if cause.diagnostic.code.starts_with("resource.") => return Err(cause),
                Err(_) => malformed_shapes += 1,
            }
        }
        if contains.is_none_or(|text| entry.identity.contains(text)) {
            let eligible = contributors.len() < top
                || contributors.last().is_some_and(|last| {
                    entry.bytes > last.bytes
                        || (entry.bytes == last.bytes
                            && (&entry.stream, &entry.identity) < (&last.stream, &last.identity))
                });
            if eligible {
                contributors.push(Contributor {
                    stream: entry.stream.clone(),
                    identity: entry.identity.clone(),
                    bytes: entry.bytes,
                    sources: located,
                });
                contributors.sort_by(|left, right| {
                    right.bytes.cmp(&left.bytes).then_with(|| {
                        (&left.stream, &left.identity).cmp(&(&right.stream, &right.identity))
                    })
                });
                contributors.truncate(top);
            }
        }
        let groups =
            assembly_groups.len() + package_groups.len() + shapes.len() + generator_bytes.len();
        if (groups as u64)
            .saturating_mul(4096)
            .saturating_add(shape_storage)
            > memory_limit / 2
        {
            return Err(error(
                "resource.memory_limit",
                "attribution aggregate state exceeds memory share",
            ));
        }
        Ok(())
    })?;
    let mut generators: Vec<_> = evidence.generators.iter().map(|generator| GeneratorReport {
        name: generator.name.clone(), version: generator.version.clone(),
        generated_files: generator.generated_files.len(), declared_inputs: generator.input_symbols.len(),
        generated_declarations: evidence.sources.iter().filter(|source| source.generated_by.as_deref() == Some(&generator.name)).count() as u64,
        candidate_accounted_bytes: *generator_bytes.get(&(generator.name.clone(), "producer_prefix_candidate".into())).unwrap_or(&0),
        asserted_accounted_bytes: *generator_bytes.get(&(generator.name.clone(), "asserted".into())).unwrap_or(&0),
        caveat: "Native-byte associations are evidence-tiered, may overlap, and are not the build-time generator DLL's size. Undeclared inputs remain unknown.".into(),
    }).collect();
    generators
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    let mut generic_families: Vec<_> = shapes.into_values().map(|(group, _)| group).collect();
    generic_families.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| (&left.stream, &left.family).cmp(&(&right.stream, &right.family)))
    });
    generic_families.truncate(top);
    let mut resources = evidence.resources.clone();
    resources.sort_by(|left, right| {
        right.bytes.cmp(&left.bytes).then_with(|| {
            (&left.assembly, &left.container, &left.name).cmp(&(
                &right.assembly,
                &right.container,
                &right.name,
            ))
        })
    });
    let full_resource_asset_bytes = resources
        .iter()
        .filter(|resource| !resource.is_container())
        .try_fold(0_u64, |sum, resource| sum.checked_add(resource.bytes))
        .ok_or_else(|| error("attribution.size", "resource inventory byte overflow"))?;
    let full_resource_container_bytes = resources
        .iter()
        .filter(|resource| resource.is_container())
        .try_fold(0_u64, |sum, resource| sum.checked_add(resource.bytes))
        .ok_or_else(|| error("attribution.size", "resource container byte overflow"))?;
    let mut duplicate_assets = asset_duplicates(&resources)?;
    let duplicate_asset_group_count = duplicate_assets.len();
    duplicate_assets.truncate(top);
    for group in &mut duplicate_assets {
        group.instances.truncate(top);
    }
    let mut routes = package_routes(evidence, memory_limit)?;
    let package_route_count = routes.len();
    routes.truncate(top);
    let generator_count = generators.len();
    generators.truncate(top);
    resources.truncate(top);
    let displayed_resource_bytes = resources.iter().map(|resource| resource.bytes).sum();
    let metadata_type_sources = index.metadata.as_ref().map_or_else(Vec::new, |analysis| {
        analysis
            .by_type
            .iter()
            .take(top)
            .map(|group| {
                let mut enclosing = false;
                let sources: Vec<_> =
                    group
                        .name
                        .split_once('!')
                        .map_or_else(Vec::new, |(assembly, type_name)| {
                            let mut owner = type_name;
                            loop {
                                let sources: Vec<_> = evidence
                                    .sources
                                    .iter()
                                    .filter(|source| {
                                        source.assembly == assembly
                                            && source.type_name == owner
                                            && source.member.is_none()
                                    })
                                    .cloned()
                                    .collect();
                                if !sources.is_empty() {
                                    break sources;
                                }
                                if let Some((parent, _)) = owner.rsplit_once('+') {
                                    owner = parent;
                                    enclosing = true;
                                } else {
                                    break Vec::new();
                                }
                            }
                        });
                MetadataTypeSource {
                    qualified_type: group.name.clone(),
                    lower_bound_bytes: group.bytes,
                    status: if sources.is_empty() {
                        "unmapped"
                    } else if enclosing {
                        "managed_enclosing_type_name_match"
                    } else {
                        "managed_type_name_match"
                    }
                    .into(),
                    sources,
                }
            })
            .collect()
    });
    Ok(AttributionReport {
        schema: "vitnet.attribution-report.v1".into(), label: evidence.label.clone(),
        provenance: evidence.provenance.clone(), accounted_bytes: index.mstat.as_ref().map(|summary| summary.accounted_size_bytes),
        metadata_lower_bound_bytes: index.metadata.as_ref().map(|analysis| analysis.total_lower_bound),
        metadata_type_sources,
        accounted_mapping_bytes: coverage, assembly_groups: ranked(assembly_groups.into_values().collect(), top),
        package_groups: ranked(package_groups.into_values().collect(), top), package_routes: routes,
        contributors, generators, generic_families, malformed_generic_identities: malformed_shapes,
        resources, duplicate_assets, displayed_resource_bytes, full_resource_asset_bytes,
        full_resource_container_bytes, package_route_count, generator_count, duplicate_asset_group_count,
        diagnostics: index.diagnostics,
        caveats: vec![
            "Producer-prefix source/package associations are candidates, not verified ownership. Explicit mappings are user assertions with their recorded basis.".into(),
            "Complete accounting coverage is independent of displayed top-N and the contributor contains filter; specialized streams overlap Blobs.".into(),
            "Distinct parsed shapes are not managed/native instantiation counts. Reference code sharing, value-type specialization and folding remain separate concerns.".into(),
            "Metadata source rows match declared managed names; source provenance/checksum diagnostics still govern whether they describe the compiled build.".into(),
            "Container bytes and inventoried child-asset bytes overlap and are reported separately. Child assets can share payload ranges; neither total is independently reclaimable native size.".into(),
            "Assets are managed/container inventories, not proven native-image inclusions or physical savings. Missing mappings are never silently assigned.".into(),
        ],
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceReport {
    pub schema: String,
    pub identity: String,
    pub contributors: Vec<CoalescedIdentity>,
    pub matches: Vec<SourceMatch>,
    pub related_files: Vec<PathBuf>,
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

/// Locates source candidates for a complete cached producer identity.
///
/// # Errors
///
/// Rejects absent identities, cache corruption, I/O and resource limits.
pub fn locate_source(
    directory: &Path,
    identity: &str,
    memory_limit: u64,
) -> Result<SourceReport, AttributionError> {
    let index: AttributionIndex = open_index(directory, memory_limit)?;
    let matcher = Matcher::new(&index.evidence);
    let mut symbols = index
        .symbols
        .as_ref()
        .map(|descriptor| crate::SymbolLookup::open(directory, descriptor, memory_limit))
        .transpose()?;
    let mut contributors = Vec::new();
    let mut associations = Vec::new();
    visit_identities(directory, &index, memory_limit, |entry| {
        if entry.identity == identity {
            contributors.push(entry.clone());
            associations.push(matcher.locate_entry(entry, symbols.as_mut())?);
        }
        Ok(())
    })?;
    if contributors.is_empty() {
        return Err(error(
            "attribution.identity.missing",
            "exact identity is absent from persisted accounting",
        ));
    }
    let related_files: BTreeSet<_> = associations
        .iter()
        .flat_map(|matched| matched.sources.iter().map(|source| source.path.clone()))
        .collect();
    let mut selected = index.clone();
    selected
        .artifacts
        .retain(|artifact| related_files.contains(&artifact.path));
    let diagnostics = crate::verify_artifacts(&selected)?;
    Ok(SourceReport {
        schema: "vitnet.attribution-source.v1".into(),
        identity: identity.into(),
        contributors,
        matches: associations,
        related_files: related_files.into_iter().collect(),
        diagnostics,
    })
}
