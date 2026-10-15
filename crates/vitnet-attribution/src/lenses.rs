//! Measured, overlapping investigation lenses, never removability predictions.
use crate::{AttributionError, SourceMatch, error, model::Evidence, parse_shape};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use vitnet_mstat::CoalescedIdentity;

pub const SCHEMA: &str = "vitnet.investigation-lenses.v1";

#[derive(Clone, Debug, Default, Serialize)]
pub struct Cost {
    pub additive_bytes: u64,
    pub overlapping_bytes: u64,
    pub methods_bytes: u64,
    pub types_bytes: u64,
    pub blobs_bytes: u64,
    pub other_additive_bytes: u64,
    pub identities: u64,
    pub canonical_shared_identities: u64,
}

impl Cost {
    fn add(&mut self, entry: &CoalescedIdentity, canonical: bool) -> Result<(), AttributionError> {
        plus(
            if entry.accounted {
                &mut self.additive_bytes
            } else {
                &mut self.overlapping_bytes
            },
            entry.bytes,
        )?;
        if entry.accounted {
            match entry.stream.as_str() {
                "Methods" => plus(&mut self.methods_bytes, entry.bytes)?,
                "Types" => plus(&mut self.types_bytes, entry.bytes)?,
                "Blobs" => plus(&mut self.blobs_bytes, entry.bytes)?,
                _ => plus(&mut self.other_additive_bytes, entry.bytes)?,
            }
        }
        plus(&mut self.identities, 1)?;
        if canonical {
            plus(&mut self.canonical_shared_identities, 1)?;
        }
        Ok(())
    }
}

fn plus(target: &mut u64, value: u64) -> Result<(), AttributionError> {
    *target = target
        .checked_add(value)
        .ok_or_else(|| error("lenses.size", "investigation total overflow"))?;
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Owner {
    pub assembly: String,
    pub namespace: String,
    pub owner: String,
    pub evidence_tier: String,
    #[serde(flatten)]
    pub cost: Cost,
    pub xaml_bytes: u64,
    pub serializer_bytes: u64,
    pub generic_bytes: u64,
    pub metadata_lower_bound_bytes: u64,
    pub examples: Vec<Example>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Example {
    pub ordinal: u64,
    pub bytes: u64,
    pub stream: String,
    pub identity: String,
    pub truncated: bool,
}

#[derive(Default)]
struct Argument {
    cost: Cost,
    families: BTreeSet<Arc<str>>,
    examples: Vec<Example>,
}

#[derive(Serialize)]
pub struct LensReport {
    pub schema: String,
    pub owners: Vec<Owner>,
    pub xaml: Vec<Value>,
    pub serializers: Vec<Value>,
    pub repetitions: Vec<Value>,
    pub arguments: Vec<Value>,
    pub reflection: Vec<Value>,
    pub coverage: Value,
}

pub struct Collector<'a> {
    evidence: &'a Evidence,
    owners: BTreeMap<(String, String, String), Owner>,
    arguments: BTreeMap<String, Argument>,
    families: BTreeMap<String, Arc<str>>,
    memory: u64,
    retained: u64,
    malformed_shapes: u64,
}

#[must_use]
pub fn normalize_type(value: &str) -> String {
    let mut text = String::new();
    let mut depth = 0_u32;
    let mut arity = false;
    for c in value.trim_start_matches("global::").chars() {
        match c {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            '`' => arity = true,
            '0'..='9' if arity => {}
            _ => {
                arity = false;
                text.push(c);
            }
        }
    }
    text
}

fn namespace(owner: &str) -> String {
    owner
        .split('+')
        .next()
        .unwrap_or(owner)
        .rsplit_once('.')
        .map_or_else(String::new, |(ns, _)| ns.into())
}

fn clip(text: &str, max: usize) -> (String, bool) {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].into(), end < text.len())
}

fn example(examples: &mut Vec<Example>, entry: &CoalescedIdentity, ordinal: u64) -> u64 {
    if examples.len() == 3
        && examples.last().is_some_and(|last| {
            entry.bytes < last.bytes || (entry.bytes == last.bytes && ordinal > last.ordinal)
        })
    {
        return 0;
    }
    let before = examples.capacity() * std::mem::size_of::<Example>()
        + examples
            .iter()
            .map(|item| item.identity.len() + item.stream.len())
            .sum::<usize>();
    let (identity, truncated) = clip(&entry.identity, 512);
    let value = Example {
        ordinal,
        bytes: entry.bytes,
        stream: entry.stream.clone(),
        identity,
        truncated,
    };
    if examples.len() < 3 {
        if examples.len() == examples.capacity() {
            examples.reserve_exact(1);
        }
        examples.push(value);
    } else if let Some(last) = examples.last_mut() {
        *last = value;
    }
    examples.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.ordinal.cmp(&b.ordinal))
    });
    examples.truncate(3);
    let after = examples.capacity() * std::mem::size_of::<Example>()
        + examples
            .iter()
            .map(|item| item.identity.len() + item.stream.len())
            .sum::<usize>();
    after.saturating_sub(before) as u64
}

fn reserve(retained: &mut u64, memory: u64, bytes: u64) -> Result<(), AttributionError> {
    *retained = retained
        .checked_add(bytes)
        .ok_or_else(|| error("resource.lenses", "investigation memory estimate overflow"))?;
    if *retained > memory {
        return Err(error(
            "resource.lenses",
            "investigation aggregate exceeds its memory budget",
        ));
    }
    Ok(())
}

fn managed_owner(candidates: &[Value]) -> Option<(String, String)> {
    let mut owners = BTreeSet::new();
    for candidate in candidates {
        let resolution = &candidate["resolution"];
        if resolution["status"] != "resolved" {
            return None;
        }
        let assembly = resolution["assembly"].as_str()?.split(',').next()?.trim();
        let owner = resolution["declaring_type"].as_str()?;
        owners.insert((assembly.to_owned(), normalize_type(owner)));
    }
    (owners.len() == 1)
        .then(|| owners.into_iter().next())
        .flatten()
}

impl<'a> Collector<'a> {
    /// # Errors
    /// Rejects insufficient aggregate memory.
    pub fn new(evidence: &'a Evidence, memory: u64) -> Result<Self, AttributionError> {
        if memory < 64 * 1024 {
            return Err(error(
                "resource.lenses",
                "investigation collector needs 64 KiB",
            ));
        }
        Ok(Self {
            evidence,
            owners: BTreeMap::new(),
            arguments: BTreeMap::new(),
            families: BTreeMap::new(),
            memory,
            retained: 0,
            malformed_shapes: 0,
        })
    }

    /// # Errors
    /// Rejects overflow or exhausted aggregate memory. Each identity is charged once per owner.
    #[allow(clippy::too_many_lines)] // One bounded identity transaction preserves all accounting partitions.
    pub fn observe(
        &mut self,
        entry: &CoalescedIdentity,
        located: &SourceMatch,
        candidates: &[Value],
        ordinal: u64,
    ) -> Result<(), AttributionError> {
        if candidates.iter().any(|candidate| {
            candidate["stream"] != entry.stream
                || candidate["raw_identity_blake3"] != entry.raw_identity_blake3
        }) {
            return Err(error(
                "symbols.integrity",
                "lens symbol belongs to another raw identity",
            ));
        }
        let shape = if entry.identity_lossy {
            None
        } else {
            match parse_shape(&entry.identity) {
                Ok(shape) => shape,
                Err(cause) if cause.diagnostic.code.starts_with("attribution.generic.") => {
                    plus(&mut self.malformed_shapes, 1)?;
                    None
                }
                Err(cause) => return Err(cause),
            }
        };
        let canonical = shape.as_ref().is_some_and(|shape| shape.canonical_shared);
        let typed = if located.status == "managed_symbol_join" {
            managed_owner(candidates)
        } else {
            None
        };
        let source_owners: BTreeSet<_> = located
            .sources
            .iter()
            .map(|source| (source.assembly.clone(), normalize_type(&source.type_name)))
            .collect();
        let (assembly, owner, tier) = if let Some((assembly, owner)) = typed {
            (assembly, owner, "managed_symbol_join".to_owned())
        } else if source_owners.len() == 1 && !located.status.contains("ambiguous") {
            let (assembly, owner) = source_owners
                .into_iter()
                .next()
                .ok_or_else(|| error("lenses.invariant", "source owner disappeared"))?;
            (assembly, owner, "source_name_candidate".into())
        } else {
            let assembly = if located.assemblies.len() == 1 {
                located.assemblies[0].clone()
            } else {
                "_unmapped_or_shared".into()
            };
            (assembly, "_unresolved_owner".into(), located.status.clone())
        };
        let key = (assembly.clone(), owner.clone(), tier.clone());
        if !self.owners.contains_key(&key) {
            reserve(
                &mut self.retained,
                self.memory,
                (assembly.len() + owner.len() + tier.len()) as u64 * 3 + 512,
            )?;
        }
        let group = self.owners.entry(key).or_insert_with(|| Owner {
            namespace: namespace(&owner),
            assembly,
            owner,
            evidence_tier: tier,
            ..Owner::default()
        });
        group.cost.add(entry, canonical)?;
        let growth = example(&mut group.examples, entry, ordinal);
        reserve(&mut self.retained, self.memory, growth)?;
        let xaml = !entry.identity_lossy
            && ["XamlIl", "XamlClosure", "CompiledAvaloniaXaml"]
                .iter()
                .any(|term| entry.identity.contains(term));
        let serializer = !entry.identity_lossy
            && [
                "JsonSerializerContext",
                "JsonContext",
                "JsonTypeInfo",
                "JsonConverter",
            ]
            .iter()
            .any(|term| entry.identity.contains(term));
        if entry.accounted {
            if xaml {
                plus(&mut group.xaml_bytes, entry.bytes)?;
            }
            if serializer {
                plus(&mut group.serializer_bytes, entry.bytes)?;
            }
            if shape.is_some() {
                plus(&mut group.generic_bytes, entry.bytes)?;
            }
        }
        if let Some(shape) = shape {
            if !self.families.contains_key(&shape.family) {
                reserve(
                    &mut self.retained,
                    self.memory,
                    shape.family.len() as u64 * 2 + 128,
                )?;
                self.families
                    .insert(shape.family.clone(), Arc::from(shape.family.as_str()));
            }
            let family = self
                .families
                .get(&shape.family)
                .ok_or_else(|| error("lenses.invariant", "family interner missing"))?
                .clone();
            let mut arguments = BTreeSet::new();
            collect_arguments(
                &shape.arguments,
                &mut arguments,
                0,
                &mut self.malformed_shapes,
            )?;
            for argument in arguments {
                if !self.arguments.contains_key(&argument) {
                    reserve(
                        &mut self.retained,
                        self.memory,
                        argument.len() as u64 * 2 + 320,
                    )?;
                }
                let value = self.arguments.entry(argument).or_default();
                if !value.families.contains(shape.family.as_str()) {
                    reserve(&mut self.retained, self.memory, 80)?;
                    value.families.insert(family.clone());
                }
                value.cost.add(entry, canonical)?;
                let growth = example(&mut value.examples, entry, ordinal);
                reserve(&mut self.retained, self.memory, growth)?;
            }
        }
        Ok(())
    }

    /// # Errors
    /// Rejects overflow and metadata groups exceeding the aggregate budget.
    pub fn metadata(&mut self, name: &str, bytes: u64) -> Result<(), AttributionError> {
        let (assembly, owner) = name.split_once('!').unwrap_or(("_unowned_metadata", name));
        let owner = normalize_type(owner);
        let key = (
            assembly.to_owned(),
            owner.clone(),
            "metadata_name_candidate".into(),
        );
        if !self.owners.contains_key(&key) {
            reserve(
                &mut self.retained,
                self.memory,
                (assembly.len() + owner.len()) as u64 * 3 + 1024,
            )?;
        }
        let value = self.owners.entry(key).or_insert_with(|| Owner {
            assembly: assembly.into(),
            namespace: namespace(&owner),
            owner,
            evidence_tier: "metadata_name_candidate".into(),
            ..Owner::default()
        });
        plus(&mut value.metadata_lower_bound_bytes, bytes)
    }

    /// # Errors
    /// Rejects exhausted source-analysis memory.
    pub fn finish(self) -> Result<LensReport, AttributionError> {
        let mut owners: Vec<_> = self.owners.into_values().collect();
        owners.sort_by(|a, b| {
            b.cost
                .additive_bytes
                .cmp(&a.cost.additive_bytes)
                .then_with(|| {
                    (&a.assembly, &a.owner, &a.evidence_tier).cmp(&(
                        &b.assembly,
                        &b.owner,
                        &b.evidence_tier,
                    ))
                })
        });
        let mut remaining = self.retained;
        let (serializers, repetitions, reflection) =
            source_lenses(self.evidence, &owners, &mut remaining, self.memory)?;
        let mut xaml = Vec::new();
        for owner in owners.iter().filter(|owner| owner.xaml_bytes > 0) {
            let documents: Vec<_> = self.evidence.xaml_documents.iter().filter(|doc|
                doc.assembly == owner.assembly && doc.declared_class.as_deref().is_some_and(|name| normalize_type(name) == owner.owner))
                .map(|doc| json!({"path":doc.path,"declared_class":doc.declared_class,"root_element":doc.root_element,"includes":doc.includes,"keys":doc.keys,"sha256":doc.sha256})).collect();
            reserve(
                &mut remaining,
                self.memory,
                serde_json::to_vec(&documents)
                    .map_err(|e| error("lenses.json", e.to_string()))?
                    .len() as u64
                    + 512,
            )?;
            xaml.push(json!({"assembly":owner.assembly,"owner":owner.owner,"namespace":owner.namespace,
                "additive_bytes":owner.xaml_bytes,"owner_cost":owner.cost,"evidence_tier":owner.evidence_tier,
                "documents":documents,"input_association":if documents.is_empty() {"not_captured_or_unresolved"} else {"declared_class_name_candidate"},
                "examples":owner.examples,"scope":"Literal XAML producer-name subset; owner totals and XAML cohorts overlap. Document class matching is not a compiler input/output proof."}));
        }
        let matcher = crate::Matcher::new(self.evidence);
        let mut arguments = Vec::new();
        for (argument, value) in self.arguments {
            let mut sources = matcher.locate("Types", &argument);
            let source_candidates = sources.sources.len();
            sources.sources.truncate(5);
            let candidate_preview:Vec<_>=sources.sources.iter().map(|source|json!({
                "assembly":source.assembly,"type_name":source.type_name,"path":source.path,"line":source.line
            })).collect();
            reserve(
                &mut remaining,
                self.memory,
                argument.len() as u64
                    + serde_json::to_vec(&candidate_preview)
                        .map_err(|e| error("lenses.json", e.to_string()))?
                        .len() as u64,
            )?;
            arguments.push(json!({
                "argument":argument,"family_count":value.families.len(),"families":value.families.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
                "cost":value.cost,"additive_bytes":value.cost.additive_bytes,"examples":value.examples,
                "source_candidate_count":source_candidates,"source_candidates":candidate_preview,"source_association":sources.status,
                "evidence_tier":"parsed_producer_argument","scope":"One charge per native identity per argument, including nested arguments. Arguments overlap; spelling/source matches are candidates, not resolved C# call sites."
            }));
        }
        arguments.sort_by(|a, b| {
            b["additive_bytes"]
                .as_u64()
                .cmp(&a["additive_bytes"].as_u64())
                .then_with(|| a["argument"].as_str().cmp(&b["argument"].as_str()))
        });
        Ok(LensReport {
            schema: SCHEMA.into(),
            coverage: json!({
                "owners":owners.len(),"xaml_groups":xaml.len(),"serializer_contexts":serializers.len(),
                "repeated_roots":repetitions.len(),"arguments":arguments.len(),"reflection_annotations":reflection.len(),
                "xaml_documents":self.evidence.xaml_documents.len(),"malformed_shapes":self.malformed_shapes,
                "tracked_aggregate_bytes":remaining,
                "scope":"Complete captured identity aggregation; no source execution, usage verdict, unique-body count, exclusive dependency ownership or proposed savings.",
                "cost_basis":"Methods are producer method accounting, not isolated instruction-body bytes. Types/Blobs are additive; metadata and specialized streams overlap.",
                "runtime_support_assignment":"Generic dictionary and hashtable buckets remain unassigned to families; slot demand and shared-body size are unknown."
            }),
            owners,
            xaml,
            serializers,
            repetitions,
            arguments,
            reflection,
        })
    }
}

fn collect_arguments(
    arguments: &[String],
    result: &mut BTreeSet<String>,
    depth: usize,
    malformed: &mut u64,
) -> Result<(), AttributionError> {
    if depth > 64 {
        return Err(error(
            "resource.lenses",
            "nested argument traversal exceeds 64",
        ));
    }
    for argument in arguments {
        result.insert(argument.clone());
        match parse_shape(argument) {
            Ok(Some(shape)) => collect_arguments(&shape.arguments, result, depth + 1, malformed)?,
            Ok(None) => {}
            Err(cause) if cause.diagnostic.code.starts_with("attribution.generic.") => {
                plus(malformed, 1)?;
            }
            Err(cause) => return Err(cause),
        }
    }
    Ok(())
}

fn attribute_name(text: &str) -> &str {
    text.trim_start_matches("global::")
        .split('(')
        .next()
        .unwrap_or(text)
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or(text)
}

fn typeof_root(text: &str) -> Option<String> {
    let token = text.find("typeof")? + 6;
    let tail = text[token..].trim_start();
    if !tail.starts_with('(') {
        return None;
    }
    let start = text.len() - tail.len() + 1;
    let mut depth = 1;
    for (offset, ch) in text[start..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            return Some(text[start..start + offset].trim().to_owned());
        }
    }
    None
}

#[allow(clippy::type_complexity, clippy::too_many_lines)] // Source-only lenses share one deduplicated declaration pass.
fn source_lenses(
    evidence: &Evidence,
    owners: &[Owner],
    retained: &mut u64,
    memory: u64,
) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>), AttributionError> {
    let mut contexts: BTreeMap<
        (String, String),
        (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>),
    > = BTreeMap::new();
    let direct_owners: BTreeMap<(&str, &str), Vec<&Owner>> =
        owners.iter().fold(BTreeMap::new(), |mut groups, owner| {
            groups
                .entry((owner.assembly.as_str(), owner.owner.as_str()))
                .or_default()
                .push(owner);
            groups
        });
    let mut reflection = Vec::new();
    for (ordinal, source) in evidence.sources.iter().enumerate() {
        let mut annotations: Vec<(&str, &str)> =
            source.annotations.as_ref().map_or_else(Vec::new, |items| {
                items
                    .iter()
                    .flat_map(|item| {
                        item.attributes
                            .iter()
                            .map(|text| (item.target.as_str(), text.as_str()))
                    })
                    .collect()
            });
        for text in &source.attributes {
            if !annotations.iter().any(|(_, captured)| *captured == text) {
                annotations.push(("declaration_target_unknown", text));
            }
        }
        for (target, text) in annotations {
            reserve(retained, memory, text.len() as u64 + 256)?;
            let name = attribute_name(text);
            if matches!(
                name,
                "JsonSerializable"
                    | "JsonSerializableAttribute"
                    | "JsonSourceGenerationOptions"
                    | "JsonSourceGenerationOptionsAttribute"
            ) {
                let context = contexts
                    .entry((source.assembly.clone(), normalize_type(&source.type_name)))
                    .or_default();
                context.2.insert(source.path.to_string_lossy().into_owned());
                if name.starts_with("JsonSerializable") {
                    context.0.insert(
                        typeof_root(text).unwrap_or_else(|| format!("_unparsed_attribute:{text}")),
                    );
                } else {
                    context.1.insert(text.into());
                }
            }
            if matches!(
                name,
                "DynamicallyAccessedMembers"
                    | "DynamicallyAccessedMembersAttribute"
                    | "DynamicDependency"
                    | "DynamicDependencyAttribute"
                    | "RequiresUnreferencedCode"
                    | "RequiresUnreferencedCodeAttribute"
            ) {
                let declaring = normalize_type(&source.type_name);
                let mut native = 0;
                let mut metadata = 0;
                if let Some(groups) =
                    direct_owners.get(&(source.assembly.as_str(), declaring.as_str()))
                {
                    for group in groups {
                        plus(&mut native, group.cost.additive_bytes)?;
                        plus(&mut metadata, group.metadata_lower_bound_bytes)?;
                    }
                }
                reflection.push(json!({"assembly":source.assembly,"owner":source.type_name,"member":source.member,
                    "target":target,"attribute":text,"path":source.path,"line":source.line,"source_ordinal":ordinal,
                    "declaring_owner_bytes":native,"metadata_lower_bound_bytes":metadata,"declared_type_target":typeof_root(text),
                    "evidence_tier":"captured_annotation_syntax","scope":"Applied attributes only, not annotation-class definitions. Footprints refer to the declaring owner, not the preserved target set; no source/build equality or sole-causality claim."}));
            }
        }
    }
    let mut roots: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut serializers = Vec::new();
    let owner_index: BTreeMap<_, Vec<_>> =
        owners.iter().fold(BTreeMap::new(), |mut index, owner| {
            let mut name = owner.owner.as_str();
            loop {
                index
                    .entry((owner.assembly.as_str(), name))
                    .or_default()
                    .push(owner);
                if let Some((parent, _)) = name.rsplit_once('+') {
                    name = parent;
                } else {
                    break;
                }
            }
            index
        });
    for ((assembly, context), (declared, options, paths)) in contexts {
        for root in &declared {
            roots
                .entry(root.clone())
                .or_default()
                .push(json!({"assembly":assembly,"context":context,"options":options}));
        }
        let observed = owner_index
            .get(&(assembly.as_str(), context.as_str()))
            .cloned()
            .unwrap_or_default();
        let mut examples: Vec<_> = observed
            .iter()
            .flat_map(|owner| owner.examples.clone())
            .collect();
        examples.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.ordinal.cmp(&b.ordinal))
        });
        examples.dedup_by_key(|example| example.ordinal);
        examples.truncate(3);
        let additive_bytes = observed
            .iter()
            .try_fold(0_u64, |sum, owner| {
                sum.checked_add(owner.cost.additive_bytes)
            })
            .ok_or_else(|| error("lenses.size", "context size overflow"))?;
        serializers.push(json!({"assembly":assembly,"context":context,"declared_roots":declared,"options":options,"source_paths":paths,
            "additive_bytes":additive_bytes,"observed_owner_groups":observed,"examples":examples,"evidence_tier":"source_context_name_candidate",
            "generated_outputs_captured":evidence.generator_runs.iter().map(|run|run.outputs.len()).sum::<usize>(),
            "scope":"Declared syntax roots and options; native owner groups are name associations, not complete generated contract closure. Different context options may require separate implementations."}));
    }
    serializers.sort_by(|a, b| {
        b["additive_bytes"]
            .as_u64()
            .cmp(&a["additive_bytes"].as_u64())
            .then_with(|| a["context"].as_str().cmp(&b["context"].as_str()))
    });
    let repetitions = roots.into_iter().filter(|(_,contexts)|contexts.len()>1).map(|(root,contexts)|json!({
        "root":root,"context_count":contexts.len(),"contexts":contexts,"evidence_tier":"literal_declared_root_repetition",
        "distinct_native_artifacts_proven":false,"scope":"Repeated typeof syntax is not proof of semantic type equality, duplicated machine code or removable bytes; inspect aliases, options and compiled owners."
    })).collect();
    Ok((serializers, repetitions, reflection))
}

/// Classifies only retained preview text, preserving upstream truncation and unknown ownership.
#[must_use]
pub fn metadata_string(value: &Value) -> Value {
    let text = value["preview"]["text"].as_str().unwrap_or("");
    let role = if text.contains("://") {
        "uri_candidate"
    } else if text.contains(".xaml") || text.contains(".axaml") {
        "xaml_path_candidate"
    } else if text.contains('.') || text.contains("::") {
        "qualified_identifier_candidate"
    } else {
        "unclassified"
    };
    let ownership = if value["type_name"].is_string() {
        "metadata_log_selected_owner"
    } else if value["assembly"].is_string() {
        "assembly_context_only"
    } else {
        "not_captured_or_unowned"
    };
    json!({"bytes":value["bytes"],"logical_offset":value["logical_offset"],"preview":value["preview"],
        "assembly":value["assembly"],"namespace":value["namespace"],"owner":value["type_name"],
        "role":role,"evidence_tier":"preview_lexical_candidate","ownership":ownership,
        "scope":"Captured top-N string lower bounds only. Classification uses retained preview text; truncated suffixes and ownership are unknown. Not additive to Metadata/Blobs."})
}
