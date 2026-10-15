use crate::model::Evidence;
use crate::{AttributionError, SourceMatch, error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vitnet_mstat::CoalescedIdentity;

pub const OPPORTUNITY_SCHEMA: &str = "vitnet.opportunities.v1";
pub const POLICY_SCHEMA: &str = "vitnet.opportunity-policy.v1";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpportunityPolicy {
    pub schema: String,
    #[serde(default)]
    pub rules: Vec<PatternRule>,
    #[serde(default)]
    pub capabilities: Vec<CapabilityRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternRule {
    pub id: String,
    pub title: String,
    pub kind: String,
    #[serde(default)]
    pub contains: Vec<String>,
    #[serde(default)]
    pub assemblies: Vec<String>,
    pub investigation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRule {
    pub id: String,
    pub title: String,
    pub assemblies: Vec<String>,
    pub investigation: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Budget {
    pub dimension: String,
    pub name: String,
    pub target: String,
    pub evidence_tier: String,
    pub additive_bytes: u64,
    pub overlapping_bytes: u64,
    pub identities: u64,
    pub streams: BTreeMap<String, u64>,
    pub packages: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpportunityExample {
    pub ordinal: u64,
    pub stream: String,
    pub bytes: u64,
    pub identity: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Opportunity {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub evidence_tier: String,
    pub basis: String,
    pub investigation: String,
    pub additive_bytes: u64,
    pub overlapping_bytes: u64,
    pub identities: u64,
    pub canonical_shared_identities: u64,
    pub streams: BTreeMap<String, u64>,
    pub examples: Vec<OpportunityExample>,
    pub assemblies: Vec<String>,
    pub family: Option<String>,
    pub selector_terms: Vec<String>,
    pub proposed_savings_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpportunityReport {
    pub schema: String,
    pub opportunities: Vec<Opportunity>,
    pub budgets: Vec<Budget>,
    pub accounted_bytes: u64,
    pub streams: BTreeMap<String, u64>,
    pub source_declarations: usize,
    pub generated_declarations: usize,
    pub generator_descriptors: usize,
    pub attribute_occurrences: BTreeMap<String, u64>,
    pub malformed_shape_identities: u64,
    pub limitations: Vec<String>,
}

fn add(value: &mut u64, amount: u64) -> Result<(), AttributionError> {
    *value = value
        .checked_add(amount)
        .ok_or_else(|| error("opportunities.size", "aggregate overflow"))?;
    Ok(())
}

fn defaults() -> Vec<PatternRule> {
    [
        ("compiled-xaml", "Compiled XAML construction", "generated_pattern", &["XamlIl", "XamlClosure", "CompiledAvaloniaXaml"][..], "Inspect view/theme registration and repeated templates; compilation is not evidence that a view is unnecessary."),
        ("serializer-contexts", "Serialization context expansion", "generated_pattern", &["JsonSerializerContext", "JsonContext"][..], "Inspect explicit roots, field inclusion, expanded contracts and context registrations; missing generated-output ownership remains unknown."),
        ("async-machinery", "Async generic runtime machinery", "generic_pattern", &["AsyncStateMachineBox", "AsyncTaskMethodBuilder"][..], "Inspect concrete state-machine and result types and their callers before proposing an async-pattern change."),
        ("generated-code", "Compiler-generated support", "generated_pattern", &["Internal_CompilerGenerated"][..], "Inspect concrete compiler nodes; compiler-generated does not mean source-generator-produced or removable."),
        ("tooling-demo", "Tooling, demos or test features", "unexpected_feature", &["DevTools", "UIDemos", "DemoView", "_Tests_", "_Benchmarks_", "_Samples_"][..], "Confirm shipping policy, then trace the reference or registration retaining these features. Names alone do not prove unused code."),
    ].into_iter().map(|(id, title, kind, contains, investigation)| PatternRule {
        id: id.into(), title: title.into(), kind: kind.into(),
        contains: contains.iter().map(|s| (*s).into()).collect(), assemblies: Vec::new(),
        investigation: investigation.into(),
    }).collect()
}

/// Validates a local, declarative policy without evaluating code or regular expressions.
///
/// # Errors
///
/// Rejects unsupported versions, empty selectors, duplicate IDs and excessive policy size.
pub fn validate_policy(policy: &OpportunityPolicy) -> Result<(), AttributionError> {
    if policy.schema != POLICY_SCHEMA {
        return Err(error(
            "opportunities.policy",
            "unsupported opportunity policy",
        ));
    }
    if policy.rules.len() + policy.capabilities.len() > 64 {
        return Err(error(
            "resource.opportunities.policy",
            "at most 64 custom rules are supported",
        ));
    }
    let mut ids: BTreeSet<String> = defaults().into_iter().map(|r| r.id).collect();
    for (id, title, selectors, action) in policy
        .rules
        .iter()
        .map(|r| (&r.id, &r.title, &r.contains, &r.investigation))
        .chain(
            policy
                .capabilities
                .iter()
                .map(|r| (&r.id, &r.title, &r.assemblies, &r.investigation)),
        )
    {
        if id.is_empty()
            || id.len() > 128
            || title.is_empty()
            || title.len() > 1024
            || action.is_empty()
            || action.len() > 4096
            || !ids.insert(id.clone())
            || selectors.len() > 64
            || selectors.iter().any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(error(
                "opportunities.policy",
                "invalid or duplicate rule identity/text",
            ));
        }
    }
    for rule in &policy.rules {
        if (rule.contains.is_empty() && rule.assemblies.is_empty())
            || rule.assemblies.len() > 64
            || rule
                .assemblies
                .iter()
                .any(|s| s.is_empty() || s.len() > 1024)
            || !matches!(
                rule.kind.as_str(),
                "generated_pattern" | "generic_pattern" | "unexpected_feature"
            )
        {
            return Err(error(
                "opportunities.policy",
                "invalid pattern kind or selector",
            ));
        }
    }
    if policy.capabilities.iter().any(|r| {
        r.assemblies.len() < 2
            || r.assemblies.iter().collect::<BTreeSet<_>>().len() != r.assemblies.len()
    }) {
        return Err(error(
            "opportunities.policy",
            "capability overlaps need at least two assemblies",
        ));
    }
    Ok(())
}

type BudgetKey = (String, String, String, String);

/// Bounded aggregates over complete identities; findings may overlap.
pub struct OpportunityCollector<'a> {
    evidence: &'a Evidence,
    rules: Vec<PatternRule>,
    capabilities: Vec<CapabilityRule>,
    budgets: BTreeMap<BudgetKey, Budget>,
    findings: BTreeMap<String, Opportunity>,
    origins: BTreeMap<(String, String), BTreeSet<String>>,
    targets: BTreeSet<String>,
    memory: u64,
    stored: u64,
    accounted: u64,
    streams: BTreeMap<String, u64>,
    malformed_shapes: u64,
}

impl<'a> OpportunityCollector<'a> {
    /// Creates an analysis using generic defaults plus optional local policy.
    ///
    /// # Errors
    ///
    /// Rejects invalid policies or budgets too small to retain aggregate state.
    pub fn new(
        evidence: &'a Evidence,
        policy: Option<&OpportunityPolicy>,
        memory: u64,
    ) -> Result<Self, AttributionError> {
        if memory < 1024 * 1024 {
            return Err(error(
                "resource.opportunities",
                "opportunity aggregation needs at least 1 MiB",
            ));
        }
        let mut rules = defaults();
        let mut capabilities = Vec::new();
        if let Some(policy) = policy {
            validate_policy(policy)?;
            rules.extend(policy.rules.clone());
            capabilities.clone_from(&policy.capabilities);
        }
        let mut origins: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        let mut targets: BTreeSet<String> =
            evidence.packages.iter().map(|p| p.target.clone()).collect();
        for mapping in &evidence.mappings {
            if mapping.stream == "package" {
                let target = mapping
                    .basis
                    .strip_prefix("assets_resolved_")
                    .and_then(|s| s.split_once(':').map(|(_, t)| t))
                    .unwrap_or("")
                    .to_owned();
                targets.insert(target.clone());
                origins
                    .entry((mapping.assembly.clone(), target))
                    .or_default()
                    .insert(mapping.identity.clone());
            }
        }
        for assembly in &evidence.assemblies {
            if let Some(package) = &assembly.package {
                origins
                    .entry((assembly.name.clone(), String::new()))
                    .or_default()
                    .insert(package.clone());
            }
        }
        if targets.is_empty() {
            targets.insert(String::new());
        }
        let mut stored = 0;
        for ((a, t), packages) in &origins {
            add(
                &mut stored,
                (a.len() + t.len() + packages.iter().map(String::len).sum::<usize>() + 512) as u64,
            )?;
        }
        add(
            &mut stored,
            serde_json::to_vec(&(&rules, &capabilities))
                .map_err(|cause| error("opportunities.json", cause.to_string()))?
                .len() as u64
                * 2,
        )?;
        let result = Self {
            evidence,
            rules,
            capabilities,
            budgets: BTreeMap::new(),
            findings: BTreeMap::new(),
            origins,
            targets,
            memory,
            stored,
            accounted: 0,
            streams: BTreeMap::new(),
            malformed_shapes: 0,
        };
        result.check()?;
        Ok(result)
    }

    fn check(&self) -> Result<(), AttributionError> {
        if self.stored > self.memory {
            Err(error(
                "resource.opportunities",
                "opportunity aggregates exceed reserved memory; increase --memory-limit",
            ))
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn budget(
        &mut self,
        dimension: &str,
        name: &str,
        target: &str,
        tier: &str,
        packages: Vec<String>,
        entry: &CoalescedIdentity,
    ) -> Result<(), AttributionError> {
        let key = (dimension.into(), name.into(), target.into(), tier.into());
        if !self.budgets.contains_key(&key) {
            add(
                &mut self.stored,
                (dimension.len()
                    + name.len()
                    + target.len()
                    + tier.len()
                    + packages.iter().map(String::len).sum::<usize>()) as u64
                    * 2
                    + 1024,
            )?;
        }
        if !self
            .budgets
            .get(&key)
            .is_some_and(|b| b.streams.contains_key(&entry.stream))
        {
            add(&mut self.stored, entry.stream.len() as u64 * 2 + 128)?;
        }
        self.check()?;
        let budget = self.budgets.entry(key).or_insert_with(|| Budget {
            dimension: dimension.into(),
            name: name.into(),
            target: target.into(),
            evidence_tier: tier.into(),
            packages,
            ..Budget::default()
        });
        add(
            &mut budget.identities,
            u64::from(entry.stream != "metadata_lower_bound"),
        )?;
        add(
            if entry.accounted {
                &mut budget.additive_bytes
            } else {
                &mut budget.overlapping_bytes
            },
            entry.bytes,
        )?;
        add(
            budget.streams.entry(entry.stream.clone()).or_default(),
            entry.bytes,
        )
    }

    /// Observes one complete identity and its separately tiered source association.
    ///
    /// # Errors
    ///
    /// Rejects arithmetic overflow and memory exhaustion. Malformed shapes are counted explicitly.
    #[allow(clippy::too_many_lines)]
    pub fn observe(
        &mut self,
        entry: &CoalescedIdentity,
        sources: &SourceMatch,
        ordinal: u64,
    ) -> Result<(), AttributionError> {
        if entry.accounted {
            add(&mut self.accounted, entry.bytes)?;
            add(
                self.streams.entry(entry.stream.clone()).or_default(),
                entry.bytes,
            )?;
        }
        let assembly = if sources.assemblies.len() == 1 {
            sources.assemblies[0].as_str()
        } else if sources.assemblies.is_empty() {
            "_unmapped"
        } else {
            "_ambiguous"
        };
        self.budget("assembly", assembly, "", &sources.status, Vec::new(), entry)?;
        for target in self.targets.clone() {
            let packages = self
                .origins
                .get(&(assembly.to_owned(), target.clone()))
                .cloned()
                .unwrap_or_default();
            let name = match packages.first() {
                Some(package) if packages.len() == 1 => package.as_str(),
                None => "_unmapped_package_origin",
                _ => "_shared_package_origin",
            };
            self.budget(
                "package",
                name,
                &target,
                &sources.status,
                packages.iter().cloned().collect(),
                entry,
            )?;
        }
        if entry.stream == "metadata_lower_bound" {
            return Ok(());
        }
        if entry.identity_lossy {
            return Ok(());
        }
        let matching: Vec<_> = self
            .rules
            .iter()
            .filter(|r| {
                (r.contains.is_empty()
                    || r.contains.iter().any(|term| entry.identity.contains(term)))
                    && (r.assemblies.is_empty()
                        || sources.assemblies.iter().any(|a| r.assemblies.contains(a)))
            })
            .cloned()
            .collect();
        for rule in matching {
            let initial = Opportunity {
                id: rule.id.clone(), kind: rule.kind, title: rule.title,
                evidence_tier: "producer_name_candidate".into(),
                basis: "Literal complete producer-name cohort and separately tiered assembly candidates; not verified generator ownership.".into(),
                investigation: rule.investigation, selector_terms: rule.contains,
                assemblies: rule.assemblies, ..Opportunity::default()
            };
            self.finding(&rule.id, initial, entry, ordinal)?;
        }
        let generators: BTreeSet<_> = sources
            .sources
            .iter()
            .filter_map(|s| s.generated_by.as_ref())
            .collect();
        if let Some(generator) = generators.first().filter(|_| generators.len() == 1) {
            let id = format!("generator:{generator}");
            let initial = Opportunity {
                id: id.clone(), kind: "generator_output".into(), title: format!("Captured generated declarations: {generator}"),
                evidence_tier: format!("{}+captured_generator_declaration", sources.status),
                basis: "Captured declaration emitter combined with this row's separately tiered source association. This does not prove generator execution or exclusive byte ownership.".into(),
                investigation: "Inspect captured output hashes, build/checksum trust, trigger links and registration paths before changing generator inputs.".into(),
                ..Opportunity::default()
            };
            self.finding(&id, initial, entry, ordinal)?;
        }
        if matches!(entry.stream.as_str(), "Methods" | "Types") {
            let parsed = crate::parse_shape(&entry.identity);
            if parsed.is_err() {
                add(&mut self.malformed_shapes, 1)?;
            }
            if let Ok(Some(shape)) = parsed {
                let id = format!("family:{}:{}", entry.stream, shape.family);
                let initial = Opportunity {
                    id: id.clone(), kind: "generic_family".into(), title: shape.family.clone(),
                    evidence_tier: "parsed_producer_family".into(),
                    basis: "Parsed complete producer shape. Identity multiplicity is not source-language instantiation count or unshared method-body count.".into(),
                    investigation: "Inspect concrete arguments, canonical sharing and repeated small bodies. Move genuinely type-independent logic only after checking semantics and retention.".into(),
                    family: Some(shape.family), ..Opportunity::default()
                };
                self.finding(&id, initial, entry, ordinal)?;
                if shape.canonical_shared {
                    let finding = self.findings.get_mut(&id).ok_or_else(|| {
                        error(
                            "opportunities.invariant",
                            "observed family aggregate is absent",
                        )
                    })?;
                    add(&mut finding.canonical_shared_identities, 1)?;
                }
            }
        }
        Ok(())
    }

    /// Adds a captured metadata assembly lower bound as a non-additive projection.
    ///
    /// # Errors
    ///
    /// Rejects overflow or exhausted aggregate memory.
    pub fn observe_metadata_budget(
        &mut self,
        assembly: &str,
        bytes: u64,
    ) -> Result<(), AttributionError> {
        let entry = CoalescedIdentity {
            stream: "metadata_lower_bound".into(),
            accounted: false,
            bytes,
            records: 0,
            identity: String::new(),
            identity_lossy: false,
            raw_identity_blake3: String::new(),
        };
        let source = SourceMatch {
            status: if assembly == "_unowned_or_omitted_metadata" { "metadata_unowned_or_omitted" } else { "metadata_record_ownership_lower_bound" }.into(),
            basis: "Captured metadata projection, not a native identity or exclusive physical ownership".into(),
            assemblies: vec![assembly.into()], sources: Vec::new(),
        };
        self.observe(&entry, &source, 0)
    }

    fn finding(
        &mut self,
        id: &str,
        initial: Opportunity,
        entry: &CoalescedIdentity,
        ordinal: u64,
    ) -> Result<(), AttributionError> {
        if !self.findings.contains_key(id) {
            add(
                &mut self.stored,
                serde_json::to_vec(&initial)
                    .map_err(|e| error("opportunities.json", e.to_string()))?
                    .len() as u64
                    * 2
                    + 2048,
            )?;
        }
        if !self
            .findings
            .get(id)
            .is_some_and(|f| f.streams.contains_key(&entry.stream))
        {
            add(&mut self.stored, entry.stream.len() as u64 * 2 + 128)?;
        }
        self.check()?;
        let finding = self.findings.entry(id.into()).or_insert(initial);
        add(&mut finding.identities, 1)?;
        add(
            if entry.accounted {
                &mut finding.additive_bytes
            } else {
                &mut finding.overlapping_bytes
            },
            entry.bytes,
        )?;
        add(
            finding.streams.entry(entry.stream.clone()).or_default(),
            entry.bytes,
        )?;
        if finding.examples.len() < 3
            || finding.examples.last().is_some_and(|e| {
                e.bytes < entry.bytes || (e.bytes == entry.bytes && ordinal < e.ordinal)
            })
        {
            let mut end = entry.identity.len().min(512);
            while !entry.identity.is_char_boundary(end) {
                end -= 1;
            }
            finding.examples.push(OpportunityExample {
                ordinal,
                stream: entry.stream.clone(),
                bytes: entry.bytes,
                identity: entry.identity[..end].into(),
                truncated: end < entry.identity.len(),
            });
            finding
                .examples
                .sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.ordinal.cmp(&b.ordinal)));
            finding.examples.truncate(3);
        }
        Ok(())
    }

    /// Finishes deterministic ranking and reconciled budgets.
    ///
    /// # Errors
    ///
    /// Rejects aggregate overflow or memory exhaustion.
    pub fn finish(mut self) -> Result<OpportunityReport, AttributionError> {
        for rule in &self.capabilities {
            let present: BTreeSet<_> = self
                .budgets
                .values()
                .filter(|b| {
                    b.dimension == "assembly"
                        && b.additive_bytes > 0
                        && rule.assemblies.contains(&b.name)
                })
                .map(|b| b.name.clone())
                .collect();
            if present.len() < 2 {
                continue;
            }
            let mut finding = Opportunity { id: rule.id.clone(), kind: "capability_overlap".into(), title: rule.title.clone(),
                evidence_tier: "policy_candidate".into(),
                basis: "Multiple policy-declared implementations have separately attributed additive identities; coexistence does not establish redundant behavior.".into(),
                investigation: rule.investigation.clone(), assemblies: present.iter().cloned().collect(), ..Opportunity::default() };
            for budget in self
                .budgets
                .values()
                .filter(|b| b.dimension == "assembly" && present.contains(&b.name))
            {
                add(&mut finding.additive_bytes, budget.additive_bytes)?;
                add(&mut finding.overlapping_bytes, budget.overlapping_bytes)?;
                add(&mut finding.identities, budget.identities)?;
                for (stream, bytes) in &budget.streams {
                    add(finding.streams.entry(stream.clone()).or_default(), *bytes)?;
                }
            }
            add(
                &mut self.stored,
                serde_json::to_vec(&finding)
                    .map_err(|cause| error("opportunities.json", cause.to_string()))?
                    .len() as u64
                    * 2
                    + 2048,
            )?;
            self.check()?;
            self.findings.insert(rule.id.clone(), finding);
        }
        let mut attribute_occurrences = BTreeMap::new();
        for source in &self.evidence.sources {
            for attribute in &source.attributes {
                let name = attribute.split('(').next().unwrap_or(attribute).trim();
                if !attribute_occurrences.contains_key(name) {
                    add(&mut self.stored, name.len() as u64 * 2 + 128)?;
                    self.check()?;
                }
                add(attribute_occurrences.entry(name.into()).or_default(), 1)?;
            }
        }
        let mut opportunities: Vec<_> = self.findings.into_values().collect();
        opportunities.retain(|f| f.identities > 1 || f.kind != "generic_family");
        opportunities.sort_by(|a, b| {
            b.additive_bytes
                .cmp(&a.additive_bytes)
                .then(a.id.cmp(&b.id))
        });
        let mut budgets: Vec<_> = self.budgets.into_values().collect();
        budgets.sort_by(|a, b| {
            b.additive_bytes.cmp(&a.additive_bytes).then(
                (&a.dimension, &a.target, &a.name, &a.evidence_tier).cmp(&(
                    &b.dimension,
                    &b.target,
                    &b.name,
                    &b.evidence_tier,
                )),
            )
        });
        Ok(OpportunityReport {
            schema: OPPORTUNITY_SCHEMA.into(), opportunities, budgets,
            accounted_bytes: self.accounted, streams: self.streams,
            source_declarations: self.evidence.sources.len(),
            generated_declarations: self.evidence.sources.iter().filter(|s| s.generated_by.is_some()).count(),
            generator_descriptors: self.evidence.generators.len(), attribute_occurrences,
            malformed_shape_identities: self.malformed_shapes,
            limitations: vec![
                "Findings overlap. Never sum cohort bytes or interpret them as removable or physical bytes.".into(),
                "Assembly budgets partition each stream by association tier. Ambiguous/unmapped identities are not charged to every candidate.".into(),
                "Package budgets reconcile separately within each target. Do not sum targets; package inventory routes are not compiler-retention paths.".into(),
                "Specialized resources/frozen objects and metadata lower bounds overlap additive Blobs; they are not extra budgets.".into(),
                "Attributes are source occurrences, not proof a generator executed, an output is compiled, or a registration is the sole retainer.".into(),
                "No controlled experiment or predicted savings is produced by this report.".into(),
            ],
        })
    }
}
