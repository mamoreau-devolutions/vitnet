use super::{Backend, data, diagnostic};
use crate::AppError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use vitnet_dgml::{IncomingOptions, IndexControl, SearchMode, SearchOptions};

fn add(ledger: &mut BTreeMap<&str, u64>, key: &'static str, value: u64) -> Result<(), AppError> {
    let field = ledger.entry(key).or_default();
    *field = field
        .checked_add(value)
        .ok_or_else(|| diagnostic("explorer.size", "feature ledger overflow"))?;
    Ok(())
}

impl Backend<'_> {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One bounded scan exposes an atomic disjoint-range ledger.
    pub(super) fn feature_footprint(
        &mut self,
        assembly: Option<&str>,
        namespace: Option<&str>,
        owner: Option<&str>,
        project: Option<&str>,
        after: Option<u64>,
        control: &IndexControl,
    ) -> Result<Value, AppError> {
        if [assembly, namespace, owner, project]
            .into_iter()
            .flatten()
            .any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "feature selectors must contain 1..1024 bytes",
            ));
        }
        let project_assembly = project
            .map(|path| {
                self.index
                    .evidence
                    .provenance
                    .get(&format!("source.project_assembly_hint:{path}"))
                    .cloned()
                    .ok_or_else(|| {
                        diagnostic("explorer.project", "project has no captured assembly hint")
                    })
            })
            .transpose()?;
        if assembly
            .zip(project_assembly.as_deref())
            .is_some_and(|(a, b)| a != b)
        {
            return Err(diagnostic(
                "explorer.query",
                "assembly conflicts with the recorded project hint",
            ));
        }
        let assembly = assembly.or(project_assembly.as_deref());
        let total = self
            .bundle
            .manifest
            .datasets
            .get("lens_feature_owners")
            .ok_or_else(|| {
                diagnostic(
                    "explorer.lenses.unavailable",
                    "reprepare this legacy bundle to capture investigation lenses",
                )
            })?
            .records;
        if after.is_some_and(|cursor| cursor >= total) {
            return Err(diagnostic(
                "explorer.cursor",
                "feature cursor is outside captured owners",
            ));
        }
        let start = after.map_or(0, |n| n + 1);
        let deadline = Instant::now();
        let mut cursor = start;
        let mut ledger = BTreeMap::new();
        let mut examples: Vec<Value> = Vec::new();
        let mut rows: Vec<Value> = Vec::new();
        let mut matched = 0_u64;
        let mut stop = "complete";
        let memory = self.memory;
        let reader = self.dataset("lens_feature_owners")?;
        while cursor < total {
            if control.is_cancelled() {
                stop = "cancelled";
                break;
            }
            if cursor - start >= crate::explorer::MAX_SCANNED {
                stop = "max_scanned";
                break;
            }
            if deadline.elapsed() >= Duration::from_millis(crate::explorer::QUERY_TIMEOUT_MS) {
                stop = "timeout";
                break;
            }
            let row = reader.record(cursor, memory)?;
            cursor += 1;
            let ns = row["namespace"].as_str().unwrap_or("");
            if assembly.is_some_and(|v| row["assembly"] != v)
                || owner.is_some_and(|v| row["owner"] != v)
                || namespace.is_some_and(|v| {
                    ns != v && !ns.strip_prefix(v).is_some_and(|tail| tail.starts_with('.'))
                })
            {
                continue;
            }
            reader.check()?;
            matched += 1;
            for key in [
                "additive_bytes",
                "overlapping_bytes",
                "methods_bytes",
                "types_bytes",
                "blobs_bytes",
                "metadata_lower_bound_bytes",
                "identities",
                "canonical_shared_identities",
            ] {
                let bytes = row[key].as_u64().ok_or_else(|| {
                    diagnostic(
                        "explorer.lenses.schema",
                        format!("owner ledger lacks {key}"),
                    )
                })?;
                add(&mut ledger, key, bytes)?;
            }
            let other = if let Some(value) = row.get("other_additive_bytes") {
                value.as_u64().ok_or_else(|| {
                    diagnostic(
                        "explorer.lenses.schema",
                        "other stream accounting is not unsigned",
                    )
                })?
            } else {
                let known = ["methods_bytes", "types_bytes", "blobs_bytes"]
                    .into_iter()
                    .try_fold(0_u64, |sum, key| {
                        sum.checked_add(row[key].as_u64().unwrap_or(0))
                    })
                    .ok_or_else(|| diagnostic("explorer.size", "stream subtotal overflow"))?;
                row["additive_bytes"]
                    .as_u64()
                    .ok_or_else(|| diagnostic("explorer.lenses.schema", "native size missing"))?
                    .checked_sub(known)
                    .ok_or_else(|| {
                        diagnostic(
                            "explorer.lenses.schema",
                            "stream subtotals exceed native cost",
                        )
                    })?
            };
            add(&mut ledger, "other_additive_bytes", other)?;
            let role = if row["owner"] == "_unresolved_owner" {
                "unresolved_bytes"
            } else if row["evidence_tier"] == "managed_symbol_join" {
                "typed_owner_bytes"
            } else {
                "candidate_owner_bytes"
            };
            add(
                &mut ledger,
                role,
                row["additive_bytes"]
                    .as_u64()
                    .ok_or_else(|| diagnostic("explorer.lenses.schema", "owner size missing"))?,
            )?;
            if rows.len() < 20 {
                rows.push(row.clone());
            }
            if let Some(items) = row["examples"].as_array() {
                examples.extend(items.iter().cloned());
                examples.sort_by(|a, b| {
                    b["bytes"]
                        .as_u64()
                        .cmp(&a["bytes"].as_u64())
                        .then_with(|| a["ordinal"].as_u64().cmp(&b["ordinal"].as_u64()))
                });
                examples.dedup_by(|a, b| a["ordinal"] == b["ordinal"]);
                examples.truncate(3);
            }
        }
        Ok(
            json!({"schema":"vitnet.feature-footprint.v1","generation":self.bundle.manifest.generation,
            "selectors":{"assembly":assembly,"namespace":namespace,"owner":owner,"project":project},
            "project_basis":project.map(|_|"recorded textual assembly hint, not evaluated project ownership"),
            "ledger":ledger,"matched_owner_groups":matched,"entries":rows,"examples":examples,
            "scanned":cursor-start,"total":total,"next_after":if cursor<total && cursor>start {Some((cursor-1).to_string())} else {None},
            "stop_reason":stop,"complete":cursor==total,
            "scope":"Ledger covers this scanned batch only. Sum disjoint continuation batches for a complete feature ledger. Source/name candidates are not exclusive physical ownership; metadata and specialized streams overlap."}),
        )
    }

    pub(super) fn cohort_retention(
        &mut self,
        kind: &str,
        ordinals: &[u64],
        control: &IndexControl,
    ) -> Result<Value, AppError> {
        if ordinals.is_empty()
            || ordinals.len() > 3
            || ordinals.iter().collect::<BTreeSet<_>>().len() != ordinals.len()
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "select one to three distinct original identity ordinals",
            ));
        }
        let mut seeds = Vec::new();
        let mut roots: BTreeMap<(u64, String), Value> = BTreeMap::new();
        for ordinal in ordinals {
            if control.is_cancelled() {
                return Err(diagnostic(
                    "resource.cancelled",
                    "cohort retention cancelled",
                ));
            }
            let entry = self.row(*ordinal)?;
            if entry.identity_lossy || entry.identity.len() > 1024 {
                seeds.push(json!({"ordinal":ordinal.to_string(),"status":"identity_not_searchable_within_exact_label_budget",
                    "witnesses":[],"scope":"Use manual graph search; no truncated or lossy identity was treated as an exact match."}));
                continue;
            }
            let graph = self.graph(kind, control)?;
            let search = graph
                .search(
                    &entry.identity,
                    &SearchOptions {
                        mode: SearchMode::Exact,
                        limit: 3,
                        max_scanned: crate::explorer::MAX_SCANNED,
                        timeout_ms: crate::explorer::QUERY_TIMEOUT_MS,
                        preview_bytes: 512,
                        generation: Some(graph.generation.clone()),
                        ..SearchOptions::default()
                    },
                )
                .map_err(AppError::Dgml)?;
            let mut witnesses = Vec::new();
            for node in &search.entries {
                let options = data::why_options(&graph.generation);
                let witness = graph.why(node.node_id, &options).map_err(AppError::Dgml)?;
                for path in &witness.paths {
                    if let Some(root) = path.nodes.first() {
                        let value=roots.entry((root.node_id,path.root_kind.clone())).or_insert_with(||json!({
                            "node_id":root.node_id.to_string(),"root_kind":path.root_kind,"label":root.label,
                            "observed_paths":0,"scope":"Observed bounded witness root, not the sole retainer or a complete removal prerequisite."}));
                        let count = value["observed_paths"].as_u64().ok_or_else(|| {
                            diagnostic("explorer.invariant", "root path count missing")
                        })?;
                        value["observed_paths"] = json!(count + 1);
                    }
                }
                let incoming = graph
                    .incoming(
                        node.node_id,
                        &IncomingOptions {
                            limit: 20,
                            preview_bytes: 256,
                            generation: Some(graph.generation.clone()),
                            timeout_ms: crate::explorer::QUERY_TIMEOUT_MS,
                            after_edge: None,
                        },
                    )
                    .map_err(AppError::Dgml)?;
                witnesses.push((witness, incoming));
            }
            let reports: Vec<_> = witnesses
                .into_iter()
                .map(|(why, incoming)| {
                    vitnet_attribution::annotate_retention(&self.index.evidence, why, incoming)
                })
                .collect();
            seeds.push(json!({"ordinal":ordinal.to_string(),"identity":entry.identity,"search":search,
                "status":if reports.is_empty() {"no_witness_in_observed_search"} else {"observed_label_match"},
                "witnesses":reports}));
        }
        Ok(
            json!({"schema":"vitnet.cohort-retention.v1","generation":self.bundle.manifest.generation,
            "graph":kind,"seeds":seeds,"observed_roots":roots.into_values().collect::<Vec<_>>(),
            "complete":false,"scope":"One to three representative identity seeds; exact graph label matches are candidates, not identity-to-node proof. Bounded searches, shortest paths and incoming previews are not all paths or prerequisites. No savings or runtime-use claim."}),
        )
    }
}
