use super::{
    AppError, BTreeMap, Backend, Duration, IndexControl, Instant, Query, QueryRequest, Value, data,
    diagnostic, elapsed, json, ranking,
};

impl Backend<'_> {
    fn scope_total(
        &mut self,
        stream: Option<&str>,
        assembly: Option<&str>,
        owner: Option<&str>,
        family: Option<&str>,
    ) -> Result<Value, AppError> {
        let dimensions: Vec<_> = [("assembly", assembly), ("owner", owner), ("family", family)]
            .into_iter()
            .filter_map(|(kind, value)| value.map(|name| (kind, name)))
            .collect();
        if dimensions.len() > 1 {
            return Ok(
                json!({"bytes":null,"identities":null,"basis":"Combined filter denominator is not a precomputed additive partition."}),
            );
        }
        let streams: Vec<_> = self.bundle.snapshot["accounting"]["streams"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| Some((s["name"].as_str()?.to_owned(), s.clone())))
            .filter(|(name, _)| stream.is_none_or(|s| s == name))
            .collect();
        if streams.is_empty() {
            return Ok(
                json!({"bytes":null,"identities":null,"basis":"No additive stream denominator is captured for this scope."}),
            );
        }
        let mut bytes = 0_u64;
        let mut identities = 0_u64;
        let memory = self.memory;
        for (name, summary) in streams {
            let summary = if let Some((dimension, selected)) = dimensions.first() {
                self.dataset("scopes")?
                    .scope(dimension, &name, selected, memory)?
            } else {
                Some(summary)
            };
            if let Some(summary) = summary {
                bytes = bytes
                    .checked_add(summary["bytes"].as_u64().ok_or_else(|| {
                        diagnostic("explorer.scopes", "scope has no unsigned byte count")
                    })?)
                    .ok_or_else(|| diagnostic("explorer.size", "scope byte overflow"))?;
                identities = identities
                    .checked_add(summary["identities"].as_u64().ok_or_else(|| {
                        diagnostic("explorer.scopes", "scope has no identity count")
                    })?)
                    .ok_or_else(|| diagnostic("explorer.size", "scope count overflow"))?;
            }
        }
        Ok(json!({"bytes":bytes,"identities":identities,
            "basis":"Complete captured partition before the text filter; assembly associations are evidence-tiered candidates or assertions, not exclusive physical ownership."}))
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn ranked_rows(
        &mut self,
        request: &QueryRequest,
        control: &IndexControl,
    ) -> Result<Value, AppError> {
        let Query::RankedRows {
            contains,
            stream,
            assembly,
            owner,
            family,
            family_record,
            accounted_only,
            min_bytes,
            max_bytes,
            exact,
            after,
            limit,
        } = &request.query
        else {
            return Err(diagnostic("explorer.invariant", "not a ranked request"));
        };
        if *limit == 0
            || *limit > super::PAGE_LIMIT
            || contains.len() > 1024
            || stream.as_ref().is_some_and(|s| s.len() > 64)
            || [assembly, owner, family]
                .into_iter()
                .any(|s| s.as_ref().is_some_and(|s| s.len() > 4096))
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "ranked page exceeds browser query budgets",
            ));
        }
        if control.is_cancelled() {
            return Err(diagnostic("resource.cancelled", "ranked query cancelled"));
        }
        if min_bytes
            .zip(*max_bytes)
            .is_some_and(|(min, max)| min > max)
        {
            return Err(diagnostic(
                "explorer.query",
                "minimum ranked bytes exceeds maximum",
            ));
        }
        if family.is_some() && family_record.is_some() {
            return Err(diagnostic(
                "explorer.query",
                "select a family by spelling or captured ordinal, not both",
            ));
        }
        let memory = self.memory;
        let captured_family = if let Some(ordinal) = family_record {
            let record = self.dataset("generic_families")?.record(*ordinal, memory)?;
            Some(
                record["family"]
                    .as_str()
                    .ok_or_else(|| diagnostic("explorer.family", "family record has no spelling"))?
                    .to_owned(),
            )
        } else {
            family.clone()
        };
        let descriptor = self.bundle.manifest.ranking.as_ref().ok_or_else(|| {
            diagnostic(
                "explorer.ranking.unavailable",
                "prepare a new bundle to enable complete byte ranking",
            )
        })?;
        if self.ranking.is_none() {
            self.ranking = Some(ranking::Reader::open(
                &self.bundle.directory,
                descriptor,
                self.bundle.manifest.identities,
            )?);
        }
        let count = descriptor.records;
        if after.is_some_and(|n| n >= count) {
            return Err(diagnostic(
                "explorer.cursor",
                "ranking cursor outside dataset",
            ));
        }
        self.ranking
            .as_ref()
            .ok_or_else(|| diagnostic("explorer.invariant", "ranking reader missing"))?
            .check()?;
        let scope = self.scope_total(
            stream.as_deref(),
            assembly.as_deref(),
            owner.as_deref(),
            captured_family.as_deref(),
        )?;
        let started = Instant::now();
        let mut entries = Vec::new();
        let mut scanned = 0;
        let mut next = *after;
        let mut stop = "complete";
        for position in after.map_or(0, |n| n + 1)..count {
            if control.is_cancelled() {
                stop = "cancelled";
                break;
            }
            if scanned >= super::super::MAX_SCANNED {
                stop = "max_scanned";
                break;
            }
            if started.elapsed() >= Duration::from_millis(super::super::QUERY_TIMEOUT_MS) {
                stop = "timeout";
                break;
            }
            let (bytes, ordinal) = self
                .ranking
                .as_mut()
                .ok_or_else(|| diagnostic("explorer.invariant", "ranking reader missing"))?
                .entry(position)?;
            let entry = self.row(ordinal)?;
            if bytes != entry.bytes {
                return Err(diagnostic(
                    "explorer.ranking.integrity",
                    "ranked bytes differ from identity",
                ));
            }
            scanned += 1;
            next = Some(position);
            if min_bytes.is_some_and(|min| bytes < min) {
                break;
            }
            if stream.as_ref().is_some_and(|s| *s != entry.stream)
                || (*exact && entry.identity != *contains)
                || (!*exact && !entry.identity.contains(contains))
                || (*accounted_only && !entry.accounted)
                || max_bytes.is_some_and(|max| bytes > max)
                || owner.as_ref().is_some_and(|owner| {
                    let prefix = entry
                        .identity
                        .split_once("__")
                        .map_or(entry.identity.as_str(), |(name, _)| name);
                    prefix.split_once('<').map_or(prefix, |(name, _)| name) != owner
                })
            {
                continue;
            }
            if let Some(assembly) = assembly {
                let located = self.located(&entry)?;
                let selected = if located.assemblies.len() == 1 {
                    &located.assemblies[0]
                } else if located.assemblies.is_empty() {
                    "_unmapped"
                } else {
                    "_ambiguous"
                };
                if selected != assembly {
                    continue;
                }
            }
            if let Some(family) = &captured_family {
                if entry.identity_lossy {
                    continue;
                }
                match vitnet_attribution::parse_shape(&entry.identity) {
                    Ok(Some(shape)) if shape.family == *family => {}
                    Err(error) if error.diagnostic.code.starts_with("resource.") => {
                        return Err(super::super::attribution(error));
                    }
                    _ => continue,
                }
            }
            entries.push(data::Row::new(&entry, ordinal));
            if entries.len() == *limit {
                if position + 1 < count {
                    stop = "limit";
                }
                break;
            }
        }
        if stop == "complete" {
            next = None;
        }
        Ok(
            json!({"entries":entries,"next_after":next.map(|n| n.to_string()),"scanned":scanned,
            "stop_reason":stop,"elapsed_ms":elapsed(started),"total":count,"scope":scope,
            "order":"bytes_desc_ordinal_asc"}),
        )
    }

    pub(super) fn related(
        &mut self,
        assembly: Option<&str>,
        package: Option<&str>,
        target: Option<&str>,
        after: Option<u64>,
        limit: usize,
        control: &IndexControl,
    ) -> Result<Value, AppError> {
        if [assembly, package, target]
            .into_iter()
            .any(|v| v.is_some_and(|s| s.len() > 4096))
        {
            return Err(diagnostic(
                "resource.explorer.query",
                "relation selector exceeds query budget",
            ));
        }
        let filters: BTreeMap<_, _> = [
            ("assembly", assembly),
            ("package", package),
            ("target", target),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.into(), value.to_owned())))
        .collect();
        let memory = self.memory;
        let result = self
            .dataset("assembly_links")?
            .page("", &filters, after, limit, memory, control)?;
        Ok(result)
    }
}
