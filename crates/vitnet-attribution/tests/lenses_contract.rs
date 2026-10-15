//! Public investigation-lens contracts over independently captured synthetic evidence.
use serde_json::{Value, json};
use vitnet_attribution::{
    AttributionError, SourceMatch,
    lenses::{Collector, Cost, LensReport, metadata_string, normalize_type},
    model::{
        EVIDENCE_SCHEMA, Evidence, GeneratorOutput, GeneratorRun, Source, SourceAnnotation,
        XamlDocument,
    },
};
use vitnet_mstat::CoalescedIdentity;

const MEMORY: u64 = 128 << 20;

fn evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA.into(),
        ..Evidence::default()
    }
}

fn source(owner: &str) -> Source {
    Source {
        assembly: "App".into(),
        type_name: owner.into(),
        path: "Capture.cs".into(),
        line: 7,
        end_line: 9,
        kind: "class".into(),
        ..Source::default()
    }
}

fn located(status: &str, assemblies: &[&str], sources: Vec<Source>) -> SourceMatch {
    SourceMatch {
        status: status.into(),
        basis: "Independent synthetic association".into(),
        assemblies: assemblies.iter().map(|s| (*s).into()).collect(),
        sources,
    }
}

fn candidate_owner(owner: &str) -> SourceMatch {
    located("producer_prefix_candidate", &["App"], vec![source(owner)])
}

fn entry(stream: &str, name: &str, bytes: u64, accounted: bool) -> CoalescedIdentity {
    CoalescedIdentity {
        stream: stream.into(),
        identity: name.into(),
        bytes,
        accounted,
        records: 99,
        identity_lossy: false,
        raw_identity_blake3: blake3::hash(name.as_bytes()).to_hex().to_string(),
    }
}

fn managed(entry: &CoalescedIdentity, assembly: &str, owner: &str) -> Value {
    json!({
        "stream": entry.stream, "raw_identity_blake3": entry.raw_identity_blake3,
        "resolution": {"status":"resolved", "assembly":assembly, "declaring_type":owner}
    })
}

fn cost(cost: &Cost) -> (u64, u64, u64, u64, u64, u64, u64) {
    assert_eq!(cost.other_additive_bytes, 0);
    (
        cost.additive_bytes,
        cost.overlapping_bytes,
        cost.methods_bytes,
        cost.types_bytes,
        cost.blobs_bytes,
        cost.identities,
        cost.canonical_shared_identities,
    )
}

fn row<'a>(rows: &'a [Value], field: &str, name: &str) -> &'a Value {
    rows.iter().find(|r| r[field] == name).unwrap()
}

fn code<T>(result: Result<T, AttributionError>) -> String {
    result
        .err()
        .expect("expected rejection")
        .diagnostic
        .code
        .clone()
}

fn assert_empty<T>(values: &[T]) {
    assert!(
        values.is_empty(),
        "expected no entries, found {}",
        values.len()
    );
}

#[test]
fn normalize_type_preserves_opaque_aliases_and_nested_spelling() {
    for (input, expected) in [
        ("", ""),
        ("Demo.Plain", "Demo.Plain"),
        ("global::global::Demo.Item", "Demo.Item"),
        ("Demo.Box<int,List<string>>.Tail", "Demo.Box.Tail"),
        ("Demo.Box`12+Inner`2", "Demo.Box+Inner"),
        (
            "global::Demo.Outer`1<int>+Inner`2<string,List<int>>",
            "Demo.Outer+Inner",
        ),
        ("Alias::Foo", "Alias::Foo"),
        (" Demo.Box<int> ", " Demo.Box "),
        ("Demo.Outer.Inner", "Demo.Outer.Inner"),
    ] {
        assert_eq!(normalize_type(input), expected, "{input}");
    }
}

#[test]
fn captured_evidence_preserves_annotation_targets_and_legacy_absence() {
    let annotations = json!([
        {"target":"declaration","attributes":["DynamicDependency(typeof(Demo.Target))"]},
        {"target":"return","attributes":["DynamicallyAccessedMembers(PublicMethods)"]},
        {"target":"parameter:value","attributes":["RequiresUnreferencedCode(\"literal text\")"]},
        {"target":"generic:T","attributes":["DynamicallyAccessedMembers(PublicFields)"]}
    ]);
    let mut captured = source("global::Demo.Owner<int>");
    captured.annotations = Some(serde_json::from_value(annotations.clone()).unwrap());
    assert_eq!(
        serde_json::to_value(&captured).unwrap()["annotations"],
        annotations
    );
    let decoded: Source = serde_json::from_value(serde_json::to_value(&captured).unwrap()).unwrap();
    assert_eq!(decoded.type_name, "global::Demo.Owner<int>");
    assert_eq!(decoded.annotations.unwrap()[2].target, "parameter:value");

    let mut legacy = serde_json::to_value(source("Demo.Owner")).unwrap();
    assert!(legacy.get("annotations").is_none());
    assert!(
        serde_json::from_value::<Source>(legacy.clone())
            .unwrap()
            .annotations
            .is_none()
    );
    legacy["annotations"] = json!([]);
    let empty: Source = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(empty.annotations.as_ref().map(Vec::len), Some(0));
    assert_eq!(
        serde_json::to_value(empty).unwrap()["annotations"],
        json!([])
    );

    let document = json!({
        "path":"Page.axaml", "assembly":"App", "declared_class":"global::Demo.Page",
        "root_element":"UserControl", "sha256":"captured-hash",
        "includes":["Styles.axaml","Theme.axaml"], "keys":["Accent","Size"]
    });
    let mut e = evidence();
    e.sources.push(captured);
    e.xaml_documents = vec![serde_json::from_value(document.clone()).unwrap()];
    let stored = serde_json::to_value(&e).unwrap();
    assert_eq!(stored["xaml_documents"], json!([document.clone()]));
    let decoded: Evidence = serde_json::from_value(stored).unwrap();
    assert_eq!(
        decoded.xaml_documents[0].declared_class.as_deref(),
        Some("global::Demo.Page")
    );
    assert_eq!(
        decoded.xaml_documents[0].includes,
        ["Styles.axaml", "Theme.axaml"]
    );
    for docs in [None, Some(json!([]))] {
        let mut raw = json!({"schema":EVIDENCE_SCHEMA});
        if let Some(docs) = docs {
            raw["xaml_documents"] = docs;
        }
        let decoded: Evidence = serde_json::from_value(raw).unwrap();
        assert!(decoded.xaml_documents.is_empty());
        assert!(
            serde_json::to_value(decoded)
                .unwrap()
                .get("xaml_documents")
                .is_none()
        );
    }
    for class in [None, Some(Value::Null)] {
        let mut raw = document.clone();
        raw.as_object_mut().unwrap().remove("declared_class");
        if let Some(class) = class {
            raw["declared_class"] = class;
        }
        assert_eq!(
            serde_json::from_value::<XamlDocument>(raw)
                .unwrap()
                .declared_class,
            None
        );
    }
    assert_capture_rejects_invalid_fields(document, legacy);
}

fn assert_capture_rejects_invalid_fields(document: Value, mut legacy: Value) {
    for invalid in [
        json!({"target":"return"}),
        json!({"attributes":[]}),
        json!({"target":"return","attributes":[],"unknown":true}),
    ] {
        assert!(serde_json::from_value::<SourceAnnotation>(invalid).is_err());
    }
    for field in [
        "path",
        "assembly",
        "root_element",
        "sha256",
        "includes",
        "keys",
    ] {
        let mut invalid = document.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<XamlDocument>(invalid).is_err(),
            "{field}"
        );
    }
    let mut invalid = document;
    invalid["unknown"] = json!(true);
    assert!(serde_json::from_value::<XamlDocument>(invalid).is_err());
    legacy["unknown"] = json!(true);
    assert!(serde_json::from_value::<Source>(legacy).is_err());
    assert!(
        serde_json::from_value::<Evidence>(json!({"schema":EVIDENCE_SCHEMA,"unknown":true}))
            .is_err()
    );
}

#[test]
fn coalesced_owners_partition_streams_and_association_tiers_once() {
    let mut e = evidence();
    e.sources = vec![source("Demo.Page`1"), source("global::Demo.Page<int>")];
    let source_match = located("asserted", &["App"], e.sources.clone());
    let rows = vec![
        entry("Methods", "App_XamlIl_JsonContext<int>", 10, true),
        entry("Types", "App_Item<__Canon>", 20, true),
        entry("Blobs", "payload", 30, true),
        entry("TemplateMethods", "XamlIl_JsonContext<int>", 40, false),
        entry("Methods", "typed", 11, true),
        entry("Types", "ambiguous", 7, true),
        entry("Blobs", "unmapped", 8, true),
        entry("Methods", "sole_assembly", 9, true),
    ];
    let matches = vec![
        source_match.clone(),
        source_match.clone(),
        source_match.clone(),
        source_match,
        located("managed_symbol_join", &["App"], vec![source("Other.Owner")]),
        located("managed_symbol_ambiguous", &["App"], e.sources.clone()),
        located("unmapped", &["App", "Other"], vec![]),
        located("unmapped", &["App"], vec![]),
    ];
    let candidates = vec![
        vec![],
        vec![],
        vec![],
        vec![],
        vec![
            managed(&rows[4], " App , Version=1.0", "global::Demo.Page<string>"),
            managed(&rows[4], "App", "Demo.Page`1"),
        ],
        vec![
            managed(&rows[5], "App", "Demo.Page"),
            managed(&rows[5], "App", "Other.Owner"),
        ],
        vec![],
        vec![],
    ];
    let before = json!({"evidence":e,"rows":rows,"matches":matches,"candidates":candidates});
    let mut c = Collector::new(&e, MEMORY).unwrap();
    for (i, ((entry, found), candidates)) in rows.iter().zip(&matches).zip(&candidates).enumerate()
    {
        c.observe(entry, found, candidates, i as u64 + 10).unwrap();
    }
    let report = c.finish().unwrap();
    assert_partitioned_owner_costs(&report);
    assert_eq!(
        json!({"evidence":e,"rows":rows,"matches":matches,"candidates":candidates}),
        before
    );
    assert_owner_selection_partitions(&e, &matches[4]);
    assert_serializer_marker_subsets(&e);
}

fn assert_partitioned_owner_costs(report: &LensReport) {
    assert_eq!(report.owners.len(), 5);
    let group = report
        .owners
        .iter()
        .find(|o| o.evidence_tier == "source_name_candidate")
        .unwrap();
    assert_eq!(
        (&*group.assembly, &*group.owner, &*group.namespace),
        ("App", "Demo.Page", "Demo")
    );
    assert_eq!(cost(&group.cost), (60, 40, 10, 20, 30, 4, 1));
    assert_eq!(
        (
            group.xaml_bytes,
            group.serializer_bytes,
            group.generic_bytes
        ),
        (10, 10, 30)
    );
    for (assembly, owner, tier, expected) in [
        (
            "App",
            "Demo.Page",
            "managed_symbol_join",
            (11, 0, 11, 0, 0, 1, 0),
        ),
        (
            "App",
            "_unresolved_owner",
            "managed_symbol_ambiguous",
            (7, 0, 0, 7, 0, 1, 0),
        ),
        (
            "_unmapped_or_shared",
            "_unresolved_owner",
            "unmapped",
            (8, 0, 0, 0, 8, 1, 0),
        ),
        (
            "App",
            "_unresolved_owner",
            "unmapped",
            (9, 0, 9, 0, 0, 1, 0),
        ),
    ] {
        let group = report
            .owners
            .iter()
            .find(|o| o.assembly == assembly && o.owner == owner && o.evidence_tier == tier)
            .unwrap();
        assert_eq!(cost(&group.cost), expected);
    }
    assert_eq!(report.xaml[0]["additive_bytes"], 10);
    assert_eq!(
        row(&report.arguments, "argument", "int")["cost"],
        json!({
            "additive_bytes":10,"overlapping_bytes":40,"methods_bytes":10,"types_bytes":0,
            "blobs_bytes":0,"other_additive_bytes":0,"identities":2,"canonical_shared_identities":0
        })
    );
}

fn assert_owner_selection_partitions(e: &Evidence, managed_match: &SourceMatch) {
    // A managed claim needs the exact status and one normalized resolved owner.
    let item = entry("Methods", "selection", 5, true);
    for (status, candidates, sources, expected_owner, expected_tier) in [
        (
            "managed_symbol_join",
            vec![managed(&item, "App", "Typed.Owner")],
            vec![source("Demo.Page")],
            "Typed.Owner",
            "managed_symbol_join",
        ),
        (
            "asserted",
            vec![managed(&item, "App", "Typed.Owner")],
            vec![source("Demo.Page")],
            "Demo.Page",
            "source_name_candidate",
        ),
        (
            "managed_symbol_join",
            vec![managed(&item, "App", "One"), managed(&item, "App", "Two")],
            vec![source("Demo.Page")],
            "Demo.Page",
            "source_name_candidate",
        ),
        (
            "managed_symbol_join",
            vec![
                json!({"stream":item.stream,"raw_identity_blake3":item.raw_identity_blake3,"resolution":{"status":"unresolved"}}),
            ],
            vec![],
            "_unresolved_owner",
            "managed_symbol_join",
        ),
        (
            "source_ambiguous",
            vec![],
            vec![source("Demo.Page")],
            "_unresolved_owner",
            "source_ambiguous",
        ),
        (
            "asserted",
            vec![],
            vec![source("Demo.A"), source("Demo.B")],
            "_unresolved_owner",
            "asserted",
        ),
    ] {
        let mut c = Collector::new(e, MEMORY).unwrap();
        c.observe(&item, &located(status, &["App"], sources), &candidates, 80)
            .unwrap();
        let r = c.finish().unwrap();
        assert_eq!(r.owners.len(), 1);
        assert_eq!(r.owners[0].assembly, "App");
        assert_eq!(
            (&*r.owners[0].owner, &*r.owners[0].evidence_tier),
            (expected_owner, expected_tier)
        );
        assert_eq!(cost(&r.owners[0].cost), (5, 0, 5, 0, 0, 1, 0));
    }
    for (field, invalid) in [("stream", "Types"), ("raw_identity_blake3", "wrong-hash")] {
        let mut candidate = managed(&item, "App", "Typed.Owner");
        candidate[field] = json!(invalid);
        let mut c = Collector::new(e, MEMORY).unwrap();
        assert_eq!(
            code(c.observe(&item, managed_match, &[candidate], 81)),
            "symbols.integrity"
        );
    }
}

fn assert_serializer_marker_subsets(e: &Evidence) {
    for name in [
        "App_JsonTypeInfo_Helper",
        "App_JsonConverter_Helper",
        "App_JsonSerializerContext_Helper",
        "App_JsonContext_Helper",
    ] {
        for accounted in [true, false] {
            let stream = if accounted {
                "Methods"
            } else {
                "TemplateMethods"
            };
            let mut c = Collector::new(e, MEMORY).unwrap();
            c.observe(
                &entry(stream, name, 5, accounted),
                &candidate_owner("Demo.Serializer"),
                &[],
                82,
            )
            .unwrap();
            let report = c.finish().unwrap();
            assert_eq!(report.owners.len(), 1, "{name} {accounted}");
            let owner = &report.owners[0];
            assert_eq!(owner.owner, "Demo.Serializer");
            assert_eq!(owner.evidence_tier, "source_name_candidate");
            assert_eq!(
                cost(&owner.cost),
                if accounted {
                    (5, 0, 5, 0, 0, 1, 0)
                } else {
                    (0, 5, 0, 0, 0, 1, 0)
                },
                "{name}"
            );
            assert_eq!(
                owner.serializer_bytes,
                if accounted { 5 } else { 0 },
                "{name}"
            );
            assert_eq!((owner.xaml_bytes, owner.generic_bytes), (0, 0));
        }
    }
}

#[test]
fn metadata_strings_preserve_lexical_preview_bytes_and_selected_ownership() {
    for (text, role) in [
        ("https://host/Page.axaml", "uri_candidate"),
        ("Views/Page.axaml", "xaml_path_candidate"),
        ("Views/Page.xaml", "xaml_path_candidate"),
        ("Demo.Type", "qualified_identifier_candidate"),
        ("Alias::Type", "qualified_identifier_candidate"),
        ("Page.AXAML", "qualified_identifier_candidate"),
        ("literal", "unclassified"),
    ] {
        for (context, ownership) in [
            (
                json!({"assembly":"App","namespace":"Demo","type_name":"Demo.Page"}),
                "metadata_log_selected_owner",
            ),
            (json!({"assembly":"App"}), "assembly_context_only"),
            (json!({}), "not_captured_or_unowned"),
        ] {
            let mut input = json!({
                "bytes":77,"logical_offset":123,
                "preview":{"text":text,"original_bytes":900,"truncated":true}
            });
            input
                .as_object_mut()
                .unwrap()
                .extend(context.as_object().unwrap().clone());
            let actual = metadata_string(&input);
            assert_eq!(actual["role"], role);
            assert_eq!(actual["ownership"], ownership);
            for field in [
                "bytes",
                "logical_offset",
                "preview",
                "assembly",
                "namespace",
            ] {
                assert_eq!(actual[field], input[field], "{field}");
            }
            assert_eq!(actual["owner"], input["type_name"]);
            assert_eq!(actual["evidence_tier"], "preview_lexical_candidate");
            assert!(
                actual["scope"]
                    .as_str()
                    .unwrap()
                    .contains("Not additive to Metadata/Blobs")
            );
        }
    }
    for (input, role, preview) in [
        (
            json!({"bytes":31,"logical_offset":4,"preview":{"text":"plain","original_bytes":5,"truncated":false}}),
            "unclassified",
            json!({"text":"plain","original_bytes":5,"truncated":false}),
        ),
        (
            json!({"bytes":88,"logical_offset":9,"preview":{"text":"Page","original_bytes":500,"truncated":true}}),
            "unclassified",
            json!({"text":"Page","original_bytes":500,"truncated":true}),
        ),
        (
            json!({"bytes":12,"logical_offset":2}),
            "unclassified",
            Value::Null,
        ),
    ] {
        let actual = metadata_string(&input);
        assert_eq!(actual["role"], role);
        assert_eq!(actual["preview"], preview);
        assert_eq!(actual["bytes"], input["bytes"]);
        assert_eq!(actual["logical_offset"], input["logical_offset"]);
        assert_eq!(actual["ownership"], "not_captured_or_unowned");
        assert_eq!(actual["owner"], Value::Null);
    }
    let missing = metadata_string(&json!({}));
    assert_eq!(
        (
            missing["bytes"].clone(),
            missing["logical_offset"].clone(),
            missing["preview"].clone()
        ),
        (Value::Null, Value::Null, Value::Null)
    );
}

#[test]
fn metadata_owner_lower_bounds_never_increase_native_costs() {
    let e = evidence();
    let mut c = Collector::new(&e, MEMORY).unwrap();
    c.observe(
        &entry("Blobs", "native_blob", 17, true),
        &candidate_owner("Demo.Owner"),
        &[],
        3,
    )
    .unwrap();
    c.metadata("App!global::Demo.Owner<int>", 70).unwrap();
    c.metadata("App!Demo.Owner`1", 11).unwrap();
    c.metadata("global::Loose.Item<string>", 13).unwrap();
    let r = c.finish().unwrap();
    assert_eq!(r.owners.len(), 3);
    let native = r
        .owners
        .iter()
        .find(|o| o.evidence_tier == "source_name_candidate")
        .unwrap();
    assert_eq!(cost(&native.cost), (17, 0, 0, 0, 17, 1, 0));
    assert_eq!(native.metadata_lower_bound_bytes, 0);
    for (assembly, owner, namespace, bytes) in [
        ("App", "Demo.Owner", "Demo", 81),
        ("_unowned_metadata", "Loose.Item", "Loose", 13),
    ] {
        let group = r
            .owners
            .iter()
            .find(|o| o.assembly == assembly && o.evidence_tier == "metadata_name_candidate")
            .unwrap();
        assert_eq!((&*group.owner, &*group.namespace), (owner, namespace));
        assert_eq!(group.metadata_lower_bound_bytes, bytes);
        assert_eq!(cost(&group.cost), (0, 0, 0, 0, 0, 0, 0));
        assert_eq!(
            (
                group.xaml_bytes,
                group.serializer_bytes,
                group.generic_bytes
            ),
            (0, 0, 0)
        );
        assert!(group.examples.is_empty());
    }
    let preview = metadata_string(&json!({
        "bytes":81,"logical_offset":900,"type_name":"Demo.Owner","assembly":"App",
        "preview":{"text":"X","original_bytes":999,"truncated":true}
    }));
    assert_eq!(preview["bytes"], 81);
    assert_eq!(preview["owner"], "Demo.Owner");
    assert_eq!(preview["preview"]["original_bytes"], 999);
    assert_eq!(preview["ownership"], "metadata_log_selected_owner");
}

#[test]
fn owner_examples_and_equal_cost_groups_use_bounded_deterministic_order() {
    let e = evidence();
    let mut c = Collector::new(&e, MEMORY).unwrap();
    for (ordinal, bytes, name) in [
        (8, 10, "low"),
        (6, 30, "high"),
        (9, 20, "tie_late"),
        (2, 20, "tie_early"),
    ] {
        c.observe(
            &entry("Methods", name, bytes, true),
            &candidate_owner("Demo.Examples"),
            &[],
            ordinal,
        )
        .unwrap();
    }
    for (assembly, owner, typed, ordinal) in [
        ("Z", "Demo.A", false, 11),
        ("App", "Demo.Z", false, 12),
        ("App", "Demo.A", false, 13),
        ("App", "Demo.A", true, 14),
    ] {
        let item = entry("Types", &format!("tie_{ordinal}"), 12, true);
        let mut s = source(owner);
        s.assembly = assembly.into();
        let found = located(
            if typed {
                "managed_symbol_join"
            } else {
                "asserted"
            },
            &[assembly],
            vec![s],
        );
        let candidates = if typed {
            vec![managed(&item, assembly, owner)]
        } else {
            vec![]
        };
        c.observe(&item, &found, &candidates, ordinal).unwrap();
    }
    let report = c.finish().unwrap();
    let examples = &report.owners[0].examples;
    assert_eq!(
        examples
            .iter()
            .map(|x| (
                x.ordinal,
                x.bytes,
                x.identity.as_str(),
                x.stream.as_str(),
                x.truncated
            ))
            .collect::<Vec<_>>(),
        [
            (6, 30, "high", "Methods", false),
            (2, 20, "tie_early", "Methods", false),
            (9, 20, "tie_late", "Methods", false)
        ]
    );
    assert_eq!(report.owners[0].cost.additive_bytes, 80);
    assert_eq!(
        report.owners[1..]
            .iter()
            .map(|o| (
                o.assembly.as_str(),
                o.owner.as_str(),
                o.evidence_tier.as_str()
            ))
            .collect::<Vec<_>>(),
        [
            ("App", "Demo.A", "managed_symbol_join"),
            ("App", "Demo.A", "source_name_candidate"),
            ("App", "Demo.Z", "source_name_candidate"),
            ("Z", "Demo.A", "source_name_candidate"),
        ]
    );
    assert_owner_preview_boundaries(&e);
}

fn assert_owner_preview_boundaries(e: &Evidence) {
    for (name, expected, truncated) in [
        ("a".repeat(511), "a".repeat(511), false),
        ("é".repeat(256), "é".repeat(256), false),
        ("a".repeat(513), "a".repeat(512), true),
        (format!("{}é", "a".repeat(511)), "a".repeat(511), true),
    ] {
        let mut c = Collector::new(e, MEMORY).unwrap();
        c.observe(
            &entry("Blobs", &name, 19, true),
            &candidate_owner("Demo.Preview"),
            &[],
            23,
        )
        .unwrap();
        let report = c.finish().unwrap();
        let example = &report.owners[0].examples[0];
        assert_eq!(example.identity, expected);
        assert_eq!(
            (
                example.ordinal,
                example.bytes,
                example.stream.as_str(),
                example.truncated
            ),
            (23, 19, "Blobs", truncated)
        );
        assert!(example.identity.len() <= 512);
    }
}

fn document(class: Option<&str>, path: &str) -> XamlDocument {
    XamlDocument {
        assembly: "App".into(),
        declared_class: class.map(str::to_owned),
        path: path.into(),
        root_element: "UserControl".into(),
        sha256: "captured-hash".into(),
        includes: vec!["Styles.axaml".into(), "Theme.axaml".into()],
        keys: vec!["Accent".into(), "Size".into()],
    }
}

#[test]
fn xaml_name_cohorts_attach_only_matching_captured_documents() {
    let mut e = evidence();
    let matching = document(Some("global::Demo.Page0<int>"), "Page.axaml");
    let mut wrong_assembly = document(Some("Demo.Page0"), "WrongAssembly.axaml");
    wrong_assembly.assembly = "Other".into();
    e.xaml_documents = vec![
        matching,
        wrong_assembly,
        document(Some("Demo.Page0.Child"), "WrongClass.axaml"),
        document(None, "NoClass.axaml"),
    ];
    let mut c = Collector::new(&e, MEMORY).unwrap();
    for (i, marker) in [
        "XamlIl",
        "XamlClosure",
        "CompiledAvaloniaXaml",
        "xamlil",
        "Ordinary",
    ]
    .iter()
    .enumerate()
    {
        c.observe(
            &entry("Methods", &format!("App_{marker}"), 10 + i as u64, true),
            &candidate_owner(&format!("Demo.Page{i}")),
            &[],
            i as u64,
        )
        .unwrap();
    }
    c.observe(
        &entry("TemplateTypes", "App_XamlIl", 15, false),
        &candidate_owner("Demo.Overlap"),
        &[],
        8,
    )
    .unwrap();
    let report = c.finish().unwrap();
    assert_eq!(
        report
            .xaml
            .iter()
            .map(|r| (
                r["owner"].as_str().unwrap(),
                r["additive_bytes"].as_u64().unwrap()
            ))
            .collect::<Vec<_>>(),
        [("Demo.Page2", 12), ("Demo.Page1", 11), ("Demo.Page0", 10)]
    );
    for (owner, bytes) in [("Demo.Page0", 10), ("Demo.Page1", 11), ("Demo.Page2", 12)] {
        let xaml = row(&report.xaml, "owner", owner);
        assert_eq!(xaml["assembly"], "App");
        assert_eq!(xaml["namespace"], "Demo");
        assert_eq!(xaml["evidence_tier"], "source_name_candidate");
        assert_eq!(
            xaml["owner_cost"],
            json!({
                "additive_bytes":bytes,"overlapping_bytes":0,"methods_bytes":bytes,"types_bytes":0,
                "blobs_bytes":0,"other_additive_bytes":0,"identities":1,"canonical_shared_identities":0
            })
        );
        let group = report.owners.iter().find(|g| g.owner == owner).unwrap();
        assert_eq!(group.xaml_bytes, bytes);
    }
    let matched = row(&report.xaml, "owner", "Demo.Page0");
    assert_eq!(
        matched["input_association"],
        "declared_class_name_candidate"
    );
    assert_eq!(
        matched["documents"],
        json!([{
            "path":"Page.axaml","declared_class":"global::Demo.Page0<int>","root_element":"UserControl",
            "includes":["Styles.axaml","Theme.axaml"],"keys":["Accent","Size"],"sha256":"captured-hash"
        }])
    );
    assert!(matched["documents"][0].get("assembly").is_none());
    for owner in ["Demo.Page1", "Demo.Page2"] {
        let missing = row(&report.xaml, "owner", owner);
        assert_eq!(missing["documents"], json!([]));
        assert_eq!(missing["input_association"], "not_captured_or_unresolved");
    }
    for owner in ["Demo.Page3", "Demo.Page4", "Demo.Overlap"] {
        assert_eq!(
            report
                .owners
                .iter()
                .find(|o| o.owner == owner)
                .unwrap()
                .xaml_bytes,
            0
        );
    }
}

#[test]
fn generic_arguments_deduplicate_nested_occurrences_and_track_families() {
    let e = evidence();
    let mut c = Collector::new(&e, MEMORY).unwrap();
    c.observe(
        &entry("Methods", "App_Box<int,int,List<int>>__Run<int>", 10, true),
        &candidate_owner("Demo.Box"),
        &[],
        3,
    )
    .unwrap();
    c.observe(
        &entry("Types", "App_Other<int,Zed,Aaa>", 25, true),
        &candidate_owner("Demo.Other"),
        &[],
        7,
    )
    .unwrap();
    let report = c.finish().unwrap();
    assert_eq!(
        report
            .arguments
            .iter()
            .map(|r| r["argument"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["int", "Aaa", "Zed", "List<int>"]
    );
    let int = row(&report.arguments, "argument", "int");
    assert_eq!(
        int["cost"],
        json!({
            "additive_bytes":35,"overlapping_bytes":0,"methods_bytes":10,"types_bytes":25,
            "blobs_bytes":0,"other_additive_bytes":0,"identities":2,"canonical_shared_identities":0
        })
    );
    assert_eq!(int["additive_bytes"], 35);
    assert_eq!(int["families"], json!(["App_Box<>__Run<>", "App_Other<>"]));
    assert_eq!(int["family_count"], 2);
    assert_eq!(
        int["examples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["ordinal"].as_u64().unwrap(), r["bytes"].as_u64().unwrap()))
            .collect::<Vec<_>>(),
        [(7, 25), (3, 10)]
    );
    for (argument, bytes, methods, types, family) in [
        ("List<int>", 10, 10, 0, "App_Box<>__Run<>"),
        ("Aaa", 25, 0, 25, "App_Other<>"),
        ("Zed", 25, 0, 25, "App_Other<>"),
    ] {
        let r = row(&report.arguments, "argument", argument);
        assert_eq!(
            r["cost"],
            json!({
                "additive_bytes":bytes,"overlapping_bytes":0,"methods_bytes":methods,"types_bytes":types,
                "blobs_bytes":0,"other_additive_bytes":0,"identities":1,"canonical_shared_identities":0
            })
        );
        assert_eq!(r["additive_bytes"], bytes);
        assert_eq!(r["families"], json!([family]));
        assert_eq!(r["family_count"], 1);
    }
    for r in &report.arguments {
        assert_eq!(r["evidence_tier"], "parsed_producer_argument");
        assert_eq!(r["source_candidate_count"], 0);
        assert_eq!(r["source_candidates"], json!([]));
        assert!(
            r["scope"]
                .as_str()
                .unwrap()
                .contains("not resolved C# call sites")
        );
    }
}

#[test]
fn malformed_and_lossy_shapes_preserve_owner_accounting_but_not_arguments() {
    let e = evidence();
    for (name, lossy, malformed) in [
        ("App_Plain", false, 0),
        ("App_Box<>", false, 1),
        ("App_Box<int", false, 1),
        ("App_Box<int>>", false, 1),
        ("App_Box<__Canon>", true, 0),
    ] {
        let mut item = entry("Methods", name, 13, true);
        item.identity_lossy = lossy;
        let mut c = Collector::new(&e, MEMORY).unwrap();
        c.observe(&item, &candidate_owner("Demo.Owner"), &[], 6)
            .unwrap();
        let r = c.finish().unwrap();
        assert_eq!(cost(&r.owners[0].cost), (13, 0, 13, 0, 0, 1, 0), "{name}");
        assert_eq!(r.owners[0].generic_bytes, 0);
        assert_eq!(r.coverage["malformed_shapes"], malformed);
        assert_eq!(r.coverage["arguments"], 0);
        assert_empty(&r.arguments);
    }
    assert_malformed_nested_arguments_retain_valid_siblings(&e);
}

fn assert_malformed_nested_arguments_retain_valid_siblings(e: &Evidence) {
    let name = "App_Box<List<>,List<int>,int>";
    let mut c = Collector::new(e, MEMORY).unwrap();
    c.observe(
        &entry("Methods", name, 13, true),
        &candidate_owner("Demo.Owner"),
        &[],
        6,
    )
    .unwrap();
    // The malformed nested argument must not abort subsequent corpus observations.
    c.observe(
        &entry("Methods", "App_Plain", 5, true),
        &candidate_owner("Demo.Owner"),
        &[],
        7,
    )
    .unwrap();
    let report = c.finish().unwrap();
    assert_eq!(report.owners.len(), 1);
    assert_eq!(cost(&report.owners[0].cost), (18, 0, 18, 0, 0, 2, 0));
    assert_eq!(report.owners[0].generic_bytes, 13);
    assert_eq!(report.coverage["malformed_shapes"], 1);
    assert_eq!(report.coverage["arguments"], 3);
    assert_eq!(
        report
            .arguments
            .iter()
            .map(|r| r["argument"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["List<>", "List<int>", "int"]
    );
    for argument in &report.arguments {
        assert_eq!(
            argument["cost"],
            json!({
                "additive_bytes":13,"overlapping_bytes":0,"methods_bytes":13,"types_bytes":0,
                "blobs_bytes":0,"other_additive_bytes":0,"identities":1,"canonical_shared_identities":0
            })
        );
        assert_eq!(argument["additive_bytes"], 13);
        assert_eq!(argument["families"], json!(["App_Box<>"]));
        assert_eq!(argument["family_count"], 1);
        assert_eq!(argument["evidence_tier"], "parsed_producer_argument");
        assert_eq!(
            argument["examples"],
            json!([{"ordinal":6,"bytes":13,"stream":"Methods","identity":name,"truncated":false}])
        );
    }
}

fn annotation(target: &str, attributes: &[&str]) -> SourceAnnotation {
    SourceAnnotation {
        target: target.into(),
        attributes: attributes.iter().map(|s| (*s).into()).collect(),
    }
}

fn serializer_evidence() -> Evidence {
    let mut e = evidence();
    let mut first = source("global::Demo.Context<T>");
    first.path = "Z.cs".into();
    first.attributes = vec![
        "JsonSerializable(typeof(global::Foo))".into(),
        "JsonSourceGenerationOptions(WriteIndented=true)".into(),
        "JsonSerializable".into(),
    ];
    first.annotations = Some(vec![annotation(
        "declaration",
        &[
            "JsonSerializable(typeof(global::Foo))",
            "JsonSourceGenerationOptions(WriteIndented=true)",
            "global::System.Text.Json.Serialization.JsonSerializableAttribute(typeof(Dictionary<string, List<(int, string)>>))",
            "JsonSerializableAttribute(typeof(Unclosed",
        ],
    )]);
    let mut partial = source("Demo.Context`1");
    partial.path = "A.cs".into();
    partial.attributes = vec![
        "JsonSerializableAttribute(typeof(global::Foo))".into(),
        "JsonSerializable(typeof(Alias::Foo))".into(),
        "System.Text.Json.Serialization.JsonSourceGenerationOptionsAttribute(PropertyNamingPolicy=SnakeCaseLower)".into(),
    ];
    let mut second = source("Demo.Second");
    second.attributes = vec![
        "JsonSerializable(typeof(global::Foo))".into(),
        "JsonSerializable(typeof(Alias::Foo))".into(),
        "JsonSerializable(typeof(global::Foo))".into(),
        "JsonSourceGenerationOptions(WriteIndented=false)".into(),
    ];
    let mut missing = source("Demo.Missing");
    missing.attributes = vec!["JsonSerializable(typeof(Solo))".into()];
    let mut other_assembly = source("Demo.Missing");
    other_assembly.assembly = "Z".into();
    other_assembly.attributes = vec!["JsonSerializable(typeof(ZSolo))".into()];
    e.sources = vec![
        first,
        partial,
        second,
        missing,
        other_assembly,
        source("JsonSerializableAttribute"),
    ];
    e
}

fn serializer_report(e: &Evidence) -> LensReport {
    let mut c = Collector::new(e, MEMORY).unwrap();
    for (stream, owner, bytes, ordinal) in [
        ("Methods", "Demo.Context", 10, 40),
        ("Types", "Demo.Context+Generated", 20, 41),
        ("Blobs", "Demo.Context+Generated+Inner", 5, 42),
        ("Methods", "Demo.Contextual", 99, 43),
        ("Types", "Demo.Context.Generated", 77, 44),
        ("Methods", "Demo.Second", 35, 46),
    ] {
        c.observe(
            &entry(stream, &format!("native_{ordinal}"), bytes, true),
            &candidate_owner(owner),
            &[],
            ordinal,
        )
        .unwrap();
    }
    let mut other = source("Demo.Context");
    other.assembly = "Other".into();
    c.observe(
        &entry("Blobs", "other_assembly", 88, true),
        &located("asserted", &["Other"], vec![other]),
        &[],
        45,
    )
    .unwrap();
    c.finish().unwrap()
}

#[test]
fn serializer_contexts_merge_applied_partial_annotations_and_native_descendants() {
    let mut e = serializer_evidence();
    for captured_outputs in [false, true] {
        if captured_outputs {
            e.generator_runs.push(GeneratorRun {
                name: "CapturedGenerator".into(),
                status: "captured".into(),
                basis: "Independent output capture".into(),
                execution_status: "not_proven".into(),
                outputs: ["Context.g.cs", "Other.g.cs"]
                    .iter()
                    .map(|path| GeneratorOutput {
                        path: (*path).into(),
                        build_match: "unknown".into(),
                        ..GeneratorOutput::default()
                    })
                    .collect(),
                ..GeneratorRun::default()
            });
        }
        let before = serde_json::to_value(&e).unwrap();
        let report = serializer_report(&e);
        assert_eq!(
            report
                .serializers
                .iter()
                .map(|r| (
                    r["assembly"].as_str().unwrap(),
                    r["context"].as_str().unwrap(),
                    r["additive_bytes"].as_u64().unwrap()
                ))
                .collect::<Vec<_>>(),
            [
                ("App", "Demo.Context", 35),
                ("App", "Demo.Second", 35),
                ("App", "Demo.Missing", 0),
                ("Z", "Demo.Missing", 0)
            ]
        );
        let context = row(&report.serializers, "context", "Demo.Context");
        assert_eq!(
            context["declared_roots"],
            json!([
                "Alias::Foo",
                "Dictionary<string, List<(int, string)>>",
                "_unparsed_attribute:JsonSerializable",
                "_unparsed_attribute:JsonSerializableAttribute(typeof(Unclosed",
                "global::Foo"
            ])
        );
        assert_eq!(
            context["options"],
            json!([
                "JsonSourceGenerationOptions(WriteIndented=true)",
                "System.Text.Json.Serialization.JsonSourceGenerationOptionsAttribute(PropertyNamingPolicy=SnakeCaseLower)"
            ])
        );
        assert_eq!(context["source_paths"], json!(["A.cs", "Z.cs"]));
        assert_serializer_observed_owner_groups(context);
        assert_eq!(
            context["examples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (r["ordinal"].as_u64().unwrap(), r["bytes"].as_u64().unwrap()))
                .collect::<Vec<_>>(),
            [(41, 20), (40, 10), (42, 5)]
        );
        for context in &report.serializers {
            assert_eq!(
                context["generated_outputs_captured"],
                if captured_outputs { 2 } else { 0 }
            );
            assert_eq!(context["evidence_tier"], "source_context_name_candidate");
            if context["context"] == "Demo.Missing" {
                assert_eq!(context["additive_bytes"], 0);
                assert_eq!(context["observed_owner_groups"], json!([]));
                assert_eq!(context["examples"], json!([]));
            }
        }
        assert_eq!(serde_json::to_value(&e).unwrap(), before);
    }
}

fn assert_serializer_observed_owner_groups(context: &Value) {
    let groups = context["observed_owner_groups"].as_array().unwrap();
    assert_eq!(groups.len(), 3);
    for (owner, bytes, methods, types, blobs) in [
        ("Demo.Context", 10, 10, 0, 0),
        ("Demo.Context+Generated", 20, 0, 20, 0),
        ("Demo.Context+Generated+Inner", 5, 0, 0, 5),
    ] {
        let group = row(groups, "owner", owner);
        for (field, expected) in [
            ("additive_bytes", bytes),
            ("overlapping_bytes", 0),
            ("methods_bytes", methods),
            ("types_bytes", types),
            ("blobs_bytes", blobs),
            ("other_additive_bytes", 0),
            ("identities", 1),
            ("canonical_shared_identities", 0),
        ] {
            assert_eq!(group[field], expected, "{owner} {field}");
        }
        assert_eq!(group["evidence_tier"], "source_name_candidate");
    }
}

#[test]
fn repeated_roots_count_contexts_not_declarations_or_native_artifacts() {
    let e = serializer_evidence();
    let report = serializer_report(&e);
    assert_eq!(
        report
            .repetitions
            .iter()
            .map(|r| r["root"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Alias::Foo", "global::Foo"]
    );
    let contexts = json!([
        {"assembly":"App","context":"Demo.Context","options":[
            "JsonSourceGenerationOptions(WriteIndented=true)",
            "System.Text.Json.Serialization.JsonSourceGenerationOptionsAttribute(PropertyNamingPolicy=SnakeCaseLower)"
        ]},
        {"assembly":"App","context":"Demo.Second","options":["JsonSourceGenerationOptions(WriteIndented=false)"]}
    ]);
    for r in &report.repetitions {
        assert_eq!(r["context_count"], 2);
        assert_eq!(r["contexts"], contexts);
        assert_eq!(r["evidence_tier"], "literal_declared_root_repetition");
        assert_eq!(r["distinct_native_artifacts_proven"], false);
        for unsupported in ["bytes", "additive_bytes", "repeated_bytes", "savings_bytes"] {
            assert!(r.get(unsupported).is_none(), "{unsupported}");
        }
        assert!(
            r["scope"]
                .as_str()
                .unwrap()
                .contains("not proof of semantic type equality")
        );
    }
}

fn reflection_evidence(dep: &str) -> Evidence {
    let mut e = evidence();
    let mut declaring = source("global::Demo.Reflect<int>");
    declaring.annotations = Some(vec![
        annotation(
            "declaration",
            &[
                dep,
                "DynamicDependencyAttribute(typeof(Other))",
                "UnknownAnnotation",
            ],
        ),
        annotation(
            "return",
            &[
                "DynamicallyAccessedMembers(PublicMethods)",
                "DynamicallyAccessedMembersAttribute(PublicFields)",
            ],
        ),
        annotation(
            "parameter:value",
            &[
                "RequiresUnreferencedCode(\"reason\")",
                "RequiresUnreferencedCodeAttribute(\"other\")",
            ],
        ),
        annotation("generic:T", &[dep]),
    ]);
    declaring.attributes = vec![dep.into(), "RequiresUnreferencedCode(\"legacy\")".into()];
    let mut member = source("global::Demo.Reflect<int>");
    member.path = "Member.cs".into();
    member.member = Some("Invoke".into());
    member.annotations = Some(vec![annotation(
        "generic:U",
        &["DynamicallyAccessedMembers(PublicConstructors)"],
    )]);
    e.sources = vec![declaring, source("DynamicDependencyAttribute"), member];
    for definition in [
        "DynamicallyAccessedMembersAttribute",
        "RequiresUnreferencedCodeAttribute",
    ] {
        e.sources.push(source(definition));
        let mut member_definition = source(definition);
        member_definition.member = Some("Constructor".into());
        e.sources.push(member_definition);
    }
    e
}

#[test]
fn reflection_rows_preserve_attached_targets_and_exclude_attribute_definitions() {
    let dep = "global::System.Diagnostics.CodeAnalysis.DynamicDependency(typeof(Target))";
    let e = reflection_evidence(dep);
    let before = serde_json::to_value(&e).unwrap();
    let mut c = Collector::new(&e, MEMORY).unwrap();
    c.observe(
        &entry("Methods", "independent_native", 17, true),
        &candidate_owner("Demo.Reflect"),
        &[],
        90,
    )
    .unwrap();
    c.metadata("App!Demo.Reflect", 11).unwrap();
    let r = c.finish().unwrap();
    assert_eq!(
        r.reflection
            .iter()
            .map(|r| (
                r["source_ordinal"].as_u64().unwrap(),
                r["target"].as_str().unwrap(),
                r["attribute"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        [
            (0, "declaration", dep),
            (
                0,
                "declaration",
                "DynamicDependencyAttribute(typeof(Other))"
            ),
            (0, "return", "DynamicallyAccessedMembers(PublicMethods)"),
            (
                0,
                "return",
                "DynamicallyAccessedMembersAttribute(PublicFields)"
            ),
            (0, "parameter:value", "RequiresUnreferencedCode(\"reason\")"),
            (
                0,
                "parameter:value",
                "RequiresUnreferencedCodeAttribute(\"other\")"
            ),
            (0, "generic:T", dep),
            (
                0,
                "declaration_target_unknown",
                "RequiresUnreferencedCode(\"legacy\")"
            ),
            (
                2,
                "generic:U",
                "DynamicallyAccessedMembers(PublicConstructors)"
            ),
        ]
    );
    for reflected in &r.reflection {
        assert_eq!(reflected["owner"], "global::Demo.Reflect<int>");
        assert_eq!(reflected["assembly"], "App");
        assert_eq!(reflected["line"], 7);
        assert_eq!(reflected["declaring_owner_bytes"], 17);
        assert_eq!(reflected["metadata_lower_bound_bytes"], 11);
        assert_eq!(reflected["evidence_tier"], "captured_annotation_syntax");
        let is_member = reflected["source_ordinal"] == 2;
        assert_eq!(
            reflected["path"],
            if is_member { "Member.cs" } else { "Capture.cs" }
        );
        assert_eq!(
            reflected["member"],
            if is_member {
                json!("Invoke")
            } else {
                Value::Null
            }
        );
        for caveat in [
            "not annotation-class definitions",
            "not the preserved target set",
            "no source/build equality or sole-causality claim",
        ] {
            assert!(reflected["scope"].as_str().unwrap().contains(caveat));
        }
    }
    assert_empty(&r.serializers);
    assert_eq!(serde_json::to_value(&e).unwrap(), before);
}

#[test]
fn canonical_costs_and_coverage_leave_runtime_support_and_unique_bodies_unassigned() {
    let mut e = evidence();
    let mut context = source("Demo.Context");
    context.attributes = vec![
        "JsonSerializable(typeof(Target))".into(),
        "DynamicDependency(typeof(Target))".into(),
    ];
    let mut other = source("Demo.OtherContext");
    other.attributes = vec!["JsonSerializable(typeof(Target))".into()];
    e.sources = vec![context, other];
    e.xaml_documents = vec![
        document(Some("Demo.Context"), "Context.axaml"),
        document(None, "Unassociated.axaml"),
    ];
    let mut c = Collector::new(&e, MEMORY).unwrap();
    for (ordinal, stream, name, bytes, accounted) in [
        (1, "Methods", "XamlIl_JsonContext<___Canon>", 10, true),
        (2, "Types", "App_Box<__Canon>", 20, true),
        (3, "Blobs", "App_Cache<int>", 30, true),
        (4, "Methods", "App___Canon_Helper", 7, true),
        (5, "TemplateMethods", "App_Box<__Canon>", 40, false),
    ] {
        c.observe(
            &entry(stream, name, bytes, accounted),
            &candidate_owner("Demo.Context"),
            &[],
            ordinal,
        )
        .unwrap();
    }
    c.observe(
        &entry("Methods", "App_Box<>", 5, true),
        &located("unmapped", &["App"], vec![]),
        &[],
        6,
    )
    .unwrap();
    c.metadata("App!Demo.Context", 13).unwrap();
    let report = c.finish().unwrap();
    assert_eq!(report.schema, "vitnet.investigation-lenses.v1");
    let owner = &report.owners[0];
    assert_eq!(owner.owner, "Demo.Context");
    assert_eq!(cost(&owner.cost), (67, 40, 17, 20, 30, 5, 3));
    assert_eq!(
        (
            owner.xaml_bytes,
            owner.serializer_bytes,
            owner.generic_bytes
        ),
        (10, 10, 60)
    );
    assert_eq!(report.xaml[0]["additive_bytes"], 10);
    assert_eq!(
        row(&report.serializers, "context", "Demo.Context")["additive_bytes"],
        67
    );
    assert_eq!(
        row(&report.arguments, "argument", "__Canon")["cost"],
        json!({
            "additive_bytes":20,"overlapping_bytes":40,"methods_bytes":0,"types_bytes":20,
            "blobs_bytes":0,"other_additive_bytes":0,"identities":2,"canonical_shared_identities":2
        })
    );
    assert_eq!(
        row(&report.arguments, "argument", "___Canon")["cost"]["canonical_shared_identities"],
        1
    );
    assert_eq!(
        row(&report.arguments, "argument", "int")["cost"]["canonical_shared_identities"],
        0
    );
    for (field, expected) in [
        ("owners", 3),
        ("xaml_groups", 1),
        ("serializer_contexts", 2),
        ("repeated_roots", 1),
        ("arguments", 3),
        ("reflection_annotations", 1),
        ("xaml_documents", 2),
        ("malformed_shapes", 1),
    ] {
        assert_eq!(report.coverage[field], expected, "{field}");
    }
    assert!(report.coverage["tracked_aggregate_bytes"].as_u64().unwrap() <= MEMORY);
    assert_coverage_uncertainty_caveats(&report.coverage);
}

fn assert_coverage_uncertainty_caveats(coverage: &Value) {
    let scope = coverage["scope"].as_str().unwrap();
    for caveat in [
        "no source execution",
        "usage verdict",
        "unique-body count",
        "exclusive dependency ownership",
        "proposed savings",
    ] {
        assert!(scope.contains(caveat));
    }
    let basis = coverage["cost_basis"].as_str().unwrap();
    for caveat in [
        "Methods are producer method accounting",
        "not isolated instruction-body bytes",
        "Types/Blobs are additive",
        "metadata and specialized streams overlap",
    ] {
        assert!(basis.contains(caveat));
    }
    let runtime = coverage["runtime_support_assignment"].as_str().unwrap();
    for caveat in [
        "Generic dictionary and hashtable buckets remain unassigned to families",
        "slot demand and shared-body size are unknown",
    ] {
        assert!(runtime.contains(caveat));
    }
    for unsupported in [
        "total_bytes",
        "unique_bodies",
        "savings_bytes",
        "coverage_percentage",
        "slot_demand",
        "shared_body_bytes",
    ] {
        assert!(coverage.get(unsupported).is_none(), "{unsupported}");
    }
}

#[test]
fn collector_rejects_checked_overflow_and_unsupported_accounting() {
    let e = evidence();
    for (stream, accounted) in [("Methods", true), ("TemplateMethods", false)] {
        let mut c = Collector::new(&e, MEMORY).unwrap();
        c.observe(
            &entry(stream, "maximum", u64::MAX, accounted),
            &candidate_owner("Demo.Owner"),
            &[],
            1,
        )
        .unwrap();
        assert_eq!(
            code(c.observe(
                &entry(stream, "adjacent", 1, accounted),
                &candidate_owner("Demo.Owner"),
                &[],
                2
            )),
            "lenses.size"
        );
    }
    let mut c = Collector::new(&e, MEMORY).unwrap();
    c.metadata("App!Demo.Owner", u64::MAX).unwrap();
    assert_eq!(code(c.metadata("App!Demo.Owner", 1)), "lenses.size");
    let mut c = Collector::new(&e, MEMORY).unwrap();
    c.observe(
        &entry("TemplateMethods", "other_additive", 3, true),
        &candidate_owner("Demo.Owner"),
        &[],
        1,
    )
    .unwrap();
    let compatible = c.finish().unwrap();
    assert_eq!(compatible.owners.len(), 1);
    assert_eq!(compatible.owners[0].owner, "Demo.Owner");
    assert_eq!(
        serde_json::to_value(&compatible.owners[0].cost).unwrap(),
        json!({
            "additive_bytes":3,"overlapping_bytes":0,"methods_bytes":0,"types_bytes":0,
            "blobs_bytes":0,"other_additive_bytes":3,"identities":1,"canonical_shared_identities":0
        })
    );
    let mut c = Collector::new(&e, MEMORY).unwrap();
    c.observe(
        &entry("TemplateMethods", "valid_overlap", 3, false),
        &candidate_owner("Demo.Owner"),
        &[],
        1,
    )
    .unwrap();
    assert_eq!(
        cost(&c.finish().unwrap().owners[0].cost),
        (0, 3, 0, 0, 0, 1, 0)
    );

    // Distinct evidence tiers have individually valid ledgers; finish must also check their sum.
    for attribute in [
        "JsonSerializable(typeof(Foo))",
        "DynamicDependency(typeof(Foo))",
    ] {
        let mut e = evidence();
        let mut s = source("Demo.Owner");
        s.attributes = vec![attribute.into()];
        e.sources = vec![s];
        let mut c = Collector::new(&e, MEMORY).unwrap();
        c.observe(
            &entry("Methods", "candidate_maximum", u64::MAX, true),
            &candidate_owner("Demo.Owner"),
            &[],
            3,
        )
        .unwrap();
        let typed = entry("Methods", "typed_adjacent", 1, true);
        c.observe(
            &typed,
            &located("managed_symbol_join", &["App"], vec![]),
            &[managed(&typed, "App", "Demo.Owner")],
            4,
        )
        .unwrap();
        assert_eq!(code(c.finish()), "lenses.size", "{attribute}");
    }
}

#[test]
fn collector_enforces_memory_and_shape_boundaries() {
    let e = evidence();
    assert_eq!(code(Collector::new(&e, 65_535)), "resource.lenses");
    let empty = Collector::new(&e, 65_536).unwrap().finish().unwrap();
    assert_empty_collector_report(&empty);
    assert_owner_growth_memory_boundary(&e);
    assert_captured_annotation_memory_boundary();
    assert_shape_length_boundary(&e);
    assert_shape_depth_boundary(&e);
    assert_nested_argument_resource_rejection(&e);
}

fn assert_empty_collector_report(empty: &LensReport) {
    assert!(empty.owners.is_empty());
    assert_empty(&empty.xaml);
    assert_empty(&empty.serializers);
    assert_empty(&empty.repetitions);
    assert_empty(&empty.arguments);
    assert_empty(&empty.reflection);
    for field in [
        "owners",
        "xaml_groups",
        "serializer_contexts",
        "repeated_roots",
        "arguments",
        "reflection_annotations",
        "xaml_documents",
        "malformed_shapes",
        "tracked_aggregate_bytes",
    ] {
        assert_eq!(empty.coverage[field], 0, "{field}");
    }
}

fn owner_growth_report(e: &Evidence, memory: u64) -> Result<LensReport, AttributionError> {
    let mut c = Collector::new(e, memory)?;
    for i in 0..128 {
        c.observe(
            &entry("Methods", &format!("native_{i}"), 1, true),
            &candidate_owner(&format!("Owner{i:02}")),
            &[],
            i,
        )?;
    }
    c.finish()
}

fn assert_owner_growth_memory_boundary(e: &Evidence) {
    let reference = owner_growth_report(e, MEMORY).unwrap();
    let retained = reference.coverage["tracked_aggregate_bytes"]
        .as_u64()
        .unwrap();
    assert!(retained > 65_536);
    assert_eq!(code(owner_growth_report(e, 65_536)), "resource.lenses");
    assert_eq!(
        code(owner_growth_report(e, retained - 1)),
        "resource.lenses"
    );
    let report = owner_growth_report(e, retained).unwrap();
    assert_eq!(report.owners.len(), 128);
    assert_eq!(report.coverage["tracked_aggregate_bytes"], retained);
    for owner in &report.owners {
        assert_eq!(cost(&owner.cost), (1, 0, 1, 0, 0, 1, 0));
    }
}

fn assert_captured_annotation_memory_boundary() {
    // Unrecognized captured annotations consume budget without producing lens rows.
    let mut e = evidence();
    let mut s = source("Demo.Owner");
    s.attributes = vec!["a".repeat(32_768), "b".repeat(32_768)];
    e.sources.push(s);
    let reference = Collector::new(&e, MEMORY).unwrap().finish().unwrap();
    let retained = reference.coverage["tracked_aggregate_bytes"]
        .as_u64()
        .unwrap();
    assert!(retained > 65_536);
    for memory in [retained, retained - 1] {
        let result = Collector::new(&e, memory).unwrap().finish();
        if memory == retained {
            let report = result.unwrap();
            assert_eq!(report.coverage["tracked_aggregate_bytes"], retained);
            assert_empty(&report.serializers);
            assert_empty(&report.reflection);
        } else {
            assert_eq!(code(result), "resource.lenses");
        }
    }
}

fn assert_shape_length_boundary(e: &Evidence) {
    for length in [1 << 20, (1 << 20) + 1] {
        let mut c = Collector::new(e, 65_536).unwrap();
        let result = c.observe(
            &entry("Methods", &"x".repeat(length), 2, true),
            &candidate_owner("Short"),
            &[],
            39,
        );
        if length == 1 << 20 {
            result.unwrap();
            let report = c.finish().unwrap();
            assert_eq!(cost(&report.owners[0].cost), (2, 0, 2, 0, 0, 1, 0));
            assert_eq!(report.coverage["malformed_shapes"], 0);
            assert_empty(&report.arguments);
            assert_eq!(report.owners[0].examples[0].identity, "x".repeat(512));
            assert!(report.owners[0].examples[0].truncated);
        } else {
            assert_eq!(code(result), "resource.memory_limit");
        }
    }
}

fn assert_shape_depth_boundary(e: &Evidence) {
    for depth in [64, 65] {
        let name = format!("{}int{}", "Box<".repeat(depth), ">".repeat(depth));
        let mut c = Collector::new(e, MEMORY).unwrap();
        c.observe(
            &entry("Types", &name, 1, true),
            &candidate_owner("Short"),
            &[],
            40,
        )
        .unwrap();
        let report = c.finish().unwrap();
        assert_eq!(cost(&report.owners[0].cost), (1, 0, 0, 1, 0, 1, 0));
        if depth == 64 {
            assert_eq!(report.coverage["malformed_shapes"], 0);
            assert_eq!(report.arguments.len(), 64);
            assert_eq!(report.owners[0].generic_bytes, 1);
            assert_eq!(
                row(&report.arguments, "argument", "int")["additive_bytes"],
                1
            );
        } else {
            assert_eq!(report.coverage["malformed_shapes"], 1);
            assert_eq!(report.owners[0].generic_bytes, 0);
            assert_empty(&report.arguments);
        }
    }
}

fn assert_nested_argument_resource_rejection(e: &Evidence) {
    let siblings = (0..256)
        .map(|i| format!("Arg{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let name = format!("App_Box<List<>,List<int>,{siblings}>");
    for memory in [MEMORY, 65_536] {
        let mut c = Collector::new(e, memory).unwrap();
        let result = c.observe(
            &entry("Methods", &name, 13, true),
            &candidate_owner("Demo.Owner"),
            &[],
            41,
        );
        if memory == MEMORY {
            result.unwrap();
            let report = c.finish().unwrap();
            assert_eq!(report.coverage["malformed_shapes"], 1);
            assert_eq!(report.arguments.len(), 259);
            assert_eq!(cost(&report.owners[0].cost), (13, 0, 13, 0, 0, 1, 0));
            assert_eq!(report.owners[0].generic_bytes, 13);
            for argument in ["List<>", "List<int>", "int", "Arg0", "Arg31"] {
                assert_eq!(
                    row(&report.arguments, "argument", argument)["additive_bytes"],
                    13
                );
            }
        } else {
            assert_eq!(code(result), "resource.lenses");
        }
    }
}

#[test]
fn unknown_accounted_stream_charges_owner_without_fabricating_known_category() {
    let e = evidence();
    let stream = "Future\n\"Producer\tStream";
    let item = entry(stream, "UnknownProducerPayload", 17, true);
    let mut collector = Collector::new(&e, MEMORY).unwrap();
    collector
        .observe(&item, &candidate_owner("Demo.Owner"), &[], 42)
        .unwrap();
    let report = collector.finish().unwrap();
    assert_eq!(report.owners.len(), 1);
    let owner = &report.owners[0];
    assert_eq!(owner.assembly, "App");
    assert_eq!(owner.namespace, "Demo");
    assert_eq!(owner.owner, "Demo.Owner");
    assert_eq!(owner.evidence_tier, "source_name_candidate");
    assert_eq!(
        serde_json::to_value(&owner.cost).unwrap(),
        json!({
            "additive_bytes":17,"overlapping_bytes":0,
            "methods_bytes":0,"types_bytes":0,"blobs_bytes":0,
            "other_additive_bytes":17,"identities":1,"canonical_shared_identities":0
        })
    );
    assert_eq!(
        (
            owner.xaml_bytes,
            owner.serializer_bytes,
            owner.generic_bytes,
            owner.metadata_lower_bound_bytes
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        serde_json::to_value(&owner.examples).unwrap(),
        json!([{
            "ordinal":42,"bytes":17,"stream":stream,
            "identity":"UnknownProducerPayload","truncated":false
        }])
    );
}
