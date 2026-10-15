/* Original frontend tests: MIT, under the repository license. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const buckets = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "src", "explorer", "assets", "buckets.json"),
  "utf8"
));
const source = fs.readFileSync(
  path.join(__dirname, "..", "src", "explorer", "assets", "investigation.js"),
  "utf8"
).replace("/*VITNET_BUCKETS*/{}", JSON.stringify(buckets));
const investigation = vm.runInNewContext(source + "\nINVESTIGATION;", {});
// Normalize arrays from the isolated VM before structural comparison.
const columns = (dataset) => JSON.parse(JSON.stringify(investigation.columns(dataset)));

test("percentages_preserve_known_zero_and_unknown_denominators_without_capping_overlap", () => {
  for (const [value, total, expected] of [
    [0, 100, "0%"], [1, 100, "1%"], [1, 3, "33.33%"],
    [2, 3, "66.67%"], [100, 100, "100%"], [150, 100, "150%"],
    [1, 10000, "0.01%"], [1, 100000, "0%"],
    [null, 100, "Unknown"], [undefined, 100, "Unknown"], ["1", 100, "Unknown"],
    [NaN, 100, "Unknown"], [Infinity, 100, "Unknown"], [-1, 100, "Unknown"],
    [1, null, "Unknown"], [1, undefined, "Unknown"], [1, "100", "Unknown"],
    [1, NaN, "Unknown"], [1, Infinity, "Unknown"], [0, 0, "Unknown"],
    [1, 0, "Unknown"], [1, -100, "Unknown"]
  ]) assert.equal(investigation.percentage(value, total), expected, `${value}/${total}`);
});

test("storage_roles_separate_both_historical_and_manifest_containers_from_assets", () => {
  for (const storage of ["manifest_container", "avalonia_container"]) {
    assert.equal(investigation.storageRole(storage), "Container (overlaps children)");
  }
  for (const storage of ["asset", "", "Manifest_container", "manifest_container_extra", null, undefined]) {
    assert.equal(investigation.storageRole(storage), "Asset inventory", String(storage));
  }
});

test("compiler_buckets_use_pinned_producer_glossary_and_never_guess_unknown_names", () => {
  const root = "https://github.com/dotnet/runtime/blob/2eb7113245f7c536ab876dca5e3533fb96c81bbf/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/";
  const descriptions = {
    DehydratedData: "Encoded data used to reconstruct runtime structures, including pointer relocations and zero runs.",
    ResourceData: "A concatenation of embedded resources from compilation input assemblies.",
    Metadata: "Encoded NativeAOT metadata for retained types, methods, fields, signatures and constants.",
    TypeGenericDictionary: "Runtime lookup slots for a concrete generic type or method, used by shared canonical code.",
    MethodGenericDictionary: "Runtime lookup slots for a concrete generic type or method, used by shared canonical code.",
    ArrayOfFrozenObjects: "A compiler-produced segment containing preinitialized managed object data.",
    ReflectionInvokeMap: "Mappings from reflection metadata to generated method bodies.",
    ExternalReferencesTable: "Indexed references to compiler symbols used by runtime tables.",
    GenericMethodsHashtable: "A runtime hashtable describing compiled generic method instantiations."
  };
  for (const [name, title, file, view] of [
    ["DehydratedData", "Dehydrated runtime data", "DependencyAnalysis/DehydratedDataNode.cs", "Evidence"],
    ["ResourceData", "Embedded resource payloads", "DependencyAnalysis/ResourceDataNode.cs", "Resources"],
    ["Metadata", "Native reflection metadata", "MetadataManager.cs", "Evidence"],
    ["TypeGenericDictionary", "Generic dictionary", "DependencyAnalysis/GenericDictionaryNode.cs", "Amplification"],
    ["MethodGenericDictionary", "Generic dictionary", "DependencyAnalysis/GenericDictionaryNode.cs", "Amplification"],
    ["ArrayOfFrozenObjects", "Preinitialized frozen objects", "DependencyAnalysis/ArrayOfFrozenObjectsNode.cs", "Contributors"],
    ["ReflectionInvokeMap", "Reflection-to-method map", "DependencyAnalysis/ReflectionInvokeMapNode.cs", "Retention"],
    ["ExternalReferencesTable", "Runtime symbol references", "DependencyAnalysis/ExternalReferencesTableNode.cs", "Retention"],
    ["GenericMethodsHashtable", "Compiled generic-method lookup", "DependencyAnalysis/GenericMethodsHashtableNode.cs", "Amplification"]
  ]) {
    const bucket = investigation.bucket(name);
    assert.equal(bucket.title, title, name);
    assert.equal(bucket.source, root + file, name);
    assert.equal(bucket.view, view, name);
    assert.deepEqual(Object.keys(bucket).sort(), ["description", "investigation", "source", "title", "view"]);
    assert.equal(bucket.description, descriptions[name], name);
  }
  assert.match(investigation.bucket("ResourceData").investigation, /overlap or differ/);
  assert.match(investigation.bucket("Metadata").investigation, /lower bound, not exclusive source ownership/);
  assert.match(investigation.bucket("DehydratedData").investigation, /not a saving recommendation/);
  assert.match(investigation.bucket("ArrayOfFrozenObjects").investigation, /do not add/);
  assert.match(investigation.bucket("GenericMethodsHashtable").investigation, /does not itself prove why/);
  for (const name of ["TypeGenericDictionary", "MethodGenericDictionary"]) {
    assert.match(investigation.bucket(name).investigation, /identity counts alone do not measure/);
  }
  assert.match(investigation.bucket("ReflectionInvokeMap").investigation, /not a proven cause/);
  assert.match(investigation.bucket("ExternalReferencesTable").investigation, /neither bytes nor unique ownership/);
  for (const name of ["", "metadata", "ResourceDataExtra", "UnknownNode", "constructor", "__proto__", "toString"]) {
    assert.equal(investigation.bucket(name), null, name);
  }
});

test("domain_columns_name_recorded_evidence_and_preserve_supplemental_dataset_shapes", () => {
  for (const [dataset, expected] of [
    ["packages", [["id", "Package"], ["version", "Version"], ["target", "Target"], ["direct", "Direct"]]],
    ["assembly_links", [["assembly", "Assembly"], ["package", "Package"], ["target", "Target"], ["basis", "Origin evidence"]]],
    ["binaries", [["path", "Binary"], ["file_bytes", "Physical file bytes", "bytes"], ["architecture", "Architecture"]]],
    ["resources", [["assembly", "Assembly"], ["container", "Container"], ["name", "Resource"], ["bytes", "Recorded bytes", "bytes"], ["storage", "Storage"]]],
    ["resource_evidence", [["assembly", "Assembly"], ["name", "Resource"], ["bytes", "Recorded bytes", "bytes"], ["storage", "Storage"]]],
    ["package_routes", [["package", "Package"], ["target", "Target"], ["direct", "Direct"]]],
    ["assemblies", [["name", "Assembly"], ["package", "Recorded package"], ["path", "Recorded path"]]],
    ["sources", [["type_name", "Type"], ["member", "Member"], ["assembly", "Assembly"], ["path", "Source path"]]],
    ["metadata_largest_strings", [["text", "Captured text"], ["bytes", "Record lower bound", "bytes"], ["logical_offset", "Logical offset", "count"]]],
    ["generic_families", [["family", "Producer family"], ["stream", "Stream"], ["bytes", "Bytes", "bytes"], ["identities", "Identities", "count"], ["canonical_shared_identities", "Canonical/shared", "count"]]],
    ["opportunities", [["title", "Investigation"], ["kind", "Kind"], ["additive_bytes", "Additive cohort", "bytes"], ["overlapping_bytes", "Overlapping projection", "bytes"], ["identities", "Identities", "count"], ["evidence_tier", "Evidence"]]],
    ["budgets", [["name", "Budget"], ["dimension", "Dimension"], ["target", "Target"], ["additive_bytes", "Additive bytes", "bytes"], ["overlapping_bytes", "Overlapping projection", "bytes"], ["evidence_tier", "Evidence"]]],
    ["opportunity_coverage", [["accounted_bytes", "Accounted bytes", "bytes"], ["source_declarations", "Source declarations", "count"], ["generated_declarations", "Generated declarations", "count"], ["generator_outputs_captured", "Captured outputs", "count"], ["generator_links", "Trigger links", "count"], ["generator_execution_observed", "Execution observed", "count"]]],
    ["generator_runs", [["name", "Generator"], ["version", "Version"], ["target_assembly", "Target assembly"], ["status", "Capture status"], ["execution_status", "Execution evidence"], ["basis", "Basis"]]],
    ["generator_links", [["generator", "Generator"], ["output_path", "Output"], ["trigger_type", "Trigger type"], ["rule", "Link rule"], ["evidence_tier", "Evidence"]]],
    ["scopes", [["name", "Scope"], ["dimension", "Dimension"], ["stream", "Stream"], ["bytes", "Bytes", "bytes"], ["identities", "Identities", "count"]]],
    ["groups", [["name", "Partition"], ["dimension", "Dimension"], ["stream", "Stream"], ["bytes", "Bytes", "bytes"], ["identities", "Identities", "count"], ["status", "Evidence"]]],
    ["provenance", [["key", "Recorded fact"], ["value", "Value"]]],
    ["diagnostics", [["code", "Diagnostic"], ["path", "Input"]]],
    ["evidence_diagnostics", [["code", "Diagnostic"], ["path", "Input"]]]
  ]) {
    assert.deepEqual(columns(dataset), expected, dataset);
    assert.deepEqual(columns("supplemental_0_" + dataset), expected, dataset);
    assert.deepEqual(columns("supplemental_123_" + dataset), expected, dataset);
  }
  assert.deepEqual(columns("metadata_by_kind"), [["name", "Name"], ["bytes", "Lower-bound bytes", "bytes"]]);
  assert.deepEqual(columns("supplemental_1_metadata_by_type"), [["name", "Name"], ["bytes", "Lower-bound bytes", "bytes"]]);
  assert.deepEqual(columns("unknown_dataset"), []);
  assert.deepEqual(columns("supplemental_bad_packages"), []);
});

test("dataset_categories_preserve_supplemental_and_graph_precedence", () => {
  for (const [dataset, category] of [
    ["supplemental_0_resources", "Supplemental evidence"],
    ["supplemental_12_packages", "Supplemental evidence"],
    ["graph_resources", "Compiler graphs"], ["graph_nodes", "Compiler graphs"],
    ["resources", "Resources"], ["duplicate_assets", "Resources"],
    ["sources", "Source and package origins"], ["mappings", "Source and package origins"],
    ["assemblies", "Source and package origins"], ["assembly_links", "Source and package origins"],
    ["packages", "Source and package origins"], ["package_routes", "Source and package origins"],
    ["identities", "Code and patterns"], ["generic_families", "Code and patterns"],
    ["opportunities", "Code and patterns"], ["opportunity_coverage", "Code and patterns"],
    ["generator_runs", "Code and patterns"], ["generator_links", "Code and patterns"],
    ["budgets", "Size accounting"],
    ["generators", "Code and patterns"], ["metadata_largest_strings", "Size accounting"],
    ["mstat_summary", "Size accounting"], ["groups", "Size accounting"], ["scopes", "Size accounting"],
    ["binaries", "Size accounting"], ["comparison", "Size accounting"], ["provenance", "Build evidence"],
    ["unknown_dataset", "Build evidence"]
  ]) assert.equal(investigation.category(dataset), category, dataset);
});

test("progressive_scan_continues_empty_partial_batches_and_stops_at_public_boundaries", () => {
  for (const reason of ["scan_limit", "response_limit", "page_limit", undefined]) {
    for (const [count, limit] of [[0, 50], [1, 50], [49, 50], [0, 1]]) {
      assert.equal(investigation.progressiveStop({ stop_reason: reason }, "0", count, limit), false,
        `${reason}: ${count}/${limit}`);
    }
    // Numeric zero is also a live graph cursor, not an exhausted scan.
    assert.equal(investigation.progressiveStop({ stop_reason: reason }, 0, 0, 50), false);
  }
  for (const count of [50, 51]) {
    assert.equal(investigation.progressiveStop({ stop_reason: "scan_limit" }, "99", count, 50), true);
  }
  assert.equal(investigation.progressiveStop({ stop_reason: "scan_limit" }, "0", 1, 1), true);
  for (const cursor of [null, undefined]) {
    assert.equal(investigation.progressiveStop({ stop_reason: "scan_limit" }, cursor, 0, 50), true);
  }
  for (const reason of ["complete", "cancelled"]) {
    assert.equal(investigation.progressiveStop({ stop_reason: reason }, "99", 0, 50), true);
    assert.equal(investigation.progressiveStop({ stop_reason: reason }, "99", 49, 50), true);
  }
});

test("witness_navigation_keeps_live_annotations_bound_and_clears_them_for_offline_paths", () => {
  const app = fs.readFileSync(path.join(__dirname, "..", "src", "explorer", "assets", "app.js"), "utf8");
  const start = app.indexOf("  const applyWhy = function");
  const end = app.indexOf("  const why = function", start);
  assert.ok(start >= 0 && end > start, "production witness-navigation boundary");
  const renders = [], errors = [];
  const context = {
    data: { graphs: [{ generation: "graph-a", kind: "scan_index" }] },
    state: { graphKind: "scan_index", annotatedRetention: null },
    NODE_CAP: 200, EDGE_CAP: 500,
    array: value => Array.isArray(value) ? value : [],
    graphNode: value => value,
    setGraph: () => {}, renderInspector: () => {},
    showError: error => errors.push(error.message)
  };
  context.renderRetention = () => renders.push({
    witness: context.state.whyResult, annotation: context.state.annotatedRetention
  });
  const applyWhy = vm.runInNewContext(app.slice(start, end) + "\napplyWhy;", context);
  const live = { generation: "graph-a", node: { node_id: "7" }, paths: [] };
  const annotation = { witness: live, annotated_paths: [{ anchors: [{ node_id: "7" }] }] };
  applyWhy(live, annotation);
  assert.equal(renders[0].witness, live);
  assert.equal(renders[0].annotation, annotation);
  const offline = { generation: "graph-a", node: { node_id: "8" }, paths: [] };
  applyWhy(offline);
  assert.equal(renders[1].witness, offline);
  assert.equal(renders[1].annotation, null, "offline witness cannot inherit another node's annotations");
  applyWhy({ generation: "missing", paths: [] }, annotation);
  assert.equal(renders.length, 2, "unavailable generations cannot replace rendered evidence");
  assert.match(errors[0], /unavailable graph generation/);
  assert.equal(context.state.whyResult, offline);
  assert.equal(context.state.annotatedRetention, null);
});

  test("connected_lens_columns_preserve_cost_roles_and_explicit_ownership", () => {
    assert.deepEqual(columns("lens_costs"), [
      ["owner", "Declaring type"], ["methods_bytes", "Methods", "bytes"],
      ["types_bytes", "Types", "bytes"], ["blobs_bytes", "Blobs", "bytes"],
      ["metadata_lower_bound_bytes", "Metadata overlap", "bytes"],
      ["canonical_shared_identities", "Canonical markers", "count"]
    ]);
    assert.deepEqual(columns("lens_metadata_strings"), [
      ["text", "Captured string preview"], ["bytes", "Lower bound", "bytes"],
      ["role", "Role candidate"], ["ownership", "Ownership capture"],
      ["owner", "Selected metadata owner"]
    ]);
    for (const name of ["lens_xaml", "lens_serializers", "lens_repetitions", "lens_arguments", "lens_reflection"]) {
      assert.equal(investigation.category(name), "Connected investigations");
      assert.equal(columns(name).length > 0, true);
      assert.deepEqual(columns("supplemental_0_" + name), columns(name));
    }
  });

  test("feature_scanning_merges_disjoint_ledgers_without_turning_partial_results_into_totals", () => {
    const app = fs.readFileSync(path.join(__dirname, "..", "src", "explorer", "assets", "app.js"), "utf8");
    const start = app.indexOf("  const measureFeature = function");
    const end = app.indexOf("  const renderLenses = function", start);
    assert.ok(start >= 0 && end > start);
    const pending = [], rendered = [];
    const state = { featureRun: 7, tab: "Investigate", lens: "feature", feature: null };
    const context = {
      state,
      array: value => Array.isArray(value) ? value : [],
      query: (body, description, accept) => pending.push({ body, accept }),
      renderLenses: () => rendered.push(state.feature)
    };
    const measure = vm.runInNewContext(app.slice(start, end) + "\nmeasureFeature;", context);
    const selectors = { assembly: "App" };
    measure(selectors, null, 7, 1);
    pending.shift().accept({ ledger: { additive_bytes: 19, metadata_lower_bound_bytes: 3 },
      scanned: 4, matched_owner_groups: 1, entries: [{ owner: "A" }], examples: [{ ordinal: 0, bytes: 19 }],
      complete: false, next_after: "3", stop_reason: "timeout" });
    assert.equal(rendered[0].complete, false);
    assert.equal(pending[0].body.after, "3");
    pending.shift().accept({ ledger: { additive_bytes: 7, metadata_lower_bound_bytes: 2 },
      scanned: 5, matched_owner_groups: 1, entries: [{ owner: "B" }], examples: [{ ordinal: 1, bytes: 7 }],
      complete: true, next_after: null, stop_reason: "complete" });
    assert.equal(state.feature.ledger.additive_bytes, 26);
    assert.equal(state.feature.ledger.metadata_lower_bound_bytes, 5);
    assert.equal(state.feature.scanned, 9);
    assert.equal(state.feature.matched_owner_groups, 2);
    assert.equal(state.feature.complete, true);
    assert.equal(state.feature.examples[0].ordinal, 0);
    assert.equal(pending.length, 0);
    state.featureRun = 8;
    measure(selectors, null, 7, 1);
    pending.shift().accept({ ledger: { additive_bytes: 999 }, entries: [], examples: [], complete: true });
    assert.equal(state.feature.ledger.additive_bytes, 26, "stale selector run cannot replace the current footprint");
  });
