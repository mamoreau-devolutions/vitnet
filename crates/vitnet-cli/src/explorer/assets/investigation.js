/* Original frontend code: MIT, under the repository license. */
const INVESTIGATION = (function () {
  "use strict";
  const buckets = /*VITNET_BUCKETS*/{};
  const columns = {
    resources: [["assembly", "Assembly"], ["container", "Container"], ["name", "Resource"], ["bytes", "Recorded bytes", "bytes"], ["storage", "Storage"]],
    resource_evidence: [["assembly", "Assembly"], ["name", "Resource"], ["bytes", "Recorded bytes", "bytes"], ["storage", "Storage"]],
    package_routes: [["package", "Package"], ["target", "Target"], ["direct", "Direct"]],
    packages: [["id", "Package"], ["version", "Version"], ["target", "Target"], ["direct", "Direct"]],
    assemblies: [["name", "Assembly"], ["package", "Recorded package"], ["path", "Recorded path"]],
    assembly_links: [["assembly", "Assembly"], ["package", "Package"], ["target", "Target"], ["basis", "Origin evidence"]],
    generic_families: [["family", "Producer family"], ["stream", "Stream"], ["bytes", "Bytes", "bytes"], ["identities", "Identities", "count"], ["canonical_shared_identities", "Canonical/shared", "count"]],
    opportunities: [["title", "Investigation"], ["kind", "Kind"], ["additive_bytes", "Additive cohort", "bytes"], ["overlapping_bytes", "Overlapping projection", "bytes"], ["identities", "Identities", "count"], ["evidence_tier", "Evidence"]],
    budgets: [["name", "Budget"], ["dimension", "Dimension"], ["target", "Target"], ["additive_bytes", "Additive bytes", "bytes"], ["overlapping_bytes", "Overlapping projection", "bytes"], ["evidence_tier", "Evidence"]],
    opportunity_coverage: [["accounted_bytes", "Accounted bytes", "bytes"], ["source_declarations", "Source declarations", "count"], ["generated_declarations", "Generated declarations", "count"], ["generator_outputs_captured", "Captured outputs", "count"], ["generator_links", "Trigger links", "count"], ["generator_execution_observed", "Execution observed", "count"]],
    generator_runs: [["name", "Generator"], ["version", "Version"], ["target_assembly", "Target assembly"], ["status", "Capture status"], ["execution_status", "Execution evidence"], ["basis", "Basis"]],
    generator_links: [["generator", "Generator"], ["output_path", "Output"], ["trigger_type", "Trigger type"], ["rule", "Link rule"], ["evidence_tier", "Evidence"]],
    groups: [["name", "Partition"], ["dimension", "Dimension"], ["stream", "Stream"], ["bytes", "Bytes", "bytes"], ["identities", "Identities", "count"], ["status", "Evidence"]],
    scopes: [["name", "Scope"], ["dimension", "Dimension"], ["stream", "Stream"], ["bytes", "Bytes", "bytes"], ["identities", "Identities", "count"]],
    sources: [["type_name", "Type"], ["member", "Member"], ["assembly", "Assembly"], ["path", "Source path"]],
    binaries: [["path", "Binary"], ["file_bytes", "Physical file bytes", "bytes"], ["architecture", "Architecture"]],
    metadata_largest_strings: [["text", "Captured text"], ["bytes", "Record lower bound", "bytes"], ["logical_offset", "Logical offset", "count"]],
    provenance: [["key", "Recorded fact"], ["value", "Value"]],
    diagnostics: [["code", "Diagnostic"], ["path", "Input"]],
    evidence_diagnostics: [["code", "Diagnostic"], ["path", "Input"]]
  };
  function base(name) { return name.replace(/^supplemental_\d+_/, ""); }
  Object.assign(columns, {
    lens_feature_owners: [["owner", "Declaring type"], ["assembly", "Assembly"], ["additive_bytes", "Native footprint", "bytes"], ["evidence_tier", "Association"]],
    lens_costs: [["owner", "Declaring type"], ["methods_bytes", "Methods", "bytes"], ["types_bytes", "Types", "bytes"], ["blobs_bytes", "Blobs", "bytes"], ["metadata_lower_bound_bytes", "Metadata overlap", "bytes"], ["canonical_shared_identities", "Canonical markers", "count"]],
    lens_xaml: [["owner", "Owner / helper family"], ["assembly", "Assembly"], ["additive_bytes", "XAML cohort", "bytes"], ["input_association", "Input association"]],
    lens_serializers: [["context", "Context"], ["assembly", "Assembly"], ["additive_bytes", "Associated owners", "bytes"], ["evidence_tier", "Association"]],
    lens_repetitions: [["root", "Declared typeof root"], ["context_count", "Contexts", "count"], ["evidence_tier", "Evidence"]],
    lens_arguments: [["argument", "Producer argument"], ["additive_bytes", "Overlapping footprint", "bytes"], ["family_count", "Families", "count"]],
    lens_reflection: [["owner", "Declaring type"], ["member", "Member"], ["target", "Annotation target"], ["attribute", "Applied attribute"]],
    lens_metadata_strings: [["text", "Captured string preview"], ["bytes", "Lower bound", "bytes"], ["role", "Role candidate"], ["ownership", "Ownership capture"], ["owner", "Selected metadata owner"]]
  });
  function percentage(value, total) {
    if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0 || value < 0) return "Unknown";
    return (100 * value / total).toLocaleString("en-US", { maximumFractionDigits: 2 }) + "%";
  }
  function category(name) {
    if (name.startsWith("supplemental_")) return "Supplemental evidence";
    if (name.startsWith("graph_")) return "Compiler graphs";
    if (name.startsWith("lens_")) return "Connected investigations";
    if (/resource|duplicate/.test(name)) return "Resources";
    if (/source|mapping|assembl|package/.test(name)) return "Source and package origins";
    if (/identit|generic|generator|opportunit/.test(name)) return "Code and patterns";
    if (/metadata|mstat|group|scope|binar|comparison|budget/.test(name)) return "Size accounting";
    return "Build evidence";
  }
  return Object.freeze({
    percentage: percentage,
    category: category,
    columns: function (name) {
      return columns[base(name)] || (base(name).startsWith("metadata_by_") ? [["name", "Name"], ["bytes", "Lower-bound bytes", "bytes"]] : []);
    },
    storageRole: function (storage) { return ["manifest_container", "avalonia_container"].includes(storage) ? "Container (overlaps children)" : "Asset inventory"; },
    bucket: function (name) {
      const entry = Object.hasOwn(buckets, name) ? buckets[name] : null;
      return entry ? { title: entry.title, description: entry.description, investigation: entry.investigation, source: entry.source, view: entry.view } : null;
    },
    progressiveStop: function (result, cursor, count, limit) {
      return count >= limit || cursor == null || ["complete", "cancelled"].includes(result.stop_reason);
    }
  });
})();
