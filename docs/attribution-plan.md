# Generic build and source attribution

## Contract

Attribution is an evidence pipeline, not a decompiler or a savings estimator.
The Rust CLI remains usable without .NET. An optional local .NET collector
imports build, assembly, source, generator, PDB and resource evidence once.
Queries consume versioned persisted evidence and reuse existing immutable graph
generations; they never rebuild graphs or execute the analyzed application.

No product names or product-specific rules belong in this implementation.
Existing dirty work and attached graph services are preserved.

## Implementation sequence

1. Add a versioned evidence schema and bounded, atomic Rust import/cache layer.
   Record file fingerprints, revision/toolchain facts, availability and drift.
2. Implement the optional collector using local Roslyn, structured build logs,
   resolved package manifests, PE/ECMA-335 metadata and portable PDB documents.
   Do not build projects, run generators or load application assemblies.
3. Add package/dependency routes, source navigation and generator amplification.
   Exact supplied mappings and inferred candidates remain distinct. Ambiguous
   mappings and unavailable evidence are explicit, never silently assigned.
4. Add source-annotated retention using generation-guarded graph sessions,
   retaining original nodes/reasons and exposing alternate incoming edges.
5. Add nested generic-shape analysis and resource-container asset inventories.
   Distinct shapes are not source occurrence or native instantiation counts.
   Asset hashes establish duplicate content; equal lengths alone do not.
6. Add controlled-build comparison using existing full MSTAT differences,
   evidence/configuration changes and physical native file/section deltas.
7. Wire import/report/explain/compare commands, generic examples and CI.
8. Run requirement-mapped synthetic tests, local corpus/source imports where
   available, compatibility validation, formatting, linting and license policy.

## Evidence limits

- A recorded revision does not prove an otherwise clean source checkout.
- Producer labels are opaque. Name-derived source/assembly matches are candidates,
  not verified ownership; collisions remain ambiguous.
- Generated files can establish the emitter without proving the input annotation.
- Native PDBs and unsupported resource/native formats must be labelled unavailable,
  rather than parsed as portable PDBs or assigned zero bytes.
- Graph witnesses prove compiler retention, not runtime execution. Conjunctive
  prerequisites and incomplete traversals remain visible.
- Method/type/blob accounting is not a physical executable section sum.
- Missing physical evidence produces unknown deltas, not zero savings.
- Byte groups overlap. Mapping coverage is calculated against complete input
  accounting, independently of top-N display.

## Validation matrix

Each of the eight user-requested capabilities receives direct regression tests,
including empty, singleton, ambiguity, malformed/truncated input, resource
limits, deterministic ordering, stale evidence and unknown-versus-zero cases.
Test planning artifacts live outside the repository. Final command examples
must execute against synthetic data and a real local evidence import.
