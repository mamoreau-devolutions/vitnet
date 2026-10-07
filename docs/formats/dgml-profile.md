# NativeAOT DGML profile

`vitnet dgml stats` accepts the XML subset emitted by NativeAOT's dependency
graph writer. It processes the document with a pull parser and does not build
an XML DOM or retain labels or edges.

The expected document shape is:

```xml
<DirectedGraph xmlns="http://schemas.microsoft.com/vs/2009/dgml">
  <Nodes>
    <Node Id="0" Label="..." />
  </Nodes>
  <Links>
    <Link Source="0" Target="1" Reason="..." />
  </Links>
  <Properties>...</Properties>
</DirectedGraph>
```

NativeAOT assigns dense, zero-based decimal node IDs and writes all nodes
before links. Labels are opaque display strings; vitnet does not parse them as
a stable type or method grammar. Parallel links are counted independently.
`Reason=""` is valid for a root link. `Stroke` is only presentation data and
is not treated as a semantic category.

## Statistics

The `vitnet.dgml-stats.v1` JSON document contains:

- input byte, node, and edge counts;
- the maximum observed node ID;
- duplicate node IDs and link endpoints without a preceding node declaration;
- exact reason counts;
- an exact in-degree distribution;
- deterministic top-N node IDs by fan-in; and
- the peak memory charged to parser and aggregation state.

Rankings use descending fan-in and then ascending numeric node ID. Reason
counts use descending count and then ordinal UTF-8 bytes. The report stores
node IDs rather than labels so memory remains independent of label volume.

## Safety and resource behavior

The parser rejects DTDs and general entity references and never follows URLs or
filesystem references. It uses checked node-index arithmetic and reusable XML
buffers. Dense per-node state consists of one fan-in `u32` and one presence
bit, so memory is proportional to the maximum node ID rather than the XML file
size. `--memory-limit` is checked before growing this state.

Malformed XML and invalid/missing numeric IDs return exit code 3. A configured
memory limit returns exit code 5. The input is never modified and no cache or
temporary file is created by `stats`.

Generic DGML permits string IDs, mixed ordering, categories, and implicit
nodes. Those behaviors are intentionally outside this NativeAOT profile.
