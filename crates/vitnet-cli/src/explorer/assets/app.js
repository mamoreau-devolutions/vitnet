/* Original frontend code: MIT, under the repository license. */
(async function () {
  "use strict";
  const $ = function (id) { return document.getElementById(id); };
  const array = function (value) { return Array.isArray(value) ? value : []; };
  const str = function (value) { return value == null ? "Unknown" : String(value); };
  const number = function (value) { return typeof value === "number" && Number.isFinite(value) ? value : null; };
  const integer = function (value) { return number(value) == null ? "Unknown" : value.toLocaleString("en-US"); };
  const bytes = function (value) {
    if (number(value) == null) return "Unknown";
    const magnitude = Math.abs(value);
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    const exponent = magnitude > 0 ? Math.min(5, Math.floor(Math.log(magnitude) / Math.log(1024))) : 0;
    return (value / Math.pow(1024, exponent)).toLocaleString("en-US", { maximumFractionDigits: exponent ? 2 : 0 }) + " " + units[exponent];
  };
  const signedBytes = function (value) { return number(value) == null ? "Unknown" : (value > 0 ? "+" : "") + bytes(value); };
  const preview = function (value, limit) {
    const text = str(value);
    return text.length > limit ? text.slice(0, limit) + "…" : text;
  };
  const el = function (tag, attributes, children) {
    const node = document.createElement(tag);
    Object.entries(attributes || {}).forEach(function (entry) {
      const key = entry[0], value = entry[1];
      if (key === "text") node.textContent = str(value);
      else if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (key === "disabled" || key === "hidden") node[key] = Boolean(value);
      else if (value != null) node.setAttribute(key, str(value));
    });
    array(children).forEach(function (child) {
      if (child != null) node.append(child instanceof Node ? child : document.createTextNode(str(child)));
    });
    return node;
  };
  const svgEl = function (tag, attributes, children) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attributes || {}).forEach(function (entry) {
      if (entry[0] === "text") node.textContent = str(entry[1]);
      else node.setAttribute(entry[0], str(entry[1]));
    });
    array(children).forEach(function (child) { node.append(child); });
    return node;
  };
  const button = function (label, action, attributes) { return el("button", Object.assign({ type: "button", text: label, onclick: action }, attributes)); };
  const note = function (text) { return el("p", { class: "note", text: text }); };
  const warning = function (text) { return el("p", { class: "warning", text: text }); };
  const empty = function (text) { return el("p", { class: "empty", text: text }); };
  const field = function (label, control, grow) {
    control.setAttribute("aria-label", label);
    return el("label", { class: "field" + (grow ? " grow" : "") }, [el("span", { text: label }), control]);
  };
  const pairs = function (entries) {
    const list = el("dl");
    entries.forEach(function (entry) { list.append(el("dt", { text: entry[0] }), el("dd", { text: entry[1] })); });
    return list;
  };
  const select = function (options, value, change) {
    const control = el("select", { onchange: function () { change(control.value); } });
    options.forEach(function (option) { control.append(el("option", { value: option[0], text: option[1] })); });
    control.value = value;
    return control;
  };
  const table = function (headers, rows, caption) {
    const result = el("table");
    if (caption) result.append(el("caption", { text: caption }));
    result.append(el("thead", {}, [el("tr", {}, headers.map(function (heading) {
      return el("th", { scope: "col", text: heading.label || heading, class: heading.numeric ? "numeric" : "" });
    }))]));
    const body = el("tbody");
    rows.slice(0, 100).forEach(function (row) {
      const cells = Array.isArray(row) ? row : row.cells;
      body.append(el("tr", { class: row.selected ? "selected" : "" }, cells.map(function (cell, index) {
        return el("td", { class: headers[index] && headers[index].numeric ? "numeric" : "" }, [cell]);
      })));
    });
    result.append(body);
    return el("div", { class: "table-wrap" }, [result]);
  };
  const numeric = function (label) { return { label: label, numeric: true }; };
  const boundedJson = function (value) {
    let count = 0;
    const limited = function (item, depth) {
      if (++count > 200 || depth > 5) return "[Additional evidence omitted from this preview]";
      if (item == null || typeof item === "number" || typeof item === "boolean") return item;
      if (typeof item === "string") return preview(item, 1024);
      if (Array.isArray(item)) {
        const result = item.slice(0, 20).map(function (child) { return limited(child, depth + 1); });
        if (item.length > 20) result.push("[" + (item.length - 20) + " more items]");
        return result;
      }
      if (typeof item === "object") {
        const result = {};
        Object.entries(item).slice(0, 30).forEach(function (entry) {
          Object.defineProperty(result, entry[0], { enumerable: true, value: limited(entry[1], depth + 1) });
        });
        return result;
      }
      return str(item);
    };
    return JSON.stringify(limited(value, 0), null, 2);
  };
  let capability = null;
  try {
    capability = new URLSearchParams(window.location.hash.slice(1)).get("token");
    if (capability && !/^[a-fA-F0-9]+$/.test(capability)) capability = null;
    if (window.location.hash) history.replaceState(null, "", window.location.pathname + window.location.search);
  } catch (error) {
    $("error-status").hidden = false;
    $("error-status").textContent = "Could not clear the session fragment: " + error.message + ". Close this page and reopen from vitnet browse.";
    capability = null;
  }
  const data = SNAPSHOT;
  if (!data || data.schema !== "vitnet.explorer-snapshot.v1") {
    $("investigation").append(el("h2", { id: "view-title", text: "Snapshot unavailable" }), empty("This page has no supported embedded evidence. Prepare a bundle, then export or browse it again."));
    $("inspector").append(el("h2", { id: "inspector-title", text: "No evidence loaded" }));
    return;
  }
  if (data.bootstrap) {
    const unavailableBootstrap = function (message) {
      $("mode-label").textContent = "Live evidence unavailable";
      $("investigation").replaceChildren(el("h2", { id: "view-title", text: "Open a capability-bearing browse URL" }),
        empty(message), note("Run vitnet explore browse for the prepared bundle, then open its complete printed URL. The capability is read once, cleared from the address bar and never stored. To use a portable report, export an offline HTML snapshot."));
      $("inspector").replaceChildren(el("h2", { id: "inspector-title", text: "No private evidence loaded" }),
        note("The public page contains only rendering limits. No snapshot request is made without a valid session capability."));
      $("query-status").classList.remove("busy");
      $("cancel-query").hidden = true;
    };
    if (OFFLINE || !capability) {
      unavailableBootstrap(OFFLINE ? "This export contains a live bootstrap instead of offline evidence. Export the bundle again." :
        "This page has no valid live session capability. Private evidence has not been requested.");
      return;
    }
    $("mode-label").textContent = "Live · connecting";
    $("investigation").append(el("h2", { id: "view-title", text: "Loading local evidence" }),
      note("Fetching the bounded snapshot through the authenticated loopback endpoint. The full graph is never loaded."));
    $("inspector").append(el("h2", { id: "inspector-title", text: "Waiting for authenticated evidence" }));
    $("query-status").textContent = "Loading the authenticated snapshot · response budget 2 MiB…";
    $("query-status").classList.add("busy");
    const bootstrapController = new AbortController();
    const cancelBootstrap = function () { bootstrapController.abort(); };
    $("cancel-query").hidden = false;
    $("cancel-query").addEventListener("click", cancelBootstrap);
    try {
      const response = await fetch("/api/snapshot", {
        method: "POST", headers: { Authorization: "Bearer " + capability, "Content-Type": "application/json" },
        body: "{}", signal: bootstrapController.signal, cache: "no-store", credentials: "omit", redirect: "error"
      });
      const actualSnapshot = await readJson(response, bootstrapController);
      if (bootstrapController.signal.aborted) throw new Error("Snapshot loading was cancelled.");
      if (!actualSnapshot || actualSnapshot.schema !== "vitnet.explorer-snapshot.v1" || actualSnapshot.bootstrap || typeof actualSnapshot.generation !== "string") {
        throw new Error("The server returned an unsupported or incomplete explorer snapshot.");
      }
      Object.assign(SNAPSHOT, actualSnapshot);
      delete SNAPSHOT.bootstrap;
    } catch (error) {
      const message = bootstrapController.signal.aborted ? "Authenticated snapshot loading was cancelled or exceeded its response budget. Reopen the browse URL to retry." :
        "Authenticated snapshot could not be loaded: " + error.message + " Reopen the browse URL or restart vitnet explore browse.";
      $("error-status").hidden = false;
      $("error-status").textContent = message;
      unavailableBootstrap(message);
      return;
    } finally {
      $("cancel-query").removeEventListener("click", cancelBootstrap);
      $("cancel-query").hidden = true;
    }
  }
  let live = !OFFLINE && Boolean(capability);
  const limits = data.limits || {};
  const PAGE = Math.min(100, Math.max(1, number(limits.page_rows) || 100));
  const NODE_CAP = Math.min(200, Math.max(1, number(limits.graph_nodes) || 200));
  const EDGE_CAP = Math.min(500, Math.max(1, number(limits.graph_edges) || 500));
  const tabs = ["Landscape", "Contributors", "Retention", "Amplification", "Resources", "Dependencies", "Comparison", "Evidence"];
  const state = {
    tab: "Landscape", dimension: "assembly", stream: "", assembly: "", owner: "", landscapeGroup: null, contains: "",
    rows: null, rowCursor: null, rowPage: 0, rowResult: null,
    detail: null, pending: null, sequence: 0, requestCounter: 0,
    graphKind: array(data.graphs)[0] ? str(data.graphs[0].kind) : "scan_index",
    graphQuery: "", graphMode: "contains", searchResult: null, searchCursor: null,
    graphNodes: [], graphEdges: [], selectedNode: null, incomingResult: null, whyResult: null,
    graphNotice: "", layoutSequence: 0, layout: null, worker: null, graphNodePage: 0, graphEdgePage: 0,
    resourceFilter: "", resourceAssembly: "", resourceContainer: "", resourcePage: 0,
    familyStream: "", familySort: "bytes", familyPage: 0, routePage: 0,
    comparisonSection: 0, comparisonPage: 0, witnessIndex: 0
  };
  const setStatus = function (text, busy) {
    $("query-status").textContent = text;
    $("query-status").classList.toggle("busy", Boolean(busy));
  };
  const showError = function (error) {
    $("error-status").hidden = false;
    $("error-status").textContent = error.message || str(error);
  };
  const clearError = function () { $("error-status").hidden = true; $("error-status").textContent = ""; };
  const unavailable = function () {
    return OFFLINE ? "Offline snapshot: full-cache search and new retention queries are unavailable. Use vitnet explore browse with this bundle for live queries." :
      "No live capability is available. Reopen the URL printed by vitnet explore browse; the token is never stored.";
  };
  const refreshBudget = function () {
    $("render-budget").textContent = "Tables ≤ " + PAGE + " rows/page · witness sheet ≤ " + NODE_CAP + " nodes / " + EDGE_CAP + " edges";
  };
  async function readJson(response, controller) {
    const limit = 2 * 1024 * 1024;
    if (Number(response.headers.get("Content-Length")) > limit) {
      controller.abort();
      throw new Error("Response exceeded the 2 MiB budget. Narrow the query and retry.");
    }
    let text;
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader(), decoder = new TextDecoder();
      let length = 0;
      const parts = [];
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        length += chunk.value.byteLength;
        if (length > limit) {
          controller.abort();
          throw new Error("Response exceeded the 2 MiB budget. Narrow the query and retry.");
        }
        parts.push(decoder.decode(chunk.value, { stream: true }));
      }
      parts.push(decoder.decode());
      text = parts.join("");
    } else {
      text = await response.text();
      if (new TextEncoder().encode(text).byteLength > limit) throw new Error("Response exceeded the 2 MiB budget. Narrow the query and retry.");
    }
    let result;
    try { result = JSON.parse(text); }
    catch (_) { throw new Error("Server returned invalid JSON (HTTP " + response.status + "). Reopen the bundle with vitnet explore browse."); }
    if (!response.ok || result.error) {
      const problem = result.error || {};
      throw new Error(str(problem.code || "HTTP " + response.status) + ": " + str(problem.message || response.statusText) +
        ". Narrow and retry; if the evidence generation changed, prepare and reopen the bundle.");
    }
    return result;
  }
  const post = async function (path, body, controller) {
    const response = await fetch(path, {
      method: "POST", headers: { Authorization: "Bearer " + capability, "Content-Type": "application/json" },
      body: JSON.stringify(body), signal: controller.signal, cache: "no-store", credentials: "omit", redirect: "error"
    });
    if (path !== "/api/query" && response.ok && (response.status === 204 || response.headers.get("Content-Length") === "0")) return {};
    return readJson(response, controller);
  };
  const cancel = function (quiet) {
    const pending = state.pending;
    if (!pending) return;
    state.pending = null;
    state.sequence++;
    if (state.detail && state.detail.loading) state.detail.loading = false;
    pending.controller.abort();
    $("cancel-query").hidden = true;
    if (!quiet) setStatus("Query cancelled. The current bounded page is unchanged.", false);
    post("/api/cancel", { request_id: pending.id }, new AbortController()).catch(function (error) {
      showError(new Error("Browser request was cancelled, but backend cancellation failed: " + error.message));
    });
  };
  const query = async function (body, description, accept) {
    if (!live) { showError(new Error(unavailable())); return; }
    cancel(true);
    clearError();
    const sequence = ++state.sequence;
    const id = "v" + Date.now().toString(36) + (++state.requestCounter).toString(36);
    const controller = new AbortController();
    state.pending = { id: id, controller: controller, sequence: sequence };
    $("cancel-query").hidden = false;
    setStatus(description + " · bounded scan, up to " + integer(limits.query_timeout_ms || 1500) + " ms", true);
    try {
      const result = await post("/api/query", Object.assign({ request_id: id, generation: data.generation }, body), controller);
      if (!state.pending || state.pending.id !== id || sequence !== state.sequence) return;
      if (result.generation && result.generation !== data.generation) {
        const graph = array(data.graphs).find(function (entry) { return entry.kind === body.graph; });
        if (!graph || result.generation !== graph.generation) throw new Error("Evidence generation mismatch. Prepare and reopen the bundle; no stale results were applied.");
      }
      state.pending = null;
      $("cancel-query").hidden = true;
      setStatus("Query completed.", false);
      accept(result);
      refreshBudget();
    } catch (error) {
      if (!state.pending || state.pending.id !== id || sequence !== state.sequence) return;
      state.pending = null;
      $("cancel-query").hidden = true;
      if (controller.signal.aborted) {
        post("/api/cancel", { request_id: id }, new AbortController()).catch(function (cancelError) {
          showError(new Error("Backend cancellation failed: " + cancelError.message));
        });
      }
      showError(new Error(error.message + " The previous page remains available."));
      setStatus("Query failed; no results applied.", false);
      if (state.detail && state.detail.loading) { state.detail.loading = false; renderInspector(); }
    }
  };
  const resultSummary = function (result, noun) {
    if (!result) return "";
    return str(result.stop_reason) + " · scanned " + integer(result.scanned == null ? result.scanned_nodes : result.scanned) +
      " " + noun + " · " + integer(result.elapsed_ms) + " ms";
  };
  const heading = function (title, description) {
    const panel = $("investigation");
    panel.replaceChildren(el("h2", { id: "view-title", text: title }), note(description));
    return panel;
  };
  const activate = function (tab) {
    cancel(false);
    clearError();
    state.tab = tab;
    if (tab !== "Retention") {
      state.searchResult = null;
      state.graphNodes = []; state.graphEdges = []; state.layout = null; state.layoutSequence++;
      state.incomingResult = null; state.whyResult = null; state.selectedNode = null;
    }
    renderTabs(); renderScope(); renderView(); renderInspector();
  };
  const renderTabs = function () {
    $("tabs").replaceChildren(...tabs.map(function (tab) {
      return button(tab, function () { activate(tab); }, { "aria-current": state.tab === tab ? "page" : null });
    }));
  };
  const renderScope = function () {
    const bar = $("scope-bar");
    bar.replaceChildren(el("strong", { text: "Contributor scope" }), el("span", { text: state.stream || "All additive streams" }), el("span", { text: "›" }),
      el("span", { text: state.assembly ? "Assembly: " + state.assembly : state.owner ? "Opaque owner: " + state.owner : "All assemblies / owners" }));
    if (state.stream || state.assembly || state.owner) bar.append(button("Clear scope", function () {
      cancel(false); state.stream = ""; state.assembly = ""; state.owner = ""; state.landscapeGroup = null;
      state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
      renderScope(); renderView();
    }));
    if (state.assembly && state.tab === "Contributors") bar.append(el("span", { class: "note", text: "Assembly is attribution evidence, not an identity-string filter." }));
    if (state.owner && state.tab === "Contributors") bar.append(el("span", { class: "note", text: "Owner is an opaque producer prefix, not a demangled namespace." }));
    if (state.contains && ["Landscape", "Contributors"].includes(state.tab)) bar.append(el("span", { class: "note", text: "Contributor text filter: " + state.contains }));
    if (!["Landscape", "Contributors"].includes(state.tab)) bar.append(el("span", { class: "note", text: "This view has its own explicitly labelled scope." }));
  };
  const chooseGroup = function (group) {
    cancel(false);
    state.stream = str(group.stream);
    if (group.dimension === "assembly") { state.assembly = str(group.name); state.owner = ""; }
    else { state.owner = str(group.name); state.assembly = ""; }
    state.landscapeGroup = group;
    state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
    state.detail = { kind: "group", value: group };
    activate("Landscape");
  };
  const zoomStream = function (stream) {
    cancel(false); state.stream = stream; state.assembly = ""; state.owner = ""; state.landscapeGroup = null;
    state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
    renderScope(); renderLandscape();
  };
  const icicle = function (name, total, children, rootAction) {
    const width = Math.min(740, Math.max(240, window.innerWidth - 70)), rowHeight = 40;
    const svg = svgEl("svg", { class: "icicle", viewBox: "0 0 " + width + " 84", role: "group",
      "aria-label": "Bounded byte icicle: " + name + ". Child rectangle widths measure bytes within this root only. Exact values are in the table below." });
    const rectangle = function (label, value, x, y, rectWidth, action, kind) {
      const group = svgEl("g", { class: "icicle-node " + (kind || ""), role: action ? "button" : "img",
        tabindex: action ? "0" : "-1", "aria-label": label + ", " + integer(value) + " bytes" + (action ? ", zoom or inspect" : "") });
      if (action) {
        group.addEventListener("click", action);
        group.addEventListener("keydown", function (event) { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); action(); } });
      }
      group.append(svgEl("rect", { x: x, y: y, width: Math.max(0, rectWidth), height: rowHeight }),
        svgEl("title", { text: label + " · " + integer(value) + " bytes" }));
      if (rectWidth > 65) group.append(svgEl("text", { x: x + 8, y: y + 25, text: preview(label, Math.max(5, Math.floor((rectWidth - 16) / 7))) }));
      svg.append(group);
    };
    rectangle(name + " · " + bytes(total), total, 0, 0, width, rootAction, "root");
    if (total > 0) {
      let x = 0;
      children.forEach(function (child) {
        const partWidth = Math.min(width - x, Math.max(0, (number(child.bytes) || 0) / total * width));
        if (partWidth > 0) rectangle(child.name, child.bytes, x, 44, partWidth, child.action, child.other ? "other" : "");
        x += partWidth;
      });
    }
    return svg;
  };
  const renderLandscape = function () {
    const panel = heading("Accounted landscape", "Partitions reconcile only within one dimension and one stream. Resource, metadata, generic and generator projections can overlap these budgets.");
    panel.append(el("div", { class: "toolbar" }, [field("Partition dimension", select([["assembly", "Assembly attribution"], ["owner", "Identity owner"]], state.dimension, function (value) {
      cancel(false); state.dimension = value; state.assembly = ""; state.owner = ""; state.landscapeGroup = null;
      state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null; renderScope(); renderLandscape();
    }))]));
    const allGroups = array(data.groups).filter(function (group) { return group.dimension === state.dimension && (!state.stream || group.stream === state.stream); });
    const streams = array((data.accounting || {}).streams).filter(function (stream) { return !state.stream || stream.name === state.stream; });
    const shownGroups = allGroups.slice(0, Math.max(0, Math.min(PAGE, 100 - 2 * streams.length)));
    const selected = state.landscapeGroup && state.landscapeGroup.dimension === state.dimension && state.landscapeGroup.stream === state.stream ? state.landscapeGroup : null;
    const breadcrumb = el("nav", { class: "landscape-breadcrumb", "aria-label": "Byte icicle zoom breadcrumb" }, [
      button("All streams", function () { zoomStream(""); }, { class: "link-button", "aria-current": !state.stream ? "location" : null })
    ]);
    if (state.stream) breadcrumb.append(el("span", { text: "›" }), button(state.stream, function () { zoomStream(state.stream); },
      { class: "link-button", "aria-current": !selected ? "location" : null }));
    if (selected) breadcrumb.append(el("span", { text: "›" }), el("span", { text: state.dimension + ": " + str(selected.name), "aria-current": "location" }));
    panel.append(breadcrumb, note("Zoomable bounded icicle · click a stream root, then a partition; use the breadcrumb to zoom out. Each root has its own byte scale. At most 100 rectangles are rendered; tables provide the same selection and exact values."));
    if (selected) {
      const total = number(selected.bytes);
      const rows = localRows().filter(function (row) { return row.accounted; }).slice(0, Math.min(PAGE, 98));
      const sum = rows.reduce(function (result, row) { return result + (number(row.bytes) || 0); }, 0);
      panel.append(el("h3", { text: str(selected.name) + " · " + bytes(total) }));
      if (total != null && total > 0 && sum <= total) {
        const children = rows.map(function (row) { return { name: preview(row.identity, 512), bytes: row.bytes, action: function () { chooseRow(row); } }; });
        if (sum < total) children.push({ name: "Other / not displayed", bytes: total - sum, other: true });
        panel.append(icicle(str(selected.name), total, children, function () { zoomStream(state.stream); }));
      }
      if (total != null && sum > total) panel.append(warning("Bundled preview matches exceed this aggregate. No child byte partition is drawn; use live exact filtering to resolve the scope."));
      panel.append(note("Zoom scope: " + state.stream + " › " + state.dimension + ": " + str(selected.name) +
        ". Child contributors use best-effort bundled identity/source previews; truncated or missing source evidence can omit matches. Other / not displayed: " +
        bytes(total == null ? null : Math.max(0, total - sum)) + ". No ownership is fabricated for this remainder."));
      panel.append(button("Inspect scoped contributors", function () { activate("Contributors"); }));
      if (rows.length) panel.append(table(["Contributor preview", "Stream", numeric("Bytes")], rows.map(function (row) {
        return [button(preview(row.identity, 512), function () { chooseRow(row); }, { class: "link-button" }), row.stream, integer(row.bytes)];
      }), "Best-effort bounded children within the selected partition; not a complete source-attribution query."));
      else panel.append(empty("No bundled contributor preview can be placed within this partition. Its complete aggregate remains measured."));
    } else {
    if (!streams.length) panel.append(empty("No additive stream accounting was supplied."));
    streams.forEach(function (stream) {
      const groups = shownGroups.filter(function (group) { return group.stream === stream.name; });
      const total = number(stream.bytes);
      const sum = groups.reduce(function (result, group) { return result + (number(group.bytes) || 0); }, 0);
      const section = el("div", { class: "budget-row" }, [
        el("div", { class: "budget-heading" }, [el("strong", { text: stream.name }), el("span", { text: bytes(total) + " · " + integer(stream.identities) + " identities" })])
      ]);
      if (total != null && total > 0 && sum <= total) {
        const children = groups.map(function (group) { return { name: str(group.name), bytes: group.bytes, action: function () { chooseGroup(group); } }; });
        const remainder = Math.max(0, total - sum);
        if (remainder) children.push({ name: "Other / not displayed", bytes: remainder, other: true });
        section.append(icicle(str(stream.name), total, children, function () { zoomStream(str(stream.name)); }));
      }
      section.append(note("Other / not displayed: " + bytes(total == null ? null : Math.max(0, total - sum)) +
        ". This remainder is not assigned fabricated ownership."));
      if (total != null && sum > total) section.append(warning("Displayed groups exceed the stream total. These groups cannot be treated as a valid additive partition."));
      panel.append(section);
    });
    if (shownGroups.length) panel.append(table(["Stream", "Partition", numeric("Bytes"), numeric("Identities"), "Evidence status"],
      shownGroups.map(function (group) { return [button(group.stream, function () { zoomStream(str(group.stream)); }, { class: "link-button" }),
        button(preview(group.name, 200), function () { chooseGroup(group); }, { class: "link-button" }), integer(group.bytes), integer(group.identities), group.status]; }),
      "Bounded partition projection: " + shownGroups.length + " of " + allGroups.length + " bundled groups. Buttons zoom the icicle and narrow contributor scope."));
    else panel.append(empty("No groups supplied for this dimension. Stream totals remain authoritative."));
    }
    const accounting = data.accounting || {};
    if (accounting.methods) panel.append(pairs([
      ["Method bodies", bytes(accounting.methods.body_bytes)], ["GC information", bytes(accounting.methods.gc_info_bytes)],
      ["Exception information", bytes(accounting.methods.exception_info_bytes)]
    ]));
    panel.append(note("Metadata lower bound: " + bytes(accounting.metadata_lower_bound_bytes) + " (overlapping projection; not added to stream totals)."));
    const coverage = data.coverage || {};
    panel.append(pairs([["Displayed accounted contributors", bytes(coverage.displayed_accounted_bytes)], ["Remaining accounted contributors", bytes(coverage.remaining_accounted_bytes)],
      ["Contributor coverage", integer(coverage.contributors_shown) + " shown / " + integer(coverage.identities) + " cache identities"]]));
  };
  const rowAssemblies = function (row) {
    const detail = data.details && data.details[String(row.ordinal)];
    const match = detail && detail.sources;
    const assemblies = array(match && match.assemblies).map(function (entry) { return typeof entry === "string" ? entry : str(entry.name || entry.assembly); });
    return assemblies;
  };
  const localAssemblyMatch = function (row) {
    if (!state.assembly) return true;
    if (row.identity_lossy) return state.assembly === "_unmapped";
    const detail = data.details && data.details[String(row.ordinal)];
    if (!detail || !detail.sources) return false;
    const assemblies = rowAssemblies(row);
    return assemblies.length === 1 ? assemblies[0] === state.assembly : assemblies.length === 0 ? state.assembly === "_unmapped" : state.assembly === "_ambiguous";
  };
  const previewOwner = function (row) {
    return str(row.identity).split("__", 1)[0].split("<", 1)[0];
  };
  const localRows = function () {
    return array(data.contributors).filter(function (row) {
      return (!state.stream || row.stream === state.stream) && localAssemblyMatch(row) && (!state.owner || previewOwner(row) === state.owner) &&
        (!state.contains || str(row.identity).toLowerCase().includes(state.contains.toLowerCase()));
    });
  };
  const fetchRows = function (after) {
    query({ action: "rows", contains: state.contains, stream: state.stream || null, assembly: state.assembly || null, owner: state.owner || null,
      after: after, limit: PAGE }, "Searching the identity cache", function (result) {
      state.rows = array(result.entries).slice(0, PAGE); state.rowCursor = result.next_after == null ? null : result.next_after; state.rowResult = result;
      renderContributors();
      setStatus(resultSummary(result, "identities"), false);
    });
  };
  const chooseRow = function (row) {
    cancel(false);
    clearError();
    const offlineDetail = data.details && data.details[String(row.ordinal)];
    state.detail = { kind: "row", value: row, source: offlineDetail || null, loading: live };
    renderInspector();
    if (live) query({ action: "source", ordinal: row.ordinal }, "Loading source candidates", function (result) {
      state.detail = { kind: "row", value: result.row || row, source: result, loading: false };
      renderInspector();
      setStatus("Source evidence loaded; emitter candidates are not compiler retainers.", false);
    });
    else setStatus("Inspecting bundled source evidence. No full-cache query was made.", false);
  };
  const renderContributors = function () {
    const panel = heading("Contributors", "Live pages are in cache-ordinal order, not global size order. Snapshot rankings are a bounded display projection; accounted=false entries do not add to the byte budget.");
    const search = el("input", { type: "search", maxlength: "2048", value: state.contains, placeholder: "Contains identity text" });
    const streamOptions = [["", "All streams"]].concat(array((data.accounting || {}).streams).map(function (entry) { return [str(entry.name), str(entry.name)]; }));
    const searchForm = el("form", { class: "toolbar", onsubmit: function (event) {
      event.preventDefault(); state.contains = search.value; state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
      renderScope();
      if (live) fetchRows(null); else renderContributors();
    } }, [
      field("Identity filter", search, true),
      field("Stream", select(streamOptions, state.stream, function (value) {
        cancel(false); state.stream = value; state.landscapeGroup = null; state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null; renderScope(); renderContributors();
      })),
      el("button", { type: "submit", text: live ? "Search full cache" : "Filter snapshot subset" })
    ]);
    panel.append(searchForm);
    if (!live) panel.append(note(unavailable() + " The filter above searches only bundled previews, not omitted text or the complete cache."));
    const local = state.rows === null;
    if (state.assembly || state.owner) panel.append(note(local ?
      "Snapshot scope is best-effort: assembly matching uses bundled source assembly previews; owner matching uses the opaque prefix before '__', then before '<'. Missing or truncated identity/source previews can omit matches. Live search applies these filters against complete evidence." :
      "Live assembly / opaque-owner filters were applied against complete identity and located assembly evidence, not the displayed previews."));
    const projection = local ? localRows() : state.rows;
    const rows = local ? projection.slice(state.rowPage * PAGE, (state.rowPage + 1) * PAGE) : projection;
    if (rows.length) panel.append(table(["Identity preview", "Stream", numeric("Bytes"), numeric("Records"), "Accounting", numeric("Ordinal")],
      rows.map(function (row) {
        const identity = el("div", {}, [button(preview(row.identity, 512), function () { chooseRow(row); }, { class: "link-button" })]);
        if (row.truncated || row.identity_lossy) identity.append(note((row.truncated ? "Truncated · " + integer(row.identity_bytes) + " original bytes" : "") + (row.identity_lossy ? " · lossy UTF-8 preview" : "")));
        return { selected: Boolean(state.detail && state.detail.kind === "row" && state.detail.value.ordinal === row.ordinal),
          cells: [identity, row.stream, integer(row.bytes), integer(row.records), row.accounted ? "Additive" : "Non-additive / unaccounted", integer(row.ordinal)] };
      }), local ? "Bounded snapshot contributor subset · " + projection.length + " matching bundled rows" : "Current cache-ordinal page only; previous pages are discarded"));
    else panel.append(empty(local ? "No bundled preview matches this scope. This does not prove the full cache has no match." : "No matches in this scan batch. A partial batch can still have a continuation cursor."));
    const pager = el("div", { class: "pagination" });
    if (local) {
      pager.append(el("span", { text: "Snapshot subset · page " + (state.rowPage + 1) }), el("div", {}, [
        button("Previous", function () { state.rowPage--; renderContributors(); }, { disabled: state.rowPage === 0 }),
        button("Next subset page", function () { state.rowPage++; renderContributors(); }, { disabled: (state.rowPage + 1) * PAGE >= projection.length })
      ]));
    } else {
      pager.append(el("span", { text: resultSummary(state.rowResult, "identities") }), el("div", {}, [
        button("Restart", function () { fetchRows(null); }),
        button("Next / continue scan", function () { fetchRows(state.rowCursor); }, { disabled: state.rowCursor == null })
      ]));
      if (state.rowCursor != null) panel.append(note("Continuation available, including after an empty partial page. Continuing replaces this page; it never appends a growing result history."));
    }
    panel.append(pager);
  };
  const graphNode = function (node) {
    return {
      node_id: str(node.node_id == null ? node.id : node.node_id), label: str(node.label),
      label_bytes: node.label_bytes, truncated: Boolean(node.truncated), incoming_edges: node.incoming_edges,
      missing: Boolean(node.missing)
    };
  };
  const resetGraph = function () {
    cancel(false); state.graphNodes = []; state.graphEdges = []; state.layout = null; state.layoutSequence++;
    state.selectedNode = null; state.incomingResult = null; state.whyResult = null; state.graphNotice = ""; state.graphNodePage = 0; state.graphEdgePage = 0;
    renderRetention();
  };
  const setGraph = function (nodes, edges, selected) {
    const map = new Map();
    array(nodes).forEach(function (node) { const normalized = graphNode(node); if (map.size < NODE_CAP || map.has(normalized.node_id)) map.set(normalized.node_id, normalized); });
    state.graphNodes = Array.from(map.values());
    state.graphEdges = array(edges).slice(0, EDGE_CAP).map(function (edge) {
      return Object.assign({}, edge, { source_id: str(edge.source_id), target_id: str(edge.target_id) });
    }).filter(function (edge) { return map.has(edge.source_id) && map.has(edge.target_id); });
    state.selectedNode = selected == null ? null : str(selected);
    state.graphNodePage = 0; state.graphEdgePage = 0;
    state.layout = null;
    const message = { sequence: ++state.layoutSequence, selected: state.selectedNode,
      nodes: state.graphNodes.map(function (node) { return { id: node.node_id }; }),
      edges: state.graphEdges.map(function (edge) { return { source: edge.source_id, target: edge.target_id }; }) };
    if (state.worker) {
      try { state.worker.postMessage(message); }
      catch (error) { state.worker.terminate(); state.worker = null; state.graphNotice = "Layout worker unavailable: " + error.message + ". Using bounded deterministic fallback."; fallbackLayout(message); }
    } else fallbackLayout(message);
  };
  const fallbackLayout = function (message) {
    const ids = new Set(message.nodes.map(function (node) { return node.id; }));
    const levels = new Map(), incoming = new Map();
    message.nodes.forEach(function (node) { incoming.set(node.id, []); });
    message.edges.forEach(function (edge) { if (ids.has(edge.source) && ids.has(edge.target)) incoming.get(edge.target).push(edge.source); });
    const queue = [];
    if (ids.has(message.selected)) { levels.set(message.selected, 0); queue.push(message.selected); }
    for (let index = 0; index < queue.length; index++) {
      const id = queue[index];
      incoming.get(id).slice().sort().forEach(function (parent) { if (!levels.has(parent)) { levels.set(parent, levels.get(id) + 1); queue.push(parent); } });
    }
    const layers = new Map();
    message.nodes.slice().sort(function (a, b) { return a.id < b.id ? -1 : a.id > b.id ? 1 : 0; }).forEach(function (node) {
      const level = levels.get(node.id) || 0;
      if (!layers.has(level)) layers.set(level, []);
      layers.get(level).push(node);
    });
    const maximum = Math.max(0, ...layers.keys()), positions = [];
    let height = 140;
    layers.forEach(function (layer, level) {
      height = Math.max(height, layer.length * 74 + 30);
      layer.forEach(function (node, index) { positions.push({ id: node.id, x: 20 + (maximum - level) * 250, y: 20 + index * 74 }); });
    });
    state.layout = { sequence: message.sequence, nodes: positions, width: (maximum + 1) * 250 + 20, height: height };
  };
  const chooseNode = function (node) {
    cancel(false);
    const normalized = graphNode(node);
    state.selectedNode = normalized.node_id;
    state.detail = { kind: "node", value: normalized };
    state.incomingResult = null; state.whyResult = null;
    renderRetention(); renderInspector();
  };
  const searchGraph = function (after) {
    query({ action: "graph_search", graph: state.graphKind, query: state.graphQuery, mode: state.graphMode, after_id: after }, "Searching the immutable graph index", function (result) {
      state.searchResult = Object.assign({}, result, { entries: array(result.entries).slice(0, 50).map(graphNode) });
      state.searchCursor = result.next_after_id == null ? null : String(result.next_after_id);
      renderRetention(); setStatus(resultSummary(result, "nodes"), false);
    });
  };
  const incoming = function (after) {
    if (state.selectedNode == null) return;
    const target = state.graphNodes.find(function (node) { return node.node_id === state.selectedNode; }) ||
      (state.detail && state.detail.kind === "node" ? state.detail.value : null);
    if (!target) return;
    query({ action: "incoming", graph: state.graphKind, node_id: target.node_id, after_edge: after }, "Loading immediate compiler retainers", function (result) {
      const nodes = [result.node || target], edges = array(result.edges).slice(0, EDGE_CAP);
      edges.forEach(function (edge) {
        nodes.push(edge.source || { node_id: String(edge.source_id), label: "Unknown source node (not present in index)", missing: true });
      });
      state.incomingResult = Object.assign({}, result, { edges: edges, next_after_edge: result.next_after_edge == null ? null : String(result.next_after_edge) });
      state.whyResult = null;
      state.graphNotice = "Immediate incoming page replaces the previous sheet. Parallel edges and original reason text remain separate.";
      setGraph(nodes, edges, target.node_id);
      state.detail = { kind: "node", value: graphNode(result.node || target) };
      renderRetention(); renderInspector();
      setStatus("Incoming page · " + str(result.stop_reason) + " · " + integer(result.elapsed_ms) + " ms", false);
    });
  };
  const applyWhy = function (report) {
    const graph = array(data.graphs).find(function (entry) { return entry.generation === report.generation; });
    if (!graph) {
      showError(new Error("This witness belongs to an unavailable graph generation. Prepare a new bundle before expanding it."));
      return;
    }
    if (state.graphKind !== graph.kind) {
      state.graphKind = graph.kind; state.searchResult = null; state.searchCursor = null;
    }
    const nodes = [], edges = [];
    array(report.paths).slice(0, 3).forEach(function (path, pathIndex) {
      const pathNodes = array(path.nodes).slice(0, Math.min(NODE_CAP, 14));
      pathNodes.forEach(function (node) { nodes.push(node); });
      for (let index = 0; index + 1 < pathNodes.length && edges.length < EDGE_CAP; index++) {
        edges.push({ source_id: String(pathNodes[index].node_id), target_id: String(pathNodes[index + 1].node_id),
          reason: array(path.reasons)[index], reason_bytes: array(path.reason_bytes)[index], reason_truncated: array(path.reasons_truncated)[index],
          witness_path: pathIndex + 1, root_kind: path.root_kind });
      }
    });
    if (report.node) nodes.push(report.node);
    state.whyResult = report; state.incomingResult = null;
    state.graphNotice = "Witness paths are bounded reachability evidence. Root conventions, repeated/missing nodes and conditional reason names are not predictions of removable bytes.";
    setGraph(nodes, edges, report.node && report.node.node_id);
    if (report.node) state.detail = { kind: "node", value: graphNode(report.node) };
    renderRetention(); renderInspector();
  };
  const why = function () {
    if (state.selectedNode == null) return;
    query({ action: "why", graph: state.graphKind, node_id: state.selectedNode }, "Finding bounded retention witnesses", function (result) {
      applyWhy(result); setStatus("Witness · " + str(result.stop_reason) + " · " + integer(result.visited_nodes) + " nodes visited · " + integer(result.elapsed_ms) + " ms", false);
    });
  };
  const renderGraphDiagram = function () {
    const sheet = el("div", { class: "graph-sheet", id: "graph-diagram" });
    const layout = state.layout;
    if (!layout) { sheet.append(note("Calculating a bounded layered layout. The tables below already contain the evidence.")); return sheet; }
    const positions = new Map(array(layout.nodes).map(function (node) { return [node.id, node]; }));
    const svg = svgEl("svg", { width: layout.width, height: layout.height, role: "img", "aria-label": "Bounded retention diagram. Equal-size nodes are not byte measurements. Accessible node and original edge-reason tables follow." });
    svg.append(svgEl("defs", {}, [svgEl("marker", { id: "vitnet-retention-arrow", viewBox: "0 0 8 8", refX: 8, refY: 4,
      markerWidth: 8, markerHeight: 8, orient: "auto", markerUnits: "userSpaceOnUse" }, [
      svgEl("path", { class: "graph-arrow", d: "M 0 0 L 8 4 L 0 8 Z" })
    ])]));
    state.graphEdges.forEach(function (edge) {
      const source = positions.get(edge.source_id), target = positions.get(edge.target_id);
      if (!source || !target) return;
      const path = svgEl("path", { class: "graph-edge", "marker-end": "url(#vitnet-retention-arrow)",
        d: "M " + (source.x + 215) + " " + (source.y + 25) + " L " + (target.x - 4) + " " + (target.y + 25) });
      path.append(svgEl("title", { text: preview(edge.reason, 512) + " · " + edge.source_id + " → " + edge.target_id }));
      svg.append(path);
    });
    state.graphNodes.forEach(function (node) {
      const position = positions.get(node.node_id);
      if (!position) return;
      const group = svgEl("g", { class: "graph-node" + (node.node_id === state.selectedNode ? " selected" : ""), transform: "translate(" + position.x + " " + position.y + ")" });
      group.append(svgEl("rect", { width: 215, height: 52, rx: 3 }),
        svgEl("text", { x: 9, y: 20, text: preview(node.label, 30) }), svgEl("text", { x: 9, y: 39, class: "node-id", text: preview(node.node_id, 31) }),
        svgEl("title", { text: preview(node.label, 512) + " · ID " + node.node_id }));
      svg.append(group);
    });
    sheet.append(svg);
    return sheet;
  };
  const renderRetention = function () {
    const panel = heading("Compiler retention", "Search and investigate a small indexed slice. Node width and degree never imply bytes. Graph IDs are not automatically joined to contributor ordinals.");
    const graphs = array(data.graphs);
    if (!live) panel.append(note(unavailable()));
    const graphOptions = graphs.map(function (graph) { return [graph.kind, graph.kind + " · " + integer(graph.node_count) + " indexed nodes"]; });
    if (graphs.length) {
      const input = el("input", { type: "search", value: state.graphQuery, maxlength: "2048", placeholder: "Graph ID or label" });
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) { event.preventDefault(); state.graphQuery = input.value; searchGraph(null); } }, [
        field("Graph index", select(graphOptions, state.graphKind, function (value) {
          state.graphKind = value; state.searchResult = null; state.searchCursor = null; resetGraph(); renderInspector();
        })),
        field("Search", input, true),
        field("Match", select([["contains", "Contains"], ["prefix", "Prefix"], ["exact", "Exact label"], ["id", "Exact node ID"]], state.graphMode, function (value) {
          cancel(false); state.graphMode = value; state.searchResult = null; state.searchCursor = null;
        })),
        el("button", { type: "submit", text: "Search index", disabled: !live })
      ]));
    } else panel.append(empty("No graph index was supplied. Contributor and source evidence remain independently usable."));
    const witnesses = array(data.witnesses);
    if (witnesses.length) {
      panel.append(el("div", { class: "toolbar" }, [
        field("Bundled offline witness", select(witnesses.slice(0, 100).map(function (report, index) { return [String(index), preview(report.node && report.node.label, 100)]; }),
          String(state.witnessIndex), function (value) { state.witnessIndex = Number(value); })),
        button("Open bundled witness", function () { cancel(false); applyWhy(witnesses[state.witnessIndex]); })
      ]));
    } else if (!live) panel.append(empty("No retention witnesses were bundled. Absence here does not mean the contributor is unretained."));
    if (state.searchResult) {
      const result = state.searchResult;
      panel.append(note(resultSummary(result, "nodes") + " · matched " + integer(result.matched_nodes) + " · omitted " + integer(result.omitted_matches)));
      if (array(result.entries).length) panel.append(table(["Graph node / label", "Node ID", numeric("Incoming edges")], result.entries.map(function (node) {
        return [button(preview(node.label, 512), function () { chooseNode(node); }, { class: "link-button" }), node.node_id, integer(node.incoming_edges)];
      }), "Graph-search page only. Truncated labels are previews, not exact full identities."));
      else panel.append(empty("No match in this graph scan batch. Check the stop reason and continuation, not only this empty page."));
      panel.append(button("Next / continue graph scan", function () { searchGraph(state.searchCursor); }, { disabled: !live || state.searchCursor == null }));
    }
    panel.append(el("div", { class: "toolbar" }, [
      button("Expand immediate retainers", function () { incoming(null); }, { disabled: !live || state.selectedNode == null }),
      button("Find root witnesses", why, { disabled: !live || state.selectedNode == null }),
      button("Reset / collapse sheet", resetGraph, { disabled: !state.graphNodes.length && state.selectedNode == null })
    ]));
    if (state.graphNotice) panel.append(note(state.graphNotice));
    if (state.graphNodes.length) {
      panel.append(note(state.graphNodes.length + " / " + NODE_CAP + " nodes · " + state.graphEdges.length + " / " + EDGE_CAP + " edges. Direction: retainer → retained. Select via node tables below."));
      panel.append(renderGraphDiagram());
      const nodeRows = state.graphNodes.slice(state.graphNodePage * PAGE, (state.graphNodePage + 1) * PAGE);
      panel.append(table(["Node label", "Node ID", "Presence", numeric("Incoming edges")], nodeRows.map(function (node) {
        return { selected: node.node_id === state.selectedNode, cells: [button(preview(node.label, 512), function () { chooseNode(node); }, { class: "link-button" }),
          node.node_id, node.missing ? "Unknown source / absent" : node.truncated ? "Truncated preview" : "Indexed", integer(node.incoming_edges)] };
      }), "Equal-size graph nodes; no byte attribution. " + nodeRows.length + " of " + state.graphNodes.length + " sheet nodes listed."));
      if (state.graphNodes.length > PAGE) panel.append(projectionPager(state.graphNodePage, state.graphNodes.length, function (value) { state.graphNodePage = value; renderRetention(); }));
      if (state.graphEdges.length) {
        const edges = state.graphEdges.slice(state.graphEdgePage * PAGE, (state.graphEdgePage + 1) * PAGE);
        panel.append(table(["Retainer → retained", "Original reason", "Reason evidence"], edges.map(function (edge) {
          return [edge.source_id + " → " + edge.target_id, preview(edge.reason, 512),
            edge.reason_truncated ? "Truncated · " + integer(edge.reason_bytes) + " original bytes" :
              edge.reason === "" ? "Empty supplied reason · NativeAOT root convention" : "Complete supplied text"];
        }), "Parallel edges remain distinct. " + edges.length + " of " + state.graphEdges.length + " sheet edges listed; conditional names are not unconditional guarantees."));
        if (state.graphEdges.length > PAGE) panel.append(projectionPager(state.graphEdgePage, state.graphEdges.length, function (value) { state.graphEdgePage = value; renderRetention(); }));
      }
    }
    if (state.incomingResult) {
      const result = state.incomingResult;
      panel.append(note("Incoming coverage: " + state.graphEdges.length + " shown / " + integer(result.total_edges) + " total edges · " + str(result.stop_reason) + " · " + integer(result.elapsed_ms) + " ms"));
      if (result.caveat) panel.append(warning(result.caveat));
      panel.append(button("Next incoming page (replace)", function () { incoming(result.next_after_edge); }, { disabled: !live || result.next_after_edge == null }));
    }
    if (state.whyResult) {
      const report = state.whyResult;
      panel.append(pairs([["Witness stop", report.stop_reason], ["Visited / examined", integer(report.visited_nodes) + " nodes / " + integer(report.examined_edges) + " edges"],
        ["Repeated / missing nodes", integer(report.repeated_nodes) + " / " + integer(report.missing_nodes)], ["Elapsed", integer(report.elapsed_ms) + " ms"]]));
      array(report.paths).slice(0, 3).forEach(function (path, index) {
        panel.append(el("h3", { text: "Witness " + (index + 1) + " · root convention: " + str(path.root_kind) }));
        const list = el("ol", { class: "evidence-list" });
        array(path.nodes).slice(0, Math.min(NODE_CAP, 14)).forEach(function (node, nodeIndex) {
          const item = el("li", {}, [button(preview(node.label, 512) + " [ID " + String(node.node_id) + "]", function () { chooseNode(node); }, { class: "link-button" })]);
          if (nodeIndex < array(path.reasons).length) item.append(note("→ " + preview(path.reasons[nodeIndex], 512) +
            (array(path.reasons_truncated)[nodeIndex] ? " · truncated from " + integer(array(path.reason_bytes)[nodeIndex]) + " bytes" : "")));
          list.append(item);
        });
        panel.append(list);
      });
      if (!array(report.paths).length) panel.append(empty("No root path returned within this query's bounds. This is not evidence of removability."));
      if (report.caveat) panel.append(warning(report.caveat));
    }
  };
  const projectionPager = function (page, total, change) {
    return el("div", { class: "pagination" }, [el("span", { text: "Bundled subset · page " + (page + 1) + " · " + total + " matching entries" }),
      el("div", {}, [button("Previous", function () { change(page - 1); }, { disabled: page === 0 }),
        button("Next subset page", function () { change(page + 1); }, { disabled: (page + 1) * PAGE >= total })])]);
  };
  const scatter = function (families) {
    const width = 640, height = 210, maxX = Math.max(1, ...families.map(function (family) { return number(family.identities) || 0; })),
      maxY = Math.max(1, ...families.map(function (family) { return number(family.bytes) || 0; }));
    const svg = svgEl("svg", { class: "scatter", viewBox: "0 0 " + width + " " + height, width: width, height: height, role: "img",
      "aria-label": "Generic family projection: linear identity count versus accounted bytes. Exact values and selection are in the following table." });
    svg.append(svgEl("line", { x1: 58, y1: 172, x2: 620, y2: 172 }), svgEl("line", { x1: 58, y1: 20, x2: 58, y2: 172 }),
      svgEl("text", { x: 58, y: 195, text: "0 identities" }), svgEl("text", { x: 500, y: 195, text: integer(maxX) + " identities" }),
      svgEl("text", { x: 65, y: 16, text: bytes(maxY) + " (bytes)" }));
    families.slice(0, PAGE).forEach(function (family) {
      const circle = svgEl("circle", { cx: 58 + (number(family.identities) || 0) / maxX * 550, cy: 172 - (number(family.bytes) || 0) / maxY * 142, r: 4 });
      circle.append(svgEl("title", { text: preview(family.family, 200) + " · " + integer(family.identities) + " identities · " + bytes(family.bytes) }));
      svg.append(circle);
    });
    return svg;
  };
  const renderAmplification = function () {
    const panel = heading("Generic & generator amplification", "Generic-family counts are indexed identities, not C# instantiation counts. These projections overlap additive stream budgets; they are not extra bytes.");
    const families = array(data.generic_families).filter(function (family) { return !state.familyStream || family.stream === state.familyStream; }).slice();
    families.sort(function (a, b) { return (number(b[state.familySort]) || 0) - (number(a[state.familySort]) || 0) || str(a.family).localeCompare(str(b.family)); });
    panel.append(el("div", { class: "toolbar" }, [
      field("Generic projection stream", select([["", "All supplied streams"]].concat([...new Set(array(data.generic_families).map(function (family) { return str(family.stream); }))].map(function (stream) { return [stream, stream]; })),
        state.familyStream, function (value) { state.familyStream = value; state.familyPage = 0; renderAmplification(); })),
      field("Rank by", select([["bytes", "Accounted bytes"], ["identities", "Identity count"]], state.familySort, function (value) { state.familySort = value; state.familyPage = 0; renderAmplification(); }))
    ]));
    const page = families.slice(state.familyPage * PAGE, (state.familyPage + 1) * PAGE);
    if (page.length) {
      panel.append(scatter(page), table(["Family preview", "Stream", numeric("Bytes"), numeric("Identities"), numeric("Canonical/shared")], page.map(function (family) {
        return [button(preview(family.family, 512), function () { state.detail = { kind: "family", value: family }; renderInspector(); }, { class: "link-button" }),
          family.stream, integer(family.bytes), integer(family.identities), integer(family.canonical_shared_identities)];
      }), "Scatter and ranking cover this bounded projection page only. Canonical/shared identities are shown separately."));
      panel.append(projectionPager(state.familyPage, families.length, function (value) { state.familyPage = value; renderAmplification(); }));
    } else panel.append(empty("No generic-family projection was supplied for this scope."));
    panel.append(note("Complete indexed generic families: " + integer((data.coverage || {}).generic_family_count) +
      " · malformed generic identities: " + integer((data.coverage || {}).malformed_generic_identities) + ". Malformed identities are not silently classified as families."));
    panel.append(el("h3", { text: "Generator evidence" }), note("Declared inputs and generated declarations are evidence about emission. Missing execution information is unknown, not zero cost."));
    const generators = array(data.generators).slice(0, PAGE);
    if (generators.length) panel.append(table(["Generator", "Version", numeric("Files"), numeric("Declarations"), numeric("Candidate bytes"), numeric("Asserted bytes")],
      generators.map(function (generator) {
        return [button(preview(generator.name, 200), function () { state.detail = { kind: "generator", value: generator }; renderInspector(); }, { class: "link-button" }), str(generator.version),
          Array.isArray(generator.generated_files) ? integer(generator.generated_files.length) : integer(generator.generated_files),
          Array.isArray(generator.generated_declarations) ? integer(generator.generated_declarations.length) : integer(generator.generated_declarations),
          integer(generator.candidate_accounted_bytes), integer(generator.asserted_accounted_bytes)];
      }), "First " + generators.length + " bundled generator records. Candidate and asserted associations are distinct; do not sum either into the budget."));
    else panel.append(empty("Generator information was not supplied. Generated files, inputs and execution costs are unknown."));
  };
  const renderResources = function () {
    const panel = heading("Resources & duplicate content", "Assembly → container → resource name. Resource assets and physical containers have separate totals; they may overlap other accounting.");
    const coverage = data.coverage || {};
    panel.append(pairs([["Full resource count", integer(coverage.resource_count)], ["Full asset bytes", bytes(coverage.resource_asset_bytes)], ["Full container bytes", bytes(coverage.resource_container_bytes)]]));
    const resources = array(data.resources);
    const assemblies = [...new Set(resources.map(function (resource) { return str(resource.assembly); }))].sort();
    const containers = [...new Set(resources.filter(function (resource) { return !state.resourceAssembly || str(resource.assembly) === state.resourceAssembly; }).map(function (resource) { return str(resource.container); }))].sort();
    const input = el("input", { type: "search", value: state.resourceFilter, maxlength: "1024", placeholder: "Resource name starts with…" });
    panel.append(el("form", { class: "toolbar", onsubmit: function (event) { event.preventDefault(); state.resourceFilter = input.value; state.resourcePage = 0; renderResources(); } }, [
      field("Assembly", select([["", "All bundled assemblies"]].concat(assemblies.map(function (assembly) { return [assembly, assembly]; })), state.resourceAssembly, function (value) {
        state.resourceAssembly = value; state.resourceContainer = ""; state.resourcePage = 0; renderResources();
      })),
      field("Container", select([["", "All bundled containers"]].concat(containers.map(function (container) { return [container, container]; })), state.resourceContainer, function (value) {
        state.resourceContainer = value; state.resourcePage = 0; renderResources();
      })),
      field("Name prefix (bounded inventory)", input, true), el("button", { type: "submit", text: "Filter subset" })
    ]));
    panel.append(note("Inventory scope: " + (state.resourceAssembly || "all bundled assemblies") + " › " + (state.resourceContainer || "all bundled containers") +
      " › " + (state.resourceFilter || "all bundled names") + ". These filters search only bundled entries, even in live mode; no full-inventory endpoint is available."));
    const filtered = resources.filter(function (resource) {
      return (!state.resourceAssembly || str(resource.assembly) === state.resourceAssembly) &&
        (!state.resourceContainer || str(resource.container) === state.resourceContainer) &&
        (!state.resourceFilter || str(resource.name).toLowerCase().startsWith(state.resourceFilter.toLowerCase()));
    });
    const page = filtered.slice(state.resourcePage * PAGE, (state.resourcePage + 1) * PAGE);
    if (page.length) panel.append(table(["Assembly", "Container", "Resource name", numeric("Asset bytes"), "Storage"], page.map(function (resource) {
      return [resource.assembly, resource.container, button(preview(resource.name, 300), function () { state.detail = { kind: "resource", value: resource }; renderInspector(); }, { class: "link-button" }), integer(resource.bytes), resource.storage];
    }), "Bounded asset inventory; container byte totals are reported separately above."));
    else panel.append(empty("No resource entry matches the bundled subset. Full resource absence cannot be inferred."));
    panel.append(projectionPager(state.resourcePage, filtered.length, function (value) { state.resourcePage = value; renderResources(); }));
    panel.append(el("h3", { text: "Duplicate content groups" }), note("SHA-256 equality proves equal content in supplied evidence, not redundant semantics or removability. Do not treat repeated bytes as savings."));
    const duplicates = array(data.duplicate_assets).slice(0, PAGE);
    if (duplicates.length) panel.append(table(["SHA-256", numeric("Bytes each"), numeric("Instances"), "Evidence"], duplicates.map(function (duplicate) {
      return [button(preview(duplicate.sha256, 64), function () { state.detail = { kind: "duplicate", value: duplicate }; renderInspector(); }, { class: "link-button" }),
        integer(duplicate.bytes_each), integer(duplicate.instance_count), preview(duplicate.caveat, 200)];
    }), "First " + duplicates.length + " bundled duplicate-content groups; no saving estimate."));
    else panel.append(empty("No duplicate-content groups were supplied."));
  };
  const renderDependencies = function () {
    const panel = heading("Package dependency routes", "Shortest package routes describe declared dependency reachability, not compiler retention. No package chain is joined to graph IDs or assigned reclaimable bytes.");
    const routes = array(data.package_routes), page = routes.slice(state.routePage * PAGE, (state.routePage + 1) * PAGE);
    if (page.length) panel.append(table(["Target", "Package", "Direct", "Shortest route", "Incomplete evidence"], page.map(function (route) {
      return [preview(route.target, 200), button(preview(route.package, 200), function () { state.detail = { kind: "route", value: route }; renderInspector(); }, { class: "link-button" }),
        route.direct == null ? "Unknown" : route.direct ? "Yes" : "No",
        route.shortest_route == null ? "No route supplied" : array(route.shortest_route).length + " route nodes",
        (route.cyclic_target ? "Cyclic target; " : "") + (array(route.missing_dependencies).length ? array(route.missing_dependencies).length + " missing dependencies" : route.missing_dependencies == null ? "Missing-dependency evidence unknown" : "No missing dependencies reported")];
    }), "Bounded supplied package route projection. Select a package to inspect the chain."));
    else panel.append(empty("No package dependency routes were supplied. Dependency and compiler-retention evidence are separate."));
    panel.append(projectionPager(state.routePage, routes.length, function (value) { state.routePage = value; renderDependencies(); }));
    array((data.coverage || {}).supplemental_inventories).slice(0, 20).forEach(function (inventory) {
      panel.append(note("Supplemental inventory " + str(inventory.label) + ": " + integer(inventory.package_count) + " packages · " + integer(inventory.resource_count) + " resources. Supplemental inventory is not automatically attributed ownership."));
    });
  };
  const renderComparison = function () {
    const panel = heading("Evidence comparison", "Signed logical deltas describe changed accounted identities. Physical output changes are separate evidence; neither is a promised saving.");
    const report = data.comparison;
    if (!report) { panel.append(empty("No before/after comparison was supplied. Prepare a bundle with compatible before evidence to populate this view.")); return; }
    panel.append(pairs([["Physical output delta", report.physical ? signedBytes(report.physical.delta_bytes) : "Unknown · physical evidence not supplied"],
      ["Logical evidence", "MSTAT section deltas below; not physical file savings"]]));
    if (report.projection_counts) panel.append(note("Comparison evidence lists are bounded to first 100 records each. Complete counts: " +
      Object.entries(report.projection_counts).map(function (entry) { return entry[0].replaceAll("_", " ") + " " + integer(entry[1]); }).join(" · ") +
      ". Consult the original comparison report for omitted detail."));
    if (report.physical && report.physical.compatible_architecture === false) panel.append(warning("Physical binaries have incompatible architectures. Do not interpret their deltas as like-for-like output changes."));
    const sections = array(report.mstat && report.mstat.sections);
    if (sections.length) {
      panel.append(el("div", { class: "toolbar" }, [field("Logical section", select(sections.map(function (section, index) { return [String(index), str(section.name || section.section || section.stream || section.kind || "Section " + (index + 1))]; }),
        String(state.comparisonSection), function (value) { state.comparisonSection = Number(value); state.comparisonPage = 0; renderComparison(); }))]));
      const section = sections[state.comparisonSection] || sections[0], entries = array(section.entries), page = entries.slice(state.comparisonPage * PAGE, (state.comparisonPage + 1) * PAGE);
      panel.append(table(["Identity", numeric("Before bytes"), numeric("After bytes"), numeric("Logical delta")], page.map(function (entry) {
        const delta = el("span", { class: number(entry.delta_bytes) > 0 ? "delta-positive" : number(entry.delta_bytes) < 0 ? "delta-negative" : "", text: signedBytes(entry.delta_bytes) });
        return [button(preview(entry.identity, 512), function () { state.detail = { kind: "comparison", value: entry }; renderInspector(); }, { class: "link-button" }),
          integer(entry.before_bytes), integer(entry.after_bytes), delta];
      }), "Signed logical deltas in the supplied comparison projection; unknown values remain unknown."));
      panel.append(projectionPager(state.comparisonPage, entries.length, function (value) { state.comparisonPage = value; renderComparison(); }));
    } else panel.append(empty("No logical identity deltas were supplied."));
    if (report.physical && array(report.physical.sections).length) {
      panel.append(el("h3", { text: "Physical section evidence" }), el("pre", { text: boundedJson(report.physical.sections) }));
    }
    ["provenance_changes", "source_changes", "diagnostics", "caveats"].forEach(function (key) {
      if (report[key] != null && (!Array.isArray(report[key]) || report[key].length)) {
        panel.append(el("h3", { text: key.replaceAll("_", " ") }), key === "diagnostics" || key === "caveats" ? warning("Review comparison compatibility and limitations below before interpreting any delta.") : note("Changes in evidence can affect comparability."),
          el("pre", { text: boundedJson(report[key]) }));
      }
    });
  };
  const renderEvidence = function () {
    const panel = heading("Evidence, provenance & limits", "Recorded inputs and uncertainty remain visible. This browser never loads the full DGML graph, opens source paths or executes the application.");
    panel.append(pairs([["Snapshot schema", data.schema], ["Bundle generation", data.generation], ["Identity coverage", integer((data.coverage || {}).identities)],
      ["Displayed contributors", integer((data.coverage || {}).contributors_shown)], ["Diagram cap", NODE_CAP + " nodes / " + EDGE_CAP + " edges"],
      ["Table cap", PAGE + " rows per page"], ["Identity preview budget", integer(limits.preview_bytes || 512) + " bytes"],
      ["Query scan limit", integer(limits.max_scanned || 100000)], ["Query timeout", integer(limits.query_timeout_ms || 1500) + " ms"],
      ["Response budget", "2 MiB"], ["Mode", live ? "Live loopback queries + bounded snapshot" : "Bounded snapshot only"]]));
    const coverage = data.coverage || {};
    const provenance = Object.entries(data.provenance || {}).slice(0, PAGE);
    const coverageText = function (shown, full) {
      return "Bounded first " + PAGE + ": " + shown + " shown / " + integer(full) + " complete records · " +
        (number(full) == null ? "omitted count unknown" : integer(Math.max(0, full - shown)) + " omitted") + ".";
    };
    panel.append(el("h3", { text: "Provenance preview" }), note(coverageText(provenance.length, coverage.provenance_count)));
    if (provenance.length) panel.append(table(["Recorded field", "Value preview"], provenance.map(function (entry) {
      return [preview(entry[0], 512), preview(typeof entry[1] === "object" ? boundedJson(entry[1]) : entry[1], 1024)];
    }), "First " + PAGE + " provenance records only; values are bounded previews, not complete input files."));
    else panel.append(note("No provenance records were bundled. Check the complete count before inferring absence."));
    panel.append(note("Consult original versioned reports for complete provenance. Nested inspector previews remain capped at 20 array entries, 30 fields, five levels and 200 values."));
    const diagnostics = array(data.diagnostics).slice(0, PAGE);
    panel.append(el("h3", { text: "Diagnostics" }), note(coverageText(diagnostics.length, coverage.diagnostic_count)));
    if (diagnostics.length) panel.append(table(["Code", "Problem", "Input path"], diagnostics.map(function (diagnostic) { return [diagnostic.code, preview(diagnostic.message, 1024), preview(diagnostic.path, 512)]; }), "First " + diagnostics.length + " supplied diagnostics"));
    else panel.append(note("No snapshot diagnostics were supplied. This is not a claim of complete source or graph coverage."));
    panel.append(el("h3", { text: "Caveats" }));
    const list = el("ul", { class: "evidence-list" });
    array(data.caveats).slice(0, PAGE).forEach(function (caveat) { list.append(el("li", { text: preview(caveat, 2048) })); });
    if (list.childElementCount) panel.append(list);
    else panel.append(note("No additional caveats were supplied."));
    const metadata = array(data.metadata && data.metadata.by_kind).slice(0, PAGE);
    if (metadata.length) panel.append(el("h3", { text: "Metadata lower-bound projection" }),
      table(["Kind", numeric("Bytes")], metadata.map(function (entry) { return [entry.name, integer(entry.bytes)]; }), "Metadata projections overlap other budgets; not added to the total."));
    if (array(data.graphs).length) panel.append(el("h3", { text: "Graph index inventory (not loaded graphs)" }),
      table(["Index", "Generation", numeric("Nodes"), numeric("Edges")], data.graphs.slice(0, PAGE).map(function (graph) {
        return [graph.kind, preview(graph.generation, 200), integer(graph.node_count), integer(graph.edge_count)];
      })));
    if (!live) panel.append(warning(unavailable()));
  };
  const renderView = function () {
    const views = { Landscape: renderLandscape, Contributors: renderContributors, Retention: renderRetention, Amplification: renderAmplification,
      Resources: renderResources, Dependencies: renderDependencies, Comparison: renderComparison, Evidence: renderEvidence };
    views[state.tab](); refreshBudget();
  };
  const inspectSources = function (panel, detail) {
    panel.append(el("h3", { text: "Source / emitter candidates" }),
      note("Source associations describe likely emission or ownership, not the compiler edge that retained this identity."));
    if (detail.loading && state.pending) panel.append(note("Loading source evidence… Cancel query leaves the bounded contributor available."));
    const evidence = detail.source, match = evidence && evidence.sources;
    if (!match) {
      panel.append(empty(detail.loading && state.pending ? "Source lookup in progress." : "Source evidence is unavailable for this row in the snapshot. Missing evidence is not a negative match."));
      return;
    }
    panel.append(pairs([["Source status", match.status], ["Association basis", match.basis], ["Assemblies", array(match.assemblies).map(function (entry) { return typeof entry === "string" ? entry : str(entry.name || entry.assembly); }).slice(0, 20).join(", ") || "None supplied"],
      ["Full source candidates", integer(evidence.total_sources)], ["Omitted by report", integer(evidence.omitted_sources)]]));
    const sources = array(match.sources), shown = sources.slice(0, 20);
    panel.append(note(shown.length + " source records shown here / " + sources.length + " bundled in this detail / " + integer(evidence.total_sources) +
      " full candidates. " + Math.max(0, sources.length - shown.length) + " additional bundled records omitted from this inspector."));
    shown.forEach(function (source) {
      panel.append(el("div", { class: "source-card" }, [el("strong", { text: preview(source.member || source.type_name || "Unnamed declaration", 512) }),
        pairs([["Assembly", source.assembly], ["Type", preview(source.type_name, 512)], ["Path (text only)", preview(source.path, 1024)],
          ["Line range", str(source.line) + " – " + str(source.end_line)], ["Declaration kind", source.kind],
          ["Generated by", source.generated_by == null ? "Not supplied" : preview(typeof source.generated_by === "object" ? boundedJson(source.generated_by) : source.generated_by, 512)],
          ["Attributes", preview(typeof source.attributes === "object" ? boundedJson(source.attributes) : source.attributes, 1024)]])]));
    });
    if (!shown.length) panel.append(empty("No source records returned. Check status, association basis and omitted counts; this does not identify a retainer."));
  };
  const renderInspector = function () {
    const panel = $("inspector");
    panel.replaceChildren(el("h2", { id: "inspector-title", text: "Inspect a contribution" }));
    const detail = state.detail;
    if (!detail) {
      panel.append(note("Choose a byte partition, contributor, resource or graph node. The inspector keeps one current selection, not an expanding evidence history."),
        el("h3", { text: "Three different questions" }), pairs([["Contribution", "What has measured accounted bytes?"], ["Emission", "Which source or generator candidates produced it?"], ["Retention", "Which compiler edges lead to it?"]]),
        warning("Retention witnesses, duplicate assets and generic families are not estimates of reclaimable bytes."));
      return;
    }
    const value = detail.value;
    if (detail.kind === "row") {
      $("inspector-title").textContent = "Contributor #" + str(value.ordinal);
      panel.append(el("div", { class: "identity", text: preview(value.identity, 512) }),
        pairs([["Stream", value.stream], ["Exact accounted bytes", integer(value.bytes)], ["Records", integer(value.records)], ["Budget role", value.accounted ? "Additive accounted identity" : "Non-additive / unaccounted"],
          ["Original identity bytes", integer(value.identity_bytes)], ["Preview", (value.truncated ? "Truncated" : "Complete supplied identity") + (value.identity_lossy ? " · lossy UTF-8" : "")],
          ["Raw identity BLAKE3", value.raw_identity_blake3]]));
      inspectSources(panel, detail);
      panel.append(el("h3", { text: "Retention is separate" }), note("A matching label is a candidate join only. Numeric graph IDs are never contributor byte ownership."));
      if (!value.truncated && !value.identity_lossy) panel.append(button("Search exact graph label", function () {
        state.graphQuery = str(value.identity); state.graphMode = "exact"; activate("Retention"); searchGraph(null);
      }, { disabled: !live || !array(data.graphs).length }));
      else panel.append(note("Exact graph label search is unavailable for truncated or lossy identities; use the Retention search explicitly."));
      if (!live) panel.append(note("Offline retention is limited to explicitly bundled witnesses. No witness is invented for this contributor."));
    } else if (detail.kind === "node") {
      $("inspector-title").textContent = "Compiler graph node";
      panel.append(el("div", { class: "identity", text: preview(value.label, 512) }), pairs([["Graph index", state.graphKind], ["Node ID (not ordinal)", value.node_id],
        ["Original label bytes", integer(value.label_bytes)], ["Preview", value.truncated ? "Truncated" : "Complete supplied label"], ["Incoming degree", integer(value.incoming_edges)],
        ["Node presence", value.missing ? "Unknown / absent source node" : "Indexed node"]]),
        note("No byte measurement is attached to this graph node. Source emitter candidates and compiler retainers have different evidence bases."),
        button("Expand this node's retainers", function () { incoming(null); }, { disabled: !live || state.tab !== "Retention" }),
        button("Find this node's root witnesses", why, { disabled: !live || state.tab !== "Retention" }));
      if (!live) panel.append(note("New graph queries require the live local explorer; only bundled witnesses are available offline."));
    } else if (detail.kind === "group") {
      $("inspector-title").textContent = "Partition scope";
      panel.append(pairs([["Dimension", value.dimension], ["Stream", value.stream], ["Partition", value.name], ["Bytes", integer(value.bytes)], ["Identities", integer(value.identities)], ["Evidence status", value.status]]),
        note("This is an aggregate partition, not a claim that every contributor has complete source attribution. Owner groups do not masquerade as assembly filters."));
    } else if (detail.kind === "resource") {
      $("inspector-title").textContent = "Resource asset";
      panel.append(pairs([["Assembly", value.assembly], ["Container", value.container], ["Name", value.name], ["Asset bytes", integer(value.bytes)],
        ["SHA-256", value.sha256], ["Source path (text only)", value.source_path], ["Storage", value.storage]]),
        warning("Asset bytes and container bytes are separate projections. Content equality does not establish removability."));
    } else if (detail.kind === "duplicate") {
      $("inspector-title").textContent = "Equal-content assets";
      panel.append(pairs([["SHA-256", value.sha256], ["Bytes per instance", integer(value.bytes_each)], ["Full instance count", integer(value.instance_count)]]),
        warning(value.caveat || "Equal hashes are content-equality evidence, not a predicted saving."));
      const instances = array(value.instances).slice(0, 20);
      panel.append(table(["Assembly", "Container", "Resource"], instances.map(function (resource) { return [resource.assembly, resource.container, preview(resource.name, 300)]; }),
        instances.length + " supplied instances shown / " + integer(value.instance_count) + " full instances"));
    } else if (detail.kind === "family") {
      $("inspector-title").textContent = "Generic family";
      panel.append(el("div", { class: "identity", text: preview(value.family, 512) }), pairs([["Stream", value.stream], ["Projected accounted bytes", integer(value.bytes)],
        ["Indexed identities", integer(value.identities)], ["Canonical/shared identities", integer(value.canonical_shared_identities)]]),
        warning("Identity count is not a source-language instantiation count. Shared/canonical identities and family projections do not imply specialization savings."));
    } else if (detail.kind === "generator") {
      $("inspector-title").textContent = "Generator evidence";
      panel.append(pairs([["Name", value.name], ["Version", value.version], ["Candidate-associated bytes", integer(value.candidate_accounted_bytes)],
        ["Asserted-associated bytes", integer(value.asserted_accounted_bytes)], ["Execution time / memory", "Not supplied · unknown, not zero"]]),
        warning(value.caveat || "Generator associations are emission evidence, not retention or execution cost."),
        el("h3", { text: "Generated files / declared inputs / declarations" }), el("pre", { text: boundedJson({
          generated_files: value.generated_files, declared_inputs: value.declared_inputs, generated_declarations: value.generated_declarations
        }) }));
    } else if (detail.kind === "route") {
      $("inspector-title").textContent = "Declared package route";
      panel.append(pairs([["Target", value.target], ["Package", value.package], ["Direct reference", value.direct == null ? "Unknown" : value.direct ? "Yes" : "No"],
        ["Target cycle", value.cyclic_target == null ? "Unknown" : value.cyclic_target ? "Cycle reported" : "No cycle reported"]]),
        note("Package dependency reachability is not compiler retention."));
      if (value.shortest_route == null) panel.append(empty("No shortest route was supplied. A missing route is not proof of no dependency."));
      else {
        const route = el("div", { class: "route", "aria-label": "Declared shortest package route, in order" });
        array(value.shortest_route).slice(0, 30).forEach(function (node, index) {
          if (index) route.append(el("span", { text: "→", "aria-hidden": "true" }));
          route.append(el("span", { class: "route-node", text: preview(node, 300) }));
        });
        panel.append(route, note(array(value.shortest_route).length + " full route nodes; at most 30 shown."));
      }
      panel.append(el("h3", { text: "Retaining packages / missing dependencies" }), el("pre", { text: boundedJson({
        retained_by_packages: value.retained_by_packages, missing_dependencies: value.missing_dependencies
      }) }));
    } else if (detail.kind === "comparison") {
      $("inspector-title").textContent = "Logical identity delta";
      panel.append(el("div", { class: "identity", text: preview(value.identity, 512) }),
        pairs([["Before bytes", integer(value.before_bytes)], ["After bytes", integer(value.after_bytes)], ["Signed logical delta", signedBytes(value.delta_bytes)]]),
        warning("A logical delta is not a physical output delta or a predicted saving. Review comparison provenance and compatibility warnings."));
    }
  };
  try {
    if (typeof Worker === "function" && typeof WORKER_SOURCE === "string" && WORKER_SOURCE) {
      const url = URL.createObjectURL(new Blob([WORKER_SOURCE], { type: "text/javascript" }));
      try { state.worker = new Worker(url); }
      finally { URL.revokeObjectURL(url); }
      state.worker.onmessage = function (event) {
        if (!event.data || event.data.sequence !== state.layoutSequence) return;
        state.layout = event.data;
        if (state.tab === "Retention") {
          const current = $("graph-diagram");
          if (current) current.replaceWith(renderGraphDiagram());
        }
      };
      state.worker.onerror = function () {
        state.worker.terminate(); state.worker = null;
        state.graphNotice = "Layout worker failed. Bounded deterministic layout is used instead; evidence remains available in tables.";
        setGraph(state.graphNodes, state.graphEdges, state.selectedNode);
        if (state.tab === "Retention") renderRetention();
      };
    }
  } catch (error) {
    state.worker = null;
    state.graphNotice = "Layout worker unavailable: " + error.message + ". Bounded deterministic fallback is enabled.";
  }
  $("cancel-query").addEventListener("click", function () { cancel(false); renderInspector(); });
  $("stop-server").hidden = !live;
  $("stop-server").addEventListener("click", async function () {
    if (!window.confirm("Stop this local explorer server? The current snapshot remains readable, but live queries will stop.")) return;
    cancel(true); clearError();
    $("stop-server").disabled = true;
    setStatus("Stopping local explorer server…", true);
    try {
      await post("/api/shutdown", {}, new AbortController());
      capability = null; live = false;
      $("stop-server").hidden = true;
      $("mode-label").textContent = "Snapshot · server stopped";
      renderView(); renderInspector();
      setStatus("Local server stopped. Reopen vitnet explore browse to restore live queries.", false);
      showError(new Error("Live transport has ended. The bounded snapshot remains readable; reopen the explorer before requesting more live evidence."));
    } catch (error) {
      $("stop-server").disabled = false; showError(error); setStatus("Server shutdown was not confirmed.", false);
    }
  });
  $("mode-label").textContent = live ? "Live · loopback" : "Offline · bounded snapshot";
  $("report-title").textContent = data.title || "Size evidence, without the whole graph";
  $("generation-label").textContent = "Generation " + str(data.generation) + " · " + integer((data.coverage || {}).identities) + " identities indexed";
  const metrics = [["Additive total", (data.accounting || {}).total_bytes]].concat(array((data.accounting || {}).streams).slice(0, 6).map(function (stream) { return [str(stream.name), stream.bytes]; }));
  $("budget-summary").replaceChildren(...metrics.map(function (entry) {
    return el("div", { class: "metric" }, [el("span", { class: "metric-label", text: entry[0] }), el("strong", { class: "metric-value", text: bytes(entry[1]) }),
      el("span", { class: "metric-unit", text: number(entry[1]) == null ? "No complete measurement supplied" : integer(entry[1]) + " bytes" })]);
  }));
  setStatus(live ? "Ready · queries use bounded scans and current-page replacement." : unavailable(), false);
  renderTabs(); renderScope(); renderView(); renderInspector();
  Object.defineProperty(window, "vitnetDebug", { configurable: false, writable: false, value: Object.freeze({
    counts: function () { return Object.freeze({ nodes: state.graphNodes.length, edges: state.graphEdges.length,
      renderedRows: document.querySelectorAll("tbody tr").length, currentTab: state.tab, pending: Boolean(state.pending) }); }
  }) });
})();
