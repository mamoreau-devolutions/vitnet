/* Original frontend code: MIT, under the repository license. */
(async function () {
  "use strict";
  const $ = function (id) { return document.getElementById(id); };
  const array = function (value) { return Array.isArray(value) ? value : []; };
  const str = function (value) { return value == null ? "Unknown" : String(value); };
  const number = function (value) { return typeof value === "number" && Number.isFinite(value) ? value : null; };
  const integer = function (value) { return number(value) == null ? "Unknown" : value.toLocaleString("en-US"); };
  const bytes = BYTE_FORMAT.format;
  const signedBytes = BYTE_FORMAT.signed;
  const percent = INVESTIGATION.percentage;
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
  const byteValue = function (value, signed) {
    const text = signed ? signedBytes(value) : bytes(value), exact = BYTE_FORMAT.exact(value);
    return el("span", { text: text, title: exact, "aria-label": text + " (" + exact + ")" });
  };
  const note = function (text) { return el("p", { class: "note", text: text }); };
  const warning = function (text) { return el("p", { class: "warning", text: text }); };
  const empty = function (text) { return el("p", { class: "empty", text: text }); };
  const field = function (label, control, grow) {
    control.setAttribute("aria-label", label);
    return el("label", { class: "field" + (grow ? " grow" : "") }, [el("span", { text: label }), control]);
  };
  const pairs = function (entries) {
    const list = el("dl");
    entries.forEach(function (entry) { list.append(el("dt", { text: entry[0] }), el("dd", {}, [entry[1] instanceof Node ? entry[1] : str(entry[1])])); });
    return list;
  };
  const select = function (options, value, change, attributes) {
    const control = el("select", Object.assign({}, attributes, { onchange: function () { change(control.value); } }));
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
  const tabs = ["Opportunities", "Investigate", "Landscape", "Contributors", "Retention", "Amplification", "Resources", "Dependencies", "Comparison", "Evidence", "All data"];
  const state = {
    tab: "Landscape", dimension: "assembly", stream: "", assembly: "", owner: "", landscapeGroup: null, contains: "",
    rows: null, rowCursor: null, rowPage: 0, rowResult: null, rowOrder: data.ranking ? "bytes" : "ordinal", family: "", familyRecord: null,
    detail: null, pending: null, sequence: 0, requestCounter: 0,
    graphKind: array(data.graphs)[0] ? str(data.graphs[0].kind) : "scan_index",
    graphQuery: "", graphMode: "contains", searchResult: null, searchCursor: null,
    graphNodes: [], graphEdges: [], selectedNode: null, incomingResult: null, whyResult: null,
    graphNotice: "", layoutSequence: 0, layout: null, worker: null, graphNodePage: 0, graphEdgePage: 0, annotatedRetention: null,
    resourceFilter: "", resourceAssembly: "", resourceContainer: "", resourcePage: 0,
    familyStream: "", familySort: "bytes", familyPage: 0, routePage: 0, related: null, familySearch: "",
    comparisonSection: 0, comparisonPage: 0, witnessIndex: 0,
    catalog: null, dataset: "resources", datasetContains: "", datasetFilters: {},
    datasetPage: null, datasetCursor: null, datasetFinder: "", domain: null,
    lens: "feature", lensPage: null, lensContains: "", lensAssembly: "", lensOwner: "",
    feature: null, featureRun: 0, cohort: null
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
      const error = new Error(str(problem.code || "HTTP " + response.status) + ": " + str(problem.message || response.statusText) +
        ". Narrow and retry; if the evidence generation changed, prepare and reopen the bundle.");
      error.code = problem.code;
      throw error;
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
    if (pending.sent) { state.cancelledAt = Date.now(); state.cancelledId = pending.id; }
    state.pending = null;
    state.sequence++;
    if (state.detail && state.detail.loading) state.detail.loading = false;
    pending.controller.abort();
    [state.rowResult, state.searchResult, state.datasetPage, state.domain && state.domain.result, state.related && state.related.result].forEach(function (result) {
      if (result && result.auto_running) { result.auto_running = false; result.stop_reason = "cancelled"; }
    });
    $("cancel-query").hidden = true;
    if (!quiet) setStatus("Query cancelled. The current bounded page is unchanged.", false);
    if (pending.sent) post("/api/cancel", { request_id: pending.id }, new AbortController()).catch(function (error) {
      showError(new Error("Browser request was cancelled, but backend cancellation failed: " + error.message));
    });
  };
  const query = async function (body, description, accept, scan) {
    if (!live) { showError(new Error(unavailable())); return; }
    cancel(true);
    clearError();
    const sequence = ++state.sequence;
    const controller = new AbortController();
    let id = "", scanned = 0, batches = 0, elapsed = 0, entries = [], cursor = scan ? body[scan.cursor] : null;
    const seen = new Set();
    const route = body.action === "feature_footprint" ? "/api/footprint" : body.action === "cohort_retention" ? "/api/cohort-retention" :
      body.action === "lens_detail" ? "/api/lenses" : body.action === "catalog" ? "/api/datasets" : body.action === "records" ? "/api/records" :
      body.action === "ranked_rows" ? "/api/rows" : body.action === "related" ? "/api/relations" :
        ["record_value", "identity_value", "identity_shape_value", "source_value", "symbol_value", "incoming_edge_value"].includes(body.action) ? "/api/value" : "/api/query";
    try {
      while (true) {
        if (sequence !== state.sequence || controller.signal.aborted) return;
        id = "v" + Date.now().toString(36) + (++state.requestCounter).toString(36);
        state.pending = { id: id, controller: controller, sequence: sequence, sent: false };
        $("cancel-query").hidden = false;
        setStatus(description + " · " + integer(scanned) + " scanned · " + batches + " batches · Cancel query to stop", true);
        const request = Object.assign({ request_id: id, generation: data.generation }, body);
        if (scan) { request.limit = scan.limit - entries.length; request[scan.cursor] = cursor; }
        while (state.cancelledId) {
          const cancelledId = state.cancelledId;
          const cancellation = await post("/api/cancel", { request_id: cancelledId }, controller);
          if (sequence !== state.sequence || controller.signal.aborted) return;
          if (!cancellation.cancelled) {
            if (state.cancelledId === cancelledId) state.cancelledId = null;
            break;
          }
          if (Date.now() > state.cancelledAt + 2000) throw new Error("Backend cancellation did not finish within two seconds. Retry after the active query stops.");
          setStatus(description + " · waiting for backend cancellation · Cancel query to stop", true);
          await new Promise(function (resolve) { setTimeout(resolve, 40); });
        }
        if (sequence !== state.sequence || controller.signal.aborted) return;
        state.pending.sent = true;
        let result;
        try { result = await post(route, request, controller); }
        catch (error) {
          if (error.code !== "explorer.busy" || Date.now() > (state.cancelledAt || 0) + 2000) throw error;
          setStatus(description + " · waiting for the cancelled query slot · Cancel query to stop", true);
          await new Promise(function (resolve) { setTimeout(resolve, 40); });
          continue;
        }
        if (!state.pending || state.pending.id !== id || sequence !== state.sequence) return;
        if (result.generation && result.generation !== data.generation) {
          const graph = array(data.graphs).find(function (entry) { return entry.kind === body.graph; });
          if (!graph || result.generation !== graph.generation) throw new Error("Evidence generation mismatch. Prepare and reopen the bundle; no stale results were applied.");
        }
        if (!scan) {
          state.pending = null; $("cancel-query").hidden = true;
          setStatus("Query completed.", false); accept(result); refreshBudget(); return;
        }
        scanned += number(result.scanned == null ? result.scanned_nodes : result.scanned) || 0;
        elapsed += number(result.elapsed_ms) || 0; batches++;
        array(result.entries).forEach(function (entry) {
          const key = str(entry.ordinal == null ? entry.node_id : entry.ordinal);
          if (seen.has(key)) throw new Error("Duplicate result across continuation batches; no complete page was claimed.");
          seen.add(key); entries.push(entry);
        });
        const next = result[scan.next] == null ? null : result[scan.next];
        const done = INVESTIGATION.progressiveStop(result, next, entries.length, scan.limit);
        const page = Object.assign({}, result, { entries: entries, scanned: scanned, scanned_nodes: scanned,
          elapsed_ms: elapsed, batches: batches, auto_running: !done });
        if (done) { state.pending = null; $("cancel-query").hidden = true; }
        accept(page); refreshBudget();
        setStatus(description + " · " + integer(scanned) + " scanned · " + batches + " batches · " + entries.length +
          "/" + scan.limit + " page results" + (done ? " · " + result.stop_reason : " · continuing automatically; Cancel query to stop"), !done);
        if (done) return;
        if (next === cursor || (cursor != null && BigInt(next) <= BigInt(cursor))) {
          throw new Error("Continuation did not advance. Restart the search or prepare a new bundle.");
        }
        cursor = next;
        await new Promise(function (resolve) { setTimeout(resolve, 20); });
      }
    } catch (error) {
      if (!state.pending || state.pending.id !== id || sequence !== state.sequence) return;
      state.pending = null;
      $("cancel-query").hidden = true;
      [state.rowResult, state.searchResult, state.datasetPage, state.domain && state.domain.result, state.related && state.related.result].forEach(function (result) {
        if (result && result.auto_running) { result.auto_running = false; result.stop_reason = "failed"; }
      });
      if (controller.signal.aborted) {
        post("/api/cancel", { request_id: id }, new AbortController()).catch(function (cancelError) {
          showError(new Error("Backend cancellation failed: " + cancelError.message));
        });
      }
      showError(new Error(error.message + " The previous page remains available."));
      setStatus("Query failed; the search is incomplete. Previously displayed records remain available.", false);
      if (scan) renderView();
      if (state.detail && state.detail.loading) { state.detail.loading = false; renderInspector(); }
    }
  };
  const resultSummary = function (result, noun) {
    if (!result) return "";
    return str(result.stop_reason) + " · scanned " + integer(result.scanned == null ? result.scanned_nodes : result.scanned) +
      " " + noun + (number(result.elapsed_ms) == null ? "" : " · " + integer(result.elapsed_ms) + " ms");
  };
  const heading = function (title, description) {
    const panel = $("investigation");
    panel.replaceChildren(el("h2", { id: "view-title", text: title }), note(description));
    completeAccess(panel);
    return panel;
  };
  const activate = function (tab) {
    cancel(false);
    clearError();
    state.tab = tab;
    if (state.detail && state.detail.kind === "node" && tab !== "Retention") state.detail = null;
    if (tab !== "Retention") {
      state.searchResult = null;
      state.graphNodes = []; state.graphEdges = []; state.layout = null; state.layoutSequence++;
      state.incomingResult = null; state.whyResult = null; state.selectedNode = null;
    }
    renderTabs(); renderScope(); renderView(); renderInspector();
    if (live && ["Resources", "Dependencies", "Amplification"].includes(tab)) ensureDomain();
    if (live && tab === "Contributors" && state.rows === null) fetchRows(null);
    if (live && tab === "All data" && state.catalog && !state.datasetPage && !state.pending) fetchDataset(null);
  };
  const renderTabs = function () {
    $("tabs").replaceChildren(...tabs.map(function (tab) {
      return button(tab, function () { activate(tab); }, { "aria-current": state.tab === tab ? "page" : null });
    }));
  };
  const renderScope = function () {
    const bar = $("scope-bar");
    if (live && state.catalog && state.catalog.complete && ["Resources", "Dependencies", "Amplification"].includes(state.tab)) {
      const dataset = { Resources: "resources", Dependencies: "package_routes", Amplification: "generic_families" }[state.tab];
      const domain = state.domain && state.domain.dataset === dataset ? state.domain : null;
      bar.replaceChildren(el("strong", { text: "Inventory scope" }),
        el("span", { text: domain ? Object.entries(domain.filters).map(function (entry) { return entry[0] + " = " + entry[1]; }).join(" · ") || "All captured records" : "Select recorded origin or load inventory" }),
        el("span", { class: "note", text: "Separate from contributor filters" + (domain && domain.contains ? " · Contains: " + preview(domain.contains, 128) : "") }));
      return;
    }
    if (state.tab === "All data") {
      bar.replaceChildren(el("strong", { text: "Dataset scope" }), el("span", { text: datasetLabel(state.dataset) }),
        el("span", { class: "note", text: "Independent of contributor scope. Only one result page is kept." }));
      return;
    }
    bar.replaceChildren(el("strong", { text: "Contributor scope" }), el("span", { text: state.stream || "All additive streams" }), el("span", { text: "›" }),
      el("span", { text: state.family ? "Producer family: " + state.family : state.assembly ? "Assembly: " + state.assembly : state.owner ? "Opaque owner: " + state.owner : "All assemblies / owners" }));
    if (state.stream || state.assembly || state.owner || state.family) bar.append(button("Clear scope", function () {
      cancel(false); state.stream = ""; state.assembly = ""; state.owner = ""; state.family = ""; state.familyRecord = null; state.landscapeGroup = null; state.detail = null;
      state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
      renderScope(); renderView(); renderInspector();
      if (live && state.tab === "Contributors") fetchRows(null);
    }));
    if (state.assembly && state.tab === "Contributors") bar.append(el("span", { class: "note", text: "Assembly is attribution evidence, not an identity-string filter." }));
    if (state.owner && state.tab === "Contributors") bar.append(el("span", { class: "note", text: "Owner is an opaque producer prefix, not a demangled namespace." }));
    if (state.contains && ["Landscape", "Contributors"].includes(state.tab)) bar.append(el("span", { class: "note", text: "Contributor text filter: " + state.contains }));
    if (!["Landscape", "Contributors", "Dependencies", "Resources"].includes(state.tab)) bar.append(el("span", { class: "note", text: "This view has its own explicitly labelled scope." }));
  };
  const chooseGroup = function (group) {
    cancel(false);
    state.stream = str(group.stream);
    state.family = "";
    state.familyRecord = null;
    if (group.dimension === "assembly") { state.assembly = str(group.name); state.owner = ""; }
    else { state.owner = str(group.name); state.assembly = ""; }
    state.landscapeGroup = group;
    state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
    state.detail = { kind: "group", value: group };
    activate("Landscape");
    if (live && data.ranking) fetchRows(null);
  };
  const zoomStream = function (stream) {
    cancel(false); state.stream = stream; state.assembly = ""; state.owner = ""; state.family = ""; state.familyRecord = null; state.landscapeGroup = null; state.detail = null;
    state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
    renderScope(); renderLandscape(); renderInspector();
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
        svgEl("title", { text: label + " · " + bytes(value) + " (" + BYTE_FORMAT.exact(value) + ")" }));
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
  const scopeBytes = function () {
    if (state.rowResult && state.rowResult.scope) return number(state.rowResult.scope.bytes);
    if (state.landscapeGroup) return number(state.landscapeGroup.bytes);
    if (state.assembly || state.owner || state.family) return null;
    const stream = array((data.accounting || {}).streams).find(function (s) { return s.name === state.stream; });
    return state.stream ? number(stream && stream.bytes) : number((data.accounting || {}).total_bytes);
  };
  const renderLedger = function (panel) {
    const accounting = data.accounting || {}, ledger = data.ledger || {}, coverage = data.coverage || {};
    panel.append(el("h3", { text: "Size ledger · global accounting" }), note(ledger.accounting_basis ||
      "Reported NativeAOT object sizes, not a measured executable file size. Specialized streams and the projections below overlap; do not add them."));
    const streams = array(accounting.streams), total = number(accounting.total_bytes);
    panel.append(table(["Additive category", numeric("Reported bytes"), numeric("% accounted total"), "Shared byte scale"], streams.map(function (stream) {
      const scale = svgEl("svg", { class: "budget-scale", viewBox: "0 0 180 12", role: "img",
        "aria-label": stream.name + ": " + percent(stream.bytes, total) + " of reported object accounting" }, [
        svgEl("rect", { class: "scale-remainder", width: 180, height: 12 }),
        svgEl("rect", { class: "scale-value", width: total > 0 ? Math.min(180, stream.bytes / total * 180) : 0, height: 12 })
      ]);
      return [button(stream.name, function () { zoomStream(stream.name); }, { class: "link-button" }), byteValue(stream.bytes), percent(stream.bytes, total), scale];
    }), "One common denominator for all categories. This is not the physical binary breakdown."));
    panel.append(pairs([
      ["Reported object total", byteValue(accounting.total_bytes)],
      ["Physical binary inventory", ledger.physical_total_bytes == null ? "Unknown · capture published binary evidence" : byteValue(ledger.physical_total_bytes)],
      ["Metadata lower bound (overlapping)", byteValue(accounting.metadata_lower_bound_bytes)],
      ["Resource child assets (overlapping)", data.ledger ? byteValue(ledger.resource_asset_bytes) : "Unknown · reprepare for corrected container accounting"],
      ["Resource containers (overlapping children)", data.ledger ? byteValue(ledger.resource_container_bytes) : "Unknown · legacy inventory classification"]
    ]));
    if (array(ledger.physical_binaries).length) panel.append(note("Physical total is the sum of supplied binary records, not proof of a single published executable or a like-for-like reconciliation."));
    panel.append(note(ledger.resource_basis || "Resource inventory and ResourceData have different evidence bases. Equality is not established; no remainder is labeled removable."),
      note("Bundled contributor-preview coverage: " + bytes(coverage.displayed_accounted_bytes) + " / " + bytes(accounting.total_bytes) +
        " · " + percent(coverage.displayed_accounted_bytes, total) + ". This is not landscape-partition coverage. Unpreviewed bytes remain accounted and accessible through complete live ranking."));
  };
  const renderLandscape = function () {
    const panel = heading("Accounted landscape", "Partitions reconcile only within one dimension and one stream. Resource, metadata, generic and generator projections can overlap these budgets.");
    if (!state.landscapeGroup) renderLedger(panel);
    panel.append(el("div", { class: "toolbar" }, [field("Partition dimension", select([["assembly", "Assembly attribution"], ["owner", "Identity owner"]], state.dimension, function (value) {
      cancel(false); state.dimension = value; state.assembly = ""; state.owner = ""; state.family = ""; state.familyRecord = null; state.landscapeGroup = null;
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
      const total = scopeBytes();
      const rows = (state.rows === null ? localRows() : state.rows).filter(function (row) { return row.accounted; }).slice(0, Math.min(PAGE, 98));
      const sum = rows.reduce(function (result, row) { return result + (number(row.bytes) || 0); }, 0);
      panel.append(el("h3", { text: str(selected.name) + " · " + bytes(total) }));
      if (total != null && total > 0 && sum <= total) {
        const children = rows.map(function (row) { return { name: preview(row.identity, 512), bytes: row.bytes, action: function () { chooseRow(row); } }; });
        if (sum < total) children.push({ name: "Other / not displayed", bytes: total - sum, other: true });
        panel.append(icicle(str(selected.name), total, children, function () { zoomStream(state.stream); }));
      }
      if (total != null && sum > total) panel.append(warning("Bundled preview matches exceed this aggregate. No child byte partition is drawn; use live exact filtering to resolve the scope."));
      panel.append(note("Zoom scope: " + state.stream + " › " + state.dimension + ": " + str(selected.name) +
        (state.rows === null ? ". Children are bundled previews; live byte ranking is available." : ". Children come from the complete byte-ranked cache, not global top-N previews.") + " Other / not displayed: " +
        bytes(total == null ? null : Math.max(0, total - sum)) + ". No ownership is fabricated for this remainder."));
      panel.append(pairs([["Scope share of accounted total", percent(total, number((data.accounting || {}).total_bytes))],
        ["Shown children / selected parent", percent(sum, total)], ["Selected-scope remainder", byteValue(total == null ? null : Math.max(0, total - sum))]]));
      panel.append(button("Inspect scoped contributors", function () { activate("Contributors"); }));
      if (rows.length) panel.append(table(["Contributor preview", "Stream", numeric("Bytes"), numeric("% parent")], rows.map(function (row) {
        return [button(preview(row.identity, 512), function () { chooseRow(row); }, { class: "link-button" }), row.stream, byteValue(row.bytes), percent(row.bytes, total)];
      }), state.rows === null ? "Bundled contributor previews; use complete ranking to inspect this scope." : "Largest matching children in complete cache byte order. Other includes every contributor not on this page."));
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
    if (shownGroups.length) panel.append(table(["Stream", "Partition", numeric("Bytes"), numeric("% total"), numeric("Identities"), "Evidence status"],
      shownGroups.map(function (group) { return [button(group.stream, function () { zoomStream(str(group.stream)); }, { class: "link-button" }),
        button(preview(group.name, 200), function () { chooseGroup(group); }, { class: "link-button" }), byteValue(group.bytes), percent(group.bytes, number((data.accounting || {}).total_bytes)), integer(group.identities), group.status]; }),
      "Bounded partition projection: " + shownGroups.length + " of " + allGroups.length + " bundled groups. Buttons zoom the icicle and narrow contributor scope."));
    else panel.append(empty("No groups supplied for this dimension. Stream totals remain authoritative."));
    }
    const accounting = data.accounting || {};
    if (accounting.methods && !state.assembly && !state.owner && (!state.stream || state.stream === "Methods")) panel.append(el("h3", { text: "Global Methods components" }), pairs([
      ["Method bodies", byteValue(accounting.methods.body_bytes)], ["GC information", byteValue(accounting.methods.gc_info_bytes)],
      ["Exception information", byteValue(accounting.methods.exception_info_bytes)]
    ]));
    if (state.landscapeGroup) renderLedger(panel);
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
    const ranked = state.rowOrder === "bytes" && Boolean(data.ranking);
    const body = { action: ranked ? "ranked_rows" : "rows", contains: state.contains, stream: state.stream || null, assembly: state.assembly || null, owner: state.owner || null,
      after: after, limit: PAGE };
    if (ranked) { body.family = state.familyRecord == null ? state.family || null : null; body.family_record = state.familyRecord; }
    query(body, ranked ? "Finding largest complete-cache contributors" : "Searching identities in original cache order", function (result) {
      state.rows = array(result.entries).slice(0, PAGE); state.rowCursor = result.next_after == null ? null : result.next_after; state.rowResult = result;
      renderView();
    }, { cursor: "after", next: "next_after", limit: PAGE });
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
    const panel = heading("Contributors", data.ranking ? "Complete-cache byte ranking · descending bytes, original ordinal for ties. Non-additive streams remain projections, not extra bytes." :
      "Legacy bundle: cache-ordinal live pages, not global size order. Prepare a new bundle for complete byte ranking; snapshot rankings are bounded.");
    const search = el("input", { type: "search", maxlength: "1024", value: state.contains, placeholder: "Contains complete identity text (case-sensitive)" });
    const streamOptions = [["", "All streams"]].concat(array((data.accounting || {}).streams).map(function (entry) { return [str(entry.name), str(entry.name)]; }));
    const searchForm = el("form", { class: "toolbar", onsubmit: function (event) {
      event.preventDefault(); state.contains = search.value; state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null;
      renderScope();
      if (live) fetchRows(null); else renderContributors();
    } }, [
      field("Identity filter", search, true),
      field("Order", select(data.ranking ? [["bytes", "Largest bytes first"], ["ordinal", "Original cache order"]] : [["ordinal", "Original cache order"]], state.rowOrder, function (value) {
        state.rowOrder = value; state.rows = null; state.rowResult = null; state.rowCursor = null;
        if (live) fetchRows(null); else renderContributors();
      }, { disabled: state.familyRecord != null || Boolean(state.family) })),
      field("Stream", select(streamOptions, state.stream, function (value) {
        cancel(false); state.stream = value; state.landscapeGroup = null; state.rows = null; state.rowPage = 0; state.rowResult = null; state.rowCursor = null; renderScope();
        if (live) fetchRows(null); else renderContributors();
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
    let cumulative = 0;
    const parent = scopeBytes(), total = number((data.accounting || {}).total_bytes);
    panel.append(note("Percentages use reported object accounting, not physical file bytes. Parent denominator excludes the text filter. Multiple intersecting scopes can have an unknown denominator."));
    if (rows.length) panel.append(table(["Identity preview", "Stream", numeric("Bytes"), numeric("% total"), numeric("% parent"), numeric("Page cumulative % parent"), "Accounting", numeric("Ordinal")],
      rows.map(function (row) {
        const identity = el("div", {}, [button(preview(row.identity, 512), function () { chooseRow(row); }, { class: "link-button" })]);
        if (row.truncated || row.identity_lossy) identity.append(note((row.truncated ? "Truncated · " + bytes(row.identity_bytes) + " original identity" : "") + (row.identity_lossy ? " · lossy UTF-8 preview" : "")));
        if (row.accounted) cumulative += number(row.bytes) || 0;
        return { selected: Boolean(state.detail && state.detail.kind === "row" && state.detail.value.ordinal === row.ordinal),
          cells: [identity, row.stream, byteValue(row.bytes), row.accounted ? percent(row.bytes, total) : "Projection", percent(row.bytes, parent),
            row.accounted ? percent(cumulative, parent) : "Projection", row.accounted ? "Additive" : "Non-additive / unaccounted", integer(row.ordinal)] };
      }), local ? "Bounded snapshot subset · " + projection.length + " matching bundled rows" : "Current " + (state.rowResult.order || "cache-ordinal") + " page. Previous pages are discarded; cumulative coverage is for this page only."));
    if (!local && parent != null) panel.append(pairs([["Parent scope", byteValue(parent)], ["Additive bytes on this page", byteValue(cumulative)],
      ["Parent bytes not on this page", byteValue(Math.max(0, parent - cumulative))], ["Page coverage", percent(cumulative, parent)]]));
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
        button("Next / continue scan", function () { fetchRows(state.rowCursor); }, { disabled: state.rowResult.auto_running || state.rowCursor == null })
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
    state.selectedNode = null; state.incomingResult = null; state.whyResult = null; state.annotatedRetention = null; state.graphNotice = ""; state.graphNodePage = 0; state.graphEdgePage = 0;
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
      renderRetention();
    }, { cursor: "after_id", next: "next_after_id", limit: 50 });
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
  const applyWhy = function (report, annotation) {
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
    state.whyResult = report; state.annotatedRetention = annotation || null; state.incomingResult = null;
    state.graphNotice = "Witness paths are bounded reachability evidence. Root conventions, repeated/missing nodes and conditional reason names are not predictions of removable bytes.";
    setGraph(nodes, edges, report.node && report.node.node_id);
    if (report.node) state.detail = { kind: "node", value: graphNode(report.node) };
    renderRetention(); renderInspector();
  };
  const why = function () {
    if (state.selectedNode == null) return;
    query({ action: "annotated_why", graph: state.graphKind, node_id: state.selectedNode }, "Finding bounded retention witnesses and source anchors", function (result) {
      applyWhy(result.witness, result);
      setStatus("Witness · " + str(result.witness.stop_reason) + " · " + integer(result.witness.visited_nodes) + " nodes visited · source anchors are separately tiered", false);
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
          const reason = state.incomingResult && edge.ordinal != null ? button(preview(edge.reason, 512) || "(Empty reason)", function () {
            openFull({ action: "incoming_edge_value", graph: state.graphKind, node_id: edge.target_id, ordinal: String(edge.ordinal) },
              "Complete incoming edge to #" + edge.target_id);
          }, { class: "link-button", disabled: !live }) : preview(edge.reason, 512);
          return [edge.source_id + " → " + edge.target_id, reason,
            edge.reason_truncated ? "Truncated · " + bytes(edge.reason_bytes) + " original reason" :
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
            (array(path.reasons_truncated)[nodeIndex] ? " · truncated from " + bytes(array(path.reason_bytes)[nodeIndex]) : "")));
          list.append(item);
        });
        panel.append(list);
      });
      if (!array(report.paths).length) panel.append(empty("No root path returned within this query's bounds. This is not evidence of removability."));
      if (report.caveat) panel.append(warning(report.caveat));
    }
    if (state.annotatedRetention && state.whyResult) {
      panel.append(el("h3", { text: "Source anchors and possible registration mechanisms" }));
      array(state.annotatedRetention.annotated_paths).slice(0, 3).forEach(function (path, index) {
        panel.append(note("Witness " + (index + 1) + " · " + integer(array(path.anchors).length) + " source anchor previews · " +
          integer(path.collapsed_unmapped_nodes) + " nodes without a captured source association. All original nodes remain in the witness above."));
        array(path.anchors).slice(0, 14).forEach(function (anchor) {
          panel.append(note("Node " + str(anchor.node_id) + " · " + str((anchor.sources || {}).status) + " · " + preview(anchor.producer_label, 300)));
          if (anchor.source_preview_truncated) panel.append(note("Source preview bounded; " + integer(anchor.total_source_candidates) + " captured candidates. Inspect complete declarations in All data → Source declarations."));
          array((anchor.sources || {}).sources).slice(0, 10).forEach(function (source) {
            panel.append(note(str(source.path) + ":" + str(source.line) + " · " + str(source.type_name) + (source.member ? " · " + source.member : "")));
          });
          if (array(anchor.possible_mechanisms).length) panel.append(warning("Possible mechanism candidates: " + anchor.possible_mechanisms.join("; ") + ". Not proof of sole retention."));
        });
      });
      array(state.annotatedRetention.caveats).forEach(function (text) { panel.append(note(text)); });
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
  const followAssembly = function (assembly, tab) {
    cancel(false); state.assembly = assembly; state.owner = ""; state.family = ""; state.familyRecord = null; state.landscapeGroup = null;
    state.rows = null; state.rowResult = null; state.rowCursor = null; state.related = null; state.domain = null; state.detail = null;
    state.resourceAssembly = assembly; activate(tab || "Contributors");
  };
  const followPackage = function (packageName, target) {
    state.domain = { dataset: "package_routes", contains: "", filters: Object.assign({ package: packageName }, target ? { target: target } : {}),
      result: null, cursor: null };
    state.detail = null; activate("Dependencies");
  };
  const chooseFamily = function (entry) {
    cancel(false); state.family = str(entry.fields.family || entry.summary); state.familyRecord = entry.ordinal;
    state.stream = str(entry.fields.stream); state.rowOrder = "bytes"; state.assembly = ""; state.owner = ""; state.landscapeGroup = null;
    state.rows = null; state.rowResult = null; state.rowCursor = null; state.detail = { kind: "family", value: entry.fields };
    activate("Contributors");
  };
  const fetchRelated = function (selectors, after) {
    query(Object.assign({ action: "related", after: after, limit: PAGE }, selectors), "Finding recorded assembly / package origins", function (result) {
      state.related = { selectors: selectors, result: result };
      renderView(); renderInspector();
    }, { cursor: "after", next: "next_after", limit: PAGE });
  };
  const renderRelations = function (panel) {
    const relation = state.related;
    if (!relation) return;
    const result = relation.result;
    panel.append(el("h3", { text: "Recorded assembly ↔ package origins" }),
      note("Explicit or assets-resolved origin evidence. Supplemental links do not alter source attribution, prove compiler retention, or assign package savings."));
    const entries = array(result.entries);
    if (entries.length) panel.append(table(["Assembly", "Package", "Target", "Evidence basis"], entries.map(function (entry) {
      const f = entry.fields || {}, cut = array(entry.capture && entry.capture.fields_truncated);
      const evidence = el("div", {}, [note(str(f.basis)), button("Full origin record", function () {
        openFull({ action: "record_value", dataset: "assembly_links", ordinal: entry.ordinal }, "Complete package origin #" + entry.ordinal);
      }, { class: "link-button" })]);
      return [button(str(f.assembly), function () { followAssembly(f.assembly, "Contributors"); }, { class: "link-button", disabled: cut.includes("assembly") }),
        button(str(f.package), function () { followPackage(f.package, f.target); }, { class: "link-button", disabled: cut.includes("package") || cut.includes("target") }), f.target || "Not recorded", evidence];
    }), "Current complete relationship page; origin links are not dependency or retention witnesses."));
    else panel.append(empty(result.stop_reason === "complete" ? "No recorded origin link matched. The package origin remains unknown; assembly names are not guessed as package IDs." : "Searching captured origin evidence…"));
    panel.append(button("Next origin page", function () { fetchRelated(relation.selectors, result.next_after); },
      { disabled: result.auto_running || result.next_after == null }));
  };
  const recordTable = function (dataset, entries) {
    const schema = INVESTIGATION.columns(dataset), headers = schema.map(function (column) { return column[2] ? numeric(column[1]) : column[1]; });
    headers.push("Full captured record", "Capture");
    headers.push("Ordinal / graph ID");
    const result = table(headers, entries.map(function (entry) {
      const fields = entry.fields || {}, cut = array(entry.capture && entry.capture.fields_truncated);
      const cells = schema.map(function (column) {
        const value = fields[column[0]];
        if (column[2] === "bytes") return byteValue(value);
        if (column[2] === "count") return integer(value);
        if (column[0] === "assembly" && value && !cut.includes("assembly")) return button(value, function () { followAssembly(value, "Contributors"); }, { class: "link-button" });
        if (column[0] === "storage" && value) return INVESTIGATION.storageRole(value) + " · " + str(value);
        return value == null ? "Not captured in preview" : typeof value === "boolean" ? value ? "Yes" : "No" : str(value);
      });
      const links = el("div", {}, [button(entry.summary || "(Empty record)", function () {
        openFull({ action: "record_value", dataset: dataset, ordinal: entry.ordinal }, datasetLabel(dataset) + " #" + entry.ordinal);
      }, { class: "link-button" })]);
      if (dataset === "generic_families" && data.ranking) links.append(button("Rank family members", function () { chooseFamily(entry); }));
      if (dataset === "package_routes" && fields.package && !cut.includes("package") && !cut.includes("target")) links.append(button("Assembly origins", function () {
        fetchRelated({ package: fields.package, target: fields.target || null }, null);
      }));
      const capture = entry.capture || {};
      cells.push(links, capture.upstream_truncated ? "Upstream text truncated · " + bytes(capture.captured_text_bytes) + " captured / " +
        bytes(capture.original_text_bytes) + " original; missing text is unavailable" : cut.length ? "Display shortened; full captured fields accessible" :
        "Captured record accessible");
      cells.push(entry.ordinal);
      return cells;
    }), "Domain fields are bounded previews. Open a record for every original captured field; only this page is resident.");
    result.classList.add("inventory-table");
    return result;
  };
  const fetchDomain = function (after) {
    const domain = state.domain;
    if (!domain) return;
    query({ action: "records", dataset: domain.dataset, contains: domain.contains, filters: domain.filters, after: after, limit: PAGE },
      "Searching complete " + datasetLabel(domain.dataset), function (result) {
        if (state.domain !== domain) return;
        domain.result = result; domain.cursor = result.next_after; renderScope(); renderView();
      }, { cursor: "after", next: "next_after", limit: PAGE });
  };
  const ensureDomain = function () {
    const name = { Resources: "resources", Dependencies: "package_routes", Amplification: "generic_families" }[state.tab];
    if (!name) return;
    if (!state.catalog) {
      if (!state.pending) query({ action: "catalog" }, "Loading complete inventory catalog", function (result) {
        state.catalog = result; renderScope(); renderView(); ensureDomain();
      });
      return;
    }
    if (!state.catalog.complete || !array(state.catalog.datasets).some(function (d) { return d.name === name; })) return;
    if (state.tab === "Dependencies" && state.assembly && !state.related && !state.domain) {
      fetchRelated({ assembly: state.assembly }, null); return;
    }
    if (!state.domain || state.domain.dataset !== name) {
      if (state.tab === "Dependencies" && state.assembly) return;
      state.domain = { dataset: name, contains: "", filters: name === "resources" && state.assembly ? { assembly: state.assembly } : {},
        result: null, cursor: null };
    }
    if (!state.domain.result && !state.pending) fetchDomain(null);
  };
  const domainPage = function (panel, dataset) {
    const domain = state.domain && state.domain.dataset === dataset ? state.domain : null, result = domain && domain.result;
    if (!result) { panel.append(empty("Loading a bounded page of the complete captured inventory…")); return; }
    if (array(result.entries).length) panel.append(recordTable(dataset, result.entries));
    else panel.append(empty(result.stop_reason === "complete" ? "No captured records match these exact filters." : "Search in progress; empty partial batches are continued automatically."));
    panel.append(el("div", { class: "pagination" }, [el("span", { text: resultSummary(result, "records") }),
      el("div", {}, [button("Restart inventory", function () { fetchDomain(null); }), button("Next inventory page", function () { fetchDomain(domain.cursor); },
        { disabled: result.auto_running || domain.cursor == null })])]));
  };
  const renderAmplification = function () {
    const panel = heading("Generic & generator amplification", "Generic-family counts are indexed identities, not C# instantiation counts. These projections overlap additive stream budgets; they are not extra bytes.");
    if (live && state.catalog && state.catalog.complete) {
      const text = el("input", { type: "search", maxlength: "1024", value: state.familySearch, placeholder: "Search captured family text" });
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
        event.preventDefault(); state.familySearch = text.value; state.domain = { dataset: "generic_families", contains: text.value,
          filters: state.familyStream ? { stream: state.familyStream } : {}, result: null, cursor: null }; fetchDomain(null);
      } }, [field("Complete family search", text, true),
        field("Stream", select([["", "All captured streams"]].concat(array((data.accounting || {}).streams).map(function (s) { return [s.name, s.name]; })),
          state.familyStream, function (value) { state.familyStream = value; state.domain = { dataset: "generic_families", contains: state.familySearch,
            filters: value ? { stream: value } : {}, result: null, cursor: null }; fetchDomain(null); })),
        el("button", { type: "submit", text: "Search all families" })]));
      panel.append(note("Complete globally byte-ranked families. Select Rank family members for exact full-spelling filtering, even when the displayed family is shortened."));
      if (state.domain && state.domain.dataset === "generic_families" && state.domain.result && state.domain.result.entries.length) {
        panel.append(scatter(state.domain.result.entries.map(function (entry) { return entry.fields; })), note("Scatter uses only the current page, not the entire family population."));
      }
      domainPage(panel, "generic_families");
      panel.append(el("h3", { text: "Generator evidence" }), note("No captured generator record means emission and execution evidence is missing, not zero cost."),
        button("All captured generator records", function () { openDataset("generators"); }));
      return;
    }
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
          family.stream, byteValue(family.bytes), integer(family.identities), integer(family.canonical_shared_identities)];
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
          byteValue(generator.candidate_accounted_bytes), byteValue(generator.asserted_accounted_bytes)];
      }), "First " + generators.length + " bundled generator records. Candidate and asserted associations are distinct; do not sum either into the budget."));
    else panel.append(empty("Generator information was not supplied. Generated files, inputs and execution costs are unknown."));
  };
  const renderResources = function () {
    const panel = heading("Resources & duplicate content", "Assembly → container → resource name. Resource assets and physical containers have separate totals; they may overlap other accounting.");
    const coverage = data.coverage || {};
    panel.append(pairs([["Full resource count", integer(coverage.resource_count)], ["Full asset bytes", byteValue(coverage.resource_asset_bytes)], ["Full container bytes", byteValue(coverage.resource_container_bytes)]]));
    if (live && state.catalog && state.catalog.complete) {
      const domain = state.domain && state.domain.dataset === "resources" ? state.domain : { filters: {}, contains: "" };
      const assembly = el("input", { type: "text", maxlength: "4096", value: domain.filters.assembly || state.assembly || "", placeholder: "Exact assembly name" });
      const container = el("input", { type: "text", maxlength: "4096", value: domain.filters.container || "", placeholder: "Exact container name" });
      const text = el("input", { type: "search", maxlength: "1024", value: domain.contains, placeholder: "Search full resource records" });
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
        event.preventDefault(); const filters = {};
        if (assembly.value) filters.assembly = assembly.value;
        if (container.value) filters.container = container.value;
        state.domain = { dataset: "resources", filters: filters, contains: text.value, result: null, cursor: null }; fetchDomain(null);
      } }, [field("Assembly (exact)", assembly, true), field("Container (exact)", container, true), field("Full resource search", text, true),
        el("button", { type: "submit", text: "Search full resource inventory" })]));
      panel.append(note("Complete inventory pages, not bundled top-N resources. manifest_container and avalonia_container records are containers; child asset bytes are separate overlapping projections."));
      domainPage(panel, "resources");
      panel.append(el("h3", { text: "Content equality, not savings" }), note("Duplicate-asset groups exclude containers. Equal hashes do not prove redundant semantics or reclaimable bytes."),
        button("All captured duplicate groups", function () { openDataset("duplicate_assets"); }));
      return;
    }
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
      " › " + (state.resourceFilter || "all bundled names") + ". These controls filter the bounded snapshot. Live All data provides the complete captured inventory."));
    const filtered = resources.filter(function (resource) {
      return (!state.resourceAssembly || str(resource.assembly) === state.resourceAssembly) &&
        (!state.resourceContainer || str(resource.container) === state.resourceContainer) &&
        (!state.resourceFilter || str(resource.name).toLowerCase().startsWith(state.resourceFilter.toLowerCase()));
    });
    const page = filtered.slice(state.resourcePage * PAGE, (state.resourcePage + 1) * PAGE);
    if (page.length) panel.append(table(["Assembly", "Container", "Resource name", numeric("Asset bytes"), "Storage"], page.map(function (resource) {
      return [resource.assembly, resource.container, button(preview(resource.name, 300), function () { state.detail = { kind: "resource", value: resource }; renderInspector(); }, { class: "link-button" }), byteValue(resource.bytes), resource.storage];
    }), "Bounded asset inventory; container byte totals are reported separately above."));
    else panel.append(empty("No resource entry matches the bundled subset. Full resource absence cannot be inferred."));
    panel.append(projectionPager(state.resourcePage, filtered.length, function (value) { state.resourcePage = value; renderResources(); }));
    panel.append(el("h3", { text: "Duplicate content groups" }), note("SHA-256 equality proves equal content in supplied evidence, not redundant semantics or removability. Do not treat repeated bytes as savings."));
    const duplicates = array(data.duplicate_assets).slice(0, PAGE);
    if (duplicates.length) panel.append(table(["SHA-256", numeric("Bytes each"), numeric("Instances"), "Evidence"], duplicates.map(function (duplicate) {
      return [button(preview(duplicate.sha256, 64), function () { state.detail = { kind: "duplicate", value: duplicate }; renderInspector(); }, { class: "link-button" }),
        byteValue(duplicate.bytes_each), integer(duplicate.instance_count), preview(duplicate.caveat, 200)];
    }), "First " + duplicates.length + " bundled duplicate-content groups; no saving estimate."));
    else panel.append(empty("No duplicate-content groups were supplied."));
  };
  const renderDependencies = function () {
    const panel = heading("Package dependency routes", "Shortest package routes describe declared dependency reachability, not compiler retention. No package chain is joined to graph IDs or assigned reclaimable bytes.");
    if (live && state.catalog && state.catalog.complete) {
      if (state.assembly) panel.append(note("Selected assembly: " + state.assembly + ". Its recorded package links appear below; choose a package to scope declared routes."));
      renderRelations(panel);
      const current = state.domain && state.domain.dataset === "package_routes" ? state.domain : null;
      const input = el("input", { type: "search", maxlength: "1024", value: current ? current.contains : "", placeholder: "Search complete package routes" });
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
        event.preventDefault(); state.domain = { dataset: "package_routes", contains: input.value, filters: {}, result: null, cursor: null }; fetchDomain(null);
      } }, [field("Complete route search", input, true), el("button", { type: "submit", text: "Search all package routes" })]));
      if (current) {
        panel.append(note(Object.keys(current.filters).length ? "Exact route scope: " + Object.entries(current.filters).map(function (e) { return e.join(" = "); }).join(" · ") :
          "Route scope: all captured packages, independent of the selected assembly until a recorded package link is selected."));
        domainPage(panel, "package_routes");
      } else panel.append(note("Choose a recorded package link, or explicitly search all routes. An unknown origin is not guessed from an assembly name."));
      return;
    }
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
    panel.append(pairs([["Physical output delta", report.physical ? byteValue(report.physical.delta_bytes, true) : "Unknown · physical evidence not supplied"],
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
        const delta = byteValue(entry.delta_bytes, true);
        delta.className = number(entry.delta_bytes) > 0 ? "delta-positive" : number(entry.delta_bytes) < 0 ? "delta-negative" : "";
        return [button(preview(entry.identity, 512), function () { state.detail = { kind: "comparison", value: entry }; renderInspector(); }, { class: "link-button" }),
          byteValue(entry.before_bytes), byteValue(entry.after_bytes), delta];
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
      ["Table cap", PAGE + " rows per page"], ["Identity preview budget", byteValue(limits.preview_bytes || 512)],
      ["Query scan limit", integer(limits.max_scanned || 100000)], ["Query timeout", integer(limits.query_timeout_ms || 1500) + " ms"],
      ["Response budget", byteValue(2 * 1024 * 1024)], ["Size display", "Decimal units: 1 KB = 1,000 bytes. Hover a size for its exact byte count."],
      ["Mode", live ? "Live loopback queries + bounded snapshot" : "Bounded snapshot only"]]));
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
    panel.append(note("Overview inspectors use bounded previews. In live mode, All data navigates every captured record and nested value without these overview caps."));
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
      table(["Kind", numeric("Bytes")], metadata.map(function (entry) { return [entry.name, byteValue(entry.bytes)]; }), "Metadata projections overlap other budgets; not added to the total."));
    if (array(data.graphs).length) panel.append(el("h3", { text: "Graph index inventory (not loaded graphs)" }),
      table(["Index", "Generation", numeric("Nodes"), numeric("Edges")], data.graphs.slice(0, PAGE).map(function (graph) {
        return [graph.kind, preview(graph.generation, 200), integer(graph.node_count), integer(graph.edge_count)];
      })));
    if (!live) panel.append(warning(unavailable()));
  };
  const renderOpportunities = function () {
    const panel = heading("Opportunities", "Ranked investigations into repeated code expansion and unexpected retained features. Measured footprint is not predicted saving.");
    if (!data.opportunity_coverage) {
      panel.append(warning("This bundle predates opportunity analysis. Prepare a new immutable bundle to capture complete findings and cross-stream budgets. Missing analysis is not an empty result."));
      return;
    }
    const coverage = data.opportunity_coverage;
    panel.append(pairs([["Complete finding catalog", integer(coverage.findings)], ["Complete budget catalog", integer(coverage.budgets)],
      ["Generator descriptors", integer(coverage.generator_descriptors)], ["Declarations with captured generator ownership", integer(coverage.generated_declarations)]]));
    panel.append(pairs([["Captured output files", integer(coverage.generator_outputs_captured)], ["Trigger links", integer(coverage.generator_links)],
      ["Typed token records", coverage.typed_symbol_records == null ? "Unknown / not captured" : integer(coverage.typed_symbol_records)]]));
    if (coverage.typed_symbol_records == null) panel.append(warning("This index has no typed NativeAOT symbol sidecar. Reimport the original MSTAT, then prepare again; name-derived owners remain candidates."));
    if (!coverage.generator_descriptors || !coverage.generated_declarations) {
      panel.append(warning("Generator attribution is incomplete. Source attributes and output-name patterns do not prove generator execution, compiled output or exclusive ownership. Capture generated output/build provenance to close this gap."));
    }
    panel.append(note("Findings overlap each other and the accounting ledger. Assembly budgets partition by evidence tier; package budgets reconcile separately per target. Unknown/shared attribution stays separate."));
    const findings = array(data.opportunities).slice(0, PAGE);
    if (!findings.length) panel.append(empty("No findings in the captured overview. Inspect the complete catalogs and capture coverage before concluding that there are no opportunities."));
    findings.forEach(function (finding) {
      const card = el("section", { class: "opportunity-card" }, [
        el("h3", { text: preview(finding.title, 200) }),
        pairs([["Additive cohort", byteValue(finding.additive_bytes)], ["Overlapping projection", byteValue(finding.overlapping_bytes)],
          ["Identities", integer(finding.identities)], ["Canonical-sharing identities", integer(finding.canonical_shared_identities)],
          ["Evidence tier", finding.evidence_tier], ["Kind", finding.kind]]),
        note(finding.basis), el("p", { text: finding.investigation })
      ]);
      const actions = el("div", { class: "toolbar" });
      if (finding.family && new TextEncoder().encode(finding.family).length <= 1024) {
        actions.append(button("Inspect complete family contributors", function () {
          state.family = finding.family; state.familyRecord = null; state.assembly = ""; state.owner = ""; state.contains = "";
          state.stream = Object.keys(finding.streams || {})[0] || ""; state.rows = null; state.rowResult = null; state.rowOrder = "bytes";
          activate("Contributors"); if (live) fetchRows(null);
        }, { disabled: !live }));
      }
      array(finding.examples).slice(0, 3).forEach(function (example) {
        actions.append(button("Source / record #" + str(example.ordinal), function () { chooseRow(example); }, { disabled: !live }));
        if (!example.truncated && new TextEncoder().encode(example.identity || "").length <= 1024) {
          actions.append(button("Retention search #" + str(example.ordinal), function () {
            state.graphQuery = example.identity; state.graphMode = "exact"; state.annotatedRetention = null;
            activate("Retention"); if (live) searchGraph(null);
          }, { disabled: !live || !array(data.graphs).length }));
        }
      });
      card.append(actions);
      panel.append(card);
    });
    panel.append(note("Overview retains at most 40 findings. All prepared findings, policy selectors, examples, stream components and budgets remain accessible in the complete catalogs."));
  };
  const lensViews = [
    ["feature", "Feature footprint"], ["lens_xaml", "XAML views and themes"], ["lens_serializers", "Serializer contexts"],
    ["lens_repetitions", "Repeated context roots"], ["lens_arguments", "Generic argument heat map"],
    ["lens_costs", "Expansion cost breakdown"], ["roots", "Retention roots and registrations"],
    ["lens_reflection", "Reflection annotation targets"], ["lens_metadata_strings", "Metadata strings and ownership"]
  ];
  const fetchLens = function (after) {
    const filters = {};
    if (state.lensAssembly) filters.assembly = state.lensAssembly;
    if (state.lensOwner) filters[state.lens === "lens_serializers" ? "context" : "owner"] = state.lensOwner;
    query({ action: "records", dataset: state.lens, contains: state.lensContains, filters: filters, after: after, limit: PAGE },
      "Searching complete investigation lens", function (result) { state.lensPage = result; renderLenses(); },
      { cursor: "after", next: "next_after", limit: PAGE });
  };
  const traceCohort = function (examples) {
    const ordinals = array(examples).slice(0, 3).map(function (item) { return String(item.ordinal); });
    if (!ordinals.length) { showError(new Error("No original identity examples were captured for this selection.")); return; }
    state.lens = "roots"; state.cohort = null; activate("Investigate");
    query({ action: "cohort_retention", graph: state.graphKind, ordinals: ordinals }, "Finding representative retention roots", function (report) {
      state.cohort = report; renderLenses();
    });
  };
  const inspectLens = function (dataset, ordinal) {
    query({ action: "lens_detail", dataset: dataset, ordinal: ordinal }, "Loading selected investigation evidence", function (result) {
      const record = result.record, panel = $("inspector");
      const cost = record.cost || record.owner_cost || record;
      panel.replaceChildren(el("h2", { id: "inspector-title", text: preview(record.owner || record.context || record.argument || record.root || record.attribute || "Investigation evidence", 512) }),
        note(record.scope || "Measured owner accounting; projections overlap and do not predict savings."));
      if (record.preview) panel.append(pairs([["Evidence tier", record.evidence_tier], ["Record lower bound (overlapping)", byteValue(record.bytes)],
        ["Role candidate", record.role], ["Selected metadata owner", record.owner || "Not captured / unowned"],
        ["Ownership evidence", record.ownership], ["Logical offset", integer(record.logical_offset)]]));
      else panel.append(pairs([["Evidence tier", record.evidence_tier], ["Additive footprint", byteValue(record.additive_bytes == null ? cost.additive_bytes : record.additive_bytes)],
          ["Methods accounting", byteValue(cost.methods_bytes)], ["Types accounting", byteValue(cost.types_bytes)],
          ["Blobs accounting", byteValue(cost.blobs_bytes)], ["Overlapping projection", byteValue(cost.overlapping_bytes)],
          ["Other additive stream accounting", byteValue(cost.other_additive_bytes)],
          ["Metadata lower bound", byteValue(record.metadata_lower_bound_bytes)], ["Canonical-marker identities", integer(cost.canonical_shared_identities)]]));
      ["declared_roots", "options", "source_paths", "families", "contexts", "documents", "observed_owner_groups", "source_candidates"].forEach(function (key) {
        if (Array.isArray(record[key])) panel.append(el("h3", { text: key.replaceAll("_", " ") }),
          note(integer(record[key].length) + " captured entries; this preview shows at most 20."),
          el("pre", { text: boundedJson(record[key]) }));
      });
      if (record.attribute) panel.append(el("h3", { text: "Applied annotation" }), pairs([["Target", record.target], ["Attribute", record.attribute], ["Path", record.path], ["Line", record.line]]));
      if (record.preview) panel.append(el("h3", { text: "Captured string preview" }), el("pre", { text: record.preview.text }),
        note("Ownership: " + record.ownership + ". Upstream preview truncated: " + Boolean(record.preview.truncated)));
      const actions = el("div", { class: "toolbar" });
      actions.append(button("Navigate every captured field", function () {
        openFull({ action: "record_value", dataset: dataset, ordinal: ordinal }, datasetLabel(dataset) + " #" + ordinal);
      }));
      array(record.examples).slice(0, 3).forEach(function (example) {
        actions.append(button("Source / native #" + example.ordinal, function () { chooseRow(example); }));
      });
      if (array(record.examples).length) actions.append(button("Compare representative retention roots", function () { traceCohort(record.examples); }, { disabled: !array(data.graphs).length }));
      if (record.source_ordinal != null) actions.append(button("Complete source declaration", function () {
        openFull({ action: "record_value", dataset: "sources", ordinal: record.source_ordinal }, "Applied annotation source");
      }));
      panel.append(actions);
    });
  };
  const measureFeature = function (selectors, after, run, batches) {
    query(Object.assign({ action: "feature_footprint", after: after }, selectors), "Measuring selected feature scope", function (result) {
      if (run !== state.featureRun || state.tab !== "Investigate" || state.lens !== "feature") return;
      const previous = state.feature;
      if (!previous) state.feature = result;
      else {
        const ledger = {};
        Object.keys(Object.assign({}, previous.ledger, result.ledger)).forEach(function (key) {
          const value = (previous.ledger[key] || 0) + (result.ledger[key] || 0);
          if (!Number.isSafeInteger(value)) throw new Error("Feature ledger exceeds browser exact-integer limits. Inspect the JSON CLI output.");
          ledger[key] = value;
        });
        state.feature = Object.assign({}, result, { ledger: ledger, scanned: previous.scanned + result.scanned,
          matched_owner_groups: previous.matched_owner_groups + result.matched_owner_groups,
          entries: array(previous.entries).concat(array(result.entries)).slice(0, 20),
          examples: array(previous.examples).concat(array(result.examples)).sort(function (a, b) { return b.bytes - a.bytes; }).slice(0, 3) });
      }
      renderLenses();
      if (!result.complete && result.next_after != null && batches < 20) measureFeature(selectors, result.next_after, run, batches + 1);
    });
  };
  const renderLenses = function () {
    const panel = heading("Connected bloat investigations", "Follow a feature or type from measured contribution to expansion and observed retention. You decide what is needed; no removal verdicts or savings estimates are inferred.");
    panel.append(field("Investigation lens", select(lensViews, state.lens, function (value) {
      state.lens = value; state.lensPage = null; state.lensAssembly = ""; state.lensOwner = ""; renderLenses();
    }), true));
    if (!data.lens_coverage) { panel.append(warning("This bundle predates connected lenses. Prepare a new immutable bundle; absent analysis is not an empty result.")); return; }
    panel.append(note("Source and XAML associations are tiered candidates. Generic arguments and metadata projections overlap; canonical markers do not count unique bodies. Complete records and capture gaps remain inspectable."));
    if (state.lens === "lens_metadata_strings") {
      const capture = data.lens_coverage.metadata_strings || {};
      panel.append(pairs([["Captured string records", integer(capture.captured_records)],
        ["Captured string lower bound (overlapping)", byteValue(capture.captured_lower_bound_bytes)],
        ["Records with selected log owner", integer(capture.records_with_selected_owner)],
        ["Truncated upstream previews", integer(capture.truncated_previews)]]),
        note(capture.scope || "Metadata strings were not captured."),
        button("Inspect complete string capture coverage", function () { openDataset("lens_coverage"); }));
    }
    if (state.lens === "lens_xaml" && !data.lens_coverage.xaml_documents) panel.append(warning("No original XAML documents were captured in this build evidence. Owner/helper cohorts remain visible, but view/template input mapping is unknown."));
    if (!live) { panel.append(empty(unavailable()), el("pre", { text: boundedJson(data.lens_coverage) })); return; }
    if (state.lens === "feature") {
      const assembly = el("input", { type: "text", maxlength: "1024", value: state.lensAssembly, placeholder: "Optional exact assembly" });
      const namespace = el("input", { type: "text", maxlength: "1024", value: state.featureSelectors && state.featureSelectors.namespace || "", placeholder: "Namespace and descendants" });
      const owner = el("input", { type: "text", maxlength: "1024", value: state.lensOwner, placeholder: "Optional exact declaring type" });
      const project = el("input", { type: "text", maxlength: "1024", value: state.featureSelectors && state.featureSelectors.project || "", placeholder: "Optional captured project path" });
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
        event.preventDefault(); state.lensAssembly = assembly.value; state.lensOwner = owner.value; state.feature = null;
        const selectors = { assembly: assembly.value || null, namespace: namespace.value || null, owner: owner.value || null, project: project.value || null };
        state.featureSelectors = selectors; measureFeature(selectors, null, ++state.featureRun, 1);
      } }, [field("Assembly", assembly, true), field("Namespace", namespace, true), field("Declaring type", owner, true),
        field("Project hint", project, true), el("button", { type: "submit", text: "Measure feature footprint" })]));
      if (!state.feature) { panel.append(empty("Choose an assembly, namespace, type or recorded project hint. Leaving selectors empty measures all captured owners.")); return; }
      const report = state.feature, ledger = report.ledger || {};
      panel.append(pairs([["Measured native footprint", byteValue(ledger.additive_bytes || 0)], ["Methods", byteValue(ledger.methods_bytes || 0)],
        ["Types", byteValue(ledger.types_bytes || 0)], ["Blobs", byteValue(ledger.blobs_bytes || 0)],
        ["Other additive streams", byteValue(ledger.other_additive_bytes || 0)],
        ["Unresolved owner subset", byteValue(ledger.unresolved_bytes || 0)], ["Candidate owner subset", byteValue(ledger.candidate_owner_bytes || 0)],
        ["Typed owner subset", byteValue(ledger.typed_owner_bytes || 0)], ["Metadata (overlapping lower bound)", byteValue(ledger.metadata_lower_bound_bytes || 0)],
        ["Specialized overlap", byteValue(ledger.overlapping_bytes || 0)], ["Owner groups", integer(report.matched_owner_groups)],
        ["Scan complete", Boolean(report.complete)], ["Stopped because", report.stop_reason]]));
      if (!report.complete) panel.append(warning("Partial scanned-range ledger, not the full selected feature footprint."),
        button("Continue measuring remaining owners", function () {
          if (report.next_after == null) { showError(new Error("No continuation progress. Retry the scope measurement.")); return; }
          measureFeature(state.featureSelectors, report.next_after, state.featureRun, 1);
        }));
      panel.append(note("Typed/candidate/unresolved figures are subsets of the native footprint, not extra bytes. Metadata is a captured lower bound; missing dimensions are not reconstructed."));
      if (array(report.examples).length) panel.append(button("Compare representative retention roots", function () { traceCohort(report.examples); }, { disabled: !array(data.graphs).length }));
      panel.append(el("div", { class: "inventory-table" }, [table(["Assembly", "Owner", numeric("Methods"), numeric("Types"), "Evidence"], array(report.entries).map(function (row) {
        return [row.assembly, row.owner, byteValue(row.methods_bytes), byteValue(row.types_bytes), row.evidence_tier];
      }), "At most 20 owner previews; use the complete owner catalog for all groups.")]));
      panel.append(button("Browse complete owner ledger", function () { openDataset("lens_feature_owners", "", state.lensAssembly ? { assembly: state.lensAssembly } : {}); }));
      return;
    }
    if (state.lens === "roots") {
      const ordinals = el("input", { type: "text", maxlength: "100", placeholder: "One to three native ordinals, comma-separated" });
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
        event.preventDefault();
        const values = ordinals.value.split(",").map(function (text) { return text.trim(); });
        if (!values.length || values.length > 3 || values.some(function (text) { return !/^\d+$/.test(text); }) || new Set(values).size !== values.length) { showError(new Error("Enter one to three distinct unsigned native identity ordinals.")); return; }
        query({ action: "cohort_retention", graph: state.graphKind, ordinals: values }, "Comparing representative retention evidence", function (report) { state.cohort = report; renderLenses(); });
      } }, [field("Original native ordinals", ordinals, true), field("Compiler graph", select(array(data.graphs).map(function (g) { return [g.kind, g.kind]; }), state.graphKind, function (value) { state.graphKind = value; })),
        el("button", { type: "submit", text: "Find observed retention roots" })]));
      if (!state.cohort) { panel.append(empty("Select representative identities from another lens, or enter their original ordinals. One bounded witness is not a removal prerequisite.")); return; }
      panel.append(warning(state.cohort.scope), table(["Root", "Kind", numeric("Observed paths")], array(state.cohort.observed_roots).map(function (root) {
        return [button(preview(root.label, 256), function () { state.graphKind = state.cohort.graph; state.selectedNode = root.node_id; activate("Retention"); why(); }, { class: "link-button" }), root.root_kind, integer(root.observed_paths)];
      }), "Observed bounded roots only; absence is not proof of no retainer."));
      array(state.cohort.seeds).forEach(function (seed) {
        panel.append(el("h3", { text: "Native identity #" + seed.ordinal }), note(seed.status),
          note("Search stop: " + (seed.search ? seed.search.stop_reason : "not searched")));
        if (seed.search && seed.search.next_after_id != null) panel.append(button("Continue this exact label search", function () {
          state.graphKind = state.cohort.graph; state.graphQuery = seed.identity; state.graphMode = "exact";
          activate("Retention"); searchGraph(seed.search.next_after_id);
        }));
        array(seed.witnesses).forEach(function (report) {
          panel.append(note("Witness stop: " + report.witness.stop_reason + " · incoming stop: " + report.alternative_incoming.stop_reason),
            button("Inspect original annotated witness", function () { activate("Retention"); applyWhy(report.witness, report); }));
        });
      });
      return;
    }
    if (!data.datasets[state.lens]) { panel.append(warning("This lens was not captured. Import the required metadata evidence and prepare again; missing capture is not zero.")); return; }
    const search = el("input", { type: "search", maxlength: "1024", value: state.lensContains, placeholder: "Search complete captured records" });
    const globalLens = ["lens_arguments", "lens_repetitions"].includes(state.lens);
    const assembly = el("input", { type: "text", maxlength: "1024", value: state.lensAssembly, placeholder: "Optional exact assembly", disabled: globalLens });
    const owner = el("input", { type: "text", maxlength: "1024", value: state.lensOwner, placeholder: "Optional exact owner/context", disabled: globalLens });
    panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
      event.preventDefault(); state.lensContains = search.value; state.lensAssembly = assembly.value; state.lensOwner = owner.value;
      state.lensPage = null; fetchLens(null);
    } }, [field("Complete-record search", search, true), field("Assembly", assembly, true), field("Owner/context", owner, true),
      el("button", { type: "submit", text: "Search lens" })]));
    if (!state.lensPage) {
      panel.append(empty("Loading a bounded page from the complete captured lens."));
      if (!state.pending) fetchLens(null);
      return;
    }
    const columns = INVESTIGATION.columns(state.lens), page = state.lensPage;
    panel.append(el("div", { class: "inventory-table" }, [table(columns.map(function (column) { return column[2] ? numeric(column[1]) : column[1]; }).concat(["Evidence"]),
      array(page.entries).map(function (entry) {
        return columns.map(function (column) {
          const value = entry.fields[column[0]];
          return column[2] === "bytes" ? byteValue(value) : column[2] === "count" ? integer(value) : preview(value, 256);
        }).concat([button("Inspect relationships", function () { inspectLens(state.lens, entry.ordinal); })]);
      }), datasetLabel(state.lens) + " · " + integer(page.total) + " captured records; each page replaces the last.")]));
    panel.append(note(integer(page.scanned) + " positions scanned · " + page.stop_reason),
      button("Next captured page", function () { fetchLens(page.next_after); }, { disabled: page.next_after == null }),
      button("All data / original records", function () { openDataset(state.lens, state.lensContains); }));
  };
  const renderView = function () {
    const views = { Opportunities: renderOpportunities, Investigate: renderLenses, Landscape: renderLandscape, Contributors: renderContributors, Retention: renderRetention, Amplification: renderAmplification,
      Resources: renderResources, Dependencies: renderDependencies, Comparison: renderComparison, Evidence: renderEvidence, "All data": renderAllData };
    views[state.tab]();
    refreshBudget();
  };
  const completeAccess = function (panel) {
    const inventories = {
      Landscape: ["groups"], Contributors: ["identities"],
      Opportunities: ["opportunities", "budgets", "opportunity_coverage", "generator_runs", "generator_links", "sources"],
      Retention: ["graph_" + state.graphKind + "_nodes", "graph_" + state.graphKind + "_edges"],
      Amplification: ["generic_families", "generators"], Resources: ["resources", "duplicate_assets"],
      Dependencies: ["package_routes", "packages"], Comparison: ["comparison"],
      Evidence: ["provenance", "diagnostics", "sources", "metadata_by_type", "metadata_largest_strings"]
    };
    if (inventories[state.tab]) {
      const access = el("div", { class: "toolbar" }, [note("This chart is a bounded overview. Complete captured records:")]);
      inventories[state.tab].forEach(function (name) {
        const count = name === "identities" ? (data.coverage || {}).identities : data.datasets && data.datasets[name] ? data.datasets[name].records : null;
        access.append(button(datasetLabel(name) + (count == null ? "" : " (" + integer(count) + ")"), function () {
          const filters = {};
          if (name === "resources") {
            if (state.resourceAssembly) filters.assembly = state.resourceAssembly;
            if (state.resourceContainer) filters.container = state.resourceContainer;
          } else if (name === "groups") {
            filters.dimension = state.dimension;
            if (state.stream) filters.stream = state.stream;
          } else if (name === "generic_families" && state.familyStream) filters.stream = state.familyStream;
          else if (name === "identities") {
            if (state.stream) filters.stream = state.stream;
            if (state.assembly) filters.assembly = state.assembly;
            if (state.owner) filters.owner = state.owner;
          }
          openDataset(name, name === "resources" ? state.resourceFilter : name === "identities" ? state.contains : "", filters);
        }, { disabled: !live }));
      });
      panel.append(access);
    }
  };
  const datasetLabel = function (name) {
    const labels = { identities: "Contributor identities", groups: "Landscape partitions", generic_families: "Generic families",
      duplicate_assets: "Duplicate assets", package_routes: "Package routes", mstat_summary: "MSTAT summary",
      generators: "Generators", opportunities: "Ranked opportunity investigations", budgets: "Cross-stream budgets",
      opportunity_coverage: "Opportunity evidence coverage", generator_runs: "Generator output capture", generator_links: "Generator triggers",
      sources: "Source declarations", metadata_by_type: "Metadata types",
      metadata_largest_strings: "Metadata strings", metadata_summary: "Metadata accounting" };
    const supplement = /^supplemental_(\d+)_(.+)$/.exec(name);
    if (supplement) {
      const inventory = array(state.catalog && state.catalog.supplements)[Number(supplement[1])];
      return (inventory && inventory.label ? inventory.label : "Supplement " + (Number(supplement[1]) + 1)) + " · " + datasetLabel(supplement[2]);
    }
    return labels[name] || name.replaceAll("_", " ").replace(/^./, function (c) { return c.toUpperCase(); });
  };
  const openDataset = function (name, contains, filters) {
    state.dataset = name; state.datasetContains = contains || ""; state.datasetFilters = filters || {};
    state.datasetPage = null; state.datasetCursor = null; state.detail = null;
    activate("All data");
  };
  const fetchDataset = function (after) {
    query({ action: "records", dataset: state.dataset, contains: state.datasetContains,
      filters: state.datasetFilters, after: after, limit: PAGE }, "Searching complete " + datasetLabel(state.dataset), function (result) {
      state.datasetPage = result; state.datasetCursor = result.next_after;
      renderAllData();
    }, { cursor: "after", next: "next_after", limit: PAGE });
  };
  const renderAllData = function () {
    const panel = heading("All captured data", "Browse complete inventories on disk, not the top-N snapshot. Open a record to navigate every field, array entry and full-text chunk; previous pages are replaced, never accumulated.");
    if (!live) {
      panel.append(empty(unavailable()), note("The portable export still contains only a bounded overview. Complete inventories are served by vitnet explore browse."));
      return;
    }
    if (!state.catalog) {
      panel.append(empty("Loading the captured dataset catalog. No inventory is downloaded in full."));
      if (!state.pending) query({ action: "catalog" }, "Loading dataset counts and capture boundaries", function (result) {
        state.catalog = result;
        if (!array(result.datasets).some(function (entry) { return entry.name === state.dataset; })) state.dataset = "identities";
        renderScope(); renderAllData(); fetchDataset(null);
      });
      return;
    }
    if (!state.catalog.complete) panel.append(warning("Legacy bundle: only contributor identities and indexed graphs are accessible in full. Run explore prepare into a new directory to retain complete inventories; this bundle is not a complete catalog."));
    panel.append(note(state.catalog.scope));
    const datasets = array(state.catalog.datasets);
    const descriptor = datasets.find(function (entry) { return entry.name === state.dataset; });
    const search = el("input", { type: "search", maxlength: "1024", value: state.datasetContains, placeholder: "Search full stored text (case-sensitive)" });
    const filterName = el("input", { type: "text", maxlength: "128", placeholder: "assembly, stream, container…" });
    const filterValue = el("input", { type: "text", maxlength: "4096", placeholder: "Exact field value" });
    const finder = el("input", { type: "search", maxlength: "256", value: state.datasetFinder, placeholder: "Find a dataset by category, name or inventory label" });
    const choices = el("select", { onchange: function () { openDataset(choices.value); } });
    const fillChoices = function () {
      const groups = new Map();
      datasets.filter(function (entry) { return !finder.value || (datasetLabel(entry.name) + " " + INVESTIGATION.category(entry.name)).toLowerCase().includes(finder.value.toLowerCase()); })
        .forEach(function (entry) {
          const category = INVESTIGATION.category(entry.name);
          if (!groups.has(category)) { const group = el("optgroup", { label: category }); groups.set(category, group); }
          groups.get(category).append(el("option", { value: entry.name, text: datasetLabel(entry.name) + " · " + integer(entry.records) + " records" }));
        });
      choices.replaceChildren(...groups.values()); choices.value = state.dataset;
    };
    finder.addEventListener("input", function () { state.datasetFinder = finder.value; fillChoices(); });
    fillChoices();
    panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
      event.preventDefault(); state.datasetContains = search.value;
      state.datasetPage = null; state.datasetCursor = null; fetchDataset(null);
    } }, [
      field("Find a dataset", finder, true), field("Captured dataset", choices, true),
      field("Full-text search", search, true),
      el("button", { type: "submit", text: "Search / browse all" })
    ]));
    if (!state.dataset.startsWith("graph_")) {
      panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
        event.preventDefault();
        if (!filterName.value) { showError(new Error("Enter a top-level field name before adding an exact filter.")); return; }
        if (!Object.hasOwn(state.datasetFilters, filterName.value) && Object.keys(state.datasetFilters).length >= 8) {
          showError(new Error("At most eight exact filters can be combined. Remove one first.")); return;
        }
        Object.defineProperty(state.datasetFilters, filterName.value, { configurable: true, enumerable: true, writable: true, value: filterValue.value });
        state.datasetPage = null; renderAllData(); fetchDataset(null);
      } }, [field("Exact field", filterName), field("Value", filterValue, true), el("button", { type: "submit", text: "Add filter" })]));
      const active = el("div", { class: "scope-bar" });
      Object.entries(state.datasetFilters).forEach(function (entry) {
        active.append(button(entry[0] + " = " + preview(entry[1], 80) + " · Remove", function () {
          delete state.datasetFilters[entry[0]]; state.datasetPage = null; renderAllData(); fetchDataset(null);
        }));
      });
      if (active.childElementCount) panel.append(active);
    }
    if (descriptor) panel.append(pairs([["Captured records", integer(descriptor.records)], ["Storage", descriptor.storage],
      ["Browser page", "At most " + PAGE + " rows"], ["Record details", "100 children or 4 KB text per page; complete field navigation"]]));
    if (state.dataset === "generators" || state.dataset === "generator_evidence") panel.append(note("Zero captured generators is missing evidence, not proof of zero generator work."));
    if (state.dataset === "comparison") panel.append(warning(state.catalog.comparison_scope));
    const result = state.datasetPage;
    if (!result) panel.append(empty("Select Search / browse all to read the first bounded page."));
    else {
      const entries = array(result.entries);
      if (entries.length) panel.append(recordTable(state.dataset, entries));
      else panel.append(empty(result.stop_reason === "complete" ? "No captured records match this search." :
        "No match in this scan batch. Continue scanning: an empty partial page is not a complete no-match result."));
      panel.append(el("div", { class: "pagination" }, [
        el("span", { text: resultSummary(result, "records / slots") }),
        el("div", {}, [button("Restart search", function () { fetchDataset(null); }),
          button("Next / continue scan", function () { fetchDataset(state.datasetCursor); }, { disabled: result.auto_running || state.datasetCursor == null })])
      ]));
    }
    const ordinalInput = el("input", { type: "text", inputmode: "numeric", pattern: "[0-9]+", maxlength: "20", placeholder: "Unsigned decimal ordinal or node ID" });
    panel.append(el("form", { class: "toolbar", onsubmit: function (event) {
      event.preventDefault();
      if (!/^[0-9]+$/.test(ordinalInput.value)) { showError(new Error("Enter an unsigned decimal record ordinal or graph node ID.")); return; }
      openFull({ action: "record_value", dataset: state.dataset, ordinal: ordinalInput.value }, datasetLabel(state.dataset) + " #" + ordinalInput.value);
    } }, [field("Open a specific record", ordinalInput, true), el("button", { type: "submit", text: "Open record" })]));
  };
  const openFull = function (base, title) {
    cancel(false); clearError();
    state.detail = { kind: "full", value: { base: base, title: title, path: [], labels: [], start: 0, history: [], key: false, page: null }, loading: true };
    renderInspector(); fetchFull();
  };
  const fetchFull = function () {
    const selection = state.detail && state.detail.kind === "full" && state.detail.value;
    if (!selection) return;
    selection.page = null; state.detail.loading = true; renderInspector();
    query(Object.assign({}, selection.base, { path: selection.path, start: selection.start, key: selection.key }),
      "Loading complete captured fields", function (result) {
        selection.page = result; state.detail.loading = false; renderInspector();
        setStatus(result.next_start == null ? "Value page complete. Every displayed child can be opened." : "Continuation available for this complete captured value.", false);
      });
  };
  const inspectFull = function (panel, selection) {
    $("inspector-title").textContent = selection.title;
    const crumbs = el("nav", { class: "landscape-breadcrumb", "aria-label": "Captured value path" }, [
      button("Record", function () {
        selection.path = []; selection.labels = []; selection.start = 0; selection.history = []; selection.key = false; fetchFull();
      })
    ]);
    selection.labels.forEach(function (label, index) {
      crumbs.append(el("span", { text: "›", "aria-hidden": "true" }), button(preview(label, 48), function () {
        selection.path = selection.path.slice(0, index + 1); selection.labels = selection.labels.slice(0, index + 1);
        selection.start = 0; selection.history = []; selection.key = false; fetchFull();
      }));
    });
    panel.append(crumbs, note("Captured data only. Paths are text, not file-open actions. Numbers retain exact decimal text."));
    if (selection.base.dataset === "identities" || selection.base.action === "identity_value") panel.append(button("All source / emitter candidates", function () {
      openFull({ action: "source_value", ordinal: selection.base.ordinal }, "Complete source associations #" + selection.base.ordinal);
    }));
    if (selection.base.dataset === "identities" || selection.base.action === "identity_value") panel.append(button("Full parsed producer shape", function () {
      openFull({ action: "identity_shape_value", ordinal: selection.base.ordinal }, "Complete producer shape #" + selection.base.ordinal);
    }));
    const page = selection.page;
    if (!page) {
      panel.append(empty(state.detail.loading ? "Loading a bounded page of this complete value…" : "No value page loaded. Use the Record breadcrumb to retry."));
      return;
    }
    if (page.kind === "string") {
      panel.append(note((selection.key ? "Field name · " : "") + "UTF-8 bytes " + selection.start + "–" +
        (selection.start + new TextEncoder().encode(page.text).byteLength) + " / " + integer(page.total_bytes)),
        el("pre", { text: page.text === "" ? "(Empty string)" : page.text }));
    } else if (page.kind === "object" || page.kind === "array") {
      if (!array(page.entries).length) panel.append(empty("Captured empty " + page.kind + "."));
      else panel.append(table(["Field / index", "Type", "Value (preview)"], array(page.entries).map(function (entry) {
        const navigate = function (key) {
          selection.path = selection.path.concat(entry.index); selection.labels = selection.labels.concat(entry.key);
          selection.start = 0; selection.history = []; selection.key = key; selection.page = null; fetchFull();
        };
        const label = el("div", {}, [button(entry.key, function () { navigate(false); }, { class: "link-button" })]);
        if (entry.key_truncated) label.append(button("Full field name", function () { navigate(true); }, { class: "link-button" }));
        return [label, entry.kind, button(entry.summary || "(Empty string)", function () { navigate(false); }, { class: "link-button" })];
      }), "Fields " + selection.start + "–" + (selection.start + array(page.entries).length) + " / " + integer(page.total) + ". Every child is navigable."));
    } else {
      const label = selection.labels[selection.labels.length - 1] || "";
      if (page.kind === "number" && /(^bytes$|_bytes$|lower_bound|bytes_each)/.test(label)) {
        panel.append(pairs([["Human size", el("span", { text: bytes(Number(page.display)), title: page.display + " bytes" })]]));
      }
      panel.append(note("Exact captured " + page.kind), el("pre", { text: page.display }));
    }
    panel.append(el("div", { class: "pagination" }, [
      el("span", { text: "One bounded value page" }),
      el("div", {}, [
        button("First page", function () { selection.start = 0; selection.history = []; fetchFull(); }, { disabled: selection.start === 0 }),
        button("Previous", function () { selection.start = selection.history.pop(); fetchFull(); }, { disabled: !selection.history.length }),
        button(page.kind === "string" ? "Next text chunk" : "Next fields", function () {
          selection.history.push(selection.start); selection.history = selection.history.slice(-64); selection.start = page.next_start; fetchFull();
        }, { disabled: page.next_start == null })
      ])
    ]));
    if (selection.base.dataset && selection.base.dataset.endsWith("_edges") && !selection.path.length) {
      const nodeFields = array(page.entries).filter(function (entry) { return entry.key === "source_id" || entry.key === "target_id"; });
      nodeFields.forEach(function (entry) {
        panel.append(button("Open " + entry.key.replace("_id", "") + " node " + entry.summary, function () {
          openFull({ action: "record_value", dataset: selection.base.dataset.replace(/_edges$/, "_nodes"), ordinal: entry.summary }, "Graph node #" + entry.summary);
        }));
      });
    }
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
    array(match.assemblies).slice(0, 20).forEach(function (entry) {
      const name = typeof entry === "string" ? entry : str(entry.name || entry.assembly);
      panel.append(button("Contributors: " + preview(name, 128), function () { followAssembly(name, "Contributors"); }, { disabled: !live }),
        button("Package origins: " + preview(name, 128), function () { followAssembly(name, "Dependencies"); }, { disabled: !live }),
        button("Resources: " + preview(name, 128), function () { followAssembly(name, "Resources"); }, { disabled: !live }));
    });
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
    if (evidence.shape) {
      panel.append(el("h3", { text: "Parsed producer pattern" }), note(preview(evidence.shape.family, 1024)),
        pairs([["Concrete argument count", integer(evidence.shape.argument_count)], ["Canonical/shared markers", evidence.shape.canonical_shared ? "Present" : "Absent"]],
        ), warning("Arguments are producer spellings, not guaranteed C# type arguments. Source matches below are candidates, not proven caller sites."));
      array(evidence.argument_sources).slice(0, 20).forEach(function (argument) {
        const candidates = argument.candidates || {};
        panel.append(el("div", { class: "source-card" }, [el("strong", { text: preview(argument.argument, 512) }),
          note("Candidate status: " + str(candidates.status) + " · " + integer(argument.total_sources) + " source candidates"),
          note(array(candidates.sources).slice(0, 5).map(function (source) { return str(source.type_name || source.member) + " · " + str(source.path) + ":" + str(source.line); }).join(" | ") || "No source candidate captured")]));
      });
    } else if (evidence.shape_diagnostic) panel.append(warning(str(evidence.shape_diagnostic.code) + ": " + str(evidence.shape_diagnostic.message)));
  };
  const inspectBucket = function (panel, name) {
    const bucket = INVESTIGATION.bucket(name);
    panel.append(el("h3", { text: bucket ? bucket.title : "Compiler bucket interpretation" }));
    if (!bucket) { panel.append(note("No verified glossary entry for this producer spelling. Bytes remain measured, but a mechanism or constituent join is not inferred.")); return; }
    panel.append(note(bucket.description), note(bucket.investigation),
      el("a", { href: bucket.source, target: "_blank", rel: "noopener noreferrer", text: "Pinned Microsoft NativeAOT producer source" }),
      button("Investigate " + bucket.view.toLowerCase(), function () {
        if (bucket.view === "Resources") { state.assembly = ""; state.domain = null; }
        if (name === "ArrayOfFrozenObjects") { state.stream = "FrozenObjects"; state.assembly = ""; state.owner = ""; state.rows = null; }
        activate(bucket.view);
      }));
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
    panel.append(note("Pinned selection: " + detail.kind + ". View changes do not change this evidence; select another record to replace it."));
    if (detail.kind === "full") {
      inspectFull(panel, value);
      return;
    } else if (detail.kind === "row") {
      $("inspector-title").textContent = "Contributor #" + str(value.ordinal);
      panel.append(el("div", { class: "identity", text: preview(value.identity, 512) }),
        pairs([["Stream", value.stream], ["Accounted size", byteValue(value.bytes)], ["Records", integer(value.records)], ["Budget role", value.accounted ? "Additive accounted identity" : "Non-additive / unaccounted"],
          ["Original identity size", byteValue(value.identity_bytes)], ["Preview", (value.truncated ? "Truncated" : "Complete supplied identity") + (value.identity_lossy ? " · lossy UTF-8" : "")],
          ["Raw identity BLAKE3", value.raw_identity_blake3]]));
      inspectSources(panel, detail);
      if (value.stream === "Blobs") inspectBucket(panel, str(value.identity).split("__", 1)[0]);
      panel.append(el("div", { class: "toolbar" }, [
        button("Full identity & fields", function () { openFull({ action: "identity_value", ordinal: value.ordinal }, "Complete contributor #" + value.ordinal); }, { disabled: !live }),
        button("All source candidates & attributes", function () { openFull({ action: "source_value", ordinal: value.ordinal }, "Complete source associations #" + value.ordinal); }, { disabled: !live })
        , button("Full parsed producer shape", function () { openFull({ action: "identity_shape_value", ordinal: value.ordinal }, "Complete producer shape #" + value.ordinal); }, { disabled: !live })
        , button("Typed token owners / signatures", function () { openFull({ action: "symbol_value", ordinal: value.ordinal }, "Captured managed token candidates #" + value.ordinal); },
          { disabled: !live || !data.opportunity_coverage || data.opportunity_coverage.typed_symbol_records == null })
      ]));
      panel.append(el("h3", { text: "Retention is separate" }), note("A matching label is a candidate join only. Numeric graph IDs are never contributor byte ownership."));
      if (!value.truncated && !value.identity_lossy) panel.append(button("Search exact graph label", function () {
        state.graphQuery = str(value.identity); state.graphMode = "exact"; activate("Retention"); searchGraph(null);
      }, { disabled: !live || !array(data.graphs).length }));
      else panel.append(note("Exact graph label search is unavailable for truncated or lossy identities; use the Retention search explicitly."));
      if (!live) panel.append(note("Offline retention is limited to explicitly bundled witnesses. No witness is invented for this contributor."));
    } else if (detail.kind === "node") {
      $("inspector-title").textContent = "Compiler graph node";
      panel.append(el("div", { class: "identity", text: preview(value.label, 512) }), pairs([["Graph index", state.graphKind], ["Node ID (not ordinal)", value.node_id],
        ["Original label size", byteValue(value.label_bytes)], ["Preview", value.truncated ? "Truncated" : "Complete supplied label"], ["Incoming degree", integer(value.incoming_edges)],
        ["Node presence", value.missing ? "Unknown / absent source node" : "Indexed node"]]),
        note("No byte measurement is attached to this graph node. Source emitter candidates and compiler retainers have different evidence bases."),
        button("Expand this node's retainers", function () { incoming(null); }, { disabled: !live || state.tab !== "Retention" }),
        button("Find this node's root witnesses", why, { disabled: !live || state.tab !== "Retention" }));
      panel.append(button("Full node label & fields", function () {
        openFull({ action: "record_value", dataset: "graph_" + state.graphKind + "_nodes", ordinal: value.node_id }, "Complete graph node #" + value.node_id);
      }, { disabled: !live || value.missing }));
      if (!live) panel.append(note("New graph queries require the live local explorer; only bundled witnesses are available offline."));
    } else if (detail.kind === "group") {
      $("inspector-title").textContent = "Partition scope";
      panel.append(pairs([["Dimension", value.dimension], ["Stream", value.stream], ["Partition", value.name], ["Bytes", byteValue(value.bytes)], ["Identities", integer(value.identities)], ["Evidence status", value.status]]),
        note("This is an aggregate partition, not a claim that every contributor has complete source attribution. Owner groups do not masquerade as assembly filters."));
      if (value.stream === "Blobs" && value.dimension === "owner") inspectBucket(panel, value.name);
      if (value.dimension === "assembly" && !["_unmapped", "_ambiguous"].includes(value.name)) panel.append(
        button("Recorded package origins", function () { followAssembly(value.name, "Dependencies"); }, { disabled: !live }),
        button("Assembly resource inventory", function () { followAssembly(value.name, "Resources"); }, { disabled: !live }));
    } else if (detail.kind === "resource") {
      $("inspector-title").textContent = INVESTIGATION.storageRole(value.storage);
      panel.append(pairs([["Assembly", value.assembly], ["Container", value.container], ["Name", value.name], ["Recorded bytes", byteValue(value.bytes)],
        ["SHA-256", value.sha256], ["Source path (text only)", value.source_path], ["Storage", value.storage]]),
        warning("Asset bytes and container bytes are separate projections. Content equality does not establish removability."));
    } else if (detail.kind === "duplicate") {
      $("inspector-title").textContent = "Equal-content assets";
      panel.append(pairs([["SHA-256", value.sha256], ["Bytes per instance", byteValue(value.bytes_each)], ["Full instance count", integer(value.instance_count)]]),
        warning(value.caveat || "Equal hashes are content-equality evidence, not a predicted saving."));
      const instances = array(value.instances).slice(0, 20);
      panel.append(table(["Assembly", "Container", "Resource"], instances.map(function (resource) { return [resource.assembly, resource.container, preview(resource.name, 300)]; }),
        instances.length + " supplied instances shown / " + integer(value.instance_count) + " full instances"));
    } else if (detail.kind === "family") {
      $("inspector-title").textContent = "Generic family";
      panel.append(el("div", { class: "identity", text: preview(value.family, 512) }), pairs([["Stream", value.stream], ["Projected accounted bytes", byteValue(value.bytes)],
        ["Indexed identities", integer(value.identities)], ["Canonical/shared identities", integer(value.canonical_shared_identities)]]),
        warning("Identity count is not a source-language instantiation count. Shared/canonical identities and family projections do not imply specialization savings."));
    } else if (detail.kind === "generator") {
      $("inspector-title").textContent = "Generator evidence";
      panel.append(pairs([["Name", value.name], ["Version", value.version], ["Candidate-associated bytes", byteValue(value.candidate_accounted_bytes)],
        ["Asserted-associated bytes", byteValue(value.asserted_accounted_bytes)], ["Execution time / memory", "Not supplied · unknown, not zero"]]),
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
        pairs([["Before bytes", byteValue(value.before_bytes)], ["After bytes", byteValue(value.after_bytes)], ["Signed logical delta", byteValue(value.delta_bytes, true)]]),
        warning("A logical delta is not a physical output delta or a predicted saving. Review comparison provenance and compatibility warnings."));
    }
    const complete = { resource: ["resources", value.name], duplicate: ["duplicate_assets", value.sha256],
      family: ["generic_families", value.family], generator: ["generators", value.name],
      route: ["package_routes", value.package], group: ["groups", value.name], comparison: ["comparison", ""] }[detail.kind];
    if (complete) panel.append(button("Browse complete records & nested fields", function () {
      openDataset(complete[0], str(complete[1] || "").slice(0, 1024));
    }, { disabled: !live }));
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
  $("cancel-query").addEventListener("click", function () { cancel(false); renderView(); renderInspector(); });
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
  const metrics = [["Reported object total", (data.accounting || {}).total_bytes]].concat(array((data.accounting || {}).streams).slice(0, 6).map(function (stream) { return [str(stream.name), stream.bytes]; }));
  $("budget-summary").replaceChildren(...metrics.map(function (entry) {
    return el("div", { class: "metric" }, [el("span", { class: "metric-label", text: entry[0] }), el("strong", { class: "metric-value" }, [byteValue(entry[1])]),
      el("span", { class: "metric-unit", text: percent(entry[1], number((data.accounting || {}).total_bytes)) + " of accounted object total" })]);
  }));
  $("budget-summary").after(note("Sizes use B, KB, MB and GB automatically (1 KB = 1,000 bytes). Hover a size for the exact byte count."));
  setStatus(live ? "Ready · queries use bounded scans and current-page replacement." : unavailable(), false);
  renderTabs(); renderScope(); renderView(); renderInspector();
  if (live) query({ action: "catalog" }, "Loading captured-data coverage", function (result) {
    state.catalog = result; renderScope(); renderView();
    if (["Resources", "Dependencies", "Amplification"].includes(state.tab)) ensureDomain();
  });
  Object.defineProperty(window, "vitnetDebug", { configurable: false, writable: false, value: Object.freeze({
    counts: function () { return Object.freeze({ nodes: state.graphNodes.length, edges: state.graphEdges.length,
      renderedRows: document.querySelectorAll("tbody tr").length, currentTab: state.tab, pending: Boolean(state.pending) }); }
  }) });
})();
