/* Original frontend code: MIT, under the repository license.
   Deterministic bounded layering, not a force simulation. */
"use strict";
self.onmessage = function (event) {
  const message = event.data;
  if (!message || !Array.isArray(message.nodes) || !Array.isArray(message.edges)) return;
  const nodes = message.nodes.slice(0, 200).map(function (node) { return { id: String(node.id) }; });
  const edges = message.edges.slice(0, 500);
  const ids = new Set(nodes.map(function (node) { return node.id; }));
  const levels = new Map();
  const incoming = new Map();
  nodes.forEach(function (node) { incoming.set(node.id, []); });
  edges.forEach(function (edge) {
    const source = String(edge.source), target = String(edge.target);
    if (ids.has(source) && ids.has(target)) incoming.get(target).push(source);
  });
  const selected = String(message.selected == null ? "" : message.selected);
  const queue = [];
  if (ids.has(selected)) { levels.set(selected, 0); queue.push(selected); }
  for (let cursor = 0; cursor < queue.length; cursor++) {
    const id = queue[cursor];
    const parents = incoming.get(id).slice().sort();
    parents.forEach(function (parent) {
      if (!levels.has(parent)) { levels.set(parent, levels.get(id) + 1); queue.push(parent); }
    });
  }
  const layers = new Map();
  nodes.slice().sort(function (a, b) { return a.id < b.id ? -1 : a.id > b.id ? 1 : 0; }).forEach(function (node) {
    const level = levels.has(node.id) ? levels.get(node.id) : 0;
    if (!layers.has(level)) layers.set(level, []);
    layers.get(level).push(node);
  });
  const maximum = Math.max(0, ...layers.keys());
  const positions = [];
  let height = 140;
  layers.forEach(function (layer, level) {
    height = Math.max(height, layer.length * 74 + 30);
    layer.forEach(function (node, index) {
      positions.push({ id: node.id, x: 20 + (maximum - level) * 250, y: 20 + index * 74 });
    });
  });
  self.postMessage({ sequence: message.sequence, nodes: positions, width: (maximum + 1) * 250 + 20, height: height });
};
