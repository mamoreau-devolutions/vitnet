/* Original frontend tests: MIT, under the repository license. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "..", "src", "explorer", "assets", "format.js"), "utf8");
const format = vm.runInNewContext(source + "\nBYTE_FORMAT;", {});

test("sizes_auto_scale_at_decimal_unit_boundaries", () => {
  for (const [value, expected] of [
    [0, "0 B"], [1, "1 B"], [999, "999 B"], [1000, "1 KB"], [1001, "1 KB"],
    [1234, "1.23 KB"], [999994, "999.99 KB"], [999995, "1 MB"], [999999, "1 MB"],
    [1000000, "1 MB"], [1000001, "1 MB"], [999999999, "1 GB"],
    [1062414426, "1.06 GB"], [1000000000, "1 GB"], [1000000000000, "1 TB"],
    [1000000000000000, "1 PB"], [1000000000000000000, "1 EB"]
  ]) assert.equal(format.format(value), expected, String(value));
});

test("deltas_preserve_sign_and_unknown_measurements", () => {
  for (const [value, expected] of [
    [1500000, "+1.5 MB"], [-1500000, "-1.5 MB"], [0, "0 B"], [-0, "0 B"],
    [null, "Unknown"], [undefined, "Unknown"], [NaN, "Unknown"],
    [Infinity, "Unknown"], [-Infinity, "Unknown"], ["1000", "Unknown"]
  ]) assert.equal(format.signed(value), expected, String(value));
  assert.equal(format.format(-1234), "-1.23 KB");
  assert.equal(format.format(0.5), "0.5 B");
});

test("exact_byte_counts_remain_available_without_scaling", () => {
  assert.equal(format.exact(1062414426), "1,062,414,426 bytes");
  assert.equal(format.exact(-1500000), "-1,500,000 bytes");
  assert.equal(format.exact(0), "0 bytes");
  assert.equal(format.exact(null), "No measurement supplied");
  assert.equal(format.exact(Infinity), "No measurement supplied");
});
