/* Original frontend code: MIT, under the repository license. */
const BYTE_FORMAT = (function () {
  "use strict";
  const units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
  const display = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
  const valid = function (value) { return typeof value === "number" && Number.isFinite(value); };
  const format = function (value) {
    if (!valid(value)) return "Unknown";
    let magnitude = Math.abs(value), exponent = 0;
    while (magnitude >= 1000 && exponent < units.length - 1) { magnitude /= 1000; exponent++; }
    if (display.format(magnitude) === "1,000" && exponent < units.length - 1) { magnitude /= 1000; exponent++; }
    return (value < 0 ? "-" : "") + display.format(magnitude) + " " + units[exponent];
  };
  return Object.freeze({
    format: format,
    signed: function (value) { return valid(value) && value > 0 ? "+" + format(value) : format(value); },
    exact: function (value) { return valid(value) ? value.toLocaleString("en-US", { maximumFractionDigits: 20 }) + " bytes" : "No measurement supplied"; }
  });
})();
