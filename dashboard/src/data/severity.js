// Shared severity palettes so the pages don't each redefine them (Overview, Reports, Threats and
// Network all used near-identical local copies).

export const SEVERITY_TEXT = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

export const SEVERITY_HEX = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

// Ordinal rank for sorting / comparing severities (higher = worse).
export const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};
