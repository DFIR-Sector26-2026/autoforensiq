export const summary = {
  totalEvidence: 128,
  criticalAlerts: 6,
  suspiciousProcesses: 14,
  injectedCode: 2,
  networkConnections: 31,
};

export const severityData = [
  { name: "Critical", value: 6 },
  { name: "High", value: 12 },
  { name: "Medium", value: 20 },
  { name: "Low", value: 40 },
];

export const tools = [
  { name: "Volatility3", status: "Success" },
  { name: "MemProcFS", status: "Graceful Failure" },
  { name: "TShark", status: "Success" },
];
