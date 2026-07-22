import { useMemo } from "react";

import useEvidence from "../hooks/useEvidence";

// process_tree_json's own `suspicious` flag covers few lineages — cross-check node names against
// the run's critical/high evidence so already-flagged processes light up here too.
function suspiciousNamesFrom(evidence, trees) {

  const hot = [];
  evidence
    .filter((e) => e.severity === "critical" || e.severity === "high")
    .forEach((e) => {
      hot.push(String(e.value || "").toLowerCase());
      (e.ioc_match || []).forEach((m) => hot.push(String(m).toLowerCase()));
    });

  const names = new Set();
  const collect = (node) => {
    if (!node) return;
    names.add(node.name);
    (node.children || []).forEach(collect);
  };
  trees.forEach((t) => collect(t.process_tree_json));

  const flagged = new Set();
  names.forEach((name) => {
    const needle = String(name || "").toLowerCase();
    if (!needle) return;
    // Word-boundary match (D3): bare includes() let a short name like "sh" match inside
    // "powershell.exe", falsely flagging the node.
    const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`);
    if (hot.some((h) => re.test(h))) flagged.add(name);
  });
  return flagged;
}

function ProcNode({ node, suspiciousNames }) {

  const suspicious = node.suspicious || suspiciousNames.has(node.name);

  return (

    <div className="ml-4 border-l border-slate-700 pl-3 py-1">

      <span className={suspicious ? "text-red-400 font-bold" : "text-slate-200"}>
        {suspicious && <span className="mr-1">⚠</span>}
        {node.name}
        {" "}
        <span className="text-slate-500 text-xs">(PID {node.pid})</span>
      </span>

      {(node.children || []).map((child) => (
        <ProcNode key={`${child.pid}-${child.name}`} node={child} suspiciousNames={suspiciousNames} />
      ))}

    </div>
  );
}

function Legend() {

  return (

    <div className="flex gap-6 mb-6 text-sm">

      <span className="flex items-center gap-2 text-red-400 font-bold">
        <span className="w-3 h-3 rounded-full bg-red-400 inline-block" />
        Suspicious
      </span>

      <span className="flex items-center gap-2 text-slate-200">
        <span className="w-3 h-3 rounded-full bg-slate-400 inline-block" />
        Normal
      </span>

    </div>
  );
}

export default function Processes() {

  const { evidence, loading } = useEvidence();

  // D3: memoized — this scans every critical/high item per tree node name, and previously
  // re-ran on every render.
  const processTrees = useMemo(
    () =>
      (Array.isArray(evidence) ? evidence : []).filter(
        (item) => item && item.evidence_type === "process_tree"
      ),
    [evidence]
  );

  const suspiciousNames = useMemo(
    () => suspiciousNamesFrom(Array.isArray(evidence) ? evidence : [], processTrees),
    [evidence, processTrees]
  );

  if (loading) {

    return (
      <div className="text-white p-6">
        Loading process trees...
      </div>
    );
  }

  return (

    <div className="text-white p-6">

      <h1 className="text-3xl font-bold mb-6">
        Process Lineage Analysis
      </h1>

      <Legend />

      {processTrees.length === 0 && (

        <div className="
          bg-slate-900
          border border-slate-700
          rounded-xl
          p-4
        ">
          No process tree evidence found.
        </div>
      )}

      <div className="space-y-4">

        {processTrees.map((tree) => (

          <div
            key={tree.artifact_id}
            className="
              bg-slate-900
              border border-slate-700
              rounded-xl
              p-4
              overflow-auto
            "
          >

            {tree.process_tree_json ? (
              <ProcNode node={tree.process_tree_json} suspiciousNames={suspiciousNames} />
            ) : (
              <pre className="text-sm whitespace-pre-wrap">
                {tree.value}
              </pre>
            )}

          </div>
        ))}

      </div>

    </div>
  );
}
