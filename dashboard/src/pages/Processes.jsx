import useEvidence from "../hooks/useEvidence";

// The process_tree_json only carries `suspicious` for a few generic lineages,
// so most runs flag nothing. Correlate node names against the run's critical/
// high evidence (commandline, file paths, ioc_match) so processes the rest of
// the pipeline already flagged (e.g. tasksche.exe, @WanaDecryptor@, injected
// csrss.exe) light up here too.
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
    const needle = name.toLowerCase();
    if (hot.some((h) => h.includes(needle))) flagged.add(name);
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

      {(node.children || []).map((child, index) => (
        <ProcNode key={index} node={child} suspiciousNames={suspiciousNames} />
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

  if (loading) {

    return (
      <div className="text-white p-6">
        Loading process trees...
      </div>
    );
  }

  const processTrees = (Array.isArray(evidence) ? evidence : []).filter(
    (item) => item && item.evidence_type === "process_tree"
  );

  const suspiciousNames = suspiciousNamesFrom(evidence, processTrees);

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

        {processTrees.map((tree, index) => (

          <div
            key={index}
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
