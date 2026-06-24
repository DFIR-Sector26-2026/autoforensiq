import useEvidence from "../hooks/useEvidence";

function ProcNode({ node }) {

  return (

    <div className="ml-4 border-l border-slate-700 pl-3">

      <span className={node.suspicious ? "text-red-400 font-bold" : "text-slate-200"}>
        {node.name}
        {" "}
        <span className="text-slate-500 text-xs">(PID {node.pid})</span>
      </span>

      {(node.children || []).map((child, index) => (
        <ProcNode key={index} node={child} />
      ))}

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

  return (

    <div className="text-white p-6">

      <h1 className="text-3xl font-bold mb-6">
        Process Lineage Analysis
      </h1>

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
              <ProcNode node={tree.process_tree_json} />
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
