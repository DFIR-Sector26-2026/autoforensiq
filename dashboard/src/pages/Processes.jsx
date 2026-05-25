import useEvidence from "../hooks/useEvidence";

export default function Processes() {

  const { evidence, loading } = useEvidence();

  if (loading) {

    return (
      <div className="text-white p-6">
        Loading process trees...
      </div>
    );
  }

  // SAFETY CHECK
  const safeEvidence = Array.isArray(evidence)
    ? evidence
    : [];

  const processTrees = safeEvidence.filter(
    (item) =>
      item &&
      item.evidence_type === "process_tree"
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

            <pre className="
              text-sm
              whitespace-pre-wrap
            ">

              {JSON.stringify(
                tree,
                null,
                2
              )}

            </pre>

          </div>
        ))}

      </div>

    </div>
  );
}
