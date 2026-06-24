import useEvidence from "../hooks/useEvidence";

const RANK = { critical: 2, high: 1 };

function cardClass(severity) {
  return severity === "critical"
    ? "bg-red-950/40 border border-red-700"
    : "bg-orange-950/30 border border-orange-700";
}

export default function Threats() {

  const { evidence, loading } = useEvidence();

  if (loading) {

    return <div className="text-white">Loading...</div>;
  }

  const threats = evidence
    .filter((e) => e.severity === "critical" || e.severity === "high")
    .sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0));

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-2">
        Threat Intelligence
      </h1>

      <p className="text-slate-400 mb-6">
        {threats.length} critical/high-severity findings
      </p>

      <div className="space-y-3">

        {threats.map((e, index) => (

          <div
            key={index}
            className={`rounded-xl p-4 ${cardClass(e.severity)}`}
          >

            <div className="flex justify-between items-center mb-1">

              <span className="uppercase text-xs font-bold">
                {e.severity} · {e.evidence_type}
              </span>

              <span className="text-slate-400 text-sm">
                {e.source_tool}
              </span>

            </div>

            <div className="font-mono text-sm break-all">
              {e.value}
            </div>

            {e.ioc_match && e.ioc_match.length > 0 && (
              <div className="text-xs text-orange-300 mt-2">
                {e.ioc_match.join(", ")}
              </div>
            )}

          </div>
        ))}

      </div>

    </div>
  );
}
