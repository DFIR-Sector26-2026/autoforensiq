const RANK = { critical: 2, high: 1 };

export default function ThreatFeed({ evidence = [] }) {

  const alerts = evidence
    .filter((e) => e.severity === "critical" || e.severity === "high")
    .sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0))
    .slice(0, 6);

  return (

    <div className="
      bg-slate-900/70
      border border-red-500/30
      rounded-2xl
      p-6
      backdrop-blur-lg
    ">

      <h2 className="text-2xl font-bold text-red-400 mb-6">
        Live Threat Feed
      </h2>

      <div className="space-y-4">

        {alerts.length === 0 && (
          <div className="text-slate-400">
            No critical or high-severity alerts.
          </div>
        )}

        {alerts.map((e, index) => (

          <div
            key={index}
            className="
              bg-red-500/10
              border border-red-500/20
              p-4 rounded-xl
            "
          >

            <span className="uppercase text-xs text-red-300">
              {e.severity} · {e.evidence_type}
            </span>

            <div className="mt-1 text-sm">
              {String(e.value).slice(0, 90)}
            </div>

          </div>

        ))}

      </div>

    </div>
  );
}
