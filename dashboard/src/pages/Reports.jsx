import useEvidence from "../hooks/useEvidence";

import { SEVERITY_TEXT } from "../data/severity";

import { humanize } from "../utils/format";

function pct(x) {
  return `${Math.round((x || 0) * 100)}%`;
}

function ConfidenceBar({ label, value }) {

  return (

    <div>

      <div className="flex justify-between text-sm mb-1">
        <span className="text-slate-300">{label}</span>
        <span className="text-slate-400">{pct(value)}</span>
      </div>

      <div className="h-2 rounded bg-slate-800">
        <div
          className="h-2 rounded bg-sky-500"
          style={{ width: pct(value) }}
        />
      </div>

    </div>
  );
}

function List({ title, items, tone }) {

  return (

    <div>

      <h3 className="text-sm font-semibold text-slate-300 mb-2">
        {title}
      </h3>

      {items && items.length > 0 ? (
        <ul className="space-y-1">
          {items.map((it) => (
            <li key={it} className={`text-sm ${tone}`}>• {humanize(it)}</li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-500">None</p>
      )}

    </div>
  );
}

export default function Reports() {

  const { summary, reconciliation, loading } = useEvidence();

  if (loading) {

    return <div className="text-white">Loading...</div>;
  }

  if (!summary) {

    return <div className="text-white">No report stats.</div>;
  }

  const sev = summary.overall_severity;
  const r = reconciliation;

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-6">
        Investigation Report
      </h1>

      {/* Final verdict banner */}
      <div className="
        bg-slate-900
        border border-slate-700
        rounded-2xl
        p-6 mb-6
      ">

        <div className="text-sm uppercase tracking-wide text-slate-400 mb-1">
          Final Verdict
        </div>

        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">

          <span className={`text-4xl font-bold ${SEVERITY_TEXT[sev] || "text-white"}`}>
            {sev.toUpperCase()}
          </span>

          {r && (
            <span className="text-xl text-slate-200 capitalize">
              {humanize(r.narrative_case_type)}
            </span>
          )}

        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">

          <Stat label="Total Evidence" value={summary.total_items} />
          <Stat label="Critical Findings" value={summary.critical_count} />
          <Stat label="IOC Count" value={summary.ioc_count} />

        </div>

      </div>

      {/* Evidence reconciliation */}
      {r ? (

        <div className="
          bg-slate-900
          border border-slate-700
          rounded-2xl
          p-6
        ">

          <div className="flex items-center justify-between mb-6">

            <h2 className="text-xl font-bold">
              Evidence Reconciliation
            </h2>

            <span className={`
              text-sm font-semibold px-3 py-1 rounded-full
              ${r.narrative_evidence_divergence
                ? "bg-red-950/50 text-red-300 border border-red-700"
                : "bg-green-950/40 text-green-300 border border-green-700"}
            `}>
              {r.narrative_evidence_divergence
                ? "Narrative diverges from evidence"
                : "Narrative supported by evidence"}
            </span>

          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <ConfidenceBar label="Classifier confidence" value={r.classifier_confidence} />
            <ConfidenceBar label="Reconciled confidence" value={r.reconciled_confidence} />
            <ConfidenceBar label="Evidence support" value={r.evidence_support_score} />
          </div>

          <p className="text-sm text-slate-400 mb-8">
            Evidence suggests:
            {" "}
            <span className="text-slate-200 font-semibold">
              {humanize(r.evidence_suggests)}
            </span>
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <List
              title="Supporting evidence types"
              items={r.supporting_evidence_types}
              tone="text-green-300"
            />
            <List
              title="Expected but absent"
              items={r.expected_but_absent}
              tone="text-amber-300"
            />
          </div>

          {r.notes && r.notes.length > 0 && (
            <div className="mt-8">
              <List title="Analyst notes" items={r.notes} tone="text-slate-300" />
            </div>
          )}

        </div>

      ) : (

        <div className="text-slate-500 text-sm">
          No reconciliation data published for this run.
        </div>
      )}

    </div>
  );
}

function Stat({ label, value }) {

  return (

    <div>
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="text-2xl font-bold text-white">
        {value}
      </div>
    </div>
  );
}
