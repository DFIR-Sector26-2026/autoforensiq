import { useState, useMemo, useRef, useEffect } from "react";

import { ChevronDown } from "lucide-react";

import useEvidence from "../hooks/useEvidence";

import { SEVERITY_TEXT } from "../data/severity";

import { humanize } from "../utils/format";

// Severities shown on this page, in display order.
const SEV_ORDER = ["critical", "high", "medium", "low"];

function Section({ severity, items, sources }) {

  if (items.length === 0) return null;

  return (

    <div className="mb-8">

      <h2 className={`text-xl font-bold uppercase tracking-wide mb-4 ${SEVERITY_TEXT[severity]}`}>
        {severity} ({items.length})
      </h2>

      <div className="overflow-x-auto">

        {/* table-fixed + shared widths: each section is its own table, so auto
            layout wouldn't align them. Detail is unsized — takes the remainder. */}
        <table className="w-full text-sm table-fixed">

          <thead>

            <tr className="
              text-left text-xs uppercase tracking-wide
              text-slate-400
              border-b border-slate-700
            ">
              <th className="w-24 py-2 pr-4 font-semibold">Severity</th>
              <th className="w-40 py-2 pr-4 font-semibold">Type</th>
              <th className="w-28 py-2 pr-4 font-semibold">Tool</th>
              <th className="w-44 py-2 pr-4 font-semibold">Source File</th>
              <th className="py-2 pr-4 font-semibold">Detail</th>
              <th className="w-44 py-2 font-semibold">IOC</th>
            </tr>

          </thead>

          <tbody>

            {items.map((e) => (

              <tr
                key={e.artifact_id}
                className="border-b border-slate-800 align-top"
              >

                <td className={`py-2 pr-4 font-bold uppercase text-xs ${SEVERITY_TEXT[e.severity] || ""}`}>
                  {e.severity}
                </td>

                {/* Every content cell truncates (clip + ellipsis inside its fixed column) */}
                <td className="py-2 pr-4 text-slate-300 truncate" title={humanize(e.evidence_type)}>
                  {humanize(e.evidence_type)}
                </td>

                <td className="py-2 pr-4 text-slate-400 truncate" title={humanize(e.source_tool)}>
                  {humanize(e.source_tool)}
                </td>

                <td
                  className="py-2 pr-4 font-mono text-xs text-slate-400 truncate"
                  title={sources[e.source_tool] || ""}
                >
                  {sources[e.source_tool] || "—"}
                </td>

                <td className="py-2 pr-4 font-mono text-xs text-slate-200 truncate" title={e.value}>
                  {e.value}
                </td>

                <td
                  className="py-2 text-xs text-orange-300 truncate"
                  title={(e.ioc_match || []).map(humanize).join(", ")}
                >
                  {(e.ioc_match || []).map(humanize).join(", ")}
                </td>

              </tr>

            ))}

          </tbody>

        </table>

      </div>

    </div>
  );
}

// Dropdown of evidence types with checkboxes for multi-select. `selected` is the list of active
// types; all-selected is shown as "All types".
function TypeFilter({ types, selected, allSelected, onToggle, onToggleAll }) {

  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const label = allSelected
    ? "All types"
    : selected.length === 0
      ? "No types"
      : `${selected.length} types`;

  return (

    <div className="relative ml-auto" ref={ref}>

      <button
        onClick={() => setOpen((o) => !o)}
        className="
          flex items-center gap-2
          bg-slate-800 border border-slate-600
          rounded-lg px-3 py-1 text-sm text-slate-200
        "
      >
        {label}
        <ChevronDown size={16} />
      </button>

      {open && (

        <div className="
          absolute right-0 mt-2 w-56 max-h-72 overflow-auto z-10
          bg-slate-800 border border-slate-600 rounded-lg p-2 shadow-xl
        ">

          <label className="
            flex items-center gap-2 px-2 py-1 rounded cursor-pointer
            text-sm font-semibold text-slate-200 hover:bg-slate-700
          ">
            <input type="checkbox" checked={allSelected} onChange={onToggleAll} />
            All types
          </label>

          <div className="my-1 border-t border-slate-700" />

          {types.map((t) => (
            <label
              key={t}
              className="
                flex items-center gap-2 px-2 py-1 rounded cursor-pointer
                text-sm text-slate-300 hover:bg-slate-700
              "
            >
              <input
                type="checkbox"
                checked={selected.includes(t)}
                onChange={() => onToggle(t)}
              />
              {humanize(t)}
            </label>
          ))}

        </div>
      )}

    </div>
  );
}

export default function Threats() {

  const { evidence, sources } = useEvidence();

  // Multi-select severity filter; Critical + High selected by default.
  const [sevFilter, setSevFilter] = useState(["critical", "high"]);
  // Multi-select type filter; null means "all types" (no restriction).
  const [typeFilters, setTypeFilters] = useState(null);

  const findings = useMemo(
    () => evidence.filter((e) => SEV_ORDER.includes(e.severity)),
    [evidence]
  );

  const types = useMemo(
    () => Array.from(new Set(findings.map((e) => e.evidence_type))).sort(),
    [findings]
  );

  // null = all types selected; otherwise the explicit list of active types.
  const activeTypes = typeFilters === null ? types : typeFilters;
  const allTypesSelected = typeFilters === null || typeFilters.length === types.length;

  const visible = findings.filter(
    (e) =>
      sevFilter.includes(e.severity) &&
      activeTypes.includes(e.evidence_type)
  );

  const toggleSev = (value) =>
    setSevFilter((prev) =>
      prev.includes(value)
        ? prev.filter((s) => s !== value)
        : [...prev, value]
    );

  const toggleType = (value) =>
    setTypeFilters((prev) => {
      const base = prev === null ? types : prev;
      return base.includes(value)
        ? base.filter((t) => t !== value)
        : [...base, value];
    });

  const toggleAllTypes = () =>
    setTypeFilters(allTypesSelected ? [] : types);

  const sevChip = (value) => (
    <button
      onClick={() => toggleSev(value)}
      className={`px-3 py-1 rounded-full text-sm border capitalize ${
        sevFilter.includes(value)
          ? "bg-slate-200 text-slate-900 border-slate-200"
          : "border-slate-600 text-slate-300 hover:border-slate-400"
      }`}
    >
      {value}
    </button>
  );

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-2">
        Threat Intelligence
      </h1>

      <p className="text-slate-400 mb-6">
        {visible.length} findings shown
      </p>

      <div className="flex flex-wrap items-center gap-3 mb-8">

        {SEV_ORDER.map((sev) => (
          <span key={sev}>{sevChip(sev)}</span>
        ))}

        <TypeFilter
          types={types}
          selected={activeTypes}
          allSelected={allTypesSelected}
          onToggle={toggleType}
          onToggleAll={toggleAllTypes}
        />

      </div>

      {SEV_ORDER.filter((sev) => sevFilter.includes(sev)).map((sev) => (
        <Section
          key={sev}
          severity={sev}
          items={visible.filter((e) => e.severity === sev)}
          sources={sources}
        />
      ))}

    </div>
  );
}
