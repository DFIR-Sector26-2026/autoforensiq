import { useMemo } from "react";

import useEvidence from "../hooks/useEvidence";

import { SEVERITY_TEXT, SEVERITY_RANK } from "../data/severity";

import { humanize } from "../utils/format";

// Evidence types that describe a file recovered from an artifact.
const FILE_TYPES = [
  "file_artifact",
  "extracted_file",
  "timeline_event",
  "yara_match",
  "suspicious_dll",
];

const rank = (sev) => SEVERITY_RANK[sev] || 0;
const worse = (a, b) => rank(a) > rank(b);      // a is more severe than b

export default function Files() {

  const { evidence, sources, byTool, loading } = useEvidence();

  // Highest severity of evidence produced by each tool — used to badge the
  // source file the tool read.
  const toolSeverity = useMemo(() => {
    const map = {};
    evidence.forEach((e) => {
      const t = e.source_tool;
      if (!map[t] || worse(e.severity, map[t])) map[t] = e.severity;
    });
    return map;
  }, [evidence]);

  // The input artifacts submitted to the investigation (the pcap, disk images,
  // …), deduplicated across tools, with how many findings each produced.
  const evidenceFiles = useMemo(() => {
    const map = {};
    Object.entries(sources || {}).forEach(([tool, files]) => {
      String(files)
        .split(",")
        .map((f) => f.trim())
        .filter(Boolean)
        .forEach((file) => {
          if (!map[file]) map[file] = { file, tools: [], findings: 0, severity: "low" };
          const entry = map[file];
          if (!entry.tools.includes(tool)) entry.tools.push(tool);
          entry.findings += byTool?.[tool] || 0;
          const sev = toolSeverity[tool];
          if (sev && worse(sev, entry.severity)) entry.severity = sev;
        });
    });
    return Object.values(map).sort((a, b) => b.findings - a.findings);
  }, [sources, byTool, toolSeverity]);

  // Files recovered *from* those artifacts (dropped payloads, suspicious files).
  const fileArtifacts = useMemo(
    () =>
      evidence
        .filter((e) => FILE_TYPES.includes(e.evidence_type))
        .sort((a, b) => rank(b.severity) - rank(a.severity)),
    [evidence]
  );

  if (loading) {

    return <div className="text-white">Loading...</div>;
  }

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-6">
        Files Involved
      </h1>

      {/* Input evidence files submitted to the investigation. */}
      <h2 className="text-xl font-bold mb-3">
        Evidence Files
      </h2>

      {evidenceFiles.length === 0 ? (

        <p className="text-slate-500 mb-8">No evidence files recorded for this run.</p>

      ) : (

        <div className="overflow-x-auto mb-10">

          <table className="w-full text-sm">

            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-400 border-b border-slate-700">
                <th className="py-2 pr-4 font-semibold">File</th>
                <th className="py-2 pr-4 font-semibold">Analyzed By</th>
                <th className="py-2 pr-4 font-semibold">Findings</th>
                <th className="py-2 font-semibold">Highest Severity</th>
              </tr>
            </thead>

            <tbody>

              {evidenceFiles.map((f) => (

                <tr key={f.file} className="border-b border-slate-800 align-top">

                  <td className="py-2 pr-4 font-mono text-xs text-slate-200 break-all">
                    {f.file}
                  </td>

                  <td className="py-2 pr-4 text-slate-400 whitespace-nowrap">
                    {f.tools.map(humanize).join(", ")}
                  </td>

                  <td className="py-2 pr-4 text-slate-300">
                    {f.findings}
                  </td>

                  <td className={`py-2 font-bold uppercase text-xs ${f.findings ? SEVERITY_TEXT[f.severity] || "" : "text-slate-600"}`}>
                    {f.findings ? f.severity : "—"}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>
      )}

      {/* Files recovered from the artifacts above. */}
      <h2 className="text-xl font-bold mb-3">
        Recovered File Artifacts
      </h2>

      {fileArtifacts.length === 0 ? (

        <p className="text-slate-500">
          No file artifacts were recovered from the evidence.
        </p>

      ) : (

        <div className="overflow-x-auto">

          <table className="w-full text-sm">

            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-400 border-b border-slate-700">
                <th className="py-2 pr-4 font-semibold">Severity</th>
                <th className="py-2 pr-4 font-semibold">File</th>
                <th className="py-2 pr-4 font-semibold">Type</th>
                <th className="py-2 pr-4 font-semibold">Tool</th>
                <th className="py-2 font-semibold">IOC</th>
              </tr>
            </thead>

            <tbody>

              {fileArtifacts.map((e, index) => (

                <tr key={index} className="border-b border-slate-800 align-top">

                  <td className={`py-2 pr-4 font-bold uppercase text-xs ${SEVERITY_TEXT[e.severity] || ""}`}>
                    {e.severity}
                  </td>

                  <td className="py-2 pr-4 font-mono text-xs text-slate-200 break-all">
                    {e.value}
                  </td>

                  <td className="py-2 pr-4 text-slate-300 whitespace-nowrap">
                    {humanize(e.evidence_type)}
                  </td>

                  <td className="py-2 pr-4 text-slate-400 whitespace-nowrap">
                    {humanize(e.source_tool)}
                  </td>

                  <td className="py-2 text-xs text-orange-300 break-all">
                    {(e.ioc_match || []).map(humanize).join(", ")}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>
      )}

    </div>
  );
}
