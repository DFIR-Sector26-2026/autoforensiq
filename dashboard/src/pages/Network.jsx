import { useMemo, useRef, useCallback, useState } from "react";

import ForceGraph2D from "react-force-graph-2d";

import useEvidence from "../hooks/useEvidence";

import { SEVERITY_HEX } from "../data/severity";

// Severities offered as node filters, in display order (issue U2).
const SEV_LEVELS = ["critical", "high", "medium", "low"];

// D2: nodes/links arrive pre-parsed in dashboard.json (report generator owns the "src → dst"
// parsing and the RFC1918 subject rule); only colors are assigned client-side.
function decorateGraph(graph) {
  const nodes = (graph.nodes || []).map((n) => ({
    id: n.id,
    isSource: n.is_source,
    severity: n.severity,
    color: n.is_source ? "#38bdf8" : SEVERITY_HEX[n.severity] || "#94a3b8",
  }));
  const links = (graph.links || []).map((l) => ({ source: l.source, target: l.target }));
  return { nodes, links };
}

export default function Network() {

  const { graph } = useEvidence();
  const graphRef = useRef(null);
  // Auto-fit only once, on initial layout. Refitting on every engine stop reset the user's zoom on
  // drag (issue U1) and on each filter change (issue U2).
  const didFit = useRef(false);

  // Multi-select severity filter for which nodes to draw (issue U2).
  const [sevFilter, setSevFilter] = useState(SEV_LEVELS);

  // Decorate the full graph once; filtering then selects a subset of the SAME node objects, so
  // positions persist across filter changes (no layout jump).
  const fullGraph = useMemo(() => decorateGraph(graph), [graph]);

  const graphData = useMemo(() => {
    const nodes = fullGraph.nodes.filter(
      (n) => n.isSource || sevFilter.includes(n.severity)
    );
    const ids = new Set(nodes.map((n) => n.id));
    const idOf = (end) => (typeof end === "object" ? end.id : end);
    const links = fullGraph.links.filter(
      (l) => ids.has(idOf(l.source)) && ids.has(idOf(l.target))
    );
    return { nodes, links };
  }, [fullGraph, sevFilter]);

  const toggleSev = (value) =>
    setSevFilter((prev) =>
      prev.includes(value)
        ? prev.filter((s) => s !== value)
        : [...prev, value]
    );

  // Apply the spacing forces the moment the graph instance exists (via the callback ref) so the
  // warmup ticks lay the nodes out spread-apart *before* the first paint — no visible settling.
  const configure = useCallback((fg) => {
    graphRef.current = fg;
    if (!fg) return;
    fg.d3Force("charge")?.strength(-260);
    fg.d3Force("link")?.distance(110);
  }, []);

  // Frame the graph once, on the first settled layout (duration 0 so it appears already fitted).
  // Later engine stops — from dragging a node or changing the filter — must NOT refit, or they'd
  // reset the user's zoom/pan (issues U1/U2).
  const handleEngineStop = useCallback(() => {
    if (didFit.current) return;
    didFit.current = true;
    requestAnimationFrame(() => graphRef.current?.zoomToFit(0, 60));
  }, []);

  return (

    <div className="h-screen">

      <h1 className="
        text-5xl font-bold
        mb-8
      ">
        Network Analysis
      </h1>

      <div className="flex flex-wrap items-center gap-3 mb-6">
        {SEV_LEVELS.map((sev) => (
          <button
            key={sev}
            onClick={() => toggleSev(sev)}
            className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm border capitalize ${
              sevFilter.includes(sev)
                ? "bg-slate-200 text-slate-900 border-slate-200"
                : "border-slate-600 text-slate-300 hover:border-slate-400"
            }`}
          >
            <span
              className="w-3 h-3 rounded-full inline-block"
              style={{ backgroundColor: SEVERITY_HEX[sev] }}
            />
            {sev}
          </button>
        ))}
      </div>

      <div className="
        bg-slate-900
        rounded-2xl
        h-[80vh]
        border border-slate-700
        overflow-hidden
      ">

        {graphData.nodes.length === 0 ? (

          <div className="text-slate-400 p-6">
            No network evidence found.
          </div>

        ) : (

          <ForceGraph2D

            ref={configure}

            graphData={graphData}

            backgroundColor="#0f172a"

            linkColor={() => "#38bdf8"}

            linkWidth={1.5}

            warmupTicks={120}

            cooldownTicks={0}

            onEngineStop={handleEngineStop}

            nodeCanvasObject={(node, ctx, globalScale) => {

              const fontSize = 14 / globalScale;

              ctx.fillStyle = node.color;

              ctx.beginPath();

              ctx.arc(
                node.x,
                node.y,
                6,
                0,
                2 * Math.PI,
                false
              );

              ctx.fill();

              ctx.font = `${fontSize}px Inter, system-ui, sans-serif`;
              ctx.textAlign = "left";
              ctx.textBaseline = "middle";
              ctx.fillStyle = "#e2e8f0";

              ctx.fillText(
                node.id,
                node.x + 10,
                node.y
              );
            }}

            // Match the hit-area to the drawn node (U1) — custom-rendered nodes otherwise get a
            // tiny default area and can't be grabbed.
            nodePointerAreaPaint={(node, color, ctx) => {
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(node.x, node.y, 6, 0, 2 * Math.PI, false);
              ctx.fill();
            }}
          />

        )}

      </div>

    </div>
  );
}
