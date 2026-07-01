import { useMemo, useRef, useCallback, useState } from "react";

import ForceGraph2D from "react-force-graph-2d";

import useEvidence from "../hooks/useEvidence";

import { SEVERITY_HEX, SEVERITY_RANK } from "../data/severity";

// Severities offered as node filters, in display order (issue U2).
const SEV_LEVELS = ["critical", "high", "medium", "low"];

const NET_TYPES = [
  "network_connection",
  "dns_query",
  "http_request",
  "suspicious_port",
];

const rankToSev = (rank) =>
  rank >= 4 ? "critical" : rank >= 3 ? "high" : rank >= 2 ? "medium" : "low";

// The internal subject is the LAN (RFC1918) endpoint — not "whatever is on the
// left of the arrow", since reply-direction connections put an external C2 on
// the left. Only true for a dotted-quad; domains are always external.
const isLan = (id) =>
  id.startsWith("10.") ||
  id.startsWith("192.168.") ||
  /^172\.(1[6-9]|2\d|3[01])\./.test(id);

// The network items carry their endpoints as free text ("... src → dst ...").
// Split on the arrow, take the host token on each side, and strip any :port or
// /path so a single endpoint (e.g. the C2 IP) collapses to one node. Each node
// is classified by its WORST connecting severity, so a host reached by both a
// critical and a high finding shows once (as critical), not in both filters
// (issue U2). Source (internal) endpoints are the subject, drawn in cyan.
function buildGraph(evidence) {

  const nodes = {};
  const links = {};

  const host = (token) => token.split(/[:/]/)[0];
  const touch = (id) => {
    if (!nodes[id]) nodes[id] = { id, isSource: false, sevRank: 0 };
    return nodes[id];
  };

  evidence
    .filter((e) => NET_TYPES.includes(e.evidence_type))
    .forEach((e) => {

      const parts = String(e.value || "").split("→");
      if (parts.length < 2) return;

      const src = host(parts[0].trim().split(/\s+/).pop());
      const dst = host(parts[1].trim().split(/\s+/)[0]);
      if (!src || !dst) return;

      const r = SEVERITY_RANK[e.severity] || 0;
      [src, dst].forEach((id) => {
        const n = touch(id);
        if (isLan(id)) n.isSource = true;         // internal subject
        else n.sevRank = Math.max(n.sevRank, r);  // external host: worst severity
      });

      links[`${src}->${dst}`] = { source: src, target: dst };
    });

  Object.values(nodes).forEach((n) => {
    n.severity = rankToSev(n.sevRank);
    n.color = n.isSource ? "#38bdf8" : SEVERITY_HEX[n.severity] || "#94a3b8";
  });

  return { nodes: Object.values(nodes), links: Object.values(links) };
}

export default function Network() {

  const { evidence, loading } = useEvidence();
  const graphRef = useRef(null);
  // Auto-fit only once, on initial layout. Refitting on every engine stop reset
  // the user's zoom on drag (issue U1) and on each filter change (issue U2).
  const didFit = useRef(false);

  // Multi-select severity filter for which nodes to draw (issue U2).
  const [sevFilter, setSevFilter] = useState(SEV_LEVELS);

  // Build the full graph once; filtering then selects a subset of the SAME node
  // objects, so positions persist across filter changes (no layout jump).
  const fullGraph = useMemo(() => buildGraph(evidence), [evidence]);

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

  // Apply the spacing forces the moment the graph instance exists (via the
  // callback ref) so the warmup ticks lay the nodes out spread-apart *before*
  // the first paint — no visible settling.
  const configure = useCallback((fg) => {
    graphRef.current = fg;
    if (!fg) return;
    fg.d3Force("charge")?.strength(-260);
    fg.d3Force("link")?.distance(110);
  }, []);

  // Frame the graph once, on the first settled layout (duration 0 so it appears
  // already fitted). Later engine stops — from dragging a node or changing the
  // filter — must NOT refit, or they'd reset the user's zoom/pan (issues U1/U2).
  const handleEngineStop = useCallback(() => {
    if (didFit.current) return;
    didFit.current = true;
    requestAnimationFrame(() => graphRef.current?.zoomToFit(0, 60));
  }, []);

  if (loading) {

    return <div className="text-white">Loading...</div>;
  }

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

            // Define the draggable/hover hit-area to match the drawn node
            // (issue U1). Without this, custom-rendered nodes fall back to a tiny
            // default area that misaligns at other zoom levels, so nodes can't be
            // grabbed. Painting the same radius keeps them draggable at any zoom.
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
