import { useMemo, useRef, useCallback } from "react";

import ForceGraph2D from "react-force-graph-2d";

import useEvidence from "../hooks/useEvidence";

import { SEVERITY_HEX } from "../data/severity";

const NET_TYPES = [
  "network_connection",
  "dns_query",
  "http_request",
  "suspicious_port",
];

// The network items carry their endpoints as free text ("... src → dst ...").
// Split on the arrow, take the host token on each side, and strip any :port or
// /path so a single endpoint (e.g. the C2 IP) collapses to one node.
function buildGraph(evidence) {

  const nodes = {};
  const links = {};

  const add = (id, color) => {
    if (!nodes[id]) nodes[id] = { id, color };
  };

  const host = (token) => token.split(/[:/]/)[0];

  evidence
    .filter((e) => NET_TYPES.includes(e.evidence_type))
    .forEach((e) => {

      const parts = String(e.value || "").split("→");
      if (parts.length < 2) return;

      const src = host(parts[0].trim().split(/\s+/).pop());
      const dst = host(parts[1].trim().split(/\s+/)[0]);
      if (!src || !dst) return;

      add(src, "#38bdf8");
      add(dst, SEVERITY_HEX[e.severity] || "#94a3b8");
      links[`${src}->${dst}`] = { source: src, target: dst };
    });

  return { nodes: Object.values(nodes), links: Object.values(links) };
}

export default function Network() {

  const { evidence, loading } = useEvidence();
  const graphRef = useRef(null);

  const graphData = useMemo(
    () => buildGraph(evidence),
    [evidence]
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

  // Frame the pre-warmed graph instantly (duration 0) so it appears already
  // centred and fitted instead of zooming in a couple of seconds later.
  const handleEngineStop = useCallback(() => {
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
          />

        )}

      </div>

    </div>
  );
}
