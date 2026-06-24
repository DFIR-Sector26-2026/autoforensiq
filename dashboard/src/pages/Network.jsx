import { useMemo } from "react";

import ForceGraph2D from "react-force-graph-2d";

import useEvidence from "../hooks/useEvidence";

const SEV_COLOR = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

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
      add(dst, SEV_COLOR[e.severity] || "#94a3b8");
      links[`${src}->${dst}`] = { source: src, target: dst };
    });

  return { nodes: Object.values(nodes), links: Object.values(links) };
}

export default function Network() {

  const { evidence, loading } = useEvidence();

  const graphData = useMemo(
    () => buildGraph(evidence),
    [evidence]
  );

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
      ">

        {graphData.nodes.length === 0 ? (

          <div className="text-slate-400 p-6">
            No network evidence found.
          </div>

        ) : (

          <ForceGraph2D

            graphData={graphData}

            nodeLabel="id"

            backgroundColor="#0f172a"

            linkColor={() => "#38bdf8"}

            nodeCanvasObject={(node, ctx) => {

              const label = node.id;

              ctx.fillStyle = node.color;

              ctx.beginPath();

              ctx.arc(
                node.x,
                node.y,
                10,
                0,
                2 * Math.PI,
                false
              );

              ctx.fill();

              ctx.fillStyle = "white";

              ctx.font = "14px Sans-Serif";

              ctx.fillText(
                label,
                node.x + 14,
                node.y + 5
              );
            }}
          />

        )}

      </div>

    </div>
  );
}
