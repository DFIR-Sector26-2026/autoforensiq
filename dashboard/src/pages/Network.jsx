import ForceGraph2D from "react-force-graph-2d";

import networkData from "../data/networkData";

export default function Network() {

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

        <ForceGraph2D

          graphData={networkData}

          nodeLabel="id"

          nodeAutoColorBy="group"

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

      </div>

    </div>
  );
}
