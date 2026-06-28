import { useMemo } from "react";

import useEvidence from "../hooks/useEvidence";

import ATTACK_MATRIX from "../data/attackMatrix";

export default function Mitre() {

  const { mitre, loading } = useEvidence();

  // Detected technique ids (e.g. "T1486") -> their detection basis, for the
  // cell tooltip. Matrix cells highlight when their id is in this map.
  const detected = useMemo(() => {
    const map = {};
    (mitre || []).forEach((m) => { map[m.id] = m; });
    return map;
  }, [mitre]);

  if (loading) {

    return <div className="text-white">Loading...</div>;
  }

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-2">
        MITRE ATT&CK Mapping
      </h1>

      <div className="flex flex-wrap items-center gap-6 mb-6 text-sm">

        <span className="text-slate-400">
          {Object.keys(detected).length} techniques detected across this case
        </span>

        <span className="flex items-center gap-2">
          <span className="w-3 h-3 rounded bg-red-600 inline-block" />
          Detected
        </span>

        <span className="flex items-center gap-2 text-slate-500">
          <span className="w-3 h-3 rounded bg-slate-800 border border-slate-700 inline-block" />
          Not observed
        </span>

      </div>

      <div className="overflow-x-auto pb-4">

        <div className="flex gap-2 min-w-max">

          {ATTACK_MATRIX.map((col) => (

            <div key={col.tactic} className="w-44 flex-shrink-0">

              <div className="
                text-xs font-bold uppercase tracking-wide
                text-slate-200
                bg-slate-800
                rounded-t-md
                px-2 py-2
                h-14
                flex items-center
                border-b-2 border-sky-500
              ">
                {col.tactic}
              </div>

              <div className="space-y-1 mt-1">

                {col.techniques.map((tech) => {

                  const hit = detected[tech.id];

                  return (

                    <div
                      key={tech.id}
                      title={hit ? `${tech.id} — ${tech.name}\n${hit.tactic} · ${hit.basis}` : `${tech.id} — ${tech.name}`}
                      className={`
                        px-2 py-1 rounded text-xs leading-tight
                        ${hit
                          ? "bg-red-600 text-white font-semibold"
                          : "bg-slate-900 text-slate-500 border border-slate-800"}
                      `}
                    >
                      <span className="font-mono">{tech.id}</span>
                      <span className="block truncate">{tech.name}</span>
                    </div>
                  );
                })}

              </div>

            </div>
          ))}

        </div>

      </div>

    </div>
  );
}
