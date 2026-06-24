import useEvidence from "../hooks/useEvidence";

export default function Mitre() {

  const { mitre, loading } = useEvidence();

  if (loading) {

    return <div>Loading...</div>;
  }

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-6">
        MITRE ATT&CK Mapping
      </h1>

      <div className="grid grid-cols-2 gap-4">

        {mitre.map((item, index) => (

          <div
            key={index}
            className="
              bg-slate-900
              border border-slate-700
              rounded-xl
              p-4
            "
          >

            <h2 className="font-bold">
              {item.id} — {item.name}
            </h2>

            <p className="text-slate-400 text-sm mt-1">
              {item.tactic}
            </p>

            <p className="text-slate-500 text-xs mt-2">
              {item.basis}
            </p>

          </div>
        ))}

      </div>

    </div>
  );
}
