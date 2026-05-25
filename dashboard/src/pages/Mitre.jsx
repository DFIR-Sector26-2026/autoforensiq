import useEvidence from "../hooks/useEvidence";

export default function Mitre() {

  const { evidence, loading } = useEvidence();

  if (loading) {

    return <div>Loading...</div>;
  }

  const items = evidence.filter(
    (e) => e.evidence_type === "mitre_mapping"
  );

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-6">
        MITRE ATT&CK Mapping
      </h1>

      <div className="grid grid-cols-2 gap-4">

        {items.map((item, index) => (

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
              {item.value.technique}
            </h2>

            <p>
              {item.value.name}
            </p>

          </div>
        ))}

      </div>

    </div>
  );
}
