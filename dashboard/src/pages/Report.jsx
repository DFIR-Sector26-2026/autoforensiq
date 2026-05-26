import useEvidence from "../hooks/useEvidence";

export default function Report() {

  const { evidence, loading } = useEvidence();

  if (loading) {

    return (
      <div className="text-white p-6">
        Loading report...
      </div>
    );
  }

  const critical = evidence.filter(
    (e) => e.severity && e.severity === "critical"
  ).length;

  const iocCount = evidence.filter(
    (e) => e.evidence_type === "ioc"
  ).length;

  return (

    <div className="p-6 text-white">

      <h1 className="text-3xl font-bold mb-6">
        Investigation Report
      </h1>

      <div className="bg-zinc-900 p-6 rounded-xl border border-zinc-700">

        <p className="mb-4">
          Total Evidence Items: {evidence.length}
        </p>

        <p className="mb-4">
          Critical Findings: {critical}
        </p>

        <p className="mb-4">
          IOC Detections: {iocCount}
        </p>

      </div>
    </div>
  );
}
