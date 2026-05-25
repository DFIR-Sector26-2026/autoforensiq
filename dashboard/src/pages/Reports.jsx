import useEvidence from "../hooks/useEvidence";

export default function Reports() {

  const { evidence, loading } = useEvidence();

  if (loading) {

    return <div>Loading...</div>;
  }

  const stats = evidence.find(
    (e) => e.evidence_type === "report_stats"
  );

  if (!stats) {

    return <div>No report stats.</div>;
  }

  return (

    <div className="text-white">

      <h1 className="text-3xl font-bold mb-6">
        Investigation Report
      </h1>

      <div className="
        bg-slate-900
        rounded-xl
        p-6
      ">

        <p>
          Total Evidence:
          {" "}
          {stats.value.total_items}
        </p>

        <p className="mt-4">
          IOC Count:
          {" "}
          {stats.value.ioc_count}
        </p>

        <p className="mt-4">
          Critical Findings:
          {" "}
          {stats.value.critical_count}
        </p>

      </div>

    </div>
  );
}
