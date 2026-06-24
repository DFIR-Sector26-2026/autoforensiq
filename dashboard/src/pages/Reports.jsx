import useEvidence from "../hooks/useEvidence";

export default function Reports() {

  const { summary, loading } = useEvidence();

  if (loading) {

    return <div>Loading...</div>;
  }

  if (!summary) {

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
          Overall Severity:
          {" "}
          {summary.overall_severity.toUpperCase()}
        </p>

        <p className="mt-4">
          Total Evidence:
          {" "}
          {summary.total_items}
        </p>

        <p className="mt-4">
          IOC Count:
          {" "}
          {summary.ioc_count}
        </p>

        <p className="mt-4">
          Critical Findings:
          {" "}
          {summary.critical_count}
        </p>

      </div>

    </div>
  );
}
