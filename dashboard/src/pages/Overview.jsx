import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
} from "recharts";

import StatCard from "../components/StatCard";

import ThreatFeed from "../components/panels/ThreatFeed";

import useEvidence from "../hooks/useEvidence";

const COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
];

export default function Overview() {

  const { evidence, summary, byTool, loading } = useEvidence();

  if (loading) {

    return <div className="text-white">Loading...</div>;
  }

  if (!summary) {

    return <div className="text-white">No run data found.</div>;
  }

  const sd = summary.severity_distribution;

  const severityData = [
    { name: "Critical", value: sd.critical },
    { name: "High", value: sd.high },
    { name: "Medium", value: sd.medium },
    { name: "Low", value: sd.low },
  ];

  const toolData = Object.entries(byTool).map(
    ([stage, count]) => ({ stage, count })
  );

  return (

    <div>

      <h1 className="text-5xl font-bold mb-10">
        DFIR Command Center
      </h1>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">

        <StatCard
          title="Total Evidence"
          value={summary.total_items}
          color="#38bdf8"
        />

        <StatCard
          title="Critical"
          value={summary.critical_count}
          color="#ef4444"
        />

        <StatCard
          title="High"
          value={sd.high}
          color="#f97316"
        />

        <StatCard
          title="IOC Indicators"
          value={summary.ioc_count}
          color="#eab308"
        />

      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-10">

        <div className="
          bg-slate-900/70
          border border-slate-700
          rounded-2xl
          p-6
        ">

          <h2 className="text-2xl font-bold mb-6">
            Severity Distribution
          </h2>

          <div className="h-80">

            <ResponsiveContainer>

              <PieChart>

                <Pie
                  data={severityData}
                  dataKey="value"
                  outerRadius={120}
                >

                  {severityData.map((entry, index) => (

                    <Cell
                      key={index}
                      fill={COLORS[index % COLORS.length]}
                    />

                  ))}

                </Pie>

                <Tooltip />

              </PieChart>

            </ResponsiveContainer>

          </div>

        </div>

        <div className="
          bg-slate-900/70
          border border-slate-700
          rounded-2xl
          p-6
        ">

          <h2 className="text-2xl font-bold mb-6">
            Evidence by Tool
          </h2>

          <div className="h-80">

            <ResponsiveContainer width="100%" height="100%">

              <BarChart data={toolData}>

                <XAxis dataKey="stage" />

                <YAxis />

                <Tooltip />

                <Bar
                  dataKey="count"
                  fill="#38bdf8"
                />

              </BarChart>

            </ResponsiveContainer>

          </div>

        </div>

      </div>

      <div className="mt-10">

        <ThreatFeed evidence={evidence} />

      </div>

    </div>
  );
}
