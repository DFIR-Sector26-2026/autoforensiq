import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
} from "recharts";

import StatCard from "../components/StatCard";

import useEvidence from "../hooks/useEvidence";

import { SEVERITY_HEX, SEVERITY_TEXT } from "../data/severity";

import { humanize } from "../utils/format";

// Dark tooltip so recharts' default white popover doesn't clash with the theme.
const TOOLTIP_STYLE = {
  backgroundColor: "#1e293b",
  border: "1px solid #334155",
  borderRadius: "0.5rem",
  color: "#e2e8f0",
};

export default function Overview() {

  const { summary, byTool, reconciliation } = useEvidence();

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
                  outerRadius={110}
                >

                  {severityData.map((entry) => (

                    <Cell
                      key={entry.name}
                      fill={SEVERITY_HEX[entry.name.toLowerCase()]}
                    />

                  ))}

                </Pie>

                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  itemStyle={{ color: "#38bdf8" }}
                  isAnimationActive={false}
                  wrapperStyle={{ transition: "none" }}
                />

                <Legend
                  layout="vertical"
                  align="left"
                  verticalAlign="middle"
                  formatter={(value, entry) => `${value}: ${entry.payload.value}`}
                />

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

                <XAxis dataKey="stage" tickFormatter={humanize} />

                <YAxis />

                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  cursor={{ fill: "rgba(56, 189, 248, 0.1)" }}
                  isAnimationActive={false}
                  wrapperStyle={{ transition: "none" }}
                  labelFormatter={humanize}
                />

                <Bar
                  dataKey="count"
                  fill="#38bdf8"
                />

              </BarChart>

            </ResponsiveContainer>

          </div>

        </div>

      </div>

      {reconciliation && (

        <div className="
          bg-slate-900/70
          border border-slate-700
          rounded-2xl
          p-6 mt-10
        ">

          <div className="text-sm uppercase tracking-wide text-slate-400 mb-3">
            Case Verdict
          </div>

          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">

            <span className={`text-3xl font-bold ${SEVERITY_TEXT[summary.overall_severity] || "text-white"}`}>
              {summary.overall_severity.toUpperCase()}
            </span>

            <span className="text-2xl text-slate-300">·</span>

            <span className="text-2xl text-slate-200 capitalize">
              {humanize(reconciliation.narrative_case_type)}
            </span>

            <span className="text-2xl text-slate-300">·</span>

            <span className="text-xl text-slate-400">
              {Math.round((reconciliation.reconciled_confidence || 0) * 100)}% confidence
            </span>

          </div>

          {reconciliation.notes && reconciliation.notes.length > 0 && (
            <p className="text-slate-400 mt-4">
              {humanize(reconciliation.notes[0])}
            </p>
          )}

        </div>

      )}

    </div>
  );
}
