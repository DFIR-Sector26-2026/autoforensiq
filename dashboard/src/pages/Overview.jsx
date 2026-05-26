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

import { summary } from "../data/mockData";

const severityData = [
  { name: "Critical", value: 6 },
  { name: "High", value: 12 },
  { name: "Medium", value: 20 },
  { name: "Low", value: 40 },
];

const timelineData = [
  { stage: "Processes", count: 14 },
  { stage: "Network", count: 31 },
  { stage: "Injected", count: 2 },
  { stage: "Threats", count: 6 },
];

const COLORS = [
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
];

export default function Overview() {

  return (

    <div>

      <h1 className="text-5xl font-bold mb-10">
        DFIR Command Center
      </h1>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">

        <StatCard
          title="Total Evidence"
          value={summary.totalEvidence}
          color="#38bdf8"
        />

        <StatCard
          title="Critical Alerts"
          value={summary.criticalAlerts}
          color="#ef4444"
        />

        <StatCard
          title="Suspicious Processes"
          value={summary.suspiciousProcesses}
          color="#f97316"
        />

        <StatCard
          title="Injected Code"
          value={summary.injectedCode}
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
            Evidence Timeline
          </h2>

          <div className="h-80">

            <ResponsiveContainer width="100%" height="100%">

              <BarChart data={timelineData}>

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

        <ThreatFeed />

      </div>

    </div>
  );
}
