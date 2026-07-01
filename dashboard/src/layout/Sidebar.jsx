import {
  Shield,
  Activity,
  Network,
  AlertTriangle,
  HardDrive,
  FileText,
  BrainCircuit,
} from "lucide-react";

export default function Sidebar({
  currentPage,
  setCurrentPage,
}) {

  const items = [
    { icon: Shield, label: "Overview" },
    { icon: Activity, label: "Processes" },
    { icon: Network, label: "Network" },
    { icon: AlertTriangle, label: "Threats" },
    { icon: HardDrive, label: "Files" },
    { icon: FileText, label: "Reports" },
    { icon: BrainCircuit, label: "MITRE" },
  ];

  return (

    <div className="
      w-72
      bg-slate-950
      border-r border-slate-800
      min-h-screen
      p-6
    ">

      <h1 className="
        text-3xl font-bold
        mb-12 text-cyan-400
      ">
        AutoForensiq
      </h1>

      <div className="space-y-4">

        {items.map((item, index) => {

          const Icon = item.icon;

          return (

            <button
              key={index}

              onClick={() =>
                setCurrentPage(item.label)
              }

              className={`
                w-full
                flex items-center gap-4
                p-4 rounded-xl

                ${
                  currentPage === item.label
                    ? "bg-cyan-500/20 border border-cyan-400"
                    : "bg-slate-900 hover:bg-cyan-500/10"
                }
              `}
            >

              <Icon
                size={22}
                className="text-cyan-400"
              />

              <span className="text-lg">
                {item.label}
              </span>

            </button>

          );
        })}

      </div>

    </div>
  );
}
