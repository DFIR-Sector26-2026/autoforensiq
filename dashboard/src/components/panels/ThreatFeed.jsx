const alerts = [
  "Injected code detected in winlogon.exe",
  "Suspicious lineage: tasksche.exe -> WannaDecryptor",
  "Critical process injection detected",
  "Possible ransomware execution chain identified",
];

export default function ThreatFeed() {

  return (

    <div className="
      bg-slate-900/70
      border border-red-500/30
      rounded-2xl
      p-6
      backdrop-blur-lg
    ">

      <h2 className="text-2xl font-bold text-red-400 mb-6">
        Live Threat Feed
      </h2>

      <div className="space-y-4">

        {alerts.map((alert, index) => (

          <div
            key={index}
            className="
              bg-red-500/10
              border border-red-500/20
              p-4 rounded-xl
              animate-pulse
            "
          >

            {alert}

          </div>

        ))}

      </div>

    </div>
  );
}
