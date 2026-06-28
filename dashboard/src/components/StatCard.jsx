export default function StatCard({
  title,
  value,
  color,
}) {

  return (

    <div
      className="
        bg-slate-900/70
        border border-slate-700
        p-6
        rounded-2xl
        shadow-2xl
      "
    >

      <h2 className="text-slate-400 text-sm">
        {title}
      </h2>

      <p
        className="text-4xl font-bold mt-3"
        style={{ color }}
      >
        {value}
      </p>

    </div>
  );
}
