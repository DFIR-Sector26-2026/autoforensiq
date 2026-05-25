import { motion } from "framer-motion";

export default function StatCard({
  title,
  value,
  color,
}) {

  return (

    <motion.div

      whileHover={{
        scale: 1.04,
      }}

      className="
        bg-slate-900/70
        backdrop-blur-lg
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

    </motion.div>
  );
}
