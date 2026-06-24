import { useEffect, useState } from "react";

export default function useEvidence() {

  const [evidence, setEvidence] = useState([]);
  const [summary, setSummary] = useState(null);
  const [mitre, setMitre] = useState([]);
  const [byTool, setByTool] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {

    Promise.all([
      fetch("/data/unified_evidence.json").then((res) => res.json()),
      fetch("/data/dashboard.json").then((res) => res.json()),
    ])
      .then(([unified, dashboard]) => {

        setEvidence(unified.evidence_items || unified || []);

        setSummary(dashboard.summary || null);

        setMitre(dashboard.mitre || []);

        setByTool(dashboard.by_tool || {});

        setLoading(false);
      })
      .catch((err) => {

        console.error(err);

        setLoading(false);
      });

  }, []);

  return { evidence, summary, mitre, byTool, loading };
}
