import { useEffect, useState } from "react";

export default function useEvidence() {

  const [evidence, setEvidence] = useState([]);
  const [summary, setSummary] = useState(null);
  const [mitre, setMitre] = useState([]);
  const [byTool, setByTool] = useState({});
  const [sources, setSources] = useState({});
  const [reconciliation, setReconciliation] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {

    Promise.all([
      fetch("/data/unified_evidence.json").then((res) => res.json()),
      fetch("/data/dashboard.json").then((res) => res.json()),
      // Reconciliation is optional — older runs may not have published it.
      fetch("/data/evidence_reconciliation.json")
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ])
      .then(([unified, dashboard, recon]) => {

        setEvidence(unified.evidence_items || unified || []);

        setSummary(dashboard.summary || null);

        setMitre(dashboard.mitre || []);

        setByTool(dashboard.by_tool || {});

        setSources(dashboard.evidence_sources || {});

        setReconciliation(recon);

        setLoading(false);
      })
      .catch((err) => {

        console.error(err);

        setLoading(false);
      });

  }, []);

  return { evidence, summary, mitre, byTool, sources, reconciliation, loading };
}
