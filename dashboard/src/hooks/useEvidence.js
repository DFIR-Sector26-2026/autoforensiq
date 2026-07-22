import { createContext, createElement, useContext, useEffect, useState } from "react";

// D1: fetched once at the App level and shared via context — every page previously ran its own
// useEffect, re-downloading and re-parsing the ~1 MB unified_evidence.json on each sidebar click.
const EvidenceContext = createContext(null);

// createElement rather than JSX: this is a .js file, outside the JSX transform.
export function EvidenceProvider({ children }) {
  const value = useEvidenceFetch();
  return createElement(EvidenceContext.Provider, { value }, children);
}

export default function useEvidence() {
  return useContext(EvidenceContext);
}

function useEvidenceFetch() {
  const [evidence, setEvidence] = useState([]);
  const [summary, setSummary] = useState(null);
  const [mitre, setMitre] = useState([]);
  const [byTool, setByTool] = useState({});
  const [sources, setSources] = useState({});
  const [reconciliation, setReconciliation] = useState(null);
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Each fetch falls back to an empty default on a missing file, so one absent artifact can't
    // blank the whole UI — render whatever's available.
    Promise.all([
      fetch("/data/unified_evidence.json")
        .then((res) => (res.ok ? res.json() : []))
        .catch(() => []),
      fetch("/data/dashboard.json")
        .then((res) => (res.ok ? res.json() : {}))
        .catch(() => ({})),
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
        // D2: the network graph is computed by the report generator; older runs lack the key.
        setGraph(dashboard.graph || { nodes: [], links: [] });
        setReconciliation(recon);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  return { evidence, summary, mitre, byTool, sources, reconciliation, graph, loading };
}
