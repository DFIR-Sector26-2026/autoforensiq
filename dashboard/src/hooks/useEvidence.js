import { useEffect, useState } from "react";

export default function useEvidence() {

  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {

    fetch("/data/unified_evidence.json")
      .then((res) => res.json())
      .then((data) => {

        const items =
          data.evidence_items || data || [];

        setEvidence(items);

        setLoading(false);
      })
      .catch((err) => {

        console.error(err);

        setLoading(false);
      });

  }, []);

  return { evidence, loading };
}
