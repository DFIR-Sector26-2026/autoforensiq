import Dashboard from "./pages/Dashboard";
import { EvidenceProvider } from "./hooks/useEvidence";

export default function App() {
  return (
    <EvidenceProvider>
      <Dashboard />
    </EvidenceProvider>
  );
}
