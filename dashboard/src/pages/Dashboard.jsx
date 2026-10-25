import { useState } from "react";

import Sidebar from "../layout/Sidebar";
import useEvidence from "../hooks/useEvidence";

import Overview from "./Overview";
import Processes from "./Processes";
import Network from "./Network";
import Threats from "./Threats";
import Files from "./Files";
import Reports from "./Reports";
import Mitre from "./Mitre";

export default function Dashboard() {

  const [currentPage, setCurrentPage] =
    useState("Overview");

  const { loading } = useEvidence();

  const renderPage = () => {

    switch(currentPage) {

      case "Processes":
        return <Processes />;

      case "Network":
        return <Network />;

      case "Threats":
        return <Threats />;

      case "Files":
        return <Files />;

      case "Reports":
        return <Reports />;

      case "MITRE":
        return <Mitre />;

      default:
        return <Overview />;
    }
  };

  return (

    <div className="
      flex bg-slate-950
      text-white min-h-screen
    ">

      <Sidebar
        currentPage={currentPage}
        setCurrentPage={setCurrentPage}
      />

      <div className="flex-1 p-8">

        {/* D6: loading resolved once here — every page previously carried its own copy. */}
        {loading ? <div className="text-white">Loading...</div> : renderPage()}

      </div>

    </div>
  );
}
