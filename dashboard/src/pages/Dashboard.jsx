import { useState } from "react";

import Sidebar from "../layout/Sidebar";

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

        {renderPage()}

      </div>

    </div>
  );
}
