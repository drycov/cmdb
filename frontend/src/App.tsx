/**
 * Root application shell and route map for the frontend SPA.
 */
import { Suspense, lazy } from "react";
import { Route, Routes } from "react-router-dom";
import Loading from "./components/Loading";
import Sidebar from "./components/Sidebar";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Inventory = lazy(() => import("./pages/Inventory"));
const Operations = lazy(() => import("./pages/Operations"));
const Topology = lazy(() => import("./pages/Topology"));

function App() {
  // Keep route-level lazy loading in one place so each page can be split independently.
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="app-content">
        <Suspense fallback={<Loading label="Подготавливаем интерфейс…" />}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/inventory" element={<Inventory />} />
            <Route path="/operations" element={<Operations />} />
            <Route path="/topology" element={<Topology />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}

export default App;
