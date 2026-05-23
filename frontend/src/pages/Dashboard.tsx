/**
 * Frontend module for pages Dashboard.
 */
import { useEffect, useMemo, useState } from "react";
import { healthCheck, listSnapshots } from "../api/snapshots";
import type { SnapshotSummaryResponse } from "../types/api";
import Loading from "../components/Loading";
import PageHeader from "../components/PageHeader";

function formatDate(isoDate: string) {
  return new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(isoDate));
}

function Dashboard() {
  const [status, setStatus] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotSummaryResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setIsLoading(true);
        const health = await healthCheck();
        setStatus(health.status);
        const snapshotData = await listSnapshots();
        setSnapshots(snapshotData.items);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsLoading(false);
      }
    }

    loadData();
  }, []);

  const latestSnapshots = useMemo(
    () => snapshots.slice(0, 3),
    [snapshots]
  );
  const totals = useMemo(() => {
    return snapshots.reduce(
      (acc, snapshot) => {
        acc.devices += snapshot.device_count;
        acc.links += snapshot.link_count;
        acc.risks += snapshot.risk_count;
        return acc;
      },
      { devices: 0, links: 0, risks: 0 }
    );
  }, [snapshots]);
  const latestSnapshot = latestSnapshots[0] ?? null;

  return (
    <div className="page-shell">
      <PageHeader
        title="Обзор"
        description="Сводка по состоянию API, последним снимкам и качеству данных.">
      </PageHeader>

      {isLoading ? (
        <Loading />
      ) : error ? (
        <div className="panel error-panel">Ошибка API: {error}</div>
      ) : (
        <section className="panel-grid">
          <article className="panel stat-card">
            <h2>Состояние API</h2>
            <p>Backend доступен и готов отдавать snapshot telemetry.</p>
            <div className="status-badge">{status}</div>
          </article>
          <article className="panel stat-card">
            <h2>Масштаб данных</h2>
            <div className="metric-grid">
              <div>
                <span className="metric-label">Снимки</span>
                <strong>{snapshots.length}</strong>
              </div>
              <div>
                <span className="metric-label">Устройства</span>
                <strong>{totals.devices}</strong>
              </div>
              <div>
                <span className="metric-label">Связи</span>
                <strong>{totals.links}</strong>
              </div>
              <div>
                <span className="metric-label">Риски</span>
                <strong>{totals.risks}</strong>
              </div>
            </div>
          </article>
          <article className="panel stat-card">
            <h2>Последний снимок</h2>
            {latestSnapshot ? (
              <>
                <p>
                  <strong>{latestSnapshot.snapshot_id}</strong>
                </p>
                <p>Статус: {latestSnapshot.status}</p>
                <p>Начат: {formatDate(latestSnapshot.started_at)}</p>
                <p>
                  Устройства: {latestSnapshot.device_count}, связи:{" "}
                  {latestSnapshot.link_count}, риски: {latestSnapshot.risk_count}
                </p>
              </>
            ) : (
              <p>Снимки еще не созданы.</p>
            )}
          </article>
          <article className="panel stat-card panel-span-2">
            <h2>Недавние снимки</h2>
            <ul className="snapshot-list">
              {latestSnapshots.map((item) => (
                <li key={item.snapshot_id}>
                  <span>{formatDate(item.started_at)}</span>
                  <strong>{item.snapshot_id}</strong>
                  <span>{item.status}</span>
                </li>
              ))}
            </ul>
          </article>
        </section>
      )}
    </div>
  );
}

export default Dashboard;
/**
 * Dashboard page summarizing the latest snapshot and high-level inventory state.
 */
