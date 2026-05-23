/**
 * Frontend module for pages Topology.
 */
import { useEffect, useMemo, useState } from "react";
import TopologyGraph from "../components/TopologyGraph";
import Loading from "../components/Loading";
import { getTopologyGraph, listSnapshots } from "../api/snapshots";
import type {
  TopologyGraphResponse,
  SnapshotSummaryResponse,
} from "../types/api";
import PageHeader from "../components/PageHeader";

function Topology() {
  const [graph, setGraph] = useState<TopologyGraphResponse | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotSummaryResponse[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState("");
  const [search, setSearch] = useState("");
  const [relationFilter, setRelationFilter] = useState("all");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadSnapshots() {
      try {
        setIsLoading(true);
        const snapshotResult = await listSnapshots();
        setSnapshots(snapshotResult.items);
        setSelectedSnapshotId(snapshotResult.items[0]?.snapshot_id ?? "");
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsLoading(false);
      }
    }

    loadSnapshots();
  }, []);

  useEffect(() => {
    async function loadGraph() {
      if (!selectedSnapshotId) {
        setGraph(null);
        return;
      }

      try {
        setIsLoading(true);
        const topologyGraph = await getTopologyGraph(selectedSnapshotId);
        setGraph(topologyGraph);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsLoading(false);
      }
    }

    loadGraph();
  }, [selectedSnapshotId]);

  const relationOptions = useMemo(() => {
    const relations = new Set(graph?.edges.map((edge) => edge.relation) ?? []);
    return ["all", ...Array.from(relations).sort()];
  }, [graph]);

  const filteredGraph = useMemo(() => {
    if (!graph) {
      return null;
    }

    const query = search.trim().toLowerCase();
    const visibleNodeIds = new Set(
      graph.nodes
        .filter((node) => {
          return (
            query.length === 0 ||
            node.identity.toLowerCase().includes(query) ||
            (node.management_ip || "").toLowerCase().includes(query) ||
            node.role.toLowerCase().includes(query) ||
            node.vendor.toLowerCase().includes(query)
          );
        })
        .map((node) => node.device_id)
    );

    const resolvedEdges = graph.edges.filter((edge) => edge.target_device_id);
    const matchingEdges = resolvedEdges.filter((edge) => {
      const matchesRelation = relationFilter === "all" || edge.relation === relationFilter;
      const matchesNodes =
        visibleNodeIds.has(edge.source_device_id) || visibleNodeIds.has(edge.target_device_id || "");
      return matchesRelation && matchesNodes;
    });

    const edgeNodeIds = new Set(
      matchingEdges.flatMap((edge) => [edge.source_device_id, edge.target_device_id || ""])
    );
    const nodes = graph.nodes.filter((node) => {
      if (query.length === 0 && relationFilter === "all") {
        return edgeNodeIds.size === 0 || edgeNodeIds.has(node.device_id);
      }
      return visibleNodeIds.has(node.device_id) || edgeNodeIds.has(node.device_id);
    });

    return {
      nodes,
      edges: matchingEdges,
      unresolvedCount: graph.edges.length - resolvedEdges.length,
    };
  }, [graph, relationFilter, search]);

  return (
    <div className="page-shell">
      <PageHeader
        title="Топология"
        description="Интерактивная карта сети с видимостью связей, устройств и доменных границ."
        actions={
          snapshots.length > 0 ? (
            <>
              <select
                className="select-field"
                value={selectedSnapshotId}
                onChange={(event) => setSelectedSnapshotId(event.target.value)}
              >
                {snapshots.map((snapshot) => (
                  <option
                    key={snapshot.snapshot_id}
                    value={snapshot.snapshot_id}
                  >
                    {snapshot.snapshot_id} — {snapshot.status}
                  </option>
                ))}
              </select>
              <input
                className="input-field"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Поиск по узлам, IP, role, vendor"
              />
              <select
                className="select-field"
                value={relationFilter}
                onChange={(event) => setRelationFilter(event.target.value)}
              >
                {relationOptions.map((relation) => (
                  <option key={relation} value={relation}>
                    {relation === "all" ? "Все связи" : relation}
                  </option>
                ))}
              </select>
            </>
          ) : null
        }
      />

      {isLoading ? (
        <Loading />
      ) : error ? (
        <div className="panel error-panel">Ошибка API: {error}</div>
      ) : filteredGraph ? (
        <div className="panel topology-panel">
          <div className="topology-summary">
            <p>Снимок: <strong>{graph?.snapshot_id}</strong></p>
            <p>Узлы: <strong>{filteredGraph.nodes.length}</strong></p>
            <p>Связи: <strong>{filteredGraph.edges.length}</strong></p>
            <p>Unresolved edges: <strong>{filteredGraph.unresolvedCount}</strong></p>
          </div>
          <TopologyGraph nodes={filteredGraph.nodes} edges={filteredGraph.edges} />
        </div>
      ) : (
        <div className="panel">Нет данных для выбранного снимка.</div>
      )}
    </div>
  );
}

export default Topology;
/**
 * Topology page for exploring graph data returned by the backend snapshot API.
 */
