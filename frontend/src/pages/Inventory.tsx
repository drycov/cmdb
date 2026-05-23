/**
 * Frontend module for pages Inventory.
 */
import { useEffect, useMemo, useState } from "react";
import { listInventory } from "../api/snapshots";
import type { InventoryEntryResponse } from "../types/api";
import Loading from "../components/Loading";
import PageHeader from "../components/PageHeader";

function Inventory() {
  const [entries, setEntries] = useState<InventoryEntryResponse[]>([]);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadInventory() {
      try {
        setIsLoading(true);
        const result = await listInventory();
        setEntries(result.items);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsLoading(false);
      }
    }

    loadInventory();
  }, []);

  const typeOptions = useMemo(() => {
    return ["all", ...Array.from(new Set(entries.map((entry) => entry.inventory_type))).sort()];
  }, [entries]);

  const filteredEntries = useMemo(() => {
    const query = search.trim().toLowerCase();
    return entries.filter((entry) => {
      const matchesType = typeFilter === "all" || entry.inventory_type === typeFilter;
      const matchesQuery =
        query.length === 0 ||
        entry.inventory_group.toLowerCase().includes(query) ||
        entry.subnet.toLowerCase().includes(query) ||
        (entry.gateway || "").toLowerCase().includes(query) ||
        (entry.vlan_name || "").toLowerCase().includes(query) ||
        String(entry.vlan_id ?? "").includes(query);
      return matchesType && matchesQuery;
    });
  }, [entries, search, typeFilter]);

  return (
    <div className="page-shell">
      <PageHeader
        title="Инвентарь"
        description="Source of truth из YAML-инвентаря, который использует backend при работе с сетью."
        actions={
          <>
            <input
              className="input-field"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Поиск по group, subnet, gateway, VLAN"
            />
            <select
              className="select-field"
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
            >
              {typeOptions.map((type) => (
                <option key={type} value={type}>
                  {type === "all" ? "Все типы" : type}
                </option>
              ))}
            </select>
          </>
        }
      />

      {isLoading ? (
        <Loading />
      ) : error ? (
        <div className="panel error-panel">Ошибка API: {error}</div>
      ) : (
        <div className="panel">
          <div className="toolbar-summary">
            <p>
              Записей в YAML: <strong>{entries.length}</strong>
            </p>
            <p>
              Показано: <strong>{filteredEntries.length}</strong>
            </p>
          </div>
          {filteredEntries.length > 0 ? (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Group</th>
                    <th>Subnet</th>
                    <th>Gateway</th>
                    <th>VLAN</th>
                    <th>OSPF</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEntries.map((entry) => (
                    <tr
                      key={[
                        entry.inventory_type,
                        entry.inventory_group,
                        entry.subnet,
                        entry.gateway || "",
                      ].join(":")}
                    >
                      <td>
                        <span className="tag">{entry.inventory_type || "—"}</span>
                      </td>
                      <td>{entry.inventory_group || "—"}</td>
                      <td>{entry.subnet}</td>
                      <td>{entry.gateway || "—"}</td>
                      <td>
                        {entry.vlan_name || entry.vlan_id
                          ? `${entry.vlan_name || "vlan"}${entry.vlan_id ? ` (${entry.vlan_id})` : ""}`
                          : "—"}
                      </td>
                      <td>{entry.ospf_instance || entry.ospf_area || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>Под текущие фильтры записи инвентаря не найдены.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default Inventory;
/**
 * Inventory page for browsing normalized networks, devices, and metadata.
 */
