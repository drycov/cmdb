/**
 * Frontend module for pages Operations.
 */
import { useEffect, useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import Loading from "../components/Loading";
import {
  createCliJob,
  getCliJob,
  listCliCommands,
  listCliJobs,
} from "../api/snapshots";
import type {
  CommandDefinitionResponse,
  CommandJobRequest,
  CommandJobResponse,
} from "../types/api";

function formatDate(isoDate: string | null) {
  if (!isoDate) {
    return "—";
  }
  return new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(isoDate));
}

function Operations() {
  const [commands, setCommands] = useState<CommandDefinitionResponse[]>([]);
  const [jobs, setJobs] = useState<CommandJobResponse[]>([]);
  const [commandName, setCommandName] = useState<CommandJobRequest["command"]>("targets");
  const [ip, setIp] = useState("");
  const [domains, setDomains] = useState("");
  const [showProgress, setShowProgress] = useState(false);
  const [exportReport, setExportReport] = useState(false);
  const [applyChanges, setApplyChanges] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState("");
  const [selectedJob, setSelectedJob] = useState<CommandJobResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadInitialData() {
      try {
        setIsLoading(true);
        const [commandResult, jobResult] = await Promise.all([
          listCliCommands(),
          listCliJobs(),
        ]);
        setCommands(commandResult.items);
        setJobs(jobResult.items);
        const currentJob = jobResult.items[0] ?? null;
        setSelectedJobId(currentJob?.job_id ?? "");
        setSelectedJob(currentJob);
        setCommandName((commandResult.items[0]?.name as CommandJobRequest["command"]) ?? "targets");
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsLoading(false);
      }
    }

    loadInitialData();
  }, []);

  useEffect(() => {
    if (jobs.length === 0) {
      return;
    }
    const hasRunningJobs = jobs.some((job) => job.status === "queued" || job.status === "running");
    if (!hasRunningJobs) {
      return;
    }

    const timer = window.setInterval(async () => {
      try {
        const result = await listCliJobs();
        setJobs(result.items);
        if (selectedJobId) {
          const job = result.items.find((item) => item.job_id === selectedJobId) ?? null;
          setSelectedJob(job);
        }
      } catch {
        return;
      }
    }, 2500);

    return () => window.clearInterval(timer);
  }, [jobs, selectedJobId]);

  useEffect(() => {
    async function loadJob() {
      if (!selectedJobId) {
        setSelectedJob(null);
        return;
      }
      try {
        const job = await getCliJob(selectedJobId);
        setSelectedJob(job);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    }

    loadJob();
  }, [selectedJobId]);

  const selectedCommand = useMemo(() => {
    return commands.find((item) => item.name === commandName) ?? null;
  }, [commandName, commands]);

  async function handleSubmit() {
    try {
      setIsSubmitting(true);
      const payload: CommandJobRequest = {
        command: commandName,
        show_progress: showProgress,
        export_report: exportReport,
        apply_changes: applyChanges,
        ip: ip.trim() || null,
        domains: domains
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
      };
      const job = await createCliJob(payload);
      setJobs((current) => [job, ...current]);
      setSelectedJobId(job.job_id);
      setSelectedJob(job);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="page-shell">
      <PageHeader
        title="Operations"
        description="Запуск тех же runtime workflow, что и в CLI: audit, topology, backup, remediation и script generation."
      />

      {isLoading ? (
        <Loading label="Загружаем registry команд…" />
      ) : error ? (
        <div className="panel error-panel">Ошибка API: {error}</div>
      ) : (
        <div className="operations-layout">
          <section className="panel operation-form">
            <h2>Запуск команды</h2>
            <p className="muted-copy">
              Backend использует тот же `AuditApplication`, что и CLI, поэтому web path запускает те же workflow, а не отдельную упрощенную логику.
            </p>

            <label className="field-label">
              Команда
              <select
                className="select-field"
                value={commandName}
                onChange={(event) => setCommandName(event.target.value as CommandJobRequest["command"])}
              >
                {commands.map((command) => (
                  <option key={command.name} value={command.name}>
                    {command.title}
                  </option>
                ))}
              </select>
            </label>

            {selectedCommand?.supports_ip || selectedCommand?.requires_ip ? (
              <label className="field-label">
                IP устройства
                <input
                  className="input-field"
                  value={ip}
                  onChange={(event) => setIp(event.target.value)}
                  placeholder="10.216.92.1"
                />
              </label>
            ) : null}

            {selectedCommand?.supports_domains ? (
              <label className="field-label">
                Domains
                <input
                  className="input-field"
                  value={domains}
                  onChange={(event) => setDomains(event.target.value)}
                  placeholder="ntp,scheduler,watchdog"
                />
              </label>
            ) : null}

            <div className="toggle-grid">
              {selectedCommand?.supports_progress ? (
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={showProgress}
                    onChange={(event) => setShowProgress(event.target.checked)}
                  />
                  <span>show_progress</span>
                </label>
              ) : null}

              {selectedCommand?.supports_export ? (
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={exportReport}
                    onChange={(event) => setExportReport(event.target.checked)}
                  />
                  <span>export_report</span>
                </label>
              ) : null}

              {selectedCommand?.supports_apply ? (
                <label className="toggle-item">
                  <input
                    type="checkbox"
                    checked={applyChanges}
                    onChange={(event) => setApplyChanges(event.target.checked)}
                  />
                  <span>apply_changes</span>
                </label>
              ) : null}
            </div>

            <div className="command-hint">
              <strong>{selectedCommand?.title}</strong>
              <p>{selectedCommand?.description}</p>
            </div>

            <button
              type="button"
              className="primary-button"
              disabled={isSubmitting || (selectedCommand?.requires_ip && !ip.trim())}
              onClick={handleSubmit}
            >
              {isSubmitting ? "Запуск…" : "Запустить"}
            </button>
          </section>

          <section className="panel operation-jobs">
            <h2>История job</h2>
            <div className="jobs-list">
              {jobs.map((job) => (
                <button
                  type="button"
                  key={job.job_id}
                  className={selectedJobId === job.job_id ? "job-card active" : "job-card"}
                  onClick={() => setSelectedJobId(job.job_id)}
                >
                  <span className="job-card-title">{job.command}</span>
                  <span className={`job-status ${job.status}`}>{job.status}</span>
                  <span>{formatDate(job.created_at)}</span>
                </button>
              ))}
              {jobs.length === 0 ? <p>Команды еще не запускались.</p> : null}
            </div>
          </section>

          <section className="panel operation-detail panel-span-2">
            <h2>Детали выполнения</h2>
            {selectedJob ? (
              <>
                <div className="detail-grid">
                  <div>
                    <span className="metric-label">Команда</span>
                    <strong>{selectedJob.command}</strong>
                  </div>
                  <div>
                    <span className="metric-label">Статус</span>
                    <strong>{selectedJob.status}</strong>
                  </div>
                  <div>
                    <span className="metric-label">Создана</span>
                    <strong>{formatDate(selectedJob.created_at)}</strong>
                  </div>
                  <div>
                    <span className="metric-label">Завершена</span>
                    <strong>{formatDate(selectedJob.completed_at)}</strong>
                  </div>
                </div>

                <p className="job-summary">{selectedJob.summary || "Summary пока нет."}</p>

                {selectedJob.artifacts.length > 0 ? (
                  <div className="artifact-list">
                    <h3>Artifacts</h3>
                    <ul>
                      {selectedJob.artifacts.map((artifact) => (
                        <li key={artifact}>{artifact}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}

                <div className="log-panel">
                  <h3>Output</h3>
                  <pre>{selectedJob.output.join("\n") || "Нет текстового вывода."}</pre>
                </div>
              </>
            ) : (
              <p>Выберите job слева, чтобы посмотреть статус и вывод.</p>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

export default Operations;
/**
 * Operations page for launching backend jobs and reviewing their progress.
 */
