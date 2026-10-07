import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck,
  LayoutDashboard,
  FolderGit2,
  GitBranch,
  Activity,
  Settings,
  ArrowUpRight,
  Plus,
  Upload,
  Download,
  LogOut,
  Search,
  CheckCircle2,
  AlertTriangle,
  X,
  FileCheck2,
  ChevronRight,
  LockKeyhole,
  Layers,
} from "lucide-react";
import "./style.css";
type Finding = {
  id: string;
  tool: string;
  severity: string;
  category: string;
  issueType?: string;
  quality?: string;
  impacts?: { softwareQuality: string; severity: string }[];
  file: string;
  line: number;
  rule: string;
  description: string;
};
type Repo = {
  id: string;
  name: string;
  url: string;
  threshold: number;
  demo: boolean;
};
type Scan = {
  id: string;
  repoId: string;
  commit: string;
  branch: string;
  source: string;
  demo: boolean;
  status: string;
  createdAt: string;
  received?: string[];
  findings: Finding[];
  score: null | {
    value: number;
    band: string;
    allowed: boolean;
    threshold: number;
    classificationComplete?: boolean;
    qualityCounts?: Record<string, number>;
    breakdown: {
      key: string;
      count: number;
      deduction: number;
      cap: number;
      weight: number;
    }[];
  };
};
type State = {
  repos: Repo[];
  sessions: Scan[];
  audit: { id: string; time: string; action: string; detail: string }[];
};
const scannerNames: Record<string, string> = {
  sonar: "SonarQube",
  trufflehog: "TruffleHog",
  "dependency-check": "Dependency-Check",
};
function App() {
  const [token, setToken] = useState(sessionStorage.getItem("bl-token") || "");
  const [setup, setSetup] = useState(false);
  const [ready, setReady] = useState(false);
  const [data, setData] = useState<State>({
    repos: [],
    sessions: [],
    audit: [],
  });
  const [page, setPage] = useState("Overview");
  const [modal, setModal] = useState("");
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [toolFilter, setToolFilter] = useState("all");
  const [connected, setConnected] = useState(false);
  async function api(path: string, body?: unknown, method?: string) {
    const r = await fetch("/api" + path, {
      method: method || (body ? "POST" : "GET"),
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: "Bearer " + token } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const d = await r.json();
    if (!r.ok) {
      if (r.status === 401 && token) {
        sessionStorage.removeItem("bl-token");
        setToken("");
      }
      throw Error(d.error || "Request failed");
    }
    return d;
  }
  async function refresh() {
    try {
      setData(await api("/state"));
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    fetch("/api/auth/status")
      .then((r) => r.json())
      .then((d) => {
        setSetup(d.setupRequired);
        setReady(true);
      })
      .catch(() => setError("Cannot reach the server"));
  }, []);
  useEffect(() => {
    if (!token) return;
    refresh();
    let ws: WebSocket;
    let retry: ReturnType<typeof setTimeout>;
    let ended = false;
    function connect() {
      ws = new WebSocket(
        `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`,
      );
      ws.onopen = () => {
        ws.send(JSON.stringify({ token }));
        setConnected(true);
      };
      ws.onmessage = () => refresh();
      ws.onclose = () => {
        setConnected(false);
        if (!ended) retry = setTimeout(connect, 3000);
      };
    }
    connect();
    return () => {
      ended = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, [token]);
  async function perform(fn: () => Promise<void>) {
    setError("");
    setBusy(true);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const current = data.sessions.find((s) => s.id === selected);
  const repoFor = (s: Scan) => data.repos.find((r) => r.id === s.repoId);
  const latest = data.repos
    .map(
      (r) =>
        data.sessions
          .filter((s) => s.repoId === r.id)
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0],
    )
    .filter(Boolean);
  const complete = latest.filter((s) => s.score);
  const avg = complete.length
    ? Math.round(
        complete.reduce((n, s) => n + s.score!.value, 0) / complete.length,
      )
    : null;
  const findings = latest.flatMap((s) => s.findings);
  const blocked = complete.filter(
    (s) => s.score!.value < (repoFor(s)?.threshold ?? 80),
  ).length;
  const openScan = (s: Scan) => {
    setSelected(s.id);
    setPage("Scan details");
    setSearch("");
    setSeverity("all");
    setToolFilter("all");
  };
  function pill(value: string) {
    return <span className={"pill " + value.toLowerCase()}>{value}</span>;
  }
  const formData = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    return Object.fromEntries(new FormData(e.currentTarget));
  };
  async function exportScan(s: Scan) {
    const blob = new Blob([JSON.stringify(s, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `gatereaper-${s.commit}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
  const empty = (
    <div className="empty">
      <FolderGit2 size={38} />
      <h3>Your security workspace starts here</h3>
      <p>
        Connect a repository and import scanner reports, or explore the labelled
        sample workspace.
      </p>
      <button onClick={() => setModal("repo")}>
        Add repository <Plus size={16} />
      </button>
      <button
        className="secondary"
        disabled={busy}
        onClick={() =>
          perform(async () => {
            await api("/demo", {});
          })
        }
      >
        Explore sample data
      </button>
    </div>
  );
  if (!token)
    return (
      <div className="login">
        <div className="login-story">
          <div className="brand">
            <ShieldCheck /> GateReaper
          </div>
          <span className="eyebrow">TEAM BLUE LOCK / DEVSECOPS</span>
          <h1>
            One clear view.
            <br />
            Every security
            <br />
            <em>decision.</em>
          </h1>
          <p>
            Bring your code, secrets, and dependency findings together. Know
            what needs fixing before you ship.
          </p>
          <div className="login-tags">
            <span>SAST</span>
            <span>Secrets</span>
            <span>Dependencies</span>
          </div>
        </div>
        <div className="login-form">
          <LockKeyhole size={32} />
          <h2>{setup ? "Create your workspace" : "Welcome back"}</h2>
          <p>
            {setup
              ? "Set up the administrator account to get started."
              : "Sign in to your security workspace."}
          </p>
          <form
            onSubmit={async (e) => {
              const d = formData(e);
              setBusy(true);
              setError("");
              try {
                const r = await api(setup ? "/auth/setup" : "/auth/login", d);
                sessionStorage.setItem("bl-token", r.token);
                setToken(r.token);
                setSetup(false);
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label>
              Email
              <input
                name="email"
                type="email"
                required
                autoComplete="username"
                placeholder="you@team.com"
              />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                minLength={setup ? 15 : 1}
                maxLength={256}
                required
                autoComplete={setup ? "new-password" : "current-password"}
              />
            </label>
            {setup && <small>Use at least 15 characters.</small>}
            {error && <div className="error">{error}</div>}
            <button disabled={busy || !ready}>
              {busy ? "Please wait…" : setup ? "Create workspace" : "Sign in"}
              <ArrowUpRight size={18} />
            </button>
          </form>
          <small>
            Local workspace • Your scanner reports stay on your server
          </small>
        </div>
      </div>
    );
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <ShieldCheck size={29} />
          <div>
            BLUE LOCK<small>SECURITY WORKSPACE</small>
          </div>
        </div>
        <div className="workspace">
          <div className="avatar">BL</div>
          <div>
            GateReaper<small>by Team Blue Lock</small>
          </div>
        </div>
        <span className="navlabel">WORKSPACE</span>
        <nav>
          {[
            [LayoutDashboard, "Overview"],
            [FolderGit2, "Repositories"],
            [Layers, "Scan history"],
            [Activity, "Audit log"],
            [Settings, "Gate policies"],
          ].map(([Icon, label]) => (
            <button
              className={page === label ? "active" : ""}
              onClick={() => {
                setPage(label as string);
                setError("");
              }}
              key={label as string}
            >
              {React.createElement(Icon as typeof Activity, { size: 19 })}
              {label as string}
            </button>
          ))}
        </nav>
        <div className="aside-bottom">
          <div className="system">
            <i className={connected ? "online" : ""} />
            {connected ? "Live updates connected" : "Reconnecting…"}
          </div>
          <button
            className="logout"
            onClick={() => {
              sessionStorage.removeItem("bl-token");
              setToken("");
            }}
          >
            <LogOut size={17} />
            Sign out
          </button>
          <small>GateReaper / v1.0</small>
        </div>
      </aside>
      <main>
        <header>
          <span>
            Workspace <ChevronRight size={14} /> {page}
          </span>
          <span className="header-right">
            <ShieldCheck size={16} /> Security operations
          </span>
        </header>
        <div className="content">
          <div className="title-row">
            <div>
              <div className="eyebrow">SECURE SOFTWARE DELIVERY</div>
              <h1>{page === "Overview" ? "Security overview" : page}</h1>
              <p>
                {page === "Overview"
                  ? "From scattered findings to confident release decisions."
                  : page === "Repositories"
                    ? "Manage the projects protected by your security gates."
                    : page === "Scan history"
                      ? "Trace each report, commit, and security decision."
                      : page === "Gate policies"
                        ? "Set the minimum score required for each repository."
                        : page === "Audit log"
                          ? "A timestamped record of workspace activity."
                          : "Inspect the evidence behind this security decision."}
              </p>
            </div>
            <button onClick={() => setModal("repo")}>
              <Plus size={17} />
              Add repository
            </button>
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
              <button className="icon" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div className="notice">
              {notice}
              <button className="icon" onClick={() => setNotice("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {page === "Overview" && (
            <>
              {data.repos.some((r) => r.demo) && (
                <div className="sample-banner">
                  <span className="pill sample">SAMPLE WORKSPACE</span>
                  Illustrative findings. No live scanners have been run for
                  these repositories.
                </div>
              )}
              <div className="stats">
                {[
                  [
                    FolderGit2,
                    "Repositories",
                    data.repos.length,
                    "Connected projects",
                  ],
                  [
                    ShieldCheck,
                    "Average health",
                    avg ?? "—",
                    "Latest completed scans",
                  ],
                  [
                    AlertTriangle,
                    "Open findings",
                    findings.length,
                    "Across latest sessions",
                  ],
                  [
                    LockKeyhole,
                    "Below threshold",
                    blocked,
                    "Completed scans only",
                  ],
                ].map(([Icon, title, value, caption]) => (
                  <div className="stat" key={title as string}>
                    <div>
                      <span>{title as string}</span>
                      {React.createElement(Icon as typeof Activity, {
                        size: 20,
                      })}
                    </div>
                    <strong>
                      {value as string}
                      {title === "Average health" && avg !== null && (
                        <small>/100</small>
                      )}
                    </strong>
                    <small>{caption as string}</small>
                  </div>
                ))}
              </div>
              {!data.repos.length ? (
                empty
              ) : (
                <>
                  <div className="overview-grid">
                    <section className="panel">
                      <div className="panel-heading">
                        <div>
                          <h2>Repository health</h2>
                          <p>Your most recent security assessments</p>
                        </div>
                        <button
                          className="text-button"
                          onClick={() => setPage("Repositories")}
                        >
                          View all <ArrowUpRight size={16} />
                        </button>
                      </div>
                      {data.repos.map((r) => {
                        const s = latest.find((s) => s.repoId === r.id);
                        return (
                          <button
                            className="repo-row"
                            key={r.id}
                            onClick={() =>
                              s
                                ? openScan(s)
                                : (setSelected(r.id), setModal("session"))
                            }
                          >
                            <div className="repo-icon">
                              <FolderGit2 size={23} />
                            </div>
                            <div className="repo-name">
                              <b>{r.name}</b>
                              <small>
                                <GitBranch size={12} />
                                {s?.branch || "No scans yet"} ·{" "}
                                {s?.commit.slice(0, 7) || "Ready for reports"}
                                {r.demo ? " · Sample" : ""}
                              </small>
                            </div>
                            <div className="health-mini">
                              <b>
                                {s?.score?.value ?? "—"}
                                <small>/100</small>
                              </b>
                              <div className="track">
                                <i
                                  style={{ width: `${s?.score?.value || 0}%` }}
                                />
                              </div>
                            </div>
                            {pill(
                              !s?.score
                                ? "Pending"
                                : s.score.value >= r.threshold
                                  ? "Pass"
                                  : "Block",
                            )}
                            <ChevronRight size={17} />
                          </button>
                        );
                      })}
                    </section>
                    <section className="panel pipeline">
                      <span className="eyebrow">THE BLUE LOCK PIPELINE</span>
                      <h2>
                        Three perspectives.
                        <br />
                        One security score.
                      </h2>
                      {Object.entries(scannerNames).map(([key, name], i) => (
                        <div className="scanner" key={key}>
                          <span>0{i + 1}</span>
                          <div>
                            <b>{name}</b>
                            <small>
                              {
                                [
                                  "Source code analysis",
                                  "Credential detection",
                                  "Dependency vulnerabilities",
                                ][i]
                              }
                            </small>
                          </div>
                          <CheckCircle2 size={18} />
                        </div>
                      ))}
                      <div className="pipeline-foot">
                        <ShieldCheck size={21} />
                        <div>
                          Evidence before deployment
                          <small>All three reports are required.</small>
                        </div>
                      </div>
                    </section>
                  </div>
                  <section className="panel">
                    <div className="panel-heading">
                      <h2>Recent activity</h2>
                      <button
                        className="text-button"
                        onClick={() => setPage("Audit log")}
                      >
                        Full audit log <ArrowUpRight size={15} />
                      </button>
                    </div>
                    {data.audit.slice(0, 4).map((a) => (
                      <div className="audit-row" key={a.id}>
                        <div className="event-dot" />
                        <div>
                          <b>{a.action}</b>
                          <small>{a.detail}</small>
                        </div>
                        <time>{new Date(a.time).toLocaleTimeString()}</time>
                      </div>
                    ))}
                  </section>
                </>
              )}
            </>
          )}
          {page === "Repositories" &&
            (!data.repos.length ? (
              empty
            ) : (
              <div className="repo-grid">
                {data.repos.map((r) => (
                  <section className="panel repo-card" key={r.id}>
                    <FolderGit2 size={28} />
                    {r.demo && pill("Sample")}
                    <h2>{r.name}</h2>
                    <p className="url">{r.url}</p>
                    <div className="card-meta">
                      <span>Gate threshold</span>
                      <b>{r.threshold}/100</b>
                    </div>
                    <div className="card-meta">
                      <span>Sessions</span>
                      <b>
                        {data.sessions.filter((s) => s.repoId === r.id).length}
                      </b>
                    </div>
                    <button
                      className="secondary"
                      onClick={() => {
                        setSelected(r.id);
                        setModal("session");
                      }}
                    >
                      <Plus size={16} />
                      New scan session
                    </button>
                  </section>
                ))}
              </div>
            ))}
          {page === "Scan history" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>
                  All scan sessions{" "}
                  <span className="count">{data.sessions.length}</span>
                </h2>
              </div>
              {!data.sessions.length ? (
                <div className="empty">
                  <p>No scans yet. Add a repository to begin.</p>
                </div>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Repository / commit</th>
                        <th>Created</th>
                        <th>Source</th>
                        <th>Status</th>
                        <th>Health</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {data.sessions.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <b>{repoFor(s)?.name}</b>
                            <small>
                              {s.commit.slice(0, 7)} · {s.branch}
                            </small>
                          </td>
                          <td>{new Date(s.createdAt).toLocaleString()}</td>
                          <td>{s.source}</td>
                          <td>
                            {pill(
                              s.status === "completed"
                                ? "Completed"
                                : "Pending",
                            )}
                          </td>
                          <td>{s.score?.value ?? "—"}</td>
                          <td>
                            <button
                              className="text-button"
                              onClick={() => openScan(s)}
                            >
                              Inspect <ArrowUpRight size={14} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}
          {page === "Audit log" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>Workspace events</h2>
                <span className="muted">Most recent 2,000 events retained</span>
              </div>
              {data.audit.map((a) => (
                <div className="audit-row" key={a.id}>
                  <Activity size={18} />
                  <div>
                    <b>{a.action}</b>
                    <small>{a.detail}</small>
                  </div>
                  <time>{new Date(a.time).toLocaleString()}</time>
                </div>
              ))}
            </section>
          )}
          {page === "Gate policies" && (
            <>
              <div className="notice">
                A gate passes only when all three reports are present and the
                score meets the current threshold. Existing scan scores retain
                their original policy snapshot.
              </div>
              <section className="panel">
                {data.repos.map((r) => (
                  <form
                    className="policy-row"
                    key={r.id}
                    onSubmit={(e) => {
                      const d = formData(e);
                      perform(async () => {
                        await api(
                          "/repos/" + r.id,
                          { threshold: Number(d.threshold) },
                          "PATCH",
                        );
                        setNotice("Gate policy saved");
                      });
                    }}
                  >
                    <div>
                      <b>{r.name}</b>
                      <small>Minimum passing score</small>
                    </div>
                    <input
                      aria-label={"Threshold for " + r.name}
                      type="number"
                      min="0"
                      max="100"
                      name="threshold"
                      defaultValue={r.threshold}
                      required
                    />
                    <button disabled={busy}>Save policy</button>
                  </form>
                ))}
              </section>
              <section className="panel scoring">
                <h2>Transparent scoring</h2>
                <p>
                  Start at 100. Apply the capped deductions below. Secrets are
                  counted separately from severity deductions.
                </p>
                <div className="formula">
                  {[
                    ["Critical", "15", "60"],
                    ["High", "8", "32"],
                    ["Medium", "3", "15"],
                    ["Low", "1", "5"],
                    ["Secret", "25", "50"],
                  ].map(([name, w, c]) => (
                    <div key={name}>
                      <b>{name}</b>
                      <strong>−{w}</strong>
                      <small>Maximum deduction {c}</small>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}
          {page === "Scan details" && current && (
            <>
              <div className="detail-bar">
                <div>
                  <h2>{repoFor(current)?.name}</h2>
                  <span className="muted">
                    {current.commit} · {current.branch} ·{" "}
                    {current.demo ? "Sample data" : current.source}
                  </span>
                </div>
                <button
                  className="secondary"
                  onClick={() => exportScan(current)}
                >
                  <Download size={16} />
                  Export JSON
                </button>
              </div>
              <div className="overview-grid">
                <section className="panel score-panel">
                  <div
                    className="score-circle"
                    style={
                      {
                        "--score": `${(current.score?.value ?? 0) * 3.6}deg`,
                      } as React.CSSProperties
                    }
                  >
                    <div>
                      <strong>{current.score?.value ?? "—"}</strong>
                      <span>OUT OF 100</span>
                    </div>
                  </div>
                  <div>
                    <span className="eyebrow">SECURITY HEALTH</span>
                    <h2>{current.score?.band || "Waiting for reports"}</h2>
                    <p>
                      {current.score
                        ? `Threshold at scan time: ${current.score.threshold}/100`
                        : "Import every scanner report to calculate a score."}
                    </p>
                    {pill(
                      current.score
                        ? current.score.allowed
                          ? "Pass"
                          : "Block"
                        : "Pending",
                    )}
                    {current.demo && (
                      <small className="muted">
                        Sample result • deployment disabled
                      </small>
                    )}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Scanner coverage</h2>
                  </div>
                  {Object.entries(scannerNames).map(([key, name]) => (
                    <div className="coverage" key={key}>
                      <span>{name}</span>
                      {current.received?.includes(key) ? (
                        pill("Received")
                      ) : (
                        <button
                          className="text-button"
                          onClick={() => setModal(key)}
                        >
                          <Upload size={14} />
                          Import report
                        </button>
                      )}
                    </div>
                  ))}
                </section>
              </div>
              {current.score && (
                <section className="panel scoring">
                  <h2>Security score calculation</h2>
                  <p>Only security findings affect this score. Reliability and maintainability findings remain available below.</p>
                  {current.score.classificationComplete === false && <p role="alert">Reimport the raw Sonar report to restore missing classifications. The gate remains blocked.</p>}
                  {current.score.qualityCounts && <p>{Object.entries(current.score.qualityCounts).map(([quality, count]) => `${quality}: ${count}`).join(" · ")}</p>}
                  <div className="formula">
                    {current.score.breakdown
                      .filter((x) => x.key !== "info")
                      .map((x) => (
                        <div key={x.key}>
                          <b>{x.key}</b>
                          <strong>−{x.deduction}</strong>
                          <small>
                            {x.count} × {x.weight}, capped at {x.cap}
                          </small>
                        </div>
                      ))}
                  </div>
                </section>
              )}
              <section className="panel">
                <div className="panel-heading">
                  <h2>
                    Unified findings{" "}
                    <span className="count">{current.findings.length}</span>
                  </h2>
                </div>
                <div className="filters">
                  <label className="search">
                    <Search size={17} />
                    <input
                      placeholder="Search file, rule, or description…"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </label>
                  <select
                    aria-label="Severity filter"
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                  >
                    <option value="all">All severities</option>
                    {["critical", "high", "medium", "low", "info"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                  <select
                    aria-label="Scanner filter"
                    value={toolFilter}
                    onChange={(e) => setToolFilter(e.target.value)}
                  >
                    <option value="all">All scanners</option>
                    {Object.entries(scannerNames).map(([k, n]) => (
                      <option key={k} value={k}>
                        {n}
                      </option>
                    ))}
                  </select>
                </div>
                {current.findings
                  .filter(
                    (f) =>
                      (severity === "all" || f.severity === severity) &&
                      (toolFilter === "all" || f.tool === toolFilter) &&
                      [f.file, f.rule, f.description]
                        .join(" ")
                        .toLowerCase()
                        .includes(search.toLowerCase()),
                  )
                  .map((f) => (
                    <details className="finding" key={f.id}>
                      <summary>
                        {pill(f.severity)}
                        <div>
                          <b>{f.description}</b>
                          <small>
                            {f.file}:{f.line || "—"} · {scannerNames[f.tool]}
                          </small>
                        </div>
                        <ChevronRight size={16} />
                      </summary>
                      <div className="finding-details">
                        <b>Rule / identifier: {f.rule}</b>
                        <p>{f.description}</p>
                        {f.impacts?.length ? <p>Sonar impacts: {f.impacts.map(i => `${i.softwareQuality}: ${i.severity}`).join(" · ")}</p> : null}
                        <small>
                          Quality: {f.quality || (f.tool === "sonar" ? "unknown — reimport Sonar report" : "security")} · Type: {f.issueType || f.category} · Finding: {f.id}
                        </small>
                      </div>
                    </details>
                  ))}
                {!current.findings.length && (
                  <div className="empty">
                    <FileCheck2 />
                    <p>
                      {current.status === "completed"
                        ? "No findings were reported by the supplied scans."
                        : "No findings imported yet. This is not a passing assessment."}
                    </p>
                  </div>
                )}
              </section>
            </>
          )}
          <footer>
            <span>BLUE LOCK</span>
            <span>
              Centralized scanning. Transparent scoring. Controlled releases.
            </span>
          </footer>
        </div>
      </main>
      {modal && (
        <div className="modal-backdrop">
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label={
              modal === "repo"
                ? "Add repository"
                : modal === "session"
                  ? "New scan session"
                  : "Import scanner report"
            }
          >
            <button
              className="close icon"
              aria-label="Close dialog"
              onClick={() => setModal("")}
            >
              <X />
            </button>
            <div className="repo-icon">
              <ShieldCheck />
            </div>
            <h2>
              {modal === "repo"
                ? "Add a repository"
                : modal === "session"
                  ? "Create a scan session"
                  : `Import ${scannerNames[modal]} report`}
            </h2>
            {error && <div className="error">{error}</div>}
            {modal === "repo" ? (
              <form
                onSubmit={(e) => {
                  const d = formData(e);
                  perform(async () => {
                    await api("/repos", {
                      ...d,
                      threshold: Number(d.threshold),
                    });
                    setModal("");
                    setPage("Repositories");
                  });
                }}
              >
                <label>
                  Repository name
                  <input
                    autoFocus
                    name="name"
                    required
                    maxLength={80}
                    placeholder="payment-service"
                  />
                </label>
                <label>
                  Repository URL
                  <input
                    name="url"
                    type="url"
                    required
                    placeholder="https://github.com/your-team/project"
                  />
                </label>
                <label>
                  Passing score
                  <input
                    name="threshold"
                    type="number"
                    min="0"
                    max="100"
                    defaultValue="80"
                    required
                  />
                </label>
                <p className="muted">
                  Registering a repository does not clone it. Import reports
                  from your trusted CI pipeline.
                </p>
                <button disabled={busy}>Add repository</button>
              </form>
            ) : modal === "session" ? (
              <form
                onSubmit={(e) => {
                  const d = formData(e);
                  perform(async () => {
                    const s = await api("/sessions", {
                      repoId: selected,
                      ...d,
                    });
                    setModal("");
                    setSelected(s.id);
                    setPage("Scan details");
                  });
                }}
              >
                <label>
                  Commit SHA
                  <input
                    autoFocus
                    name="commit"
                    pattern="[a-f0-9]{7,40}"
                    required
                    placeholder="Full commit SHA recommended"
                  />
                </label>
                <label>
                  Branch
                  <input name="branch" defaultValue="main" required />
                </label>
                <button disabled={busy}>Create session</button>
              </form>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const form = e.currentTarget;
                  perform(async () => {
                    const file = (
                      form.elements.namedItem("report") as HTMLInputElement
                    ).files?.[0];
                    if (!file) throw Error("Select a report");
                    if (file.size > 7 * 1024 * 1024)
                      throw Error("Choose a report smaller than 7 MB");
                    await api(`/sessions/${selected}/reports/${modal}`, {
                      report: await file.text(),
                    });
                    setModal("");
                    setNotice(
                      "Report accepted. The score appears after all three reports are processed.",
                    );
                  });
                }}
              >
                <p>
                  Choose the complete scanner export for this commit. Empty
                  reports must still be imported to confirm scanner coverage.
                </p>
                <label className="upload-zone">
                  <Upload />
                  <span>
                    Choose JSON {modal === "trufflehog" ? "or JSONL" : ""}{" "}
                    report
                  </span>
                  <input
                    autoFocus
                    name="report"
                    type="file"
                    accept=".json,.jsonl,.ndjson"
                    required
                  />
                </label>
                <small>
                  TruffleHog secret values are discarded before persistence.
                </small>
                <button disabled={busy}>
                  {busy ? "Importing…" : "Import report"}
                </button>
              </form>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
