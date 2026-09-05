import { useEffect, useRef, useState, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Activity,
  ArrowRight,
  Check,
  CheckCheck,
  ChevronDown,
  CircleHelp,
  ClipboardPaste,
  Clock3,
  Copy,
  EthernetPort,
  Fingerprint,
  Globe2,
  KeyRound,
  LockKeyhole,
  Monitor,
  Moon,
  Network,
  Plus,
  Power,
  Radio,
  RefreshCw,
  Search,
  Send,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { hasNativeHost, send, subscribe } from "./bridge";
import {
  formatDuration,
  initialConfig,
  initialSnapshot,
  validateConfig,
  type Config,
  type LogEntry,
  type Snapshot,
} from "./model";

type Page = "connection" | "activity" | "preferences";
type Theme = "dark" | "light" | "system";
const phaseLabels: Record<Snapshot["phase"], string> = {
  idle: "Not connected",
  authorizing: "Waiting for approval",
  connecting: "Connecting",
  connected: "Connected",
  listening: "Server is listening",
  reconnecting: "Reconnecting",
  stopping: "Disconnecting",
};

function Mark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <Shield size={23} strokeWidth={1.65} />
      <span>T</span>
    </span>
  );
}
function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={`card ${className}`}>{children}</section>;
}
function CardTitle({
  icon,
  title,
  subtitle,
  trailing,
}: {
  icon: ReactNode;
  title: string;
  subtitle?: string;
  trailing?: ReactNode;
}) {
  return (
    <div className="card-heading">
      <span className="section-icon">{icon}</span>
      <div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {trailing && <div className="heading-trailing">{trailing}</div>}
    </div>
  );
}
function FieldError({ id, children }: { id: string; children?: string }) {
  return children ? (
    <p className="field-error" id={id}>
      {children}
    </p>
  ) : null;
}
function LogRows({
  logs,
  compact = false,
}: {
  logs: LogEntry[];
  compact?: boolean;
}) {
  return (
    <div className={`log-rows ${compact ? "compact" : ""}`}>
      {logs.map((log) => (
        <div className="log-row" key={log.id}>
          <time>{log.time}</time>
          <span className={`log-dot ${log.level}`} />
          <span className="log-message">{log.message}</span>
        </div>
      ))}
    </div>
  );
}

export function App() {
  const [page, setPage] = useState<Page>("connection");
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [config, setConfig] = useState(initialConfig);
  const [errors, setErrors] = useState<ReturnType<typeof validateConfig>>({});
  const [help, setHelp] = useState(false);
  const [rotate, setRotate] = useState(false);
  const [theme, setTheme] = useState<Theme>("dark");
  const [query, setQuery] = useState("");
  const [logFilter, setLogFilter] = useState("all");
  const [chat, setChat] = useState("");
  const [follow, setFollow] = useState(true);
  const [localNotice, setLocalNotice] = useState("");
  const logEnd = useRef<HTMLDivElement>(null);
  const keyAction = useRef<HTMLButtonElement>(null);
  const helpReturn = useRef<HTMLElement | null>(null);
  const busy = snapshot.phase !== "idle";
  const active =
    snapshot.phase === "connected" || snapshot.phase === "listening";
  const chatBytes = new TextEncoder().encode(chat.trim()).length;
  const canSend = active && chatBytes > 0 && chatBytes <= 512;
  const working = busy && !active;
  const server = config.role === "server";
  const native = hasNativeHost();
  const adapter = snapshot.adapters.find((item) => item.id === config.adapter);

  useEffect(
    () =>
      subscribe((next) => {
        setSnapshot(next);
        setConfig((previous) =>
          !previous.adapter && next.adapters[0]
            ? { ...previous, adapter: next.adapters[0].id }
            : previous,
        );
      }),
    [],
  );
  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: light)");
    const apply = () =>
      (document.documentElement.dataset.theme =
        theme === "system" ? (media.matches ? "light" : "dark") : theme);
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
  useEffect(() => {
    if (follow && page === "activity")
      logEnd.current?.scrollIntoView({ block: "nearest" });
  }, [snapshot.logs, follow, page]);
  useEffect(() => {
    if (snapshot.keyReady)
      setErrors((previous) => ({ ...previous, key: undefined }));
  }, [snapshot.keyReady]);
  useEffect(() => {
    if (!localNotice) return;
    const timeout = setTimeout(() => setLocalNotice(""), 4000);
    return () => clearTimeout(timeout);
  }, [localNotice]);
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if (
        event.target instanceof HTMLInputElement ||
        event.target instanceof HTMLTextAreaElement ||
        event.target instanceof HTMLSelectElement ||
        help ||
        rotate
      )
        return;
      if (event.key === "?") {
        helpReturn.current = document.activeElement as HTMLElement;
        setHelp(true);
      }
      if (event.ctrlKey && ["1", "2", "3"].includes(event.key)) {
        event.preventDefault();
        setPage(
          (["connection", "activity", "preferences"] as Page[])[
            Number(event.key) - 1
          ],
        );
      }
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, [help, rotate]);
  function openHelp() {
    helpReturn.current = document.activeElement as HTMLElement;
    setHelp(true);
  }
  function update<K extends keyof Config>(key: K, value: Config[K]) {
    setConfig((previous) => ({ ...previous, [key]: value }));
    setErrors((previous) => ({ ...previous, [key]: undefined }));
  }
  function connect() {
    const next = validateConfig(config, snapshot);
    setErrors(next);
    if (Object.values(next).some(Boolean)) {
      setPage("connection");
      requestAnimationFrame(() =>
        document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus(),
      );
      return;
    }
    if (!native) {
      setLocalNotice(
        "Open TrueTunnel.exe to connect. This browser view has no VPN engine.",
      );
      return;
    }
    send({
      type: "start",
      config: { ...config, address: config.address.trim() },
    });
  }
  const filteredLogs = snapshot.logs.filter(
    (log) =>
      (logFilter === "all" || log.level === logFilter) &&
      log.message.toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Main navigation">
        <div className="brand">
          <Mark />
          <span>
            TrueTunnel<span className="brand-subtitle">PRIVATE NETWORK</span>
          </span>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav>
          {(
            [
              { id: "connection", label: "Connection", icon: <Network /> },
              { id: "activity", label: "Activity", icon: <Activity /> },
              { id: "preferences", label: "Preferences", icon: <Settings2 /> },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              aria-label={item.label}
              title={item.label}
              className={`nav-item ${page === item.id ? "selected" : ""}`}
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => setPage(item.id)}
            >
              {item.icon}
              <span>{item.label}</span>
              {item.id === "activity" &&
                snapshot.logs.some((log) => log.level === "error") && (
                  <span className="nav-notification" />
                )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button
            className="nav-item help-nav"
            aria-label="Help & shortcuts"
            title="Help & shortcuts"
            onClick={openHelp}
          >
            <CircleHelp />
            <span>Help & shortcuts</span>
            <span className="shortcut">?</span>
          </button>
          <div className="sidebar-footer">
            <span
              className={`status-dot ${snapshot.engineReady ? "good" : ""}`}
            />
            <div>
              {native ? "Native desktop app" : "Browser preview"}
              <span>TrueTunnel 3.1.0</span>
            </div>
          </div>
        </div>
      </aside>

      <main id="main" tabIndex={-1} className="main-content">
        <header className="page-header">
          <div>
            <div className="eyebrow">YOUR WORKSPACE</div>
            <h1>
              {page === "connection"
                ? "Connection"
                : page === "activity"
                  ? "Activity"
                  : "Preferences"}
            </h1>
            <p>
              {page === "connection"
                ? "A clear view of your private network."
                : page === "activity"
                  ? "Connection events and encrypted peer messages."
                  : "Make the workspace feel like yours."}
            </p>
          </div>
          <div className="platform-tag">
            <Monitor size={14} />
            <span>Windows</span>
            <span className="separator-dot" />
            IPv4
          </div>
        </header>

        {(snapshot.error || localNotice || !native) && (
          <div
            role={snapshot.error ? "alert" : "status"}
            className={`notice ${snapshot.error ? "error-notice" : ""}`}
          >
            <CircleHelp size={17} />
            <span>
              {snapshot.error ||
                localNotice ||
                "Browser preview · Network actions are available in the desktop app."}
            </span>
          </div>
        )}

        {page === "connection" && (
          <div className="page-enter">
            <section
              className={`connection-hero ${active ? "is-connected" : ""}`}
              aria-label="Connection status"
            >
              <div className={`hero-symbol ${working ? "is-working" : ""}`}>
                <div className="symbol-ring" />
                {active ? (
                  <ShieldCheck size={31} strokeWidth={1.5} />
                ) : (
                  <Shield size={31} strokeWidth={1.5} />
                )}
                <span className="symbol-status">
                  {active ? <Check size={10} /> : <LockKeyhole size={9} />}
                </span>
              </div>
              <div className="hero-copy">
                <div
                  className={`connection-label ${active ? "good-text" : ""}`}
                >
                  <span
                    className={`status-dot ${active ? "good" : working ? "pending" : ""}`}
                  />
                  <span role="status" aria-live="polite">
                    {phaseLabels[snapshot.phase]}
                  </span>
                </div>
                <h2>
                  {active
                    ? server
                      ? "Your network is ready."
                      : "Your tunnel is active."
                    : snapshot.phase === "reconnecting"
                      ? "Restoring your connection."
                      : working
                        ? "Getting your tunnel ready."
                        : "Ready to connect."}
                </h2>
                <p>
                  {snapshot.phase === "reconnecting"
                    ? `Attempt ${snapshot.retryAttempt} · next retry in ${Math.ceil(snapshot.retryDelay / 1000)} seconds`
                    : snapshot.phase === "authorizing"
                      ? "Approve the Windows prompt to start the network worker."
                      : active
                        ? server
                          ? `Accepting authenticated ${config.transport.toUpperCase()} clients on port ${config.port}.`
                          : config.address
                        : "Choose your endpoint and access key below."}
                </p>
              </div>
              <div className="hero-action">
                <button
                  className={`button primary connect-button ${busy ? "stop-button" : ""}`}
                  disabled={snapshot.phase === "stopping"}
                  onClick={busy ? () => send({ type: "stop" }) : connect}
                >
                  {working ? (
                    <RefreshCw size={17} className="spin" />
                  ) : (
                    <Power size={17} />
                  )}
                  <span>
                    {snapshot.phase === "stopping"
                      ? "Disconnecting"
                      : busy
                        ? working
                          ? "Cancel connection"
                          : server
                            ? "Stop server"
                            : "Disconnect"
                        : server
                          ? "Start server"
                          : "Connect"}
                  </span>
                  {!busy && <ArrowRight size={16} />}
                </button>
                <span>
                  {busy
                    ? "Your settings stay in this session"
                    : "Approval requested only on connect"}
                </span>
              </div>
            </section>

            <div className="session-strip">
              <div>
                <Clock3 />
                <span>
                  Session time
                  <strong>
                    {active ? formatDuration(snapshot.uptime) : "—"}
                  </strong>
                </span>
              </div>
              <div>
                <LockKeyhole />
                <span>
                  Encryption<strong>AES-256-GCM</strong>
                </span>
              </div>
              <div>
                <RefreshCw />
                <span>
                  Traffic keys<strong>Automatic renewal</strong>
                </span>
              </div>
              <div>
                <EthernetPort />
                <span>
                  Network interface
                  <strong title={adapter?.name}>
                    {adapter?.name || "Select an adapter"}
                  </strong>
                </span>
              </div>
            </div>

            <div className="configuration-grid">
              <Card className="connection-card">
                <CardTitle
                  icon={<Globe2 size={18} />}
                  title="Connection setup"
                  subtitle="Choose how this device joins the network."
                />
                <fieldset disabled={busy} className="config-fieldset">
                  <legend className="sr-only">Connection settings</legend>
                  <div
                    className="role-switch"
                    role="group"
                    aria-label="Device role"
                  >
                    <button
                      type="button"
                      aria-pressed={!server}
                      className={!server ? "chosen" : ""}
                      onClick={() => update("role", "client")}
                    >
                      <Monitor size={16} />
                      Client
                    </button>
                    <button
                      type="button"
                      aria-pressed={server}
                      className={server ? "chosen" : ""}
                      onClick={() => update("role", "server")}
                    >
                      <Server size={16} />
                      Server
                    </button>
                  </div>
                  <div className="endpoint-row">
                    <div className="field endpoint-field">
                      <label htmlFor="address">
                        {server ? "Listen address" : "Server address"}
                      </label>
                      <div className="input-with-icon">
                        <Globe2 size={15} />
                        <input
                          id="address"
                          placeholder="vpn.example.com"
                          value={
                            server
                              ? adapter?.ip || "Select an adapter"
                              : config.address
                          }
                          readOnly={server}
                          maxLength={253}
                          spellCheck={false}
                          autoComplete="off"
                          aria-invalid={Boolean(errors.address)}
                          aria-describedby={
                            errors.address ? "address-error" : undefined
                          }
                          onChange={(event) =>
                            update("address", event.target.value)
                          }
                        />
                      </div>
                    </div>
                    <div className="field port-field">
                      <label htmlFor="port">Port</label>
                      <input
                        id="port"
                        value={config.port}
                        inputMode="numeric"
                        maxLength={5}
                        aria-invalid={Boolean(errors.port)}
                        aria-describedby={
                          errors.port ? "port-error" : undefined
                        }
                        onChange={(event) => update("port", event.target.value)}
                      />
                    </div>
                  </div>
                  <FieldError id="address-error">{errors.address}</FieldError>
                  <FieldError id="port-error">{errors.port}</FieldError>
                  <div className="field transport-field">
                    <span className="field-label">Transport</span>
                    <div
                      className="transport-options"
                      role="group"
                      aria-label="Transport protocol"
                    >
                      <button
                        aria-pressed={config.transport === "udp"}
                        className={`transport-option ${config.transport === "udp" ? "chosen" : ""}`}
                        onClick={() => update("transport", "udp")}
                      >
                        <span className="transport-icon">
                          <Zap size={18} />
                        </span>
                        <span>
                          <strong>
                            UDP
                            <span className="recommend-label">Recommended</span>
                          </strong>
                          <small>Fast, responsive traffic</small>
                        </span>
                        <span className="radio-indicator" />
                      </button>
                      <button
                        aria-pressed={config.transport === "tcp"}
                        className={`transport-option ${config.transport === "tcp" ? "chosen" : ""}`}
                        onClick={() => update("transport", "tcp")}
                      >
                        <span className="transport-icon">
                          <Radio size={18} />
                        </span>
                        <span>
                          <strong>TCP</strong>
                          <small>For restricted networks</small>
                        </span>
                        <span className="radio-indicator" />
                      </button>
                    </div>
                    <p className="field-hint">
                      {config.transport === "udp"
                        ? "DTLS 1.3 · Best for low latency when UDP is available."
                        : "TLS 1.3 · Compatible with TCP-only networks; loss can add delay."}
                    </p>
                  </div>
                  <div className="field adapter-field">
                    <div className="label-row">
                      <label htmlFor="adapter">Physical network</label>
                      <button
                        className="text-button"
                        onClick={() => send({ type: "refreshAdapters" })}
                      >
                        <RefreshCw size={12} />
                        Refresh
                      </button>
                    </div>
                    <div className="select-wrap">
                      <Wifi size={16} />
                      <select
                        id="adapter"
                        value={config.adapter}
                        onChange={(event) =>
                          update("adapter", event.target.value)
                        }
                        aria-invalid={Boolean(errors.adapter)}
                        aria-describedby={
                          errors.adapter ? "adapter-error" : undefined
                        }
                      >
                        {snapshot.adapters.length === 0 && (
                          <option value="">No available IPv4 adapters</option>
                        )}
                        {snapshot.adapters.map((item) => (
                          <option key={item.id} value={item.id}>
                            {item.name} · {item.ip}
                          </option>
                        ))}
                      </select>
                      <ChevronDown size={15} />
                    </div>
                    <FieldError id="adapter-error">{errors.adapter}</FieldError>
                    <p
                      className="field-hint truncate"
                      title={adapter?.description}
                    >
                      {adapter?.description ||
                        "Refresh to find your Ethernet or Wi-Fi connection."}
                    </p>
                  </div>
                </fieldset>
              </Card>

              <div className="right-column">
                <Card className="key-card">
                  <CardTitle
                    icon={<KeyRound size={18} />}
                    title="Access key"
                    trailing={
                      <span
                        className={`mini-badge ${snapshot.keyReady ? "success-badge" : ""}`}
                      >
                        {snapshot.keyReady ? (
                          <>
                            <Check size={11} />
                            Ready
                          </>
                        ) : (
                          "Required"
                        )}
                      </span>
                    }
                  />
                  <p className="card-description">
                    {server
                      ? "Generate a key, then share it with your clients through a trusted channel."
                      : "Use the generated key from your server to authenticate this device."}
                  </p>
                  <div
                    className={`key-display ${errors.key ? "invalid" : ""}`}
                    aria-label={
                      snapshot.keyReady
                        ? "256-bit access key configured; value stays in native memory"
                        : "No access key configured"
                    }
                  >
                    <Fingerprint size={23} />
                    <span>
                      {snapshot.keyReady
                        ? "•••• •••• •••• •••• •••• ••••"
                        : "No access key added"}
                    </span>
                    <LockKeyhole size={14} />
                  </div>
                  <FieldError id="key-error">{errors.key}</FieldError>
                  <div className="key-actions">
                    <button
                      ref={keyAction}
                      className="button secondary"
                      disabled={busy}
                      aria-invalid={Boolean(errors.key)}
                      aria-describedby={errors.key ? "key-error" : undefined}
                      onClick={() =>
                        server
                          ? snapshot.keyReady
                            ? setRotate(true)
                            : send({ type: "generateKey" })
                          : send({ type: "pasteKey" })
                      }
                    >
                      {server ? (
                        <Plus size={15} />
                      ) : (
                        <ClipboardPaste size={15} />
                      )}
                      <span>
                        {server
                          ? snapshot.keyReady
                            ? "Regenerate"
                            : "Generate key"
                          : snapshot.keyReady
                            ? "Replace key"
                            : "Paste key"}
                      </span>
                    </button>
                    <button
                      className="button secondary icon-button"
                      aria-label="Copy access key"
                      disabled={!snapshot.keyReady}
                      onClick={() => send({ type: "copyKey" })}
                    >
                      {snapshot.clipboardSeconds > 0 ? (
                        <CheckCheck size={16} />
                      ) : (
                        <Copy size={16} />
                      )}
                    </button>
                    <button
                      className="button ghost icon-button"
                      aria-label="Clear access key"
                      disabled={!snapshot.keyReady || busy}
                      onClick={() => send({ type: "clearKey" })}
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                  <p className="key-footnote">
                    <ShieldCheck size={13} />
                    {snapshot.clipboardSeconds > 0
                      ? `Copied · Clipboard clears in ${snapshot.clipboardSeconds}s`
                      : snapshot.keyReady
                        ? "256-bit key · Stored only in native memory"
                        : "Never saved to disk or browser storage"}
                  </p>
                </Card>

                <Card className="recovery-card">
                  <div className="recovery-heading">
                    <span className="section-icon">
                      <RefreshCw size={18} />
                    </span>
                    <div>
                      <h2>Automatic recovery</h2>
                      <span>
                        {server
                          ? "Client connection preference"
                          : "Reconnect after a short outage"}
                      </span>
                    </div>
                    <button
                      role="switch"
                      aria-label="Automatic recovery"
                      aria-checked={config.recovery && !server}
                      disabled={busy || server}
                      className={`switch ${config.recovery && !server ? "on" : ""}`}
                      onClick={() => update("recovery", !config.recovery)}
                    >
                      <span />
                    </button>
                  </div>
                  <p className="card-description">
                    {server
                      ? "The server accepts fresh client sessions automatically. Enable recovery on each client."
                      : "Keep an eye on the connection and retry automatically if it drops."}
                  </p>
                  <div className="recovery-details">
                    <span>
                      <strong>5s</strong>Heartbeat
                    </span>
                    <span>
                      <strong>15s</strong>Timeout
                    </span>
                    <span>
                      <strong>1–30s</strong>Retry delay
                    </span>
                  </div>
                  <div className="subtle-note">
                    <span
                      className={`status-dot ${config.recovery && !server ? "good" : ""}`}
                    />
                    {config.recovery && !server
                      ? "Enabled · Disconnect always cancels retries"
                      : "Optional · Off by default"}
                  </div>
                </Card>
              </div>
            </div>

            <Card className="recent-card">
              <CardTitle
                icon={<Activity size={18} />}
                title="Recent activity"
                trailing={
                  <button
                    className="text-button"
                    onClick={() => setPage("activity")}
                  >
                    View all
                    <ArrowRight size={13} />
                  </button>
                }
              />
              {snapshot.logs.length ? (
                <LogRows logs={snapshot.logs.slice(-3)} compact />
              ) : (
                <div className="empty-inline">
                  <span className="empty-icon">
                    <Activity size={18} />
                  </span>
                  <div>
                    <strong>All quiet here.</strong>
                    <p>
                      Your connection events will appear as you use TrueTunnel.
                    </p>
                  </div>
                </div>
              )}
            </Card>
            <div className="page-footnote">
              <Shield size={13} />
              <span>TrueTunnel VPN Adapter · Stable Windows identity</span>
              <button onClick={openHelp}>
                How your connection works
                <ArrowRight size={12} />
              </button>
            </div>
          </div>
        )}

        {page === "activity" && (
          <div className="page-enter activity-page">
            <Card className="activity-card">
              <CardTitle
                icon={<Activity size={18} />}
                title="Connection log"
                trailing={
                  <button
                    className="button ghost small"
                    disabled={!snapshot.logs.length}
                    onClick={() => send({ type: "clearLogs" })}
                  >
                    <Trash2 size={14} />
                    Clear
                  </button>
                }
              />
              <div className="log-toolbar">
                <div className="input-with-icon search-input">
                  <Search size={15} />
                  <input
                    aria-label="Search activity"
                    placeholder="Search activity…"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                </div>
                <select
                  aria-label="Filter activity"
                  value={logFilter}
                  onChange={(event) => setLogFilter(event.target.value)}
                >
                  <option value="all">All events</option>
                  <option value="warning">Warnings</option>
                  <option value="error">Errors</option>
                  <option value="success">Success</option>
                </select>
              </div>
              <div
                className="log-scroll"
                role="region"
                aria-label="Activity events"
                tabIndex={0}
              >
                {filteredLogs.length ? (
                  <LogRows logs={filteredLogs} />
                ) : (
                  <div className="empty-state">
                    <Activity size={30} />
                    <h3>
                      {query || logFilter !== "all"
                        ? "No matching events"
                        : "Your session starts here"}
                    </h3>
                    <p>
                      {query || logFilter !== "all"
                        ? "Try another search or event filter."
                        : "Connect to see authentication, key renewal, and recovery events."}
                    </p>
                  </div>
                )}
                <div ref={logEnd} />
              </div>
              <div className="log-footer">
                <span>{filteredLogs.length} events · Up to 500 retained</span>
                <label>
                  <input
                    type="checkbox"
                    checked={follow}
                    onChange={(event) => setFollow(event.target.checked)}
                  />
                  Follow latest
                </label>
              </div>
            </Card>
            <Card className="chat-card">
              <CardTitle
                icon={<Send size={18} />}
                title="Message your peers"
                subtitle="Sent through the authenticated tunnel."
              />
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  if (canSend) {
                    send({ type: "sendMessage", text: chat.trim() });
                    setChat("");
                  }
                }}
              >
                <label className="sr-only" htmlFor="chat">
                  Message to peers
                </label>
                <input
                  id="chat"
                  value={chat}
                  maxLength={512}
                  aria-invalid={chatBytes > 512}
                  aria-describedby="chat-hint"
                  disabled={!active}
                  placeholder={
                    active
                      ? "Write a message…"
                      : "Connect to send an encrypted message"
                  }
                  onChange={(event) => setChat(event.target.value)}
                />
                <button className="button primary" disabled={!canSend}>
                  <Send size={15} />
                  Send
                </button>
              </form>
              <p
                id="chat-hint"
                className={chatBytes > 512 ? "field-error" : "field-hint"}
              >
                {chatBytes > 512
                  ? "Message exceeds 512 UTF-8 bytes. Shorten it before sending."
                  : "Messages appear in Activity. Keep shared keys out of chat."}
              </p>
            </Card>
          </div>
        )}

        {page === "preferences" && (
          <div className="page-enter preferences-page">
            <Card>
              <CardTitle
                icon={<Sparkles size={18} />}
                title="Appearance"
                subtitle="Choose a comfortable view for your workspace."
              />
              <div
                className="theme-options"
                role="group"
                aria-label="Appearance"
              >
                {(
                  [
                    { id: "dark", label: "Dark", icon: <Moon /> },
                    { id: "light", label: "Light", icon: <Sun /> },
                    { id: "system", label: "System", icon: <Monitor /> },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    className={`theme-option ${theme === item.id ? "chosen" : ""}`}
                    aria-pressed={theme === item.id}
                    onClick={() => setTheme(item.id)}
                  >
                    <span className={`theme-preview ${item.id}`}>
                      <i />
                      <i />
                      <i />
                    </span>
                    <span>
                      {item.icon}
                      {item.label}
                      {theme === item.id && <Check size={14} />}
                    </span>
                  </button>
                ))}
              </div>
              <p className="field-hint">
                Motion follows your Windows accessibility preference. Appearance
                applies to this session.
              </p>
            </Card>
            <Card>
              <CardTitle
                icon={<ShieldCheck size={18} />}
                title="Connection protection"
                subtitle="Fixed security settings, without guesswork."
              />
              <dl className="protection-list">
                <div>
                  <dt>Transport security</dt>
                  <dd>TLS 1.3 / DTLS 1.3</dd>
                </div>
                <div>
                  <dt>Encryption</dt>
                  <dd>AES-256-GCM</dd>
                </div>
                <div>
                  <dt>Traffic-key lifecycle</dt>
                  <dd>Automatic renewal and updates</dd>
                </div>
                <div>
                  <dt>Access key</dt>
                  <dd>256-bit generated group key</dd>
                </div>
                <div>
                  <dt>Windows interface</dt>
                  <dd>TrueTunnel VPN Adapter</dd>
                </div>
              </dl>
              <div className="information-panel">
                <Shield size={18} />
                <p>
                  The tunnel protects IPv4 traffic routed through it. A kill
                  switch, DNS-leak protection, and IPv6 tunneling are not
                  included.
                </p>
              </div>
            </Card>
            <div className="about-row">
              <Mark />
              <div>
                <strong>TrueTunnel</strong>
                <p>3.1.0 · React + native Windows networking</p>
              </div>
            </div>
          </div>
        )}
      </main>

      <Dialog.Root open={help} onOpenChange={setHelp}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content
            className="dialog-content"
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              helpReturn.current?.focus();
            }}
          >
            <Dialog.Close
              className="dialog-close icon-button"
              aria-label="Close help"
            >
              <X size={19} />
            </Dialog.Close>
            <span className="dialog-icon">
              <ShieldCheck size={25} />
            </span>
            <Dialog.Title>
              One private network.
              <br />A simple connection.
            </Dialog.Title>
            <Dialog.Description>
              Start with a server, then connect your devices using its access
              key.
            </Dialog.Description>
            <ol className="help-steps">
              <li>
                <span>1</span>
                <div>
                  <strong>Start your server</strong>
                  <p>
                    Choose Server, select a physical network, generate an access
                    key, then start the server.
                  </p>
                </div>
              </li>
              <li>
                <span>2</span>
                <div>
                  <strong>Connect a client</strong>
                  <p>
                    Enter the reachable server address and matching port. Choose
                    the same transport, then paste its key.
                  </p>
                </div>
              </li>
              <li>
                <span>3</span>
                <div>
                  <strong>Keep the connection healthy</strong>
                  <p>
                    Use UDP when available. Optional recovery watches for
                    outages and reconnects with fresh session keys.
                  </p>
                </div>
              </li>
            </ol>
            <div className="help-note">
              <LockKeyhole size={16} />
              <p>
                Transfer your key privately. Everyone with the group key can
                join; generate a new one after exposure or a membership change.
              </p>
            </div>
            <Dialog.Close className="button primary full-width">
              Got it
              <ArrowRight size={15} />
            </Dialog.Close>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
      <Dialog.Root open={rotate} onOpenChange={setRotate}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content
            className="dialog-content small-dialog"
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              keyAction.current?.focus();
            }}
          >
            <Dialog.Close
              className="dialog-close icon-button"
              aria-label="Cancel regeneration"
            >
              <X size={19} />
            </Dialog.Close>
            <span className="dialog-icon">
              <KeyRound size={25} />
            </span>
            <Dialog.Title>Generate a new access key?</Dialog.Title>
            <Dialog.Description>
              Your current key will be erased from this app. Share the new key
              with every client before starting the server again.
            </Dialog.Description>
            <div className="dialog-actions">
              <Dialog.Close className="button secondary">
                Keep current key
              </Dialog.Close>
              <button
                className="button primary"
                onClick={() => {
                  send({ type: "generateKey" });
                  setRotate(false);
                }}
              >
                Generate new key
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
