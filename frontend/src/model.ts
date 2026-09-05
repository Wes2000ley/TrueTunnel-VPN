export type Phase =
  | "idle"
  | "authorizing"
  | "connecting"
  | "connected"
  | "listening"
  | "reconnecting"
  | "stopping";
export type Config = {
  role: "client" | "server";
  transport: "udp" | "tcp";
  address: string;
  port: string;
  adapter: string;
  recovery: boolean;
};
export type Adapter = {
  id: string;
  name: string;
  description: string;
  ip: string;
};
export type LogEntry = {
  id: number;
  time: string;
  level: "info" | "success" | "warning" | "error";
  message: string;
};
export type Snapshot = {
  phase: Phase;
  adapters: Adapter[];
  keyReady: boolean;
  keyGenerated: boolean;
  logs: LogEntry[];
  error: string;
  uptime: number;
  retryAttempt: number;
  retryDelay: number;
  engineReady: boolean;
  clipboardSeconds: number;
};
export type Command =
  | {
      type:
        | "ready"
        | "refreshAdapters"
        | "generateKey"
        | "pasteKey"
        | "copyKey"
        | "clearKey"
        | "clearLogs"
        | "stop";
    }
  | { type: "start"; config: Config }
  | { type: "sendMessage"; text: string };

export const initialSnapshot: Snapshot = {
  phase: "idle",
  adapters: [],
  keyReady: false,
  keyGenerated: false,
  logs: [],
  error: "",
  uptime: 0,
  retryAttempt: 0,
  retryDelay: 0,
  engineReady: false,
  clipboardSeconds: 0,
};
export const initialConfig: Config = {
  role: "client",
  transport: "udp",
  address: "",
  port: "5555",
  adapter: "",
  recovery: false,
};

export function validateConfig(
  config: Config,
  snapshot: Snapshot,
): Partial<Record<keyof Config | "key", string>> {
  const errors: Partial<Record<keyof Config | "key", string>> = {};
  if (
    config.role === "client" &&
    !/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(
      config.address.trim(),
    )
  )
    errors.address =
      "Enter an IPv4 address or hostname, without a port or URL.";
  if (
    !/^\d{1,5}$/.test(config.port) ||
    Number(config.port) < 1 ||
    Number(config.port) > 65535
  )
    errors.port = "Use a port from 1 to 65535.";
  if (!snapshot.adapters.some((adapter) => adapter.id === config.adapter))
    errors.adapter = "Select an available network adapter.";
  if (!snapshot.keyReady)
    errors.key =
      config.role === "server"
        ? "Generate an access key before starting."
        : "Paste the server’s access key to continue.";
  else if (config.role === "server" && !snapshot.keyGenerated)
    errors.key = "Generate a new key for this server.";
  return errors;
}

export function formatDuration(seconds: number): string {
  return [
    Math.floor(seconds / 3600),
    Math.floor(seconds / 60) % 60,
    seconds % 60,
  ]
    .map((value) => Math.floor(value).toString().padStart(2, "0"))
    .join(":");
}
