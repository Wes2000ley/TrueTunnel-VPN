import type { Command, Snapshot } from "./model";

declare global {
  interface Window {
    chrome?: {
      webview?: {
        postMessage: (
          message: Command | { type: "smokeResult"; ok: boolean },
        ) => void;
        addEventListener: (
          type: "message",
          callback: (event: MessageEvent<Snapshot>) => void,
        ) => void;
        removeEventListener: (
          type: "message",
          callback: (event: MessageEvent<Snapshot>) => void,
        ) => void;
      };
    };
  }
}

export const hasNativeHost = () => Boolean(window.chrome?.webview);
export function send(command: Command): void {
  window.chrome?.webview?.postMessage(command);
}
export function subscribe(listener: (snapshot: Snapshot) => void): () => void {
  const handler = (event: MessageEvent<Snapshot>) => listener(event.data);
  window.chrome?.webview?.addEventListener("message", handler);
  send({ type: "ready" });
  return () => window.chrome?.webview?.removeEventListener("message", handler);
}
