import { Component, type ReactNode } from "react";
import { hasNativeHost, send, subscribe } from "./bridge";

export class ErrorBoundary extends Component<
  { children: ReactNode },
  { failed: boolean; canReload: boolean }
> {
  state = { failed: false, canReload: false };
  private unsubscribe?: () => void;

  static getDerivedStateFromError() {
    return { failed: true, canReload: false };
  }

  componentDidCatch() {
    // Request normal native teardown, and wait for the actual idle state before
    // permitting a reload. Never display exception data or reconnect implicitly.
    send({ type: "stop" });
    if (hasNativeHost()) {
      this.unsubscribe = subscribe((snapshot) =>
        this.setState({ canReload: snapshot.phase === "idle" }),
      );
    } else {
      this.setState({ canReload: true });
    }
  }

  componentWillUnmount() {
    this.unsubscribe?.();
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="desktop-error card" role="alert">
        <span className="eyebrow">TRUETUNNEL</span>
        <h1>The interface needs a fresh start.</h1>
        <p>
          {this.state.canReload
            ? "The tunnel is stopped. Reload the interface to try again."
            : "A safe disconnect has been requested. Wait for cleanup, or close this window and reopen TrueTunnel."}
        </p>
        <button
          className="button primary"
          disabled={!this.state.canReload}
          onClick={() => window.location.reload()}
        >
          Reload interface
        </button>
      </main>
    );
  }
}
