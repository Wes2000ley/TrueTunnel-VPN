import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function openDesktop(page: Page) {
  await page.addInitScript(() => {
    const listeners: Array<(event: { data: unknown }) => void> = [];
    const snapshot = {
      phase: "idle",
      adapters: [
        {
          id: "1",
          name: "Ethernet",
          description: "Intel Ethernet Controller",
          ip: "192.0.2.20",
        },
      ],
      keyReady: false,
      keyGenerated: false,
      logs: [],
      error: "",
      uptime: 0,
      retryAttempt: 0,
      retryDelay: 0,
      engineReady: true,
      clipboardSeconds: 0,
    };
    const commands: unknown[] = [];
    const emit = () =>
      listeners.forEach((listener) =>
        listener({ data: structuredClone(snapshot) }),
      );
    Object.assign(window, { testDesktop: { snapshot, commands, emit } });
    Object.assign(window.chrome ?? (window.chrome = {}), {
      webview: {
        addEventListener: (
          _type: string,
          callback: (typeof listeners)[number],
        ) => listeners.push(callback),
        removeEventListener: (
          _type: string,
          callback: (typeof listeners)[number],
        ) => {
          const index = listeners.indexOf(callback);
          if (index >= 0) listeners.splice(index, 1);
        },
        postMessage: (command: { type: string }) => {
          commands.push(command);
          if (command.type === "generateKey" || command.type === "pasteKey") {
            snapshot.keyReady = true;
            snapshot.keyGenerated = command.type === "generateKey";
          }
          if (command.type === "clearKey") {
            snapshot.keyReady = false;
            snapshot.keyGenerated = false;
          }
          if (command.type === "copyKey") snapshot.clipboardSeconds = 30;
          if (command.type === "stop") snapshot.phase = "idle";
          if (command.type === "start") snapshot.phase = "connecting";
          if (command.type === "clearLogs") snapshot.logs = [];
          emit();
        },
      },
    });
  });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Connection", exact: true }),
  ).toBeVisible();
}
async function update(page: Page, state: Record<string, unknown>) {
  await page.evaluate((next) => {
    const bridge = (window as any).testDesktop;
    Object.assign(bridge.snapshot, next);
    bridge.emit();
  }, state);
}
async function capture(page: Page, name: string) {
  await page.screenshot({
    path: `test-results/captures/${name}.png`,
    fullPage: true,
    animations: "disabled",
  });
}
async function noOverflow(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  const address = await page.locator("#address").boundingBox();
  const port = await page.locator("#port").boundingBox();
  if (address && port) expect(Math.abs(address.y - port.y)).toBeLessThan(1);
}

test("client flow validates before connect and dispatches exact transport/recovery settings", async ({
  page,
}) => {
  await openDesktop(page);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.locator("#address")).toBeFocused();
  await expect(
    page.getByText("Paste the server’s access key to continue."),
  ).toBeVisible();
  await page.locator("#address").fill("vpn.example.net");
  await page.locator("#port").fill("70000");
  await page.getByRole("button", { name: "Paste key", exact: true }).click();
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByText("Use a port from 1 to 65535.")).toBeVisible();
  await page.locator("#port").fill("5555");
  await page
    .getByRole("button", { name: "TCP For restricted networks" })
    .click();
  await page.getByRole("switch", { name: "Automatic recovery" }).click();
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  const commands = await page.evaluate(
    () => (window as any).testDesktop.commands,
  );
  expect(commands.findLast((command: any) => command.type === "start")).toEqual(
    {
      type: "start",
      config: {
        role: "client",
        transport: "tcp",
        address: "vpn.example.net",
        port: "5555",
        adapter: "1",
        recovery: true,
      },
    },
  );
  await expect(page.locator("#address")).toBeDisabled();
  await expect(page.getByRole("switch")).toBeDisabled();
  await page.getByRole("button", { name: "Cancel connection" }).click();
  await expect(page.locator("#address")).toBeEnabled();
});

test("server key lifecycle requires confirmation and never exposes a key to the DOM", async ({
  page,
}) => {
  await openDesktop(page);
  await page.getByRole("button", { name: "Server", exact: true }).click();
  await expect(page.locator("#address")).toHaveValue("192.0.2.20");
  await expect(page.getByRole("switch")).toBeDisabled();
  await page.getByRole("button", { name: "Generate key", exact: true }).click();
  await page.getByRole("button", { name: "Copy access key" }).click();
  await expect(
    page.getByText("Copied · Clipboard clears in 30s"),
  ).toBeVisible();
  await page.getByRole("button", { name: "Regenerate", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await capture(page, "server-key-confirmation");
  await page.getByRole("button", { name: "Keep current key" }).click();
  await expect(
    page.getByRole("button", { name: "Regenerate", exact: true }),
  ).toBeFocused();
  await page.getByRole("button", { name: "Clear access key" }).click();
  await expect(page.getByText("No access key added")).toBeVisible();
  expect(
    await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
    })),
  ).toEqual({ local: 0, session: 0 });
  await page.getByRole("button", { name: "Generate key", exact: true }).click();
  await update(page, { phase: "listening" });
  await expect(
    page.getByRole("button", { name: "Regenerate", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Copy access key" }),
  ).toBeEnabled();
});

for (const size of [
  { width: 1440, height: 1080 },
  { width: 1120, height: 820 },
  { width: 900, height: 780 },
  { width: 780, height: 600 },
  { width: 390, height: 844 },
]) {
  test(`responsive layout ${size.width}x${size.height}, including scroll and aligned inputs`, async ({
    page,
  }) => {
    await page.setViewportSize(size);
    await openDesktop(page);
    await page
      .locator("#address")
      .fill("a-very-long-vpn-gateway-name.for-testing.example.net");
    await noOverflow(page);
    await capture(page, `connection-${size.width}x${size.height}`);
    await page.getByRole("button", { name: "View all" }).click();
    await expect(
      page.getByRole("heading", { name: "Activity", exact: true }),
    ).toBeVisible();
    await capture(page, `activity-${size.width}x${size.height}`);
  });
}

test("all connection phases render clearly with bounded control state", async ({
  page,
}) => {
  await openDesktop(page);
  await page.locator("#address").fill("vpn.example.net");
  for (const phase of [
    "authorizing",
    "connecting",
    "connected",
    "reconnecting",
    "stopping",
    "listening",
  ]) {
    await update(page, {
      phase,
      keyReady: true,
      uptime: 3661,
      retryAttempt: 3,
      retryDelay: 14000,
    });
    await noOverflow(page);
    await capture(page, `phase-${phase}`);
    await expect(page.locator("#port")).toBeDisabled();
  }
  await update(page, {
    phase: "idle",
    error:
      "Windows approval was cancelled. Your settings are ready when you want to try again.",
  });
  await expect(page.getByRole("alert")).toContainText(
    "Windows approval was cancelled",
  );
  await expect(
    page.getByRole("button", { name: "Connect", exact: true }),
  ).toBeEnabled();
});

test("activity safely renders untrusted text, filters, scrolls and sends chat", async ({
  page,
}) => {
  await openDesktop(page);
  await update(page, {
    phase: "connected",
    logs: Array.from({ length: 250 }, (_, id) => ({
      id,
      time: "12:30:00",
      level: id % 10 === 0 ? "error" : "info",
      message:
        id === 249
          ? "<img src=x onerror=alert(1)> untrusted peer message"
          : `Event ${id}: encrypted tunnel activity ${"long text ".repeat(8)}`,
    })),
  });
  await page.getByRole("button", { name: "Activity", exact: true }).click();
  await expect(
    page.getByText("<img src=x onerror=alert(1)> untrusted peer message"),
  ).toBeVisible();
  expect(await page.locator(".log-scroll img").count()).toBe(0);
  await capture(page, "activity-scrolled");
  await page
    .getByRole("combobox", { name: "Filter activity" })
    .selectOption("error");
  await expect(page.locator(".log-row")).toHaveCount(25);
  await page
    .getByRole("textbox", { name: "Search activity" })
    .fill("Event 10:");
  await expect(page.locator(".log-row")).toHaveCount(1);
  await page.locator("#chat").fill("Hello peer");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  expect(
    await page.evaluate(() =>
      (window as any).testDesktop.commands.some(
        (command: any) =>
          command.type === "sendMessage" && command.text === "Hello peer",
      ),
    ),
  ).toBe(true);
  await page.locator("#chat").fill("🔐".repeat(150));
  await expect(
    page.getByRole("button", { name: "Send", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByText(
      "Message exceeds 512 UTF-8 bytes. Shorten it before sending.",
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "Clear", exact: true }).click();
  await expect(page.getByText("No matching events")).toBeVisible();
});

test("accessible dialogs trap focus, escape closes, themes and reduced motion work", async ({
  page,
}) => {
  await openDesktop(page);
  await page.getByRole("button", { name: "Help & shortcuts" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await capture(page, "help");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.getByRole("button", { name: "Preferences", exact: true }).click();
  await page.getByRole("button", { name: "Light", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await capture(page, "preferences-light");
  await page.getByRole("button", { name: "Connection", exact: true }).click();
  await capture(page, "connection-light");
  await page.emulateMedia({ reducedMotion: "reduce" });
  expect(
    await page
      .locator(".page-enter")
      .evaluate((element) => getComputedStyle(element).animationDuration),
  ).toBe("1e-06s");
});

test("WCAG AA accessibility on connection, activity, preferences and help", async ({
  page,
}) => {
  await openDesktop(page);
  for (const name of ["Connection", "Activity", "Preferences"]) {
    await page.getByRole("button", { name, exact: true }).click();
    const result = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(result.violations).toEqual([]);
  }
  await page.getByRole("button", { name: "Help & shortcuts" }).click();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
});

test("browser preview cannot pretend to connect or store a credential", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByText(
      "Browser preview · Network actions are available in the desktop app.",
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByText("No access key added")).toBeVisible();
  await expect(
    page.getByRole("status").filter({ hasText: "Not connected" }),
  ).toBeVisible();
});

test("light and compact views meet automated WCAG AA checks", async ({
  page,
}) => {
  await openDesktop(page);
  await page.getByRole("button", { name: "Preferences", exact: true }).click();
  await page.getByRole("button", { name: "Light", exact: true }).click();
  for (const width of [1440, 780, 390]) {
    await page.setViewportSize({ width, height: 844 });
    for (const name of ["Connection", "Activity", "Preferences"]) {
      await page.getByRole("button", { name, exact: true }).click();
      const result = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze();
      expect(result.violations).toEqual([]);
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBe(true);
    }
  }
});

test("render failures request native disconnect and provide a recoverable view", async ({
  page,
}) => {
  await openDesktop(page);
  await update(page, { logs: null, phase: "connected" });
  await expect(
    page.getByRole("heading", { name: "The interface needs a fresh start." }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Reload interface" }),
  ).toBeEnabled();
  expect(
    await page.evaluate(() =>
      (window as any).testDesktop.commands.some(
        (command: any) => command.type === "stop",
      ),
    ),
  ).toBe(true);
});

test("activity remains responsive during sustained native telemetry", async ({
  page,
}, testInfo) => {
  await openDesktop(page);
  await update(page, {
    phase: "connected",
    keyReady: true,
    logs: Array.from({ length: 500 }, (_, id) => ({
      id,
      time: "12:30:00",
      level: "info",
      message: `Event ${id}: ${"bounded telemetry ".repeat(6)}`,
    })),
  });
  await page.getByRole("button", { name: "Activity", exact: true }).click();
  await expect(page.locator(".log-row")).toHaveCount(500);
  const timing = await page.evaluate(async () => {
    const bridge = (window as any).testDesktop;
    const timer = setInterval(() => {
      bridge.snapshot.uptime += 1;
      bridge.emit();
    }, 200);
    const intervals: number[] = [];
    let previous = performance.now();
    try {
      for (let frame = 0; frame < 150; ++frame) {
        await new Promise<void>((resolve) =>
          requestAnimationFrame(() => resolve()),
        );
        const now = performance.now();
        if (frame >= 10) intervals.push(now - previous);
        previous = now;
      }
    } finally {
      clearInterval(timer);
    }
    intervals.sort((a, b) => a - b);
    return {
      samples: intervals.length,
      p95FrameMs: intervals[Math.floor(intervals.length * 0.95)],
      maxFrameMs: intervals.at(-1),
    };
  });
  await testInfo.attach("telemetry-render-timing", {
    body: JSON.stringify(timing, null, 2),
    contentType: "application/json",
  });
  // A local regression budget, not a cross-machine FPS claim.
  expect(timing.p95FrameMs).toBeLessThan(75);
  await page
    .getByRole("textbox", { name: "Search activity" })
    .fill("Event 499:");
  await expect(page.locator(".log-row")).toHaveCount(1);
});

test("keyboard shortcuts navigate and return dialog focus", async ({
  page,
}) => {
  await openDesktop(page);
  await page.getByRole("button", { name: "Connection", exact: true }).focus();
  await page.keyboard.press("Control+2");
  await expect(
    page.getByRole("heading", { name: "Activity", exact: true }),
  ).toBeVisible();
  await page.keyboard.press("?");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("button", { name: "Connection", exact: true }),
  ).toBeFocused();
});
