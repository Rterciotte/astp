const ASTP_ORIGIN = "http://127.0.0.1:8765";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForTabComplete(tabId, timeoutMs = 30000) {
  const started = Date.now();
  for (;;) {
    const tab = await chrome.tabs.get(tabId);
    if (tab.status === "complete") return tab;
    if (Date.now() - started > timeoutMs) {
      throw new Error(`Timed out waiting for tab ${tabId}`);
    }
    await sleep(250);
  }
}

function capturePageInTab() {
  const text = document.body ? document.body.innerText : "";
  const title = document.title || "";
  const lower = text.toLowerCase();

  const links = Array.from(document.querySelectorAll("a[href]")).map((anchor) => {
    const container = anchor.closest("article,li,tr,section,div");
    const context = (container?.innerText || anchor.innerText || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 1000);
    return {
      text: (anchor.innerText || anchor.textContent || "")
        .replace(/\s+/g, " ")
        .trim(),
      href: anchor.href,
      context,
    };
  });

  const tables = Array.from(document.querySelectorAll("table")).map((table) =>
    Array.from(table.rows).map((row) =>
      Array.from(row.cells).map((cell) => (cell.innerText || "").trim())
    )
  );

  const signals = [];
  let operational_status_hint = null;
  let operational_status_evidence = null;
  const onlinePatterns = [
    "programa online",
    "programa está online",
    "programa esta online",
    "status: online",
  ];
  const offlinePatterns = [
    "programa offline",
    "programa está offline",
    "programa esta offline",
    "status: offline",
  ];

  const onlineHit = onlinePatterns.find((pattern) => lower.includes(pattern));
  const offlineHit = offlinePatterns.find((pattern) => lower.includes(pattern));

  if (offlineHit) {
    operational_status_hint = "offline";
    operational_status_evidence = offlineHit;
    signals.push({
      kind: "explicit_status",
      status: "offline",
      evidence: offlineHit,
      visible: true,
      enabled: null,
    });
  } else if (onlineHit) {
    operational_status_hint = "online";
    operational_status_evidence = onlineHit;
    signals.push({
      kind: "explicit_status",
      status: "online",
      evidence: onlineHit,
      visible: true,
      enabled: null,
    });
  }

  return {
    schema_version: "1",
    url: location.href,
    title,
    text,
    tables,
    links,
    operational_status_hint,
    operational_status_evidence,
    operational_signals: signals,
    captured_at: new Date().toISOString(),
  };
}

async function captureTab(tabId) {
  const result = await chrome.scripting.executeScript({
    target: { tabId },
    func: capturePageInTab,
  });
  if (!result?.length) throw new Error("No browser capture returned");
  return result[0].result;
}

async function postAstp(path, token, payload) {
  const response = await fetch(`${ASTP_ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-ASTP-Intake-Token": token,
    },
    body: JSON.stringify(payload),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      `${path} failed (${response.status}): ${body.error || "unknown error"}`
    );
  }
  return body;
}

async function setStatus(patch) {
  const current =
    (await chrome.storage.local.get("astpNightlyStatus")).astpNightlyStatus || {};
  await chrome.storage.local.set({
    astpNightlyStatus: {
      ...current,
      ...patch,
      updatedAt: new Date().toISOString(),
    },
  });
}

async function runSync({ token, tabId }) {
  await setStatus({
    running: true,
    phase: "discover",
    completed: 0,
    total: 0,
    error: null,
  });

  const originalTab = await chrome.tabs.get(tabId);
  const originalUrl = originalTab.url;
  if (!originalUrl?.startsWith("https://admin.bughunt.com.br/")) {
    throw new Error(
      "Open the authenticated BugHunt programs page before starting sync."
    );
  }

  const listingCapture = await captureTab(tabId);
  const discovery = await postAstp(
    "/v1/discover-programs",
    token,
    listingCapture
  );
  const candidates = discovery.candidates || [];
  await setStatus({
    phase: "details",
    total: candidates.length,
    completed: 0,
  });

  let completed = 0;
  for (const candidate of candidates) {
    await chrome.tabs.update(tabId, { url: candidate.detail_url });
    await waitForTabComplete(tabId);
    await sleep(600);

    const detailCapture = await captureTab(tabId);
    await postAstp("/v1/program-detail", token, {
      candidate,
      capture: detailCapture,
    });

    completed += 1;
    await setStatus({ completed, currentProgram: candidate.name });
  }

  if (originalUrl) {
    await chrome.tabs.update(tabId, { url: originalUrl });
    await waitForTabComplete(tabId).catch(() => null);
  }

  await setStatus({
    running: false,
    phase: "complete",
    completed,
    total: candidates.length,
    currentProgram: null,
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ASTP_START_SYNC") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        if (!tab?.id) throw new Error("No active browser tab");
        await runSync({ token: message.token, tabId: tab.id });
      } catch (error) {
        await setStatus({
          running: false,
          phase: "failed",
          error: String(error?.message || error),
        });
      }
    })();
    sendResponse({ accepted: true });
    return true;
  }

  if (message?.type === "ASTP_STATUS") {
    (async () => {
      const stored = await chrome.storage.local.get(["astpNightlyStatus"]);
      sendResponse(stored);
    })();
    return true;
  }
});
