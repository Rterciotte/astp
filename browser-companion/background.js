const ENDPOINT = "http://127.0.0.1:8765";
const EXPECTED_PROTOCOL_VERSION = "2";

function clean(value) {
  return String(value || "").trim();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function setState(message, extra = {}) {
  const state = {
    message,
    updated_at: new Date().toISOString(),
    ...extra
  };
  await chrome.storage.session.set({astpState: state}).catch(() => {});
  chrome.runtime.sendMessage({type: "astp-progress", state}).catch(() => {});
}

async function captureTab(tabId) {
  const [{result}] = await chrome.scripting.executeScript({
    target: {tabId},
    func: () => {
      const cleanValue = (value) => String(value || "").trim();
      const tables = [...document.querySelectorAll("table")].map((table) =>
        [...table.rows].map((row) => [...row.cells].map((cell) => cleanValue(cell.innerText)))
      );
      const links = [...document.querySelectorAll("a[href]")]
        .slice(0, 2000)
        .map((link) => {
          const container = link.closest("article, li, tr, .card, [class*='card'], [class*='program']");
          return {
            text: cleanValue(link.innerText),
            href: link.href,
            context: cleanValue(container?.innerText).slice(0, 1200)
          };
        });
      return {
        schema_version: "1",
        url: location.href,
        title: document.title,
        text: cleanValue(document.body?.innerText),
        tables,
        links,
        captured_at: new Date().toISOString()
      };
    }
  });
  return result;
}

async function astpPost(path, token, payload = {}) {
  let response;
  try {
    response = await fetch(`${ENDPOINT}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ASTP-Intake-Token": token
      },
      body: JSON.stringify(payload)
    });
  } catch (error) {
    throw new Error(`Cannot reach ASTP at ${ENDPOINT}: ${clean(error.message)}`);
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `ASTP HTTP ${response.status}`);
  }
  return body;
}

async function checkHealth(token) {
  const result = await astpPost("/v1/health", token, {});
  if (result.protocol_version !== EXPECTED_PROTOCOL_VERSION) {
    throw new Error(
      `Protocol mismatch: browser=${EXPECTED_PROTOCOL_VERSION}, ASTP=${result.protocol_version || "unknown"}`
    );
  }
  return result;
}

function waitForComplete(tabId, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let timer;
    const listener = (updatedId, changeInfo) => {
      if (updatedId === tabId && changeInfo.status === "complete") {
        chrome.tabs.onUpdated.removeListener(listener);
        clearTimeout(timer);
        resolve();
      }
    };
    chrome.tabs.onUpdated.addListener(listener);
    timer = setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(listener);
      reject(new Error("Timed out waiting for authenticated program page to load."));
    }, timeoutMs);
  });
}

async function waitForDomSettled(tabId) {
  let previousLength = -1;
  let stableChecks = 0;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await sleep(500);
    const [{result}] = await chrome.scripting.executeScript({
      target: {tabId},
      func: () => String(document.body?.innerText || "").length
    });
    if (result === previousLength && result > 0) {
      stableChecks += 1;
      if (stableChecks >= 2) return;
    } else {
      stableChecks = 0;
      previousLength = result;
    }
  }
}

async function importCurrent(token) {
  await setState("Checking ASTP connection…", {phase: "health"});
  await checkHealth(token);
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab?.id) throw new Error("No active browser tab found.");
  await setState("Capturing current page…", {phase: "capture"});
  const capture = await captureTab(tab.id);
  const result = await astpPost("/v1/browser-capture", token, capture);
  await setState("Current page imported into ASTP.", {phase: "complete"});
  return result;
}

async function discoverAndSync(token) {
  await setState("Checking ASTP connection…", {phase: "health"});
  await checkHealth(token);
  const [sourceTab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!sourceTab?.id) throw new Error("No active browser tab found.");

  await setState("Reading authenticated program listing…", {phase: "discovery"});
  const listing = await captureTab(sourceTab.id);
  const discovery = await astpPost("/v1/discover-programs", token, listing);
  const candidates = discovery.candidates || [];
  await setState(`Discovered ${candidates.length} program candidates.`, {
    phase: "discovery",
    discovered: candidates.length
  });
  if (!candidates.length) {
    return {discovery, synced: [], failed: []};
  }

  const synced = [];
  const failed = [];
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    await setState(`Syncing ${index + 1}/${candidates.length}: ${candidate.name}`, {
      phase: "sync",
      current: index + 1,
      total: candidates.length,
      program: candidate.name
    });
    let tab;
    try {
      tab = await chrome.tabs.create({url: candidate.detail_url, active: false});
      if (!tab.id) throw new Error("Browser did not create the program tab.");
      if (tab.status !== "complete") await waitForComplete(tab.id);
      await waitForDomSettled(tab.id);
      const capture = await captureTab(tab.id);
      const result = await astpPost("/v1/program-detail", token, {candidate, capture});
      synced.push({candidate, result});
    } catch (error) {
      failed.push({candidate, error: clean(error.message)});
    } finally {
      if (tab?.id) await chrome.tabs.remove(tab.id).catch(() => {});
    }
  }
  await setState(`Synchronization complete: ${synced.length} synced, ${failed.length} failed.`, {
    phase: "complete",
    synced: synced.length,
    failed: failed.length
  });
  return {discovery, synced, failed};
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !["astp-health", "astp-import-current", "astp-discover-sync"].includes(message.type)) {
    return false;
  }
  let task;
  if (message.type === "astp-health") {
    task = checkHealth(message.token);
  } else if (message.type === "astp-discover-sync") {
    task = discoverAndSync(message.token);
  } else {
    task = importCurrent(message.token);
  }
  task.then((result) => sendResponse({ok: true, result}))
    .catch(async (error) => {
      const messageText = clean(error.message);
      await setState(`ASTP intake failed: ${messageText}`, {phase: "error"});
      sendResponse({ok: false, error: messageText});
    });
  return true;
});
