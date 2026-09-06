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

      const isVisible = (node) => {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
          return false;
        }
        const rect = node.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      };
      const isEnabled = (node) => {
        if (!node) return false;
        if (node.disabled === true) return false;
        if (String(node.getAttribute("aria-disabled") || "").toLowerCase() === "true") return false;
        if (String(node.className || "").toLowerCase().split(/\s+/).includes("disabled")) return false;
        const style = window.getComputedStyle(node);
        if (style.pointerEvents === "none") return false;
        return true;
      };
      const describeNode = (node) => {
        const identity = [
          node.tagName.toLowerCase(),
          node.id ? `#${node.id}` : "",
          node.className && typeof node.className === "string"
            ? `.${node.className.trim().replace(/\s+/g, ".")}`
            : ""
        ].join("");
        const text = cleanValue(node.innerText || node.textContent).replace(/\s+/g, " ").slice(0, 240);
        return `${identity}: ${text}`;
      };

      const operationalSignals = [];
      const statusCandidates = [];
      const statusSelectors = [
        "[data-status]",
        "[class*='status' i]",
        "[class*='badge' i]",
        "[aria-label*='status' i]"
      ].join(",");
      for (const node of document.querySelectorAll(statusSelectors)) {
        if (!isVisible(node)) continue;
        const text = cleanValue(node.innerText || node.textContent).replace(/\s+/g, " ");
        if (!text || text.length > 120) continue;
        const lowered = text.toLowerCase();
        let status = null;
        if (["online", "programa online", "program online"].includes(lowered)) {
          status = "online";
        } else if (["offline", "programa offline", "program offline"].includes(lowered)) {
          status = "offline";
        }
        if (status) {
          const evidence = describeNode(node);
          statusCandidates.push({status, evidence});
          operationalSignals.push({
            kind: "explicit_status",
            status,
            evidence,
            visible: true,
            enabled: null
          });
        }
      }
      for (const row of document.querySelectorAll("tr")) {
        const cells = [...row.cells].map((cell) => cleanValue(cell.innerText));
        if (cells.length >= 2 && /^status$/i.test(cells[0])) {
          const value = cells[1].toLowerCase();
          if (value === "online" || value === "offline") {
            const evidence = `table row: ${cells.slice(0, 2).join(" | ")}`;
            statusCandidates.push({status: value, evidence});
            operationalSignals.push({
              kind: "explicit_status",
              status: value,
              evidence,
              visible: true,
              enabled: null
            });
          }
        }
      }

      // Short, visible page-level banners are safe to interpret; long policy prose is not.
      for (const node of document.querySelectorAll("[role='alert'], .alert, [class*='banner' i], [class*='notice' i]")) {
        if (!isVisible(node)) continue;
        const text = cleanValue(node.innerText || node.textContent).replace(/\s+/g, " ");
        if (!text || text.length > 240) continue;
        const lowered = text.toLowerCase();
        if (/\b(programa|program)\b.*\b(offline|pausado|pausada|suspenso|suspensa|encerrado|encerrada)\b/.test(lowered)) {
          operationalSignals.push({
            kind: "blocking_banner",
            status: "offline",
            evidence: describeNode(node),
            visible: true,
            enabled: null
          });
        }
      }

      // BugHunt-specific operational affordance. This is captured as evidence; ASTP decides
      // whether the combination is sufficient for an attestation.
      const host = location.hostname.toLowerCase();
      const isBugHuntProgramDetail = host.endsWith("bughunt.com.br") && /\/program\/detail/i.test(location.pathname);
      if (isBugHuntProgramDetail) {
        const controls = [...document.querySelectorAll("a, button, [role='button']")];
        for (const node of controls) {
          const text = cleanValue(node.innerText || node.textContent).replace(/\s+/g, " ");
          if (!/^(submeter relat[oó]rio|submit report)$/i.test(text)) continue;
          operationalSignals.push({
            kind: "submission_control",
            status: null,
            evidence: describeNode(node),
            visible: isVisible(node),
            enabled: isVisible(node) && isEnabled(node)
          });
        }
        const bodyText = cleanValue(document.body?.innerText);
        const publishedMatch = bodyText.match(/Publicado h[áa]\s+[^\n]{1,80}/i);
        if (publishedMatch) {
          operationalSignals.push({
            kind: "published_marker",
            status: null,
            evidence: publishedMatch[0].replace(/\s+/g, " ").slice(0, 160),
            visible: true,
            enabled: null
          });
        }
      }

      const explicitOffline = operationalSignals.find((item) => item.status === "offline");
      const uniqueStatuses = [...new Set(statusCandidates.map((item) => item.status))];
      const operationalStatusHint = explicitOffline
        ? "offline"
        : (uniqueStatuses.length === 1 ? uniqueStatuses[0] : null);
      const operationalStatusEvidence = operationalStatusHint
        ? operationalSignals.find((item) => item.status === operationalStatusHint)?.evidence || null
        : null;

      return {
        schema_version: "1",
        url: location.href,
        title: document.title,
        text: cleanValue(document.body?.innerText),
        tables,
        links,
        operational_status_hint: operationalStatusHint,
        operational_status_evidence: operationalStatusEvidence,
        operational_signals: operationalSignals,
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
