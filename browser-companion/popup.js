const statusEl = document.getElementById("status");
const tokenEl = document.getElementById("token");

async function loadSession() {
  const values = await chrome.storage.session.get(["astpToken", "astpState"]);
  if (values.astpToken) tokenEl.value = values.astpToken;
  if (values.astpState?.message) statusEl.textContent = values.astpState.message;
}

async function token() {
  const value = tokenEl.value.trim();
  if (!value) throw new Error("Paste the ASTP intake token first.");
  await chrome.storage.session.set({astpToken: value});
  return value;
}

async function currentOriginPattern() {
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab?.url) throw new Error("No active page URL available.");
  const url = new URL(tab.url);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Open the authenticated bug bounty platform page first.");
  }
  return `${url.origin}/*`;
}

async function hasCurrentOriginAccess() {
  const originPattern = await currentOriginPattern();
  return chrome.permissions.contains({origins: [originPattern]});
}

async function grantCurrentOriginAccess() {
  const originPattern = await currentOriginPattern();
  const alreadyGranted = await chrome.permissions.contains({origins: [originPattern]});
  if (alreadyGranted) {
    statusEl.textContent = `Platform access already granted: ${originPattern}`;
    return;
  }
  statusEl.textContent = `Requesting access to ${originPattern}…`;
  const granted = await chrome.permissions.request({origins: [originPattern]});
  if (!granted) throw new Error("Platform access was not granted.");
  // Chrome may close this popup while showing the permission prompt. The grant persists.
  await chrome.storage.session.set({
    astpState: {
      message: `Platform access granted: ${originPattern}. Reopen ASTP and start discovery.`,
      phase: "permission"
    }
  });
}

async function send(type) {
  const value = await token();
  return chrome.runtime.sendMessage({type, token: value});
}

async function health() {
  statusEl.textContent = "Checking ASTP connection…";
  const response = await send("astp-health");
  if (!response?.ok) throw new Error(response?.error || "unknown ASTP health error");
  statusEl.textContent = [
    "ASTP server reachable ✓",
    "Token accepted ✓",
    `Protocol v${response.result.protocol_version} ✓`,
    `Platform: ${response.result.platform}`
  ].join("\n");
}

async function run(type) {
  if (type === "astp-discover-sync" && !(await hasCurrentOriginAccess())) {
    throw new Error("Platform access is not granted. Click 'Grant access to current platform' first.");
  }
  statusEl.textContent = type === "astp-discover-sync"
    ? "Starting authenticated program discovery…"
    : "Capturing current page…";
  const response = await send(type);
  if (!response?.ok) throw new Error(response?.error || "unknown ASTP intake error");
  if (type === "astp-discover-sync") {
    const result = response.result;
    statusEl.textContent = [
      `Discovered: ${result.discovery.candidates.length}`,
      `Synced: ${result.synced.length}`,
      `Failed: ${result.failed.length}`,
      ...(result.discovery.warnings || [])
    ].join("\n");
  } else {
    statusEl.textContent = "Current page imported into ASTP.";
  }
}

async function guarded(fn) {
  try {
    await fn();
  } catch (error) {
    statusEl.textContent = `ASTP intake failed: ${String(error?.message || error)}`;
  }
}

document.getElementById("health").addEventListener("click", () => guarded(health));
document.getElementById("grant").addEventListener("click", () => guarded(grantCurrentOriginAccess));
document.getElementById("discover").addEventListener("click", () => guarded(() => run("astp-discover-sync")));
document.getElementById("capture").addEventListener("click", () => guarded(() => run("astp-import-current")));

tokenEl.addEventListener("change", () => {
  chrome.storage.session.set({astpToken: tokenEl.value.trim()}).catch(() => {});
});

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "astp-progress" && message.state?.message) {
    statusEl.textContent = message.state.message;
  }
});

loadSession().catch(() => {});
