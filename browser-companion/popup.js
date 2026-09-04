const statusEl = document.getElementById("status");

document.getElementById("capture").addEventListener("click", async () => {
  const token = document.getElementById("token").value.trim();
  if (!token) { statusEl.textContent = "Paste the one-time ASTP intake token."; return; }
  statusEl.textContent = "Capturing…";
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  const [{result}] = await chrome.scripting.executeScript({
    target: {tabId: tab.id},
    func: () => {
      const clean = (value) => String(value || "").trim();
      const tables = [...document.querySelectorAll("table")].map((table) =>
        [...table.rows].map((row) => [...row.cells].map((cell) => clean(cell.innerText)))
      );
      const links = [...document.querySelectorAll("a[href]")]
        .slice(0, 1000)
        .map((link) => ({text: clean(link.innerText), href: link.href}));
      return {
        schema_version: "1",
        url: location.href,
        title: document.title,
        text: clean(document.body?.innerText),
        tables,
        links,
        captured_at: new Date().toISOString()
      };
    }
  });
  try {
    const response = await fetch("http://127.0.0.1:8765/v1/browser-capture", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-ASTP-Intake-Token": token},
      body: JSON.stringify(result)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.json();
    statusEl.textContent = `Imported. SHA-256: ${body.sha256.slice(0, 12)}…`;
  } catch (error) {
    statusEl.textContent = `ASTP intake unavailable: ${error.message}`;
  }
});
