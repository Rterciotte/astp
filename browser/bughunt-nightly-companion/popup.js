const token = document.getElementById("token");
const status = document.getElementById("status");
const start = document.getElementById("start");

async function refresh() {
  const response = await chrome.runtime.sendMessage({ type: "ASTP_STATUS" });
  const row = response?.astpNightlyStatus || {};
  status.textContent = JSON.stringify(row, null, 2);
  start.disabled = Boolean(row.running);
}

start.addEventListener("click", async () => {
  if (!token.value.trim()) {
    status.textContent = "Cole o intake token impresso pelo ASTP.";
    return;
  }
  await chrome.runtime.sendMessage({
    type: "ASTP_START_SYNC",
    token: token.value.trim(),
  });
  await refresh();
});

refresh();
setInterval(refresh, 1000);
