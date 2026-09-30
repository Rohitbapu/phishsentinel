importScripts("config.js");

async function cfg() {
  const s = await chrome.storage.sync.get(PS_DEFAULTS);
  return { ...PS_DEFAULTS, ...s };
}
async function call(path, body) {
  const c = await cfg();
  const r = await fetch(c.server.replace(/\/$/, "") + "/api/v1" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(c.key ? { "x-api-key": c.key } : {}) },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error("server said " + r.status);
  return r.json();
}
async function getReport(id) {
  const c = await cfg();
  const r = await fetch(c.server.replace(/\/$/, "") + "/api/v1/reports/" + id, { headers: c.key ? { "x-api-key": c.key } : {} });
  if (!r.ok) throw new Error("server said " + r.status);
  return r.json();
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  (async () => {
    const c = await cfg();
    if (msg.type === "report") {
      const res = await call("/reports", { reporter: c.reporter, sender: msg.sender, subject: msg.subject, text: msg.text, links: msg.links });
      // poll briefly so the reporter gets feedback (the pipeline is asynchronous)
      for (let i = 0; i < 12; i++) {
        await new Promise((r) => setTimeout(r, 500));
        const rep = await getReport(res.report_id);
        if (rep.verdict) return reply({ ok: true, report: rep });
      }
      return reply({ ok: true, report: { id: res.report_id, verdict: null } });
    }
    if (msg.type === "scan") return reply({ ok: true, scan: await call("/scan", { url: msg.url }) });
    reply({ ok: false, error: "unknown message" });
  })().catch((e) => reply({ ok: false, error: String(e) }));
  return true; // async reply
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "ps-scan", title: "PhishSentinel: scan this link", contexts: ["link"] });
});
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "ps-scan" || !info.linkUrl) return;
  try {
    const s = await call("/scan", { url: info.linkUrl });
    chrome.tabs.sendMessage(tab.id, { type: "toast", text: `${s.threat_level} (${s.risk_score}/100): ${s.short_explanation}`, level: s.threat_level });
  } catch (e) {
    chrome.tabs.sendMessage(tab.id, { type: "toast", text: "Scan failed: " + e, level: "WARNING" });
  }
});
