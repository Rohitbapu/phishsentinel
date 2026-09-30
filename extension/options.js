const ids = ["server", "key", "reporter"];
chrome.storage.sync.get(PS_DEFAULTS, (s) => ids.forEach((i) => (document.getElementById(i).value = s[i])));
document.getElementById("save").onclick = () => {
  const v = {}; ids.forEach((i) => (v[i] = document.getElementById(i).value.trim()));
  chrome.storage.sync.set(v, () => (document.getElementById("ok").textContent = "Saved"));
};
