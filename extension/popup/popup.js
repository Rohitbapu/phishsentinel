const API_URL = "http://127.0.0.1:8000/api/v1";

document.getElementById('scanBtn').addEventListener('click', async () => {
    const text = document.getElementById('manualText').value;
    const fileInput = document.getElementById('qrUpload');
    const statusEl = document.getElementById('status');
    
    if (!text && fileInput.files.length === 0) {
        statusEl.textContent = "Error: Enter text or upload a QR image.";
        statusEl.style.color = "#ef4444";
        return;
    }

    statusEl.textContent = "Transmitting to SOC...";
    statusEl.style.color = "#fbbf24";

    let base64Image = null;
    if (fileInput.files.length > 0) {
        base64Image = await getBase64(fileInput.files[0]);
    }

    const payload = {
        reporter: "employee@corp.test",
        text: text || "",
        qr_image: base64Image
    };

    sendToBackend(payload, statusEl);
});

document.getElementById('pageScanBtn').addEventListener('click', () => {
    const statusEl = document.getElementById('status');
    statusEl.textContent = "Scraping page context...";
    statusEl.style.color = "#fbbf24";

    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        chrome.tabs.sendMessage(tabs[0].id, {action: "scrape_page"}, function(response) {
            if (chrome.runtime.lastError || !response) {
                statusEl.textContent = "Error: Cannot scrape this page.";
                statusEl.style.color = "#ef4444";
                return;
            }
            sendToBackend({
                reporter: "employee@corp.test",
                text: response.text,
                sender: response.sender,
                subject: response.subject
            }, statusEl);
        });
    });
});

function getBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    });
}

function sendToBackend(payload, statusEl) {
    fetch(`${API_URL}/live_scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(res => {
        if (!res.ok) throw new Error("Server rejected request");
        return res.json();
    })
    .then(data => {
        if (data.is_threat) {
            statusEl.innerHTML = `
                <div style="color: #ef4444; margin-bottom: 5px; font-weight: bold;">
                    ⚠️ Threat Detected! Score: ${(data.threat_score * 100).toFixed(1)}%
                </div>
                <div style="color: #d1d5db; font-size: 11px; background: #1f2937; padding: 8px; border-radius: 4px; text-align: left; line-height: 1.4;">
                    <strong>AI Reasoning:</strong> ${data.reasoning}
                </div>
            `;
            
            // Pass the AI's flagged links to the webpage so it highlights the correct ones
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                if (tabs[0]) {
                    chrome.tabs.sendMessage(tabs[0].id, {
                        action: "show_threat_flag",
                        score: data.threat_score,
                        reasoning: data.reasoning,
                        flagged_links: data.flagged_links || [] // <-- This was missing!
                    }).catch(err => console.log("Page blocked banner injection."));
                }
            });
        } else {
            statusEl.textContent = "✅ Scan clean. No threats detected.";
            statusEl.style.color = "#10b981";
        }
    })
    .catch(err => {
        statusEl.textContent = "Error: Backend server unreachable.";
        statusEl.style.color = "#ef4444";
        console.error(err);
    });
}
