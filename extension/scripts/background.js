console.log("[PhishSentinel] Background service worker initialized.");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "auto_scan") {
        fetch("http://127.0.0.1:8000/api/v1/live_scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request.payload)
        })
        .then(res => res.json())
        .then(data => sendResponse(data))
        .catch(err => sendResponse({error: err.toString()}));
        
        return true; // Keep the messaging channel open for the async response
    }
});