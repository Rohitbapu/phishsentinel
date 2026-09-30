// Add CSS animation for the warning banner's smooth entry
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
    }
`;
document.head.append(style);

// Automatically trigger scan after the page loads
window.addEventListener('load', () => {
    setTimeout(() => {
        let pageText = document.body.innerText.substring(0, 3000);
        // Scrapes ALL links on the page (removed the 10 link limit)
        let links = Array.from(document.links).map(a => a.href);
        
        chrome.runtime.sendMessage({
            action: "auto_scan",
            payload: { 
                text: pageText, 
                links: links, 
                reporter: "auto_scanner@corp.test" 
            }
        }, response => {
            // If the background worker detects a threat, trigger the visual flag
            if (response && response.is_threat) {
                injectThreatFlag(response.threat_score, response.reasoning, response.flagged_links || []);
            }
        });
    }, 1500); 
});

// Listen for manual scan requests from the extension popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scrape_page") {
        let pageText = document.body.innerText.substring(0, 3000);
        let links = Array.from(document.links).map(a => a.href);
        
        sendResponse({ 
            text: pageText, 
            links: links, 
            url: window.location.href 
        });
    }

    if (request.action === "show_threat_flag") {
        injectThreatFlag(request.score, request.reasoning, request.flagged_links || []);
    }
    return true;
});

function injectThreatFlag(score, reasoning, flaggedLinks = []) {
    // Prevent duplicate banners from being injected
    if (document.getElementById("phishsentinel-warning-flag")) return;

    // 1. Inject the Top Warning Banner (Recolour Flag)
    const banner = document.createElement("div");
    banner.id = "phishsentinel-warning-flag";
    banner.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; z-index: 999999;
        background-color: #dc2626; color: white; padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-bottom: 5px solid #991b1b;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        text-align: center; animation: slideDown 0.5s ease-out;
    `;
    
    banner.innerHTML = `
        <h1 style="margin: 0 0 10px 0; font-size: 24px; font-weight: bold; text-transform: uppercase;">
            ⚠️ Critical Security Threat Detected
        </h1>
        <p style="margin: 0 0 5px 0; font-size: 16px;">
            <strong>AI Threat Score:</strong> ${(score * 100).toFixed(1)}%
        </p>
        <p style="margin: 0 0 15px 0; font-size: 14px; background: rgba(0,0,0,0.2); padding: 10px; display: inline-block; border-radius: 4px;">
            <strong>AI Reasoning:</strong> ${reasoning}
        </p>
        <br>
        <button id="ps-dismiss-btn" style="background: white; color: #dc2626; border: none; padding: 8px 16px; font-weight: bold; border-radius: 4px; cursor: pointer;">
            Dismiss Warning
        </button>
    `;
    document.body.prepend(banner);

    // 2. Apply Red Dotted Borders to the Email Body / Main DOM element
    const emailBody = window.location.hostname.includes("mail.google.com") 
        ? (document.querySelector('.a3s.aiL') || document.querySelector('.a3s'))
        : (document.querySelector('#email-content') || document.body);
    
    if (emailBody) {
        emailBody.style.border = "3px dotted #dc2626";
        emailBody.style.backgroundColor = "rgba(220, 38, 38, 0.03)";
        emailBody.style.padding = "10px";
    }

    // 3. Apply Red Dotted Borders ONLY to the links the AI explicitly flagged
    const allLinks = document.querySelectorAll('a');
    allLinks.forEach(link => {
        if (flaggedLinks.includes(link.href)) {
            link.style.border = "2px dotted #dc2626";
            link.style.backgroundColor = "#fee2e2";
            link.style.color = "#991b1b";
            link.style.fontWeight = "bold";
            link.style.padding = "2px";
            link.classList.add("ps-malicious-link"); 
        }
    });

    // 4. Handle Dismissal (Clean up DOM and styles)
    document.getElementById("ps-dismiss-btn").addEventListener("click", () => {
        banner.remove();
        
        if (emailBody) {
            emailBody.style.border = "";
            emailBody.style.backgroundColor = "";
            emailBody.style.padding = "";
        }
        
        document.querySelectorAll('.ps-malicious-link').forEach(link => {
            link.style.border = "";
            link.style.backgroundColor = "";
            link.style.color = "";
            link.style.fontWeight = "";
            link.style.padding = "";
            link.classList.remove("ps-malicious-link");
        });
    });
}