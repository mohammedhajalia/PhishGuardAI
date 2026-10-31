
const API_URL = "http://127.0.0.1:8000";

// HTML safety helper
function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, function (char) {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"
        };
        return entities[char];
    });
}


// Switch between scanners
const messageTab = document.getElementById("messageTab");
const urlTab = document.getElementById("urlTab");

const messagePanel = document.getElementById("messagePanel");
const urlPanel = document.getElementById("urlPanel");

messageTab.addEventListener("click", function () {

    messagePanel.style.display = "block";
    urlPanel.style.display = "none";

    messageTab.classList.add("active");
    urlTab.classList.remove("active");

    document.getElementById("result").innerHTML = "";
});


urlTab.addEventListener("click", function () {

    messagePanel.style.display = "none";
    urlPanel.style.display = "block";

    urlTab.classList.add("active");
    messageTab.classList.remove("active");

    document.getElementById("result").innerHTML = "";
});


// Display analysis results
function displayResult(data) {

    const result = document.getElementById("result");

    const findings = data.findings.map(function (item) {
        return `<li>${escapeHTML(item)}</li>`;
    }).join("");

    const risk = escapeHTML(data.risk_level);
    const score = Number(data.risk_score);

    let recommendation = "Verify the source before sharing sensitive information.";

    if (risk === "Critical") {
        recommendation = "Do not interact with this message or website. Never share passwords, OTPs or banking details.";
    } else if (risk === "High") {
        recommendation = "Avoid interacting with this content. Verify the sender or website independently.";
    } else if (risk === "Medium") {
        recommendation = "Proceed cautiously and verify the source before taking action.";
    } else if (risk === "Low") {
        recommendation = "No suspicious patterns were detected by the current rules. This does not guarantee safety.";
    }

    result.innerHTML = `
        <div class="result-card">
            <h3>📊 Investigation Results</h3>

            <p><strong>Risk Score:</strong> ${score}/100</p>

            <p><strong>Risk Level:</strong> ${risk}</p>

            <p><strong>Investigation Findings:</strong></p>

            <ul>${findings}</ul>

            <p><strong>🛡️ Security Recommendation:</strong></p>

            <p>${escapeHTML(recommendation)}</p>

            <p><small>Preliminary rule-based assessment. A low score does not guarantee safety.</small></p>
        </div>
    `;
}


// Message scanner
document.getElementById("messageScan").addEventListener("click", async function () {

    const message = document.getElementById("messageInput").value.trim();

    const result = document.getElementById("result");

    if (!message) {
        result.textContent = "Please enter a message to analyze.";
        return;
    }

    result.textContent = "🔍 Analyzing message...";

    try {

        const response = await fetch(`${API_URL}/analyze-message`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: message
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Message analysis failed.");
        }

        displayResult(data);

    } catch (error) {

        result.textContent = "Connection error: " + error.message;

    }
});


// URL investigator
document.getElementById("urlScan").addEventListener("click", async function () {

    const url = document.getElementById("urlInput").value.trim();

    const result = document.getElementById("result");

    if (!url) {
        result.textContent = "Please enter a URL to investigate.";
        return;
    }

    result.textContent = "🌐 Investigating URL...";

    try {

        const response = await fetch(`${API_URL}/analyze-url`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "URL investigation failed.");
        }

        displayResult(data);

    } catch (error) {

        result.textContent = "Connection error: " + error.message;

    }
});

