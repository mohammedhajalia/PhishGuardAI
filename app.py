import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from io import BytesIO

import streamlit as st

# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide"
)

DB_NAME = "phishguard.db"


# ---------------- DATABASE ----------------

def init_database():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                message TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings TEXT NOT NULL
            )
        """)


def save_scan(message, score, risk, findings):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            INSERT INTO scans (
                scan_time, message, risk_score,
                risk_level, findings
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            message,
            score,
            risk,
            "\n".join(findings)
        ))

def save_url_scan(url, score, risk, findings):
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            INSERT INTO url_scans (
                scan_time, url, risk_score,
                risk_level, findings
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            score,
            risk,
            "\n".join(findings)
        ))


def get_dashboard_stats():

    with sqlite3.connect(DB_NAME) as conn:

        message_total = conn.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        url_total = conn.execute(
            "SELECT COUNT(*) FROM url_scans"
        ).fetchone()[0]

        message_high = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE risk_level IN ('High', 'Critical')"
        ).fetchone()[0]

        url_high = conn.execute(
            "SELECT COUNT(*) FROM url_scans WHERE risk_level IN ('High', 'Critical')"
        ).fetchone()[0]

    return {
        "messages": message_total,
        "urls": url_total,
        "total": message_total + url_total,
        "high_risk": message_high + url_high
    }


def get_risk_distribution():

    risk_counts = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }

    with sqlite3.connect(DB_NAME) as conn:

        for table in ["scans", "url_scans"]:

            rows = conn.execute(
                f"SELECT risk_level, COUNT(*) FROM {table} GROUP BY risk_level"
            ).fetchall()

            for risk, count in rows:
                if risk in risk_counts:
                    risk_counts[risk] += count

    return risk_counts



def get_history():
    with sqlite3.connect(DB_NAME) as conn:
        return conn.execute("""
            SELECT id, scan_time, message,
                   risk_score, risk_level, findings
            FROM scans
            ORDER BY id DESC
        """).fetchall()
def get_url_history():
    with sqlite3.connect(DB_NAME) as conn:
        return conn.execute("""
            SELECT id, scan_time, url,
                   risk_score, risk_level, findings
            FROM url_scans
            ORDER BY id DESC
        """).fetchall()    


def clear_history():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM scans")


# ---------------- DETECTION ENGINE ----------------


def analyze_message(message):

    findings = []
    score = 0
    text = message.lower()

    # 1. Urgency and threats
    urgent_words = [
        "urgent", "immediately", "account blocked",
        "account suspended", "act now", "expire today",
        "failure to act", "within 24 hours",
        "within 2 hours", "permanently blocked",
        "final warning", "limited time"
    ]

    found_urgent = [
        word for word in urgent_words if word in text
    ]

    if found_urgent:
        score += 20
        findings.append(
            "Urgent or threatening language: "
            + ", ".join(found_urgent)
        )

    # 2. Sensitive information requests
    sensitive_words = [
        "password", "otp", "one-time password",
        "bank details", "credit card", "pin number",
        "atm pin", "atm pin number", "share your pin",
        "verify your account", "login credentials",
        "banking details", "account number"
    ]

    found_sensitive = [
        word for word in sensitive_words if word in text
    ]

    if found_sensitive:
        score += 30
        findings.append(
            "Sensitive information requests: "
            + ", ".join(found_sensitive)
        )

    # 3. Suspicious URLs
    urls = re.findall(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        message,
        flags=re.IGNORECASE
    )

    for url in urls:

        cleaned_url = url.rstrip(".,!?;:)")

        candidate = cleaned_url

        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate

        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()

        reasons = []

        if parsed.scheme == "http":
            reasons.append("uses unencrypted HTTP")

        if "xn--" in hostname:
            reasons.append("contains encoded internationalized domain")

        if "secure-" in hostname or "verify" in hostname:
            reasons.append("contains security-related wording")

        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname):
            reasons.append("uses an IP address as hostname")

        if "@" in parsed.netloc:
            reasons.append("contains an @ symbol")

        if reasons:
            score += 20
            findings.append(
                "URL warning for " + cleaned_url + ": "
                + "; ".join(reasons)
            )

    # 4. Manipulation and financial fraud
    manipulation_words = [
        "you have won", "claim your prize",
        "free gift", "send money", "payment required",
        "click here", "verify now",
        "processing fee", "cash prize",
        "claim your reward", "pay immediately"
    ]

    found_manipulation = [
        word for word in manipulation_words if word in text
    ]

    if found_manipulation:
        score += 20
        findings.append(
            "Possible manipulation tactics: "
            + ", ".join(found_manipulation)
        )

    # 5. Account and banking threats
    banking_words = [
        "bank account", "atm card", "debit card",
        "credit card", "net banking", "bank account"
    ]

    found_banking = [
        word for word in banking_words if word in text
    ]

    if found_banking:
        score += 15
        findings.append(
            "Banking-related content detected: "
            + ", ".join(set(found_banking))
        )

    # 6. Score limitation
    score = min(score, 100)

    # 7. Risk classification
    if score >= 70:
        risk = "Critical"
    elif score >= 45:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No warning signs from the current rule set were detected."
        )

    return score, risk, findings, urls

# ---------------- URL INVESTIGATION ENGINE ----------------

import ipaddress
from urllib.parse import urlparse



def analyze_url(url):

    findings = []
    score = 0

    url = url.strip()

    # 1. Basic URL validation
    if not url or any(char.isspace() for char in url):
        return 0, "Invalid", ["URL is empty or contains spaces."]

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        # Check hostname
        if not hostname:
            return 0, "Invalid", ["Invalid URL format."]

        hostname = hostname.lower().rstrip(".")

        # Validate port
        try:
            parsed.port
        except ValueError:
            return 0, "Invalid", ["URL contains an invalid port."]

        if parsed.scheme not in ("http", "https"):
            return 0, "Invalid", ["Unsupported URL protocol."]

    except Exception:
        return 0, "Invalid", ["Unable to parse this URL."]

    # 2. HTTP checking
    if parsed.scheme == "http":
        score += 15
        findings.append(
            "Website uses HTTP instead of HTTPS."
        )

    # 3. IP address detection
    try:
        ip = ipaddress.ip_address(hostname)

        score += 30
        findings.append(
            "URL uses an IP address instead of a domain name."
        )

        if not ip.is_global:
            score += 25
            findings.append(
                "URL uses a private or reserved IP address."
            )

    except ValueError:
        # 4. Domain validation
        if "." not in hostname:
            score += 15
            findings.append(
                "Domain does not contain a standard public domain structure."
            )

        labels = hostname.split(".")

        if any(not label or len(label) > 63 for label in labels):
            return 0, "Invalid", ["Invalid domain structure."]

        if len(hostname) > 253:
            return 0, "Invalid", ["Domain name is too long."]

    # 5. Suspicious domain words
    suspicious_words = [
        "login", "verify", "secure",
        "account", "update", "banking"
    ]

    found_words = [
        word for word in suspicious_words
        if word in hostname
    ]

    if found_words:
        score += 15
        findings.append(
            "Domain contains security-related words: "
            + ", ".join(found_words)
        )

    # 6. Username or password inside URL
    if parsed.username is not None or parsed.password is not None:
        score += 25
        findings.append(
            "URL contains embedded username or password information."
        )

    # 7. Excessive subdomains
    if len(hostname.split(".")) > 4:
        score += 20
        findings.append(
            "URL contains an unusually long subdomain chain."
        )

    # 8. Punycode detection
    if "xn--" in hostname:
        score += 25
        findings.append(
            "Domain contains encoded international characters."
        )

    # Limit score
    score = min(score, 100)

    # 9. Risk classification
    if score >= 70:
        risk = "Critical"
    elif score >= 45:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No suspicious patterns detected by the current rules."
        )

    return score, risk, findings


def generate_url_pdf(result):

    buffer = BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=A4)

    width, height = A4
    y = height - 25 * mm

    # Header
    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawString(20 * mm, y, "PhishGuard AI")

    y -= 12 * mm

    pdf.setFont("Helvetica-Bold", 15)
    pdf.drawString(20 * mm, y, "URL Investigation Report")

    y -= 15 * mm

    # Date and time
    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        20 * mm,
        y,
        "Generated: " + datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    )

    y -= 15 * mm

    # URL
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(20 * mm, y, "Investigated URL:")

    y -= 8 * mm

    pdf.setFont("Helvetica", 10)

    url = result.get("url", "URL not available")

    for i in range(0, len(url), 75):
        pdf.drawString(20 * mm, y, url[i:i + 75])
        y -= 6 * mm

    y -= 5 * mm

    # Risk score
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(
        20 * mm,
        y,
        "Risk Score: " + str(result["score"]) + "/100"
    )

    y -= 9 * mm

    pdf.drawString(
        20 * mm,
        y,
        "Risk Level: " + result["risk"]
    )

    y -= 15 * mm

    # Findings
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(20 * mm, y, "Investigation Findings")

    y -= 10 * mm

    pdf.setFont("Helvetica", 10)

    for finding in result["findings"]:

        if y < 30 * mm:
            pdf.showPage()
            y = height - 25 * mm
            pdf.setFont("Helvetica", 10)

        pdf.drawString(22 * mm, y, "- " + finding[:100])
        y -= 8 * mm

    y -= 8 * mm

    # Recommendations
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(20 * mm, y, "Security Recommendation")

    y -= 10 * mm

    pdf.setFont("Helvetica", 10)

    recommendations = {
        "Critical": "Do not visit this website or share sensitive information.",
        "High": "Avoid interacting with this website.",
        "Medium": "Verify the official domain before proceeding.",
        "Low": "No suspicious patterns detected. Still verify the website."
    }

    recommendation = recommendations.get(
        result["risk"],
        "Exercise caution when visiting unknown websites."
    )

    pdf.drawString(20 * mm, y, recommendation[:100])

    y -= 20 * mm

    pdf.setFont("Helvetica-Oblique", 9)
    pdf.drawString(
        20 * mm,
        y,
        "Note: This report contains a preliminary rule-based assessment."
    )

    pdf.save()

    buffer.seek(0)

    return buffer




# ---------------- DESIGN ----------------

st.markdown("""
<style>
```css
.stApp {
    background-color: #020817;

    background-image:
        radial-gradient(
            circle at 50% 45%,
            rgba(0, 153, 255, 0.28),
            transparent 30%
        ),

        radial-gradient(
            circle at 50% 45%,
            rgba(0, 80, 180, 0.20),
            transparent 55%
        ),

        repeating-linear-gradient(
            90deg,
            transparent 0px,
            transparent 48px,
            rgba(0, 174, 255, 0.07) 49px,
            transparent 50px
        ),

        repeating-linear-gradient(
            0deg,
            transparent 0px,
            transparent 48px,
            rgba(0, 174, 255, 0.07) 49px,
            transparent 50px
        ),

        linear-gradient(
            135deg,
            #020817,
            #061b35,
            #020817
        );

    background-attachment: fixed;
    color: white;
}

/* Glowing cybersecurity elements */

.stApp::before {
    content: "🛡";
    position: fixed;
    top: 35%;
    left: 50%;
    transform: translate(-50%, -50%);

    font-size: 180px;

    color: #00c8ff;

    opacity: 0.12;

    text-shadow:
        0 0 20px #008cff,
        0 0 50px #008cff,
        0 0 100px #00c8ff;

    pointer-events: none;
    z-index: 0;
}

/* Technical glow */

.stApp::after {
    content: "";
    position: fixed;
    inset: 0;

    background:
        radial-gradient(
            circle at 15% 30%,
            rgba(0, 174, 255, 0.15),
            transparent 18%
        ),
        radial-gradient(
            circle at 85% 70%,
            rgba(0, 255, 200, 0.10),
            transparent 20%
        );

    pointer-events: none;
    z-index: 0;
}

/* Dashboard content */

h1, h2, h3, p, label {
    color: white !important;
}

.stTextArea textarea {
    background-color: #091a30;
    color: white;
    border: 1px solid #087cff;
}

.stButton button {
    background: linear-gradient(
        90deg,
        #0066ff,
        #00c8ff
    );

    color: white;
    font-weight: bold;
    border-radius: 8px;
    border: none;
}

.stButton button:hover {
    box-shadow: 0 0 18px #008cff;
}
```

}
h1, h2, h3, p, label {
    color: white !important;
}
.stTextArea textarea {
    background-color: #151d32;
    color: white;
}
.stButton button {
    background-color: #00c896;
    color: #06121b;
    font-weight: bold;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)


# Initialize database
init_database()


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.title("🛡️ PhishGuard AI")
    st.write("Cybersecurity Investigation Dashboard")
    st.divider()

    page = st.radio(
        "Navigation",
        [
            "📊 Dashboard",
            "🔍 Message Analysis",
            "🌐 URL Investigation",
            "🗂️ Scan History"
        ]
    )

    st.divider()
    st.caption("Prototype v3.0")


# ---------------- MESSAGE ANALYSIS ----------------
if page == "📊 Dashboard":

    st.title("📊 PhishGuard AI Dashboard")
    st.caption("Your cybersecurity investigation overview.")

    stats = get_dashboard_stats()

    st.divider()

    # Statistics cards
    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Total Scans",
            stats["total"]
        )

    with col2:
        st.metric(
            "High/Critical Detections",
            stats["high_risk"]
        )

    col3, col4 = st.columns(2)

    with col3:
        st.metric(
            "Messages Scanned",
            stats["messages"]
        )

    with col4:
        st.metric(
            "URLs Investigated",
            stats["urls"]
        )

    st.divider()

    # Scan activity chart
    st.subheader("📈 Scan Activity")

    chart_data = {
        "Messages": [stats["messages"]],
        "URLs": [stats["urls"]]
    }

    st.bar_chart(chart_data)
    st.divider()

    # Risk distribution chart
    st.subheader("🚨 Risk Distribution")

    risk_counts = get_risk_distribution()

    risk_data = {
        "Risk Level": ["Low", "Medium", "High", "Critical"],
        "Number of Scans": [
            risk_counts["Low"],
            risk_counts["Medium"],
            risk_counts["High"],
            risk_counts["Critical"]
        ]
    }

    st.bar_chart(
        risk_data,
        x="Risk Level",
        y="Number of Scans"
    )

    st.divider()

    st.info(
        "Statistics are automatically updated using your scan history."
    )
if page == "🔍 Message Analysis":

    st.title("🛡️ PhishGuard AI")
    st.caption("Phishing Detection & Investigation Platform")
    st.divider()

    st.subheader("🔍 Analyze a Suspicious Message")

    message = st.text_area(
        "Email or SMS content",
        height=200,
        placeholder="Paste a suspicious message here..."
    )

    if st.button("🔎 Analyze Message", use_container_width=True):

        if not message.strip():
            st.warning("Please enter a message first.")

        else:
            score, risk, findings, urls = analyze_message(message)

            # Save the result to SQLite
            save_scan(message, score, risk, findings)

            st.session_state["latest_scan"] = {
                "score": score,
                "risk": risk,
                "findings": findings,
                "urls": urls
            }

            st.success("Analysis completed and saved to Scan History!")

    result = st.session_state.get("latest_scan")

    if result:
        st.divider()
        st.subheader("📊 Analysis Results")

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Risk Score", str(result["score"]) + "/100")

        with col2:
            st.metric("Risk Level", result["risk"])

        st.progress(result["score"] / 100)

        if result["risk"] == "Critical":
            st.error("🚨 Critical risk: strong warning signs detected.")
        elif result["risk"] == "High":
            st.error("🔴 High risk: investigate this message carefully.")
        elif result["risk"] == "Medium":
            st.warning("🟠 Medium risk: review the warning signs.")
        else:
            st.success("🟢 Low risk under the current detection rules.")

        st.subheader("🧠 Evidence and Warning Signs")

        for finding in result["findings"]:
            st.write("⚠️ " + finding)

        st.subheader("🔗 URLs Found")

        if result["urls"]:
            for url in result["urls"]:
                st.code(url)
        else:
            st.write("No URLs detected.")

            st.info(
            "This is a preliminary rule-based assessment. "
            "No website was opened or contacted. "
            "A low score does not guarantee safety."
        )

        st.download_button(
            label="📄 Download PDF Report",
            data=generate_url_pdf(result),
            file_name="PhishGuard_URL_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )
    st.divider()
    st.subheader("🚀 Platform Capabilities")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 🔍 Message Analysis")
        st.write("Identify common phishing warning signs.")

    with col2:
        st.markdown("### 🔗 URL Investigation")
        st.write("Inspect URL characteristics without opening links.")

    with col3:
        st.markdown("### 📊 Risk Assessment")
        st.write("Review scores and supporting evidence.")
        # ---------------- URL INVESTIGATION PAGE ----------------

elif page == "🌐 URL Investigation":

    st.title("🌐 URL Investigation")
    st.caption("Analyze suspicious website links safely.")
    st.divider()

    st.subheader("🔍 Enter a Website URL")

    user_url = st.text_input(
        "Website URL",
        placeholder="https://example.com"
    )

    if st.button("🔎 Investigate URL", use_container_width=True):

        if not user_url.strip():
            st.warning("Please enter a URL.")

        else:
            score, risk, findings = analyze_url(user_url)
            save_url_scan(user_url, score, risk, findings)


            st.session_state["url_result"] = {
                "url": user_url,
                "score": score,
                "risk": risk,
                "findings": findings
            }

    result = st.session_state.get("url_result")

    if result:

        st.divider()
        st.subheader("📊 URL Investigation Results")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "URL Risk Score",
                str(result["score"]) + "/100"
            )

        with col2:
            st.metric(
                "Risk Level",
                result["risk"]
            )

        st.progress(result["score"] / 100)

        st.write("**Investigated URL:**")
        st.code(result["url"])

        st.subheader("🧠 Investigation Findings")

        for finding in result["findings"]:
            st.write("⚠️ " + finding)

        if result["risk"] == "Critical":
            st.error("🚨 Critical risk detected.")
        elif result["risk"] == "High":
            st.error("🔴 High risk detected.")
        elif result["risk"] == "Medium":
            st.warning("🟠 Medium risk detected.")
        else:
            st.success("🟢 Low risk under current detection rules.")

        st.info(
            "This is a preliminary rule-based assessment. "
            "No website was opened or contacted. "
            "A low score does not guarantee safety."
        )
        
        st.divider()
        st.subheader("🛡️ Security Recommendations")

        if result["risk"] == "Critical":
            st.error(
                "Do not visit this website. "
                "Never enter passwords, OTPs or banking details."
            )

        elif result["risk"] == "High":
            st.warning(
                "Avoid interacting with this website. "
                "Do not share personal or financial information."
            )

        elif result["risk"] == "Medium":
            st.warning(
                "Check the website address carefully. "
                "Verify the official domain before proceeding."
            )

        else:
            st.success(
                "No suspicious patterns were detected by our current rules. "
                "Still verify the website before sharing sensitive information."
            )
            st.divider()

        st.download_button(
            label="📄 Download PDF Report",
            data=generate_url_pdf(result),
            file_name="PhishGuard_URL_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )


# ---------------- SCAN HISTORY ----------------

elif page == "🗂️ Scan History":

    st.title("🗂️ Scan History")
    st.write("Review previous PhishGuard AI investigations.")

    history = get_history()
    url_history = get_url_history()

    if history or url_history:

        st.metric(
            "Total Investigations",
            len(history) + len(url_history)
        )

        # MESSAGE HISTORY

        st.subheader("📩 Message Investigation History")

        if history:

            for row in history:

                scan_id, scan_time, message, score, risk, findings = row

                with st.expander(
                    f"Message Scan #{scan_id} | {scan_time} | {risk} ({score}/100)"
                ):

                    st.write("**Message analyzed:**")
                    st.code(message)

                    st.write("**Risk Score:**", str(score) + "/100")
                    st.write("**Risk Level:**", risk)

                    st.write("**Evidence:**")

                    for finding in findings.split("\n"):
                        st.write("⚠️ " + finding)

        else:
            st.info("No message investigations found.")

        st.divider()

        # URL HISTORY

        st.subheader("🌐 URL Investigation History")

        if url_history:

            for row in url_history:

                scan_id, scan_time, url, score, risk, findings = row

                with st.expander(
                    f"URL Scan #{scan_id} | {scan_time} | {risk} ({score}/100)"
                ):

                    st.write("**Investigated URL:**")
                    st.code(url)

                    st.write("**Risk Score:**", str(score) + "/100")
                    st.write("**Risk Level:**", risk)

                    st.write("**Investigation Findings:**")

                    for finding in findings.split("\n"):
                        st.write("⚠️ " + finding)

        else:
            st.info("No URL investigations found.")

        st.divider()

        # CLEAR HISTORY

        confirm_clear = st.checkbox(
            "I understand that clearing history permanently deletes all saved scans."
        )

        if st.button("🗑️ Clear All Scan History"):

            if confirm_clear:

                clear_history()

                with sqlite3.connect(DB_NAME) as conn:
                    conn.execute("DELETE FROM url_scans")

                st.success("All scan history cleared!")
                st.rerun()

            else:
                st.warning("Please confirm before clearing history.")

    else:
        st.info("No investigations saved yet.")

st.divider()

st.caption(
    "PhishGuard AI | Hackathon Prototype | Version 3.0"
)
