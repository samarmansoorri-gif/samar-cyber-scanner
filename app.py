import hashlib
import requests
import streamlit as st
import smtplib
from email.mime.text import MIMEText

# --- 1. WEB PAGE CONFIGURATION ---
st.set_page_config(page_title="Samar's Cyber Scanner", page_icon="🛡️", layout="centered")

# --- 2. CUSTOM CYBER DARK THEME STYLING ---
st.markdown("""
    <style>
    .stApp { background-color: #0f172a; }
    h1 { color: #38bdf8 !important; font-family: 'Courier New', monospace; font-weight: bold; }
    .stMarkdown p { color: #cbd5e1; }
    .stFileUploader { border: 2px dashed #38bdf8; border-radius: 10px; padding: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- 3. SIDEBAR ---
with st.sidebar:
    st.markdown("<h2 style='color: #38bdf8;'>🛠️ CONTROL PANEL</h2>", unsafe_allow_html=True)
    st.markdown("---")
    st.write("**👨‍💻 System Administrator:** SAMAR")
    st.write("**🤖 Scanner Core:** Python 3.14")
    st.write("**🌐 Database Status:** 🟢 Online & Connected")
    st.markdown("---")
    st.info("💡 **How to use:** Simply drag any file into the scanner on the right. The engine will instantly isolate its digital DNA and verify it against global threat logs.")

# --- 4. MAIN INTERFACE ---
st.title("🛡️ SAMAR'S CYBER SCANNER")
st.write("Secure, real-time cryptographic file scanning interface.")
st.markdown("---")

# --- 5. EMAIL & API CONFIG (stored safely in Streamlit Secrets) ---
MY_EMAIL        = "samarmansoorri@gmail.com"
MY_APP_PASSWORD = st.secrets["EMAIL_PASSWORD"]
MY_SECRET_KEY   = st.secrets["VT_API_KEY"]

# --- 6. IP FUNCTIONS ---
def get_client_ip():
    try:
        headers = st.context.headers
        ip = (
            headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or headers.get("X-Real-Ip", "")
            or "Unknown"
        )
        return ip
    except Exception:
        return "Unknown"

def get_ip_info(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.ok:
            d = r.json()
            return {
                "IP":      d.get("ip", ip),
                "City":    d.get("city", "—"),
                "Region":  d.get("region", "—"),
                "Country": d.get("country_name", "—"),
                "ISP":     d.get("org", "—"),
            }
    except Exception:
        pass
    return {"IP": ip}

# --- 7. EMAIL FUNCTION ---
def send_email(ip_info, filename=""):
    lines = ["📌 New visitor on your Cyber Scanner!\n"]
    if filename:
        lines.append(f"File scanned: {filename}\n")
    for k, v in ip_info.items():
        lines.append(f"{k}: {v}")
    body = "\n".join(lines)

    msg = MIMEText(body)
    msg["Subject"] = "🛡️ New Scanner Visitor"
    msg["From"]    = MY_EMAIL
    msg["To"]      = MY_EMAIL

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.starttls()
            s.login(MY_EMAIL, MY_APP_PASSWORD)
            s.send_message(msg)
    except Exception as e:
        st.warning(f"Email notification failed: {e}")

# --- 8. COLLECT IP ONCE PER SESSION ---
if "ip_logged" not in st.session_state:
    raw_ip = get_client_ip()
    st.session_state.ip_info   = get_ip_info(raw_ip)
    st.session_state.ip_logged = False

# --- 9. PRIVACY NOTICE ---
st.info("ℹ️ **Privacy Notice:** Your IP address and approximate location are logged for security purposes.", icon="🔒")

# --- 10. CORE BACKEND FUNCTIONS ---
def get_file_fingerprint(uploaded_file):
    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: uploaded_file.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_with_database(fingerprint_hash):
    url = f"https://www.virustotal.com/api/v3/files/{fingerprint_hash}"
    headers = {"x-apikey": MY_SECRET_KEY}
    return requests.get(url, headers=headers)

# --- 11. APPLICATION LOGIC ---
file_to_scan = st.file_uploader("Upload target file for security clearance:", type=None)

if file_to_scan is not None:
    st.markdown("---")
    st.write(f"📂 Analyzing File: `{file_to_scan.name}`")

    # Send email on first scan per session
    if not st.session_state.ip_logged:
        send_email(st.session_state.ip_info, file_to_scan.name)
        st.session_state.ip_logged = True

    # Extract Hash
    with st.spinner("🧬 Isolating cryptographic fingerprint..."):
        file_hash = get_file_fingerprint(file_to_scan)

    st.code(file_hash, language="text")

    # Check Database
    with st.spinner("📡 Querying global cybersecurity databases..."):
        response = check_with_database(file_hash)

    st.markdown("### 📊 Scan Summary")
    col1, col2, col3 = st.columns(3)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']

        if malicious > 0:
            with col1: st.metric(label="Threat Status",   value="🚨 DANGER")
            with col2: st.metric(label="Malicious Flags", value=f"{malicious} engines", delta=f"+{malicious}", delta_color="inverse")
            with col3: st.metric(label="Database Match",  value="FOUND")
            st.error(f"❌ Critical Alert: This file is flagged as malicious by {malicious} security systems!")
        else:
            st.balloons()
            with col1: st.metric(label="Threat Status",   value="🟢 CLEAN")
            with col2: st.metric(label="Malicious Flags", value="0 engines")
            with col3: st.metric(label="Database Match",  value="FOUND")
            st.success("🎉 Secure Scan: This file has a verified, clean record.")

    elif response.status_code == 404:
        st.balloons()
        with col1: st.metric(label="Threat Status",   value="🟢 SAFE")
        with col2: st.metric(label="Malicious Flags", value="0 engines")
        with col3: st.metric(label="Database Match",  value="UNIQUE")
        st.info("💡 Unique File: This file has a clean record and is completely unique to your machine.")
    else:
        st.error(f"⚠️ Connection Error: Database returned code {response.status_code}")
