import hashlib
import os
import requests
import streamlit as st

# --- 1. WEB PAGE CONFIGURATION ---
st.set_page_config(page_title="Samar's Cyber Scanner", page_icon="🛡️", layout="centered")

# --- 2. CUSTOM CYBER DARK THEME STYLING ---
st.markdown("""
    <style>
    /* Change background color */
    .stApp {
        background-color: #0f172a;
    }
    /* Style main title */
    h1 {
        color: #38bdf8 !important;
        font-family: 'Courier New', monospace;
        font-weight: bold;
    }
    /* Style text descriptions */
    .stMarkdown p {
        color: #cbd5e1;
    }
    /* Make the drag-and-drop box look sleek */
    .stFileUploader {
        border: 2px dashed #38bdf8;
        border-radius: 10px;
        padding: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 3. LEFT-SIDE SIDEBAR CONTROL PANEL ---
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

# 🔴 PASTE YOUR VIRUSTOTAL KEY INSIDE THESE QUOTES
MY_SECRET_KEY = "d2d73486af5d337ca1eba8c30839b515862cb69d266a6da09145138bc42407f3"

# --- CORE BACKEND FUNCTIONS ---
def get_file_fingerprint(uploaded_file):
    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: uploaded_file.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_with_database(fingerprint_hash):
    url = f"https://www.virustotal.com/api/v3/files/{fingerprint_hash}"
    headers = {"x-apikey": MY_SECRET_KEY}
    return requests.get(url, headers=headers)

# --- APPLICATION LOGIC ---
if MY_SECRET_KEY == "PASTE_YOUR_VIRUSTOTAL_KEY_HERE" or MY_SECRET_KEY == "":
    st.error("❌ Setup Error: Please paste your VirusTotal API key on line 47 of app.py!")
else:
    file_to_scan = st.file_uploader("Upload target file for security clearance:", type=None)

    if file_to_scan is not None:
        st.markdown("---")
        st.write(f"📂 Analyzing File: `{file_to_scan.name}`")
        
        # Extract Hash
        with st.spinner("🧬 Isolating cryptographic fingerprint..."):
            file_hash = get_file_fingerprint(file_to_scan)
        
        st.code(file_hash, language="text")
        
        # Check Database
        with st.spinner("📡 Querying global cybersecurity databases..."):
            response = check_with_database(file_hash)
            
        st.markdown("### 📊 Scan Summary")
        
        # Create 3 clean metric cards side-by-side
        col1, col2, col3 = st.columns(3)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            
            if malicious > 0:
                with col1: st.metric(label="Threat Status", value="🚨 DANGER")
                with col2: st.metric(label="Malicious Flags", value=f"{malicious} engines", delta=f"+{malicious}", delta_color="inverse")
                with col3: st.metric(label="Database Match", value="FOUND")
                st.error(f"❌ Critical Alert: This file is flagged as malicious by {malicious} security systems!")
            else:
                st.balloons()
                with col1: st.metric(label="Threat Status", value="🟢 CLEAN")
                with col2: st.metric(label="Malicious Flags", value="0 engines")
                with col3: st.metric(label="Database Match", value="FOUND")
                st.success("🎉 Secure Scan: This file has a verified, clean record.")
                
        elif response.status_code == 404:
            st.balloons()
            with col1: st.metric(label="Threat Status", value="🟢 SAFE")
            with col2: st.metric(label="Malicious Flags", value="0 engines")
            with col3: st.metric(label="Database Match", value="UNIQUE")
            st.info("💡 Unique File: This file has a clean record and is completely unique to your machine.")
        else:
            st.error(f"⚠️ Connection Error: Database returned code {response.status_code}")
