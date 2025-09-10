# Secure Data Encryption App - Demo Version
import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# ---------------- Session State Init ----------------
if "key_verified" not in st.session_state:
    st.session_state["key_verified"] = False
if "authorized" not in st.session_state:
    st.session_state["authorized"] = False

# ---------------- Encryption Setup ----------------
@st.cache_resource
def get_fernet():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = get_fernet()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


# Secret key access control

if not st.session_state["key_verified"]:
    st.title("🔑 Enter Access Key (Demo Only)")
    secret_key = st.text_input("Access Key", type="password")
    if st.button("Submit Key"):
        if secret_key == "GumroadDemo123":
            st.session_state["key_verified"] = True
            st.rerun()  # Refresh to move to login
        else:
            st.error("⚠️ Access denied! Only Gumroad buyers can use this demo.")
    st.stop()  # ⬅️ STOP here until key is verified


# ---------------- Login Page ----------------
if not st.session_state["authorized"]:
    st.title("🔐 Secure Data Vault - Demo Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "Ekta Khatri" and password == "ekki123":
            st.session_state["authorized"] = True
            st.success("✅ Login successful!")
            st.rerun()
        else:
            st.error("❌ Invalid credentials")

# ---------------- Main App ----------------
else:
    st.sidebar.title("🔒 Secure Data Encryption - Demo")
    st.sidebar.write("Demo version – Limited features.")
    st.sidebar.write("Buy Pro version on Gumroad for unlimited storage & multi-user support.")

    menu = st.sidebar.radio("Select Option", ["🏠 Home", "➕ Insert Data", "🔓 Retrieve Data", "🚪 Logout"])

    if menu == "🏠 Home":
        st.title("Welcome to Secure Data Vault Demo")
        st.write("🔐 Store and retrieve your encrypted data securely. Limited to 2 entries in this demo.")

    elif menu == "➕ Insert Data":
        if len(st.session_state["stored_data"]) >= 2:
            st.warning("⚠️ Demo limit reached! Upgrade to Pro for unlimited storage.")
        else:
            st.header("Insert Data")
            user_key = st.text_input("Enter a unique key for your data (e.g., 'user1_data'):")
            text = st.text_area("Enter the text to store securely:")
            passkey = st.text_input("Enter a secret passkey:", type="password")

            if st.button("Encrypt and Store"):
                if user_key and text and passkey:
                    encrypted_text = encrypt_data(text)
                    hashed_passkey = hash_passkey(passkey)
                    st.session_state["stored_data"][user_key] = {
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey
                    }
                    st.success("✅ Data encrypted and stored successfully!")
                else:
                    st.warning("Please fill in all fields.")

    elif menu == "🔓 Retrieve Data":
        st.header("Retrieve Data")
        user_key = st.text_input("Enter the key of the data to retrieve:")
        passkey = st.text_input("Enter your secret passkey:", type="password")

        if st.button("Decrypt"):
            data = st.session_state["stored_data"].get(user_key)
            if data:
                if hash_passkey(passkey) == data["passkey"]:
                    try:
                        decrypted_text = decrypt_data(data["encrypted_text"])
                        st.success("🔓 Decrypted Text:")
                        st.code(decrypted_text)
                        st.session_state["attempts"] = 0
                    except Exception:
                        st.error("Decryption failed. Try again.")
                else:
                    st.session_state["attempts"] += 1
                    remaining = 3 - st.session_state["attempts"]
                    st.error(f"❌ Wrong passkey! {remaining} attempt(s) remaining.")
                    if st.session_state["attempts"] >= 3:
                        st.session_state["authorized"] = False
                        st.session_state["attempts"] = 0
                        st.warning("Too many failed attempts. Please login again.")
                        st.rerun()
            else:
                st.warning("No data found for the provided key.")

    elif menu == "🚪 Logout":
        st.session_state["authorized"] = False
        st.success("You have been logged out.")
        st.rerun()
