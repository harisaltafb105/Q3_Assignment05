import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib

# In-memory data store
if "data_store" not in st.session_state:
    st.session_state.data_store = {}

# Failed attempt counter
if "failures" not in st.session_state:
    st.session_state.failures = 0

# Login state
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Key generation from passkey
def get_fernet_key(passkey: str) -> bytes:
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Login page (forced after 3 failures)
def show_login():
    st.title("🔒 Reauthorization Required")
    password = st.text_input("Enter system password to continue:", type="password")
    if st.button("Login"):
        if password == "admin123":  # Hardcoded reauth password
            st.session_state.failures = 0
            st.session_state.authorized = True
            st.success("Access granted.")
        else:
            st.error("Incorrect password.")

# Store data
def store_data_ui():
    st.subheader("📦 Store Data")
    key = st.text_input("Choose a unique passkey:", type="password")
    data = st.text_area("Enter your secret data:")
    if st.button("Store"):
        if key and data:
            fernet = Fernet(get_fernet_key(key))
            encrypted = fernet.encrypt(data.encode())
            st.session_state.data_store[key] = encrypted
            st.success("Data stored securely.")
        else:
            st.warning("Please provide both a passkey and data.")

# Retrieve data
def retrieve_data_ui():
    st.subheader("🔐 Retrieve Data")
    key = st.text_input("Enter your passkey to retrieve data:", type="password")
    if st.button("Retrieve"):
        if key in st.session_state.data_store:
            try:
                fernet = Fernet(get_fernet_key(key))
                decrypted = fernet.decrypt(st.session_state.data_store[key]).decode()
                st.success("Decrypted Data:")
                st.code(decrypted)
                st.session_state.failures = 0
            except InvalidToken:
                st.session_state.failures += 1
                st.error("Invalid passkey.")
        else:
            st.session_state.failures += 1
            st.error("Passkey not found.")

        if st.session_state.failures >= 3:
            st.session_state.authorized = False

# Main app logic
def main():
    st.title("🧠 Secure In-Memory Data Vault")

    if not st.session_state.authorized:
        show_login()
        return

    menu = st.sidebar.radio("Select Action", ["Store Data", "Retrieve Data"])
    
    if menu == "Store Data":
        store_data_ui()
    elif menu == "Retrieve Data":
        retrieve_data_ui()

if __name__ == "__main__":
    main()
