import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

# Generate key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Simple in-memory database
stored_data = {}

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_text(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_text(text):
    return cipher.decrypt(text.encode()).decode()

# Session states
if "authorized" not in st.session_state:
    st.session_state.authorized = True

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

st.title("🔐 Secure Data Storage App")

# LOGIN page after 3 wrong tries
if not st.session_state.authorized:
    st.subheader("🔒 Re-login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "1234":
            st.success("Login Successful!")
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
        else:
            st.error("Wrong Username or Password.")

# MAIN app
else:
    menu = st.selectbox("Select an option", ["Home", "Insert Data", "Retrieve Data"])

    if menu == "Home":
        st.write("👋 Welcome! This project was created.")
        st.write("You can insert and retrieve your text safely with a passkey.")

    elif menu == "Insert Data":
        st.subheader("📥 Insert New Data")
        text = st.text_area("Enter the text you want to store:")
        passkey = st.text_input("Enter a passkey:", type="password")

        if st.button("Store Data"):
            if text and passkey:
                hashed = hash_passkey(passkey)
                encrypted = encrypt_text(text)
                stored_data[hashed] = encrypted
                st.success("✅ Data Stored Successfully!")
            else:
                st.error("❗ Please fill both fields!")

    elif menu == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        passkey = st.text_input("Enter your passkey to retrieve data:", type="password")

        if st.button("Retrieve"):
            if passkey:
                hashed = hash_passkey(passkey)
                if hashed in stored_data:
                    decrypted = decrypt_text(stored_data[hashed])
                    st.success("✅ Your stored text is:")
                    st.write(decrypted)
                    st.session_state.failed_attempts = 0  # Reset attempts
                else:
                    st.error("❗ Wrong passkey!")
                    st.session_state.failed_attempts += 1
                    st.warning(f"Failed Attempts: {st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        st.error("🔒 Too many failed attempts. Please re-login.")
                        st.session_state.authorized = False
            else:
                st.error("❗ Please enter a passkey.")

       
       
