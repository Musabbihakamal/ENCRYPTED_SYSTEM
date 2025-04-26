 in st.session_state:
    st.session_state.failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

st.title("🔒 Simple Secure Data Storage")

# Login page after 3 wrong tries
if not st.session_state.authorized:
    st.subheader("🔑 Please Login Again")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username == "admin" and password == "1234":
            st.success("Login Successful!")
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
        else:
            st.error("Incorrect Username or Password")

# Main app if authorized
else:
    menu = st.sidebar.selectbox("Menu", ["🏠 Home", "➕ Insert Data", "🔍 Retrieve Data"])

    if menu == "🏠 Home":
        st.write("👋 Welcome! Save and retrieve your text securely using a secret passkey.")

    elif menu == "➕ Insert Data":
        st.subheader("➕ Insert New Data")
        text = st.text_area("Enter your text:")
        passkey = st.text_input("Enter a passkey:", type="password")

        if st.button("Save Data"):
            if text and passkey:
                hashed_key = hash_passkey(passkey)
                stored_data[hashed_key] = text
                st.success("✅ Data Stored Successfully!")
            else:
                st.error("Please fill all fields!")

    elif menu == "🔍 Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Retrieve"):
            if passkey:
                hashed_key = hash_passkey(passkey)
                if hashed_key in stored_data:
                    st.success("✅ Data Retrieved Successfully!")
                    st.write(stored_data[hashed_key])
                    st.session_state.failed_attempts = 0
                else:
                    st.error("Wrong passkey!")
                    st.session_state.failed_attempts += 1
                    st.warning(f"❌ Attempts: {st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= 3:
                        st.session_state.authorized = False
                        st.error("🚫 Too many wrong tries. Login required!")
            else:
                st.error("Please enter a passkey.")
