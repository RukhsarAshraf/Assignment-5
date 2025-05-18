import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
import streamlit as st

# Convert password to Fernet-compatible key
def generate_key(password):
    if not password:
        raise ValueError("Password cannot be empty")
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# Encrypt the input text
def encrypt_text(text, password):
    if not text:
        raise ValueError("Text cannot be empty")
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode()

# Decrypt the encrypted text
def decrypt_text(encrypted_text, password):
    if not encrypted_text:
        raise ValueError("Encrypted text cannot be empty")
    key = generate_key(password)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except InvalidToken:
        return "❌ Decryption failed - wrong password or corrupted data"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# Streamlit UI
st.set_page_config(page_title="Secure Encryption App", layout="centered")

# Custom CSS to make all text black except headings
st.markdown("""
    <style>
        body, .stText, .stTextInput, .stTextArea, .stRadio, .stDownloadButton button, .stButton button, .stAlert {
            color: black !important;
        }
        .block-container {
            font-size: 16px;
        }
    </style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='text-align: center; color: #4CAF50;'>🔐 Secure Data Encryption </h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Protect your sensitive messages using strong password-based encryption.</p>", unsafe_allow_html=True)

st.info("💡 *Tip: If you forget the password, your encrypted data can't be recovered.*")

st.markdown("---")

# Input layout
st.markdown("### 📝 Enter Details Below")
col1, col2 = st.columns(2)

with col1:
    text = st.text_area("✍️ Message", height=150, placeholder="Type or paste your message here...")

with col2:
    password = st.text_input("🔑 Password", type="password", placeholder="Enter strong password")
    mode = st.radio("🔁 Choose Action", ["Encrypt", "Decrypt"], horizontal=True)
    show_confirm = st.toggle("✔️ Confirm password (for encryption)")
    confirm_pass = st.text_input("🔁 Re-enter Password", type="password", placeholder="Repeat password") if show_confirm and mode == "Encrypt" else None

# Action button
st.markdown("")

if st.button("🚀 Process Now"):
    if not text or not password:
        st.error("⚠️ Please provide both the message and the password.")
    elif mode == "Encrypt" and confirm_pass and password != confirm_pass:
        st.error("❗ Passwords do not match. Please try again.")
    else:
        try:
            if mode == "Encrypt":
                result = encrypt_text(text, password)
                st.success("✅ Message Encrypted Successfully!")
                st.code(result)
                st.download_button("📥 Download Encrypted Text", result, file_name="encrypted.txt")
            else:
                result = decrypt_text(text, password)
                if result.startswith("❌"):
                    st.error(result)
                else:
                    st.success("🔓 Message Decrypted Successfully!")
                    st.code(result)
        except Exception as e:
            st.error(f"❌ Unexpected Error: {str(e)}")

# Footer
st.markdown("---")
st.markdown("<p style='text-align: center; font-size: 0.9em;'>Built with ❤️ using Streamlit</p>", unsafe_allow_html=True)
