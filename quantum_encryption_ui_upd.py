import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import graphviz

st.set_page_config(page_title="🔐 Quantum-Safe Encryption Demo", layout="wide")

st.title("🔐 Quantum-Safe Encryption (Hybrid AES + RSA)")
st.markdown("### **How does Post-Quantum Hybrid Encryption Work?**")
st.info("This demo encrypts data using **AES-256** for message security and **RSA-4096** for key exchange.")

# Function to generate RSA key pair
def generate_rsa_keypair():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# Encrypt function
def hybrid_encrypt(message, rsa_public_key):
    aes_key = get_random_bytes(32)  # Generate 256-bit AES key
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key).decode(), base64.b64encode(cipher_aes.nonce).decode(), base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode()

# Decrypt function
def hybrid_decrypt(encrypted_aes_key, nonce, ciphertext, tag, rsa_private_key):
    encrypted_aes_key = base64.b64decode(encrypted_aes_key)
    nonce = base64.b64decode(nonce)
    ciphertext = base64.b64decode(ciphertext)
    tag = base64.b64decode(tag)

    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message.decode()

# Interactive Visualization of Encryption Flow
def visualize_encryption_flow():
    dot = graphviz.Digraph()

    # Nodes
    dot.node("A", "🔑 Generate RSA Key Pair", shape="box", style="filled", fillcolor="lightblue")
    dot.node("B", "🛡 Generate AES Key", shape="box", style="filled", fillcolor="lightgreen")
    dot.node("C", "🔒 Encrypt Message (AES-256)", shape="box", style="filled", fillcolor="lightgreen")
    dot.node("D", "🔐 Encrypt AES Key (RSA-4096)", shape="box", style="filled", fillcolor="lightblue")
    dot.node("E", "📤 Send Encrypted AES Key & Ciphertext", shape="box", style="filled", fillcolor="lightgray")

    # Arrows
    dot.edge("A", "D", label="RSA Encrypt")
    dot.edge("B", "C", label="AES Encrypt")
    dot.edge("C", "E", label="Send Data")
    dot.edge("D", "E", label="Send AES Key")

    return dot

def visualize_decryption_flow():
    dot = graphviz.Digraph()

    # Nodes
    dot.node("X", "📥 Receive Encrypted Data", shape="box", style="filled", fillcolor="lightgray")
    dot.node("Y", "🔑 Decrypt AES Key (RSA-4096)", shape="box", style="filled", fillcolor="lightblue")
    dot.node("Z", "🛡 Decrypt Message (AES-256)", shape="box", style="filled", fillcolor="lightgreen")
    dot.node("W", "✅ Retrieve Original Message", shape="box", style="filled", fillcolor="lightgreen")

    # Arrows
    dot.edge("X", "Y", label="RSA Decrypt")
    dot.edge("Y", "Z", label="AES Decrypt")
    dot.edge("Z", "W", label="Retrieve Message")

    return dot

# Generate keys
if st.button("🚀 Generate RSA Key Pair"):
    public_key, private_key = generate_rsa_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key
    st.success("🔑 RSA Key Pair Generated!")

message = st.text_area("✍️ Enter a Message to Encrypt", "Quantum encryption is the future!")

# Encryption Process
if st.button("🔒 Encrypt Message"):
    if "public_key" in st.session_state:
        enc_aes_key, enc_nonce, enc_ciphertext, enc_tag = hybrid_encrypt(message, st.session_state.public_key)
        st.session_state.enc_aes_key = enc_aes_key
        st.session_state.enc_nonce = enc_nonce
        st.session_state.enc_ciphertext = enc_ciphertext
        st.session_state.enc_tag = enc_tag

        st.success("🔒 Message Encrypted Successfully!")
        st.subheader("📜 **Encryption Details**")
        st.code(f"🔑 AES Key (Encrypted): {enc_aes_key[:50]}...")
        st.code(f"🔒 Ciphertext: {enc_ciphertext[:50]}...")

        st.subheader("🔹 Encryption Flow")
        st.graphviz_chart(visualize_encryption_flow())
    else:
        st.error("❌ Generate RSA Key Pair first!")

# Decryption Process
if st.button("🔓 Decrypt Message"):
    if "private_key" in st.session_state:
        decrypted_message = hybrid_decrypt(st.session_state.enc_aes_key, st.session_state.enc_nonce, st.session_state.enc_ciphertext, st.session_state.enc_tag, st.session_state.private_key)
        
        st.success("✅ Decryption Successful!")
        st.subheader("🔍 **Decrypted Message**")
        st.code(decrypted_message, language="plaintext")

        st.subheader("🔹 Decryption Flow")
        st.graphviz_chart(visualize_decryption_flow())
    else:
        st.error("❌ Missing encryption data!")

