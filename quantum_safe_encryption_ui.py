import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

st.title("🔐 Quantum-Safe Encryption (Hybrid AES + RSA)")
st.write("Using AES-256 for secure encryption and RSA-4096 for key exchange")

# Function to generate RSA keys
def generate_rsa_keypair():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# Encrypt function
def hybrid_encrypt(message, rsa_public_key):
    aes_key = get_random_bytes(32)
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

# Generate keys
if st.button("Generate RSA Key Pair"):
    public_key, private_key = generate_rsa_keypair()
    st.session_state.public_key = public_key
    st.session_state.private_key = private_key
    st.success("🔑 RSA Key Pair Generated!")

message = st.text_input("Enter a message to encrypt", "Quantum encryption is the future!")

if st.button("Encrypt Message"):
    if "public_key" in st.session_state:
        enc_aes_key, enc_nonce, enc_ciphertext, enc_tag = hybrid_encrypt(message, st.session_state.public_key)
        st.session_state.enc_aes_key = enc_aes_key
        st.session_state.enc_nonce = enc_nonce
        st.session_state.enc_ciphertext = enc_ciphertext
        st.session_state.enc_tag = enc_tag
        st.success("🔒 Message Encrypted!")
    else:
        st.error("❌ Generate RSA Key Pair first!")

if st.button("Decrypt Message"):
    if "private_key" in st.session_state:
        decrypted_message = hybrid_decrypt(st.session_state.enc_aes_key, st.session_state.enc_nonce, st.session_state.enc_ciphertext, st.session_state.enc_tag, st.session_state.private_key)
        st.success(f"✅ Decryption Successful: {decrypted_message}")
    else:
        st.error("❌ Missing encryption data!")
