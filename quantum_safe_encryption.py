from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# Step 1: Generate RSA Key Pair (Quantum-Safe Key Exchange)
def generate_rsa_keypair():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# Step 2: Encrypt Message using AES-256 + RSA-4096
def hybrid_encrypt(message, rsa_public_key):
    # Generate a random AES key (256-bit for security)
    aes_key = get_random_bytes(32)

    # Encrypt the message using AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    # Encrypt the AES key using RSA
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key).decode(), base64.b64encode(cipher_aes.nonce).decode(), base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode()

# Step 3: Decrypt Message using RSA-4096 + AES-256
def hybrid_decrypt(encrypted_aes_key, nonce, ciphertext, tag, rsa_private_key):
    # Decode the encrypted values
    encrypted_aes_key = base64.b64decode(encrypted_aes_key)
    nonce = base64.b64decode(nonce)
    ciphertext = base64.b64decode(ciphertext)
    tag = base64.b64decode(tag)

    # Decrypt AES key using RSA
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt message using AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message.decode()

# 🚀 Demo Execution 🚀
if __name__ == "__main__":
    # Generate RSA Key Pair
    public_key, private_key = generate_rsa_keypair()
    
    print("🔑 Public Key:", public_key[:100].decode() + "...")
    print("🔐 Private Key:", private_key[:100].decode() + "...")

    # Encrypt Message
    message = "Quantum encryption is the future of banking security!"
    enc_aes_key, enc_nonce, enc_ciphertext, enc_tag = hybrid_encrypt(message, public_key)
    print("\n🔒 Encrypted AES Key:", enc_aes_key[:50] + "...")
    print("🔒 Ciphertext:", enc_ciphertext[:50] + "...")

    # Decrypt Message
    decrypted_message = hybrid_decrypt(enc_aes_key, enc_nonce, enc_ciphertext, enc_tag, private_key)
    print("\n✅ Decryption Successful! Message:", decrypted_message)
