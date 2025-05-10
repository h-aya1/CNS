from flask import Flask, request, jsonify, render_template
import os
import base64
import subprocess
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# ===========================
#  OTP (One-Time Pad) Encryption
# ===========================
def otp_encrypt(plaintext):
    key = os.urandom(len(plaintext))  # Generate a random key
    ciphertext = bytes([p ^ k for p, k in zip(plaintext.encode(), key)])
    return base64.b64encode(ciphertext).decode(), base64.b64encode(key).decode()

def otp_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    key = base64.b64decode(key)
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    return plaintext.decode()

# ===========================
#  3DES Encryption
# ===========================
def des3_encrypt(plaintext):
    key = DES3.adjust_key_parity(get_random_bytes(24))
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = plaintext.ljust(16)  # Simple padding
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode(), base64.b64encode(key).decode()

def des3_decrypt(ciphertext, key):
    key = base64.b64decode(key)
    ciphertext = base64.b64decode(ciphertext)
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext).decode().strip()
    return decrypted

# ===========================
#  AES Encryption
# ===========================
def aes_encrypt(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = plaintext.ljust(16)  # Simple padding
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode(), base64.b64encode(key).decode()

def aes_decrypt(ciphertext, key):
    key = base64.b64decode(key)
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext).decode().strip()
    return decrypted

# ===========================
#  RSA Encryption using OpenSSL
# ===========================
def rsa_encrypt(plaintext):
    with open("plaintext.txt", "w") as f:
        f.write(plaintext)
    
    subprocess.run([
        "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", "public_key.pem", "-in", "plaintext.txt", "-out", "message.enc"
    ], check=True)
    
    with open("message.enc", "rb") as f:
        ciphertext = base64.b64encode(f.read()).decode()
    return ciphertext

def rsa_decrypt(ciphertext):
    with open("message.enc", "wb") as f:
        f.write(base64.b64decode(ciphertext))
    
    subprocess.run([
        "openssl", "pkeyutl", "-decrypt", "-inkey", "private_key.pem", "-in", "message.enc", "-out", "decrypted.txt"
    ], check=True)
    
    with open("decrypted.txt", "r") as f:
        plaintext = f.read()
    return plaintext

# ===========================
#  Flask Routes
# ===========================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    plaintext = data.get("text")
    method = data.get("method")

    if method == "OTP":
        ciphertext, key = otp_encrypt(plaintext)
    elif method == "3DES":
        ciphertext, key = des3_encrypt(plaintext)
    elif method == "AES":
        ciphertext, key = aes_encrypt(plaintext)
    elif method == "RSA":
        ciphertext = rsa_encrypt(plaintext)
        key = "Public key is used; no key needed for encryption"
    else:
        return jsonify({"error": "Invalid encryption method"}), 400

    return jsonify({"ciphertext": ciphertext, "key": key})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    ciphertext = data.get("ciphertext")
    key = data.get("key")
    method = data.get("method")

    if method == "OTP":
        plaintext = otp_decrypt(ciphertext, key)
    elif method == "3DES":
        plaintext = des3_decrypt(ciphertext, key)
    elif method == "AES":
        plaintext = aes_decrypt(ciphertext, key)
    elif method == "RSA":
        plaintext = rsa_decrypt(ciphertext)
    else:
        return jsonify({"error": "Invalid decryption method"}), 400

    return jsonify({"plaintext": plaintext})

if __name__ == '__main__':
    # Run the app with SSL certificates
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
