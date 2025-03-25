from flask import Flask, request, jsonify, render_template
import os
import base64
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# Helper function for OTP (One-Time Pad)
def otp_encrypt(plaintext):
    key = os.urandom(len(plaintext))  # Generate a random key
    ciphertext = bytes([p ^ k for p, k in zip(plaintext.encode(), key)])
    return base64.b64encode(ciphertext).decode(), base64.b64encode(key).decode()

def otp_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    key = base64.b64decode(key)
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    return plaintext.decode()

# Helper function for 3DES
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

# Helper function for AES
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

# Homepage route
@app.route('/')
def home():
    return render_template('index.html')  # Loads the frontend

# API route for encryption
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
    else:
        return jsonify({"error": "Invalid encryption method"}), 400

    return jsonify({"ciphertext": ciphertext, "key": key})

# API route for decryption
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
    else:
        return jsonify({"error": "Invalid decryption method"}), 400

    return jsonify({"plaintext": plaintext})

if __name__ == '__main__':
    app.run(debug=True)
