# app.py
import base64
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify

app = Flask(__name__)

# Kunci harus 4-56 byte
KEY = b'3ncRypt3dFr4m3w0rk0p3r4t10n022!@'  # 32 byte

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json.get('data', '')
        if not data:
            return jsonify({'error': 'Data tidak boleh kosong'}), 400

        data = data.encode('utf-8')
        cipher = Blowfish.new(KEY, Blowfish.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
        encoded = base64.b64encode(ciphertext).decode('utf-8')
        return jsonify({'encrypted': encoded})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json.get('data', '')
        if not data:
            return jsonify({'error': 'Data tidak boleh kosong'}), 400

        ciphertext = base64.b64decode(data)
        cipher = Blowfish.new(KEY, Blowfish.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        decoded = unpad(plaintext, Blowfish.block_size).decode('utf-8')
        return jsonify({'decrypted': decoded})
    except Exception as e:
        return jsonify({'error': f"Gagal dekripsi: {str(e)}"}), 400

@app.route('/')
def home():
    return '<h1>🔐 API Enkripsi Blowfish Aktif</h1>'
