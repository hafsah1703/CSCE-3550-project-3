from flask import Flask, request, jsonify
import os
import secrets
import sqlite3
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
ph = PasswordHasher()

# Function to generate a random AES encryption key
def generate_aes_key():
    return secrets.token_bytes(32)  # 32 bytes for AES-256

# Function to encrypt a private key using AES-GCM
def encrypt_private_key(private_key, encryption_key):
    iv = os.urandom(12)  
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(private_key.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# Function to decrypt an encrypted private key using AES-GCM
def decrypt_private_key(encrypted_data, encryption_key):
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Function to create the users table in the database
def create_users_table():
    # Print the current working directory to verify the path
    print("Current working directory:", os.getcwd())

    conn = sqlite3.connect('your_database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL UNIQUE,
                 password_hash TEXT NOT NULL,
                 email TEXT UNIQUE,
                 date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 last_login TIMESTAMP)''')
    conn.commit()
    conn.close()

    print("Users table created successfully")

# Function to register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    # Generate a secure password for the user
    password = secrets.token_urlsafe(32)  # Increase length to 32 characters
    password_hash = ph.hash(password)

    try:
        # Save the user details to the database
        conn = sqlite3.connect('your_database.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Email address already in use'}), 409  # HTTP status code 409 for conflict

    return jsonify({'password': password}), 201

# Function to authenticate a user
@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Log the authentication request
    request_ip = request.remote_addr

    # Retrieve the hashed password from the database
    conn = sqlite3.connect('your_database.db')
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result:
        user_id, stored_password_hash = result
        # Log the authentication request
        log_auth_request(request_ip, user_id)
        try:
            # Verify the password using the stored hash
            if ph.verify(stored_password_hash, password):
                return jsonify({'message': 'Authentication successful'}), 200
            else:
                return jsonify({'message': 'Authentication failed'}), 401
        except Exception as e:
            return jsonify({'message': 'Error verifying password'}), 500
    else:
        return jsonify({'message': 'User not found'}), 404

# Function to log authentication requests
def log_auth_request(request_ip, user_id):
    conn = sqlite3.connect('your_database.db')
    c = conn.cursor()
    c.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
    conn.commit()
    conn.close()

# Example usage
if __name__ == '__main__':
    create_users_table()
    app.run(debug=True, port=8080)
