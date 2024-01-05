from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import time

def generate_rsa_key_pair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

def get_file_size(file_path):
    return os.path.getsize(file_path)

def encrypt_file_rsa_aes(file_path, public_key_path, output_file_path):
    start_time = time.time()  # Start timing
    data = None
    with open(file_path, 'rb') as file:
        data = file.read()

    aes_key = os.urandom(24)  # Generate a random AES key
    cipher_rsa = serialization.load_pem_public_key(load_key_from_file(public_key_path))
    encrypted_aes_key = cipher_rsa.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = os.urandom(16)  # Initialization Vector for AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    padded_data = encryptor.update(data) + encryptor.finalize()

    with open(output_file_path, 'wb') as file:
        file.write(encrypted_aes_key + iv + padded_data)

    end_time = time.time()  # End timing
    execution_time = end_time - start_time
    print(f"Encryption Time: {execution_time} seconds")
    print(f"Original File Size: {get_file_size(file_path)} bytes")
    print(f"Encrypted File Size: {get_file_size(output_file_path)} bytes")

def decrypt_file_rsa_aes(file_path, private_key_path, output_file_path):
    start_time = time.time()
    encrypted_data = None
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    private_key = serialization.load_pem_private_key(
        load_key_from_file(private_key_path),
        password=None
    )

    encrypted_aes_key = encrypted_data[:private_key.key_size // 8]
    iv = encrypted_data[private_key.key_size // 8: private_key.key_size // 8 + 16]
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[private_key.key_size // 8 + 16:]) + decryptor.finalize()

    with open(output_file_path, 'wb') as file:
        file.write(decrypted_data)

    end_time = time.time()  # End timing
    execution_time = end_time - start_time
    print(f"Decryption Time: {execution_time} seconds")
    print(f"Encrypted File Size: {get_file_size(file_path)} bytes")
    print(f"Decrypted File Size: {get_file_size(output_file_path)} bytes")

# Penggunaan
# 1. Generate key pair (jalankan hanya sekali)
private_key = generate_rsa_key_pair()
public_key = private_key.public_key()

save_key_to_file(
    public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
    'public_key.pem'
)

save_key_to_file(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ),
    'private_key.pem'
)

# 2. Enkripsi file menggunakan public key
encrypt_file_rsa_aes('kalimat.txt', 'public_key.pem', 'kalimat.txt.enc')

# 3. Dekripsi file menggunakan private key
decrypt_file_rsa_aes('kalimat.txt.enc', 'private_key.pem', 'kalimat_dekripsi.txt')
